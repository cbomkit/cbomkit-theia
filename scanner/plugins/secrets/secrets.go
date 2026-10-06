// Copyright 2024 PQCA
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package secrets

import (
	_ "embed"
	"io"
	"strings"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"

	"github.com/cbomkit/cbomkit-theia/provider/filesystem"
	"github.com/cbomkit/cbomkit-theia/scanner/pem"
	"github.com/cbomkit/cbomkit-theia/scanner/plugins"

	cdx "github.com/CycloneDX/cyclonedx-go"
	gitleaksConfig "github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/detect"
	"github.com/zricethezav/gitleaks/v8/report"
)

// extraGitleaksRules holds cbomkit-theia's additional Gitleaks rules. They are appended to
// Gitleaks' default configuration rather than layered on with `[extend] useDefault = true`, see
// newSecretsDetector.
//
//go:embed gitleaks.toml
var extraGitleaksRules string

// pathFallbackRuleContentCounterparts maps the rule ID of a path-only fallback rule (which flags
// a file by extension alone, catching raw-DER key material with no PEM text markers) to the
// content-based rule ID(s) that supersede it whenever the same file also matches on content.
var pathFallbackRuleContentCounterparts = map[string][]string{
	"public-key-file": {"pem-public-key"},
}

func NewSecretsPlugin() (plugins.Plugin, error) {
	return &Plugin{}, nil
}

type Plugin struct{}

func (*Plugin) GetName() string {
	return "Secret Detection Plugin"
}

func (*Plugin) GetExplanation() string {
	return "Find Secrets & Keys"
}

func (*Plugin) GetType() plugins.PluginType {
	return plugins.PluginTypeAppend
}

type findingWithMetadata struct {
	report.Finding
	raw []byte
}

func (*Plugin) UpdateBOM(fs filesystem.Filesystem, bom *cdx.BOM) error {
	detector, err := newSecretsDetector()
	if err != nil {
		return err
	}
	// Detect findings
	components := make([]cdx.Component, 0)
	if err := fs.WalkDir(func(path string) error {
		// Skip large files
		maxFileSize := viper.GetInt64("keys.max_file_size")
		if maxFileSize <= 0 {
			maxFileSize = 1024 * 1024 // Default to 1MB
		}

		readCloser, err := fs.Open(path)
		if err != nil {
			return nil // skip and continue
		}
		defer readCloser.Close()

		limitReader := io.LimitReader(readCloser, maxFileSize+1)
		content, err := io.ReadAll(limitReader)
		if err != nil {
			log.WithField("path", path).Warn("Unable to read file")
			return nil
		}

		// Skip large files
		if int64(len(content)) > maxFileSize {
			log.Warnf("Skipping large file: %s (exceeds limit of %d bytes)", path, maxFileSize)
			return nil
		}

		fragment := detect.Fragment{Raw: string(content), FilePath: path}
		findings := detector.Detect(fragment)

		// A path-only fallback rule (e.g. "public-key-file") and its content-based counterpart
		// (e.g. "pem-public-key") can both match the same file - the fallback exists only to
		// catch raw-DER files the content regex can't see. When the content rule also matched,
		// skip the fallback's finding so it doesn't add a redundant generic-secret component.
		matchedRuleIDs := make(map[string]bool, len(findings))
		for _, finding := range findings {
			matchedRuleIDs[finding.RuleID] = true
		}

		for _, finding := range findings {
			if isSupersededPathFallback(finding.RuleID, matchedRuleIDs) {
				continue
			}

			// Hand each finding only the text its rule matched, not the whole file. Otherwise every
			// finding would re-parse every key in the file, yielding N*N components for N keys.
			findingMeta := findingWithMetadata{
				Finding: finding,
				raw:     []byte(finding.Match),
			}
			log.WithFields(log.Fields{
				"type": finding.RuleID, "file": finding.File,
			}).Info("Secret detected")

			// Create CDX Components
			currentComponents, err := findingMeta.getComponents()
			if err != nil {
				log.WithError(err).Warn("Could not add secret finding to BOM component")
				continue
			}
			components = append(components, currentComponents...)
		}
		return nil
	}); err != nil {
		log.WithError(err).Error("Error while trying to scan for secrets")
		return err
	}

	if len(components) == 0 {
		log.Info("No secrets found.")
		return nil
	}

	// Write  bom
	*bom.Components = append(*bom.Components, components...)
	return nil
}

// isSupersededPathFallback reports whether ruleID is a path-only fallback rule whose
// content-based counterpart also matched the same file.
func isSupersededPathFallback(ruleID string, matchedRuleIDs map[string]bool) bool {
	for _, contentRuleID := range pathFallbackRuleContentCounterparts[ruleID] {
		if matchedRuleIDs[contentRuleID] {
			return true
		}
	}
	return false
}

// newSecretsDetector builds a Gitleaks detector from Gitleaks' default rules plus
// extraGitleaksRules. It keeps the detection rules and content allowlists, but leaves file
// exclusion to the filesystem's explicit ignore patterns: Gitleaks' default global allowlist
// otherwise suppresses all findings under paths such as node_modules, even when the user has not
// ignored them in Theia.
//
// Two Gitleaks behaviours are deliberately avoided here:
//   - `[extend] useDefault = true` increments a package-global depth counter in Gitleaks that is
//     never reset, so from the third detector onward the default rules are silently dropped. The
//     extra rules are therefore merged into the default rules in Go (see mergeExtraRules), with
//     the same semantics as `[extend]`.
//   - detect.NewDetectorDefaultConfig replaces the application's global Viper configuration, so a
//     private Viper instance is used.
func newSecretsDetector() (*detect.Detector, error) {
	return newDetectorWithExtraRules(extraGitleaksRules)
}

func newDetectorWithExtraRules(extraRules string) (*detect.Detector, error) {
	parsed, err := parseGitleaksConfig(gitleaksConfig.DefaultConfig)
	if err != nil {
		return nil, err
	}
	extra, err := parseGitleaksConfig(extraRules)
	if err != nil {
		return nil, err
	}
	mergeExtraRules(&parsed, extra)

	cfg, err := parsed.Translate()
	if err != nil {
		return nil, err
	}
	if err := removePathAllowlists(&cfg); err != nil {
		return nil, err
	}
	return detect.NewDetector(cfg), nil
}

// parseGitleaksConfig reads TOML through a private Viper instance so the application's global
// Viper configuration is left alone.
func parseGitleaksConfig(toml string) (gitleaksConfig.ViperConfig, error) {
	settings := viper.New()
	settings.SetConfigType("toml")
	var parsed gitleaksConfig.ViperConfig
	if err := settings.ReadConfig(strings.NewReader(toml)); err != nil {
		return parsed, err
	}
	err := settings.Unmarshal(&parsed)
	return parsed, err
}

// mergeExtraRules adds extra's rules to base the way Gitleaks' `[extend]` does: a rule with a new
// ID is added, and a rule reusing an existing ID is merged into it. Description, path, regex,
// entropy and secret group replace the base's when set; tags, keywords and allowlists are
// appended. Merging happens before Translate so validation sees the finished rule.
func mergeExtraRules(base *gitleaksConfig.ViperConfig, extra gitleaksConfig.ViperConfig) {
	index := make(map[string]int, len(base.Rules))
	for i, rule := range base.Rules {
		index[rule.ID] = i
	}
	for _, rule := range extra.Rules {
		i, exists := index[rule.ID]
		if !exists {
			index[rule.ID] = len(base.Rules)
			base.Rules = append(base.Rules, rule)
			continue
		}
		merged := &base.Rules[i]
		if rule.Description != "" {
			merged.Description = rule.Description
		}
		if rule.Entropy != 0 {
			merged.Entropy = rule.Entropy
		}
		if rule.SecretGroup != 0 {
			merged.SecretGroup = rule.SecretGroup
		}
		if rule.Regex != "" {
			merged.Regex = rule.Regex
		}
		if rule.Path != "" {
			merged.Path = rule.Path
		}
		merged.Tags = append(merged.Tags, rule.Tags...)
		merged.Keywords = append(merged.Keywords, rule.Keywords...)
		merged.Allowlists = append(merged.Allowlists, rule.Allowlists...)
		if rule.AllowList != nil {
			merged.Allowlists = append(merged.Allowlists, rule.AllowList)
		}
	}
	base.Allowlists = append(base.Allowlists, extra.Allowlists...)
}

// removePathAllowlists drops the path-based part of cfg's global allowlists.
func removePathAllowlists(cfg *gitleaksConfig.Config) error {
	globalAllowlists := make([]*gitleaksConfig.Allowlist, 0, len(cfg.Allowlists))
	for _, allowlist := range cfg.Allowlists {
		if len(allowlist.Paths) == 0 {
			globalAllowlists = append(globalAllowlists, allowlist)
			continue
		}
		// An AND allowlist with a path condition cannot retain its original
		// meaning after removing the path, so discard it instead.
		if allowlist.MatchCondition == gitleaksConfig.AllowlistMatchAnd {
			continue
		}

		withoutPaths := &gitleaksConfig.Allowlist{
			Description:    allowlist.Description,
			MatchCondition: allowlist.MatchCondition,
			Commits:        allowlist.Commits,
			RegexTarget:    allowlist.RegexTarget,
			Regexes:        allowlist.Regexes,
			StopWords:      allowlist.StopWords,
		}
		if len(withoutPaths.Commits) == 0 && len(withoutPaths.Regexes) == 0 && len(withoutPaths.StopWords) == 0 {
			continue
		}
		if err := withoutPaths.Validate(); err != nil {
			return err
		}
		globalAllowlists = append(globalAllowlists, withoutPaths)
	}
	cfg.Allowlists = globalAllowlists
	return nil
}

func (finding findingWithMetadata) getComponents() ([]cdx.Component, error) {
	switch finding.RuleID {
	case "private-key":
		return finding.getPrivateKeyComponent()
	case "pem-public-key":
		return finding.getPEMPublicKeyComponent()
	}
	return []cdx.Component{finding.getGenericSecretComponent()}, nil
}

func (finding findingWithMetadata) getPrivateKeyComponent() ([]cdx.Component, error) {
	// Filter for private keys only
	privateKeyFilter := pem.Filter{
		FilterType: pem.TypeAllowlist,
		List: []pem.BlockType{
			pem.BlockTypePrivateKey,
			pem.BlockTypeEncryptedPrivateKey,
			pem.BlockTypeRSAPrivateKey,
			pem.BlockTypeECPrivateKey,
			pem.BlockTypeOPENSSHPrivateKey,
		},
	}

	// Parse PEM blocks
	blocks := pem.ParsePEMToBlocksWithTypeFilter(finding.raw, privateKeyFilter)
	if len(blocks) == 0 {
		return []cdx.Component{finding.getGenericSecretComponent()}, nil
	}

	log.Infof("Found %d private key(s) in %s", len(blocks), finding.File)

	components := make([]cdx.Component, 0)
	for block := range blocks {
		currentComponents, err := pem.GenerateCdxComponents(block)
		if err != nil {
			// The PEM block is a recognized private-key type (e.g. encrypted, or otherwise
			// undecodable), but its contents could not be parsed into key material. Still
			// record it as a generic secret rather than dropping a confirmed finding.
			log.WithError(err).WithField("path", finding.File).Warn("Found private key PEM block but could not parse its key material; recording as generic secret")
			components = append(components, finding.getGenericSecretComponent())
			continue
		}

		finding.annotateComponents(currentComponents)
		components = append(components, currentComponents...)
	}
	return components, nil
}

// annotateComponents appends finding's description onto each component's existing description
// (joined by ";", or set outright if the component has none) and attaches an Evidence occurrence
// pointing at finding's location.
func (finding findingWithMetadata) annotateComponents(components []cdx.Component) {
	for i := range components {
		if description := components[i].Description; description != "" {
			components[i].Description = strings.Join([]string{description, finding.Description}, ";")
		} else {
			components[i].Description = finding.Description
		}
		components[i].Evidence = &cdx.Evidence{
			Occurrences: &[]cdx.EvidenceOccurrence{
				{
					Location: finding.File,
					Line:     &finding.StartLine,
				},
			},
		}
	}
}

func (finding findingWithMetadata) getPEMPublicKeyComponent() ([]cdx.Component, error) {
	publicKeyFilter := pem.Filter{
		FilterType: pem.TypeAllowlist,
		List: []pem.BlockType{
			pem.BlockTypePublicKey,
			pem.BlockTypeRSAPublicKey,
		},
	}

	blocks := pem.ParsePEMToBlocksWithTypeFilter(finding.raw, publicKeyFilter)
	if len(blocks) == 0 {
		return []cdx.Component{finding.getGenericSecretComponent()}, nil
	}

	log.Infof("Found %d public key(s) in %s", len(blocks), finding.File)

	components := make([]cdx.Component, 0)
	for block := range blocks {
		currentComponents, err := pem.GenerateCdxComponents(block)
		if err != nil {
			// A recognized public-key block whose contents could not be parsed is still a
			// confirmed finding; record it as a generic secret rather than dropping it.
			log.WithError(err).WithField("path", finding.File).Warn("Found public key PEM block but could not parse its key material; recording as generic secret")
			components = append(components, finding.getGenericSecretComponent())
			continue
		}

		finding.annotateComponents(currentComponents)
		components = append(components, currentComponents...)
	}
	return components, nil
}

func (finding findingWithMetadata) getGenericSecretComponent() cdx.Component {
	return cdx.Component{
		Name:        finding.RuleID,
		Description: finding.Description,
		Type:        cdx.ComponentTypeCryptographicAsset,
		CryptoProperties: &cdx.CryptoProperties{
			AssetType: cdx.CryptoAssetTypeRelatedCryptoMaterial,
			RelatedCryptoMaterialProperties: &cdx.RelatedCryptoMaterialProperties{
				Type: getRelatedCryptoAssetTypeFromRuleID(finding.RuleID),
			},
		},
		Evidence: &cdx.Evidence{
			Occurrences: &[]cdx.EvidenceOccurrence{
				{
					Location: finding.File,
					Line:     &finding.StartLine,
				},
			},
		},
	}
}

func getRelatedCryptoAssetTypeFromRuleID(id string) cdx.RelatedCryptoMaterialType {
	switch {
	case strings.Contains(id, "private-key"):
		return cdx.RelatedCryptoMaterialTypePrivateKey
	case strings.Contains(id, "token") ||
		strings.Contains(id, "jwt"):
		return cdx.RelatedCryptoMaterialTypeToken
	case strings.Contains(id, "key"):
		return cdx.RelatedCryptoMaterialTypeKey
	case strings.Contains(id, "password"):
		return cdx.RelatedCryptoMaterialTypePassword
	default:
		return cdx.RelatedCryptoMaterialTypeUnknown
	}
}
