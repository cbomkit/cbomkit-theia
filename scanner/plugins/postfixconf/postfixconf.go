// Copyright 2025 PQCA
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

package postfixconf

import (
	"bufio"
	"io"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
	provcdx "github.com/cbomkit/cbomkit-theia/provider/cyclonedx"
	"github.com/cbomkit/cbomkit-theia/provider/filesystem"
	"github.com/cbomkit/cbomkit-theia/scanner/plugins"
	"github.com/cbomkit/cbomkit-theia/scanner/plugins/certresolver"
	"github.com/cbomkit/cbomkit-theia/scanner/tls"
	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"
)

// Plugin implements plugins.Plugin
// It scans for Postfix main.cf configuration files and extracts TLS settings as CBOM components.
type Plugin struct{}

func NewPostfixConfPlugin() (plugins.Plugin, error) { return &Plugin{}, nil }

func (*Plugin) GetName() string { return "Postfix Config Plugin" }

func (*Plugin) GetExplanation() string {
	return "Scans for Postfix main.cf configuration files and extracts TLS settings (protocols, ciphers, certificates) as CBOM components."
}

func (*Plugin) GetType() plugins.PluginType { return plugins.PluginTypeAppend }

func (p *Plugin) UpdateBOM(fs filesystem.Filesystem, bom *cdx.BOM) error {
	found := make([]configFinding, 0)
	if err := fs.WalkDir(func(path string) error {
		if isPostfixConf(path) {
			exists, err := fs.Exists(path)
			if err != nil {
				return err
			} else if !exists {
				return nil
			}
			rc, err := fs.Open(path)
			if err != nil {
				return nil
			}
			defer rc.Close()
			settings, err := parsePostfixConf(rc)
			if err != nil {
				log.WithError(err).WithField("path", path).Warn("Failed to parse Postfix config")
				return nil
			}
			if hasTLSDirectives(settings) {
				found = append(found, configFinding{path: path, settings: settings})
				log.WithFields(log.Fields{"file": path}).Info("Postfix TLS config detected")
			}
		}
		return nil
	}); err != nil {
		return err
	}

	if len(found) == 0 {
		log.Info("No Postfix TLS configuration files found.")
		return nil
	}

	components := make([]cdx.Component, 0)

	for _, f := range found {
		props := extractRelevantProperties(f.settings)

		fileComp := cdx.Component{
			Type:        cdx.ComponentTypeFile,
			Name:        filepath.Base(f.path),
			Description: "Postfix TLS configuration",
			BOMRef:      uuid.New().String(),
			Properties:  &props,
			Evidence:    &cdx.Evidence{Occurrences: &[]cdx.EvidenceOccurrence{{Location: f.path}}},
		}
		components = append(components, fileComp)

		// Build protocol components for inbound (smtpd)
		smtpdVersions := detectTLSVersions(f.settings, "smtpd_tls_protocols", "smtpd_tls_mandatory_protocols")
		smtpdSuites := detectCipherSuiteNames(f.settings, "tls_high_cipherlist", "tls_medium_cipherlist")
		if len(smtpdVersions) > 0 && len(smtpdSuites) > 0 {
			for _, v := range smtpdVersions {
				algoComps, protoComp, depMap := tls.BuildTLSProtocolComponents(v, smtpdSuites, f.path)
				if len(algoComps) > 0 {
					components = append(components, algoComps...)
				}
				if protoComp != nil {
					components = append(components, *protoComp)
				}
				if len(depMap) > 0 {
					provcdx.AddDependencies(bom, depMap)
				}
			}
		}

		// Build protocol components for outbound (smtp)
		smtpVersions := detectTLSVersions(f.settings, "smtp_tls_protocols", "smtp_tls_mandatory_protocols")
		if len(smtpVersions) > 0 && len(smtpdSuites) > 0 {
			for _, v := range smtpVersions {
				algoComps, protoComp, depMap := tls.BuildTLSProtocolComponents(v, smtpdSuites, f.path)
				if len(algoComps) > 0 {
					components = append(components, algoComps...)
				}
				if protoComp != nil {
					components = append(components, *protoComp)
				}
				if len(depMap) > 0 {
					provcdx.AddDependencies(bom, depMap)
				}
			}
		}

		// Build crypto-material components
		cryptoComps, certDeps := buildCryptoMaterialComponents(f.settings, f.path, fs, fileComp.BOMRef)
		components = append(components, cryptoComps...)
		if len(certDeps) > 0 {
			provcdx.AddDependencies(bom, certDeps)
		}
	}

	sort.Slice(components, func(i, j int) bool { return components[i].BOMRef < components[j].BOMRef })

	if bom.Components == nil {
		comps := make([]cdx.Component, 0, len(components))
		bom.Components = &comps
	}
	*bom.Components = append(*bom.Components, components...)
	return nil
}

type configFinding struct {
	path     string
	settings map[string]string
}

func isPostfixConf(path string) bool {
	name := strings.ToLower(filepath.Base(path))
	if name == "main.cf" {
		return strings.Contains(strings.ToLower(path), "postfix")
	}
	return false
}

// parsePostfixConf parses Postfix main.cf format: parameter = value, one per line.
// Supports continuation lines (lines starting with whitespace).
func parsePostfixConf(rc io.Reader) (map[string]string, error) {
	scanner := bufio.NewScanner(rc)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	cfg := make(map[string]string)

	var currentKey, currentValue string

	flushCurrent := func() {
		if currentKey != "" {
			cfg[currentKey] = strings.TrimSpace(currentValue)
		}
	}

	for scanner.Scan() {
		line := scanner.Text()
		// Skip comments
		if trimmed := strings.TrimSpace(line); trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}

		// Continuation line (starts with whitespace)
		if len(line) > 0 && (line[0] == ' ' || line[0] == '\t') {
			if currentKey != "" {
				currentValue += " " + strings.TrimSpace(line)
			}
			continue
		}

		// New directive
		flushCurrent()

		parts := strings.SplitN(strings.TrimSpace(line), "=", 2)
		if len(parts) < 2 {
			currentKey = ""
			currentValue = ""
			continue
		}
		currentKey = strings.TrimSpace(parts[0])
		currentValue = strings.TrimSpace(parts[1])
	}
	flushCurrent()

	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return cfg, nil
}

func hasTLSDirectives(cfg map[string]string) bool {
	for k := range cfg {
		if strings.Contains(k, "tls") || strings.Contains(k, "TLS") {
			return true
		}
	}
	return false
}

var tlsVersionRe = regexp.MustCompile(`(?i)TLSv?(\d(?:\.\d)?)`)

func detectTLSVersions(cfg map[string]string, keys ...string) []string {
	versions := make([]string, 0, 4)
	seen := map[string]struct{}{}

	for _, key := range keys {
		if protocols, ok := cfg[key]; ok && protocols != "" {
			// Postfix protocol format: "!SSLv2, !SSLv3, !TLSv1, !TLSv1.1"
			// or "TLSv1.2, TLSv1.3"
			for _, token := range strings.FieldsFunc(protocols, func(r rune) bool { return r == ',' || r == ' ' }) {
				token = strings.TrimSpace(token)
				if strings.HasPrefix(token, "!") {
					continue // excluded
				}
				if m := tlsVersionRe.FindStringSubmatch(token); len(m) == 2 {
					if _, ex := seen[m[1]]; !ex {
						versions = append(versions, m[1])
						seen[m[1]] = struct{}{}
					}
				}
			}
		}
	}

	sort.Strings(versions)
	return versions
}

func detectCipherSuiteNames(cfg map[string]string, keys ...string) []string {
	names := make([]string, 0)
	seen := map[string]struct{}{}

	for _, key := range keys {
		if ciphers, ok := cfg[key]; ok && ciphers != "" {
			opensslNames := strings.Split(ciphers, ":")
			mapped := tls.MapOpenSSLNamesToTLS(opensslNames)
			for _, n := range mapped {
				if _, exists := seen[n]; !exists {
					seen[n] = struct{}{}
					names = append(names, n)
				}
			}
		}
	}

	sort.Strings(names)
	return names
}

func buildCryptoMaterialComponents(cfg map[string]string, srcPath string, fs filesystem.Filesystem, fileCompBOMRef string) ([]cdx.Component, map[cdx.BOMReference][]string) {
	components := make([]cdx.Component, 0)
	depMap := make(map[cdx.BOMReference][]string)

	resolveCert := func(certPath string) {
		resolved, certDeps, certRefs := certresolver.ResolveCertificateComponents(fs, certPath)
		if resolved != nil {
			components = append(components, resolved...)
			for k, v := range certDeps {
				depMap[k] = append(depMap[k], v...)
			}
			for _, ref := range certRefs {
				depMap[cdx.BOMReference(fileCompBOMRef)] = append(depMap[cdx.BOMReference(fileCompBOMRef)], ref)
			}
		} else {
			components = append(components, makeCertificateComponent(certPath))
		}
	}

	// Inbound (smtpd) certs
	if certPath, ok := cfg["smtpd_tls_cert_file"]; ok && certPath != "" {
		resolveCert(certPath)
	}
	if keyPath, ok := cfg["smtpd_tls_key_file"]; ok && keyPath != "" {
		components = append(components, makePrivateKeyComponent(keyPath))
	}
	if caPath, ok := cfg["smtpd_tls_CAfile"]; ok && caPath != "" {
		resolveCert(caPath)
	}

	// Outbound (smtp) certs
	if certPath, ok := cfg["smtp_tls_cert_file"]; ok && certPath != "" {
		resolveCert(certPath)
	}
	if keyPath, ok := cfg["smtp_tls_key_file"]; ok && keyPath != "" {
		components = append(components, makePrivateKeyComponent(keyPath))
	}
	if caPath, ok := cfg["smtp_tls_CAfile"]; ok && caPath != "" {
		resolveCert(caPath)
	}

	// DH parameters
	if dhPath, ok := cfg["smtpd_tls_dh1024_param_file"]; ok && dhPath != "" {
		components = append(components, cdx.Component{
			Type:   cdx.ComponentTypeCryptographicAsset,
			Name:   filepath.Base(dhPath),
			BOMRef: uuid.New().String(),
			CryptoProperties: &cdx.CryptoProperties{
				AssetType: cdx.CryptoAssetTypeRelatedCryptoMaterial,
				RelatedCryptoMaterialProperties: &cdx.RelatedCryptoMaterialProperties{
					Type: cdx.RelatedCryptoMaterialTypePublicKey,
				},
			},
			Evidence: &cdx.Evidence{Occurrences: &[]cdx.EvidenceOccurrence{{Location: dhPath}}},
		})
	}

	return components, depMap
}

func makeCertificateComponent(certPath string) cdx.Component {
	return cdx.Component{
		Type:   cdx.ComponentTypeCryptographicAsset,
		Name:   filepath.Base(certPath),
		BOMRef: uuid.New().String(),
		CryptoProperties: &cdx.CryptoProperties{
			AssetType:             cdx.CryptoAssetTypeCertificate,
			CertificateProperties: &cdx.CertificateProperties{},
		},
		Evidence: &cdx.Evidence{Occurrences: &[]cdx.EvidenceOccurrence{{Location: certPath}}},
	}
}

func makePrivateKeyComponent(keyPath string) cdx.Component {
	return cdx.Component{
		Type:   cdx.ComponentTypeCryptographicAsset,
		Name:   filepath.Base(keyPath),
		BOMRef: uuid.New().String(),
		CryptoProperties: &cdx.CryptoProperties{
			AssetType: cdx.CryptoAssetTypeRelatedCryptoMaterial,
			RelatedCryptoMaterialProperties: &cdx.RelatedCryptoMaterialProperties{
				Type: cdx.RelatedCryptoMaterialTypePrivateKey,
			},
		},
		Evidence: &cdx.Evidence{Occurrences: &[]cdx.EvidenceOccurrence{{Location: keyPath}}},
	}
}

func extractRelevantProperties(cfg map[string]string) []cdx.Property {
	properties := make([]cdx.Property, 0)
	keys := []string{
		"smtpd_tls_cert_file",
		"smtpd_tls_key_file",
		"smtpd_tls_CAfile",
		"smtpd_tls_security_level",
		"smtpd_tls_protocols",
		"smtpd_tls_mandatory_protocols",
		"smtpd_tls_ciphers",
		"smtpd_tls_mandatory_ciphers",
		"smtpd_tls_exclude_ciphers",
		"smtp_tls_cert_file",
		"smtp_tls_key_file",
		"smtp_tls_CAfile",
		"smtp_tls_security_level",
		"smtp_tls_protocols",
		"smtp_tls_mandatory_protocols",
		"tls_high_cipherlist",
		"tls_medium_cipherlist",
		"tls_preempt_cipherlist",
	}
	for _, k := range keys {
		if v, ok := cfg[k]; ok && v != "" {
			properties = append(properties, cdx.Property{Name: "theia:postfix:" + k, Value: v})
		}
	}
	return properties
}
