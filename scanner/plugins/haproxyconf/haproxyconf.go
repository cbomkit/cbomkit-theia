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

package haproxyconf

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
// It scans for HAProxy configuration files and extracts SSL/TLS settings as CBOM components.
type Plugin struct{}

func NewHAProxyConfPlugin() (plugins.Plugin, error) { return &Plugin{}, nil }

func (*Plugin) GetName() string { return "HAProxy Config Plugin" }

func (*Plugin) GetExplanation() string {
	return "Scans for HAProxy configuration files and extracts SSL/TLS settings (protocols, ciphers, certificates) as CBOM components."
}

func (*Plugin) GetType() plugins.PluginType { return plugins.PluginTypeAppend }

func (p *Plugin) UpdateBOM(fs filesystem.Filesystem, bom *cdx.BOM) error {
	found := make([]configFinding, 0)
	if err := fs.WalkDir(func(path string) error {
		if isHAProxyConf(path) {
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
			settings, err := parseHAProxyConf(rc)
			if err != nil {
				log.WithError(err).WithField("path", path).Warn("Failed to parse HAProxy config")
				return nil
			}
			if hasSSLDirectives(settings) {
				found = append(found, configFinding{path: path, settings: settings})
				log.WithFields(log.Fields{"file": path}).Info("HAProxy SSL config detected")
			}
		}
		return nil
	}); err != nil {
		return err
	}

	if len(found) == 0 {
		log.Info("No HAProxy SSL configuration files found.")
		return nil
	}

	components := make([]cdx.Component, 0)

	for _, f := range found {
		props := extractRelevantProperties(f.settings)

		fileComp := cdx.Component{
			Type:        cdx.ComponentTypeFile,
			Name:        filepath.Base(f.path),
			Description: "HAProxy SSL configuration",
			BOMRef:      uuid.New().String(),
			Properties:  &props,
			Evidence:    &cdx.Evidence{Occurrences: &[]cdx.EvidenceOccurrence{{Location: f.path}}},
		}
		components = append(components, fileComp)

		versions := detectTLSVersions(f.settings)
		suites := detectCipherSuiteNames(f.settings)

		if len(versions) > 0 && len(suites) > 0 {
			for _, v := range versions {
				algoComps, protoComp, depMap := tls.BuildTLSProtocolComponents(v, suites, f.path)
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

func isHAProxyConf(path string) bool {
	name := strings.ToLower(filepath.Base(path))
	if name == "haproxy.cfg" {
		return true
	}
	if strings.HasSuffix(name, ".cfg") {
		return strings.Contains(strings.ToLower(path), "haproxy")
	}
	return false
}

// parseHAProxyConf extracts SSL-related directives from an HAProxy config.
// It parses section-based format (global, defaults, frontend, backend) and
// extracts ssl-default-* directives and bind line SSL options.
func parseHAProxyConf(rc io.Reader) (map[string]string, error) {
	scanner := bufio.NewScanner(rc)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	cfg := make(map[string]string)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Check for ssl-default-* directives
		lower := strings.ToLower(line)
		if strings.HasPrefix(lower, "ssl-default-") || strings.HasPrefix(lower, "ssl-min-ver") || strings.HasPrefix(lower, "ssl-max-ver") || strings.HasPrefix(lower, "ssl-dh-param-file") || strings.HasPrefix(lower, "tune.ssl.") {
			parts := strings.SplitN(line, " ", 2)
			if len(parts) >= 2 {
				cfg[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
			}
			continue
		}

		// Parse bind lines for SSL options
		if strings.HasPrefix(lower, "bind ") {
			parseBind(line, cfg)
			continue
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return cfg, nil
}

var bindOptionRe = regexp.MustCompile(`(?i)\b(crt|ca-file|crl-file|curves|ciphers|ciphersuites|ssl-min-ver|ssl-max-ver)\s+(\S+)`)

func parseBind(line string, cfg map[string]string) {
	// Extract key=value style options from bind lines
	matches := bindOptionRe.FindAllStringSubmatch(line, -1)
	for _, m := range matches {
		if len(m) == 3 {
			key := "bind:" + strings.ToLower(m[1])
			cfg[key] = m[2]
		}
	}
}

func hasSSLDirectives(cfg map[string]string) bool {
	for k := range cfg {
		lower := strings.ToLower(k)
		if strings.HasPrefix(lower, "ssl-") || strings.HasPrefix(lower, "bind:") || strings.HasPrefix(lower, "tune.ssl.") {
			return true
		}
	}
	return false
}

var tlsVersionRe = regexp.MustCompile(`(?i)TLSv?(\d(?:\.\d)?)`)

func detectTLSVersions(cfg map[string]string) []string {
	versions := make([]string, 0, 4)
	seen := map[string]struct{}{}

	// Check ssl-default-bind-options for version info
	addFromOptions := func(opts string) {
		for _, token := range strings.Fields(opts) {
			if m := tlsVersionRe.FindStringSubmatch(token); len(m) == 2 {
				if _, ex := seen[m[1]]; !ex {
					versions = append(versions, m[1])
					seen[m[1]] = struct{}{}
				}
			}
		}
	}

	// Check ssl-min-ver / ssl-max-ver
	addVersion := func(key string) {
		if v, ok := cfg[key]; ok && v != "" {
			if m := tlsVersionRe.FindStringSubmatch(v); len(m) == 2 {
				if _, ex := seen[m[1]]; !ex {
					versions = append(versions, m[1])
					seen[m[1]] = struct{}{}
				}
			}
		}
	}

	if opts, ok := cfg["ssl-default-bind-options"]; ok {
		addFromOptions(opts)
	}
	addVersion("ssl-min-ver")
	addVersion("ssl-max-ver")
	addVersion("bind:ssl-min-ver")
	addVersion("bind:ssl-max-ver")

	// Infer from no-* options (e.g., "no-tlsv10 no-tlsv11" implies 1.2+)
	if opts, ok := cfg["ssl-default-bind-options"]; ok {
		disabled := map[string]struct{}{}
		for _, token := range strings.Fields(opts) {
			lower := strings.ToLower(token)
			if strings.HasPrefix(lower, "no-") {
				if m := tlsVersionRe.FindStringSubmatch(lower[3:]); len(m) == 2 {
					disabled[m[1]] = struct{}{}
				}
			}
		}
		// If specific versions are disabled, the remaining are enabled
		if len(disabled) > 0 && len(versions) == 0 {
			for _, v := range []string{"1", "1.1", "1.2", "1.3"} {
				if _, ex := disabled[v]; !ex {
					if _, ex2 := seen[v]; !ex2 {
						versions = append(versions, v)
						seen[v] = struct{}{}
					}
				}
			}
		}
	}

	sort.Strings(versions)
	return versions
}

func detectCipherSuiteNames(cfg map[string]string) []string {
	names := make([]string, 0)
	seen := map[string]struct{}{}

	addCiphers := func(value string) {
		opensslNames := strings.Split(value, ":")
		mapped := tls.MapOpenSSLNamesToTLS(opensslNames)
		for _, n := range mapped {
			if _, exists := seen[n]; !exists {
				seen[n] = struct{}{}
				names = append(names, n)
			}
		}
	}

	// TLS 1.2 ciphers
	if v, ok := cfg["ssl-default-bind-ciphers"]; ok && v != "" {
		addCiphers(v)
	}
	if v, ok := cfg["bind:ciphers"]; ok && v != "" {
		addCiphers(v)
	}

	// TLS 1.3 ciphersuites (already in TLS_* format)
	addTLS13 := func(value string) {
		for _, s := range strings.Split(value, ":") {
			s = strings.TrimSpace(s)
			if s != "" {
				if _, exists := seen[s]; !exists {
					seen[s] = struct{}{}
					names = append(names, s)
				}
			}
		}
	}

	if v, ok := cfg["ssl-default-bind-ciphersuites"]; ok && v != "" {
		addTLS13(v)
	}
	if v, ok := cfg["bind:ciphersuites"]; ok && v != "" {
		addTLS13(v)
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

	// Certificate from bind line
	if certPath, ok := cfg["bind:crt"]; ok && certPath != "" {
		resolveCert(certPath)
	}

	// CA file
	if caPath, ok := cfg["bind:ca-file"]; ok && caPath != "" {
		resolveCert(caPath)
	}

	// DH parameter file
	if dhPath, ok := cfg["ssl-dh-param-file"]; ok && dhPath != "" {
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

func extractRelevantProperties(cfg map[string]string) []cdx.Property {
	properties := make([]cdx.Property, 0)
	keys := []string{
		"ssl-default-bind-ciphers",
		"ssl-default-bind-ciphersuites",
		"ssl-default-bind-options",
		"ssl-default-server-ciphers",
		"ssl-default-server-ciphersuites",
		"ssl-default-server-options",
		"ssl-min-ver",
		"ssl-max-ver",
		"ssl-dh-param-file",
		"bind:crt",
		"bind:ca-file",
		"bind:ciphers",
		"bind:ciphersuites",
		"bind:ssl-min-ver",
		"bind:ssl-max-ver",
	}
	for _, k := range keys {
		if v, ok := cfg[k]; ok && v != "" {
			properties = append(properties, cdx.Property{Name: "theia:haproxy:" + k, Value: v})
		}
	}
	return properties
}
