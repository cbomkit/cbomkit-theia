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

package nginxconf

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
// It scans for Nginx configuration files and extracts TLS settings as CBOM components.
type Plugin struct{}

func NewNginxConfPlugin() (plugins.Plugin, error) { return &Plugin{}, nil }

func (*Plugin) GetName() string { return "Nginx Config Plugin" }

func (*Plugin) GetExplanation() string {
	return "Scans for Nginx configuration files and extracts TLS settings (protocols, ciphers, certificates) as CBOM components."
}

func (*Plugin) GetType() plugins.PluginType { return plugins.PluginTypeAppend }

func (p *Plugin) UpdateBOM(fs filesystem.Filesystem, bom *cdx.BOM) error {
	found := make([]configFinding, 0)
	if err := fs.WalkDir(func(path string) error {
		if isNginxConf(path) {
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
			settings, err := parseNginxConf(rc)
			if err != nil {
				log.WithError(err).WithField("path", path).Warn("Failed to parse nginx config")
				return nil
			}
			if hasSSLDirectives(settings) {
				found = append(found, configFinding{path: path, settings: settings})
				log.WithFields(log.Fields{"file": path}).Info("Nginx TLS config detected")
			}
		}
		return nil
	}); err != nil {
		return err
	}

	if len(found) == 0 {
		log.Info("No Nginx TLS configuration files found.")
		return nil
	}

	components := make([]cdx.Component, 0)

	for _, f := range found {
		props := extractRelevantProperties(f.settings)

		fileComp := cdx.Component{
			Type:        cdx.ComponentTypeFile,
			Name:        filepath.Base(f.path),
			Description: "Nginx TLS configuration",
			BOMRef:      uuid.New().String(),
			Properties:  &props,
			Evidence:    &cdx.Evidence{Occurrences: &[]cdx.EvidenceOccurrence{{Location: f.path}}},
		}
		components = append(components, fileComp)

		// Build protocol + cipher suite components
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

var nginxConfRe = regexp.MustCompile(`(?i)^(nginx\.conf|.*ssl\.conf)$`)

func isNginxConf(path string) bool {
	name := strings.ToLower(filepath.Base(path))
	// Match nginx.conf or any .conf file in nginx-related paths
	if nginxConfRe.MatchString(name) {
		return true
	}
	if strings.HasSuffix(name, ".conf") {
		lower := strings.ToLower(path)
		return strings.Contains(lower, "nginx")
	}
	return false
}

// parseNginxConf extracts ssl_* directives from an Nginx configuration file.
// It handles block-based format by stripping braces and extracting directive-value pairs.
func parseNginxConf(rc io.Reader) (map[string]string, error) {
	scanner := bufio.NewScanner(rc)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	cfg := make(map[string]string)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Remove trailing semicolons and braces
		line = strings.TrimRight(line, ";")
		line = strings.TrimSpace(line)
		if line == "" || line == "{" || line == "}" {
			continue
		}

		// Split into directive and value
		parts := strings.SplitN(line, " ", 2)
		if len(parts) < 1 {
			continue
		}
		directive := strings.ToLower(strings.TrimSpace(parts[0]))
		if !strings.HasPrefix(directive, "ssl_") {
			continue
		}
		value := ""
		if len(parts) >= 2 {
			value = strings.TrimSpace(parts[1])
			// Strip surrounding quotes
			if len(value) >= 2 && ((value[0] == '"' && value[len(value)-1] == '"') || (value[0] == '\'' && value[len(value)-1] == '\'')) {
				value = value[1 : len(value)-1]
			}
		}
		cfg[directive] = value
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return cfg, nil
}

func hasSSLDirectives(cfg map[string]string) bool {
	for k := range cfg {
		if strings.HasPrefix(k, "ssl_") {
			return true
		}
	}
	return false
}

var tlsVersionRe = regexp.MustCompile(`(?i)TLSv?(\d(?:\.\d)?)`)

func detectTLSVersions(cfg map[string]string) []string {
	versions := make([]string, 0, 4)
	seen := map[string]struct{}{}

	if protocols, ok := cfg["ssl_protocols"]; ok && protocols != "" {
		for _, token := range strings.Fields(protocols) {
			if m := tlsVersionRe.FindStringSubmatch(token); len(m) == 2 {
				ver := m[1]
				if _, ex := seen[ver]; !ex {
					versions = append(versions, ver)
					seen[ver] = struct{}{}
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

	if ciphers, ok := cfg["ssl_ciphers"]; ok && ciphers != "" {
		opensslNames := strings.Split(ciphers, ":")
		mapped := tls.MapOpenSSLNamesToTLS(opensslNames)
		for _, n := range mapped {
			if _, exists := seen[n]; !exists {
				seen[n] = struct{}{}
				names = append(names, n)
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

	// Server certificate
	if certPath, ok := cfg["ssl_certificate"]; ok && certPath != "" {
		resolveCert(certPath)
	}

	// Server private key
	if keyPath, ok := cfg["ssl_certificate_key"]; ok && keyPath != "" {
		components = append(components, makePrivateKeyComponent(keyPath))
	}

	// Client CA certificate
	if caPath, ok := cfg["ssl_client_certificate"]; ok && caPath != "" {
		resolveCert(caPath)
	}

	// Trusted CA for OCSP
	if trustedPath, ok := cfg["ssl_trusted_certificate"]; ok && trustedPath != "" {
		resolveCert(trustedPath)
	}

	// DH parameters
	if dhPath, ok := cfg["ssl_dhparam"]; ok && dhPath != "" {
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
		"ssl_protocols",
		"ssl_ciphers",
		"ssl_certificate",
		"ssl_certificate_key",
		"ssl_client_certificate",
		"ssl_trusted_certificate",
		"ssl_dhparam",
		"ssl_ecdh_curve",
		"ssl_prefer_server_ciphers",
		"ssl_early_data",
		"ssl_stapling",
		"ssl_verify_client",
	}
	for _, k := range keys {
		if v, ok := cfg[k]; ok && v != "" {
			properties = append(properties, cdx.Property{Name: "theia:nginx:" + k, Value: v})
		}
	}
	return properties
}
