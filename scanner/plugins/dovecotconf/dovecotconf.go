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

package dovecotconf

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
// It scans for Dovecot configuration files and extracts SSL/TLS settings as CBOM components.
type Plugin struct{}

func NewDovecotConfPlugin() (plugins.Plugin, error) { return &Plugin{}, nil }

func (*Plugin) GetName() string { return "Dovecot Config Plugin" }

func (*Plugin) GetExplanation() string {
	return "Scans for Dovecot configuration files and extracts SSL/TLS settings (protocols, ciphers, certificates) as CBOM components."
}

func (*Plugin) GetType() plugins.PluginType { return plugins.PluginTypeAppend }

func (p *Plugin) UpdateBOM(fs filesystem.Filesystem, bom *cdx.BOM) error {
	found := make([]configFinding, 0)
	if err := fs.WalkDir(func(path string) error {
		if isDovecotConf(path) {
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
			settings, err := parseDovecotConf(rc)
			if err != nil {
				log.WithError(err).WithField("path", path).Warn("Failed to parse Dovecot config")
				return nil
			}
			if hasSSLDirectives(settings) {
				found = append(found, configFinding{path: path, settings: settings})
				log.WithFields(log.Fields{"file": path}).Info("Dovecot SSL config detected")
			}
		}
		return nil
	}); err != nil {
		return err
	}

	if len(found) == 0 {
		log.Info("No Dovecot SSL configuration files found.")
		return nil
	}

	components := make([]cdx.Component, 0)

	for _, f := range found {
		props := extractRelevantProperties(f.settings)

		fileComp := cdx.Component{
			Type:        cdx.ComponentTypeFile,
			Name:        filepath.Base(f.path),
			Description: "Dovecot SSL configuration",
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

func isDovecotConf(path string) bool {
	name := strings.ToLower(filepath.Base(path))
	lower := strings.ToLower(path)

	// Direct match for dovecot.conf or 10-ssl.conf under dovecot paths
	if name == "dovecot.conf" {
		return true
	}
	if strings.HasSuffix(name, ".conf") && strings.Contains(lower, "dovecot") {
		return true
	}
	return false
}

// parseDovecotConf parses Dovecot configuration format: key = value.
// File paths may use < prefix (e.g., ssl_cert = </path/to/cert).
func parseDovecotConf(rc io.Reader) (map[string]string, error) {
	scanner := bufio.NewScanner(rc)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	cfg := make(map[string]string)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Skip block opening/closing
		if line == "{" || line == "}" || strings.HasSuffix(line, "{") {
			continue
		}

		parts := strings.SplitN(line, "=", 2)
		if len(parts) < 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		// Only interested in ssl_* directives
		if !strings.HasPrefix(key, "ssl") {
			continue
		}

		// Strip < prefix used for file paths in Dovecot (ssl_cert = </path/to/cert)
		value = strings.TrimPrefix(value, "<")
		value = strings.TrimSpace(value)

		cfg[key] = value
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return cfg, nil
}

func hasSSLDirectives(cfg map[string]string) bool {
	for k := range cfg {
		if strings.HasPrefix(k, "ssl") {
			return true
		}
	}
	return false
}

var tlsVersionRe = regexp.MustCompile(`(?i)TLSv?(\d(?:\.\d)?)`)

func detectTLSVersions(cfg map[string]string) []string {
	versions := make([]string, 0, 4)
	seen := map[string]struct{}{}

	if minProto, ok := cfg["ssl_min_protocol"]; ok && minProto != "" {
		if m := tlsVersionRe.FindStringSubmatch(minProto); len(m) == 2 {
			ver := m[1]
			if _, ex := seen[ver]; !ex {
				versions = append(versions, ver)
				seen[ver] = struct{}{}
			}
		}
		// If min is specified, infer higher versions are also supported
		verMap := map[string]int{"1": 1, "1.1": 2, "1.2": 3, "1.3": 4}
		allVers := []string{"1", "1.1", "1.2", "1.3"}
		if m := tlsVersionRe.FindStringSubmatch(minProto); len(m) == 2 {
			minIdx := verMap[m[1]]
			for _, v := range allVers {
				if verMap[v] >= minIdx {
					if _, ex := seen[v]; !ex {
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

	// ssl_cipher_list: OpenSSL format for TLS 1.2
	if ciphers, ok := cfg["ssl_cipher_list"]; ok && ciphers != "" {
		opensslNames := strings.Split(ciphers, ":")
		mapped := tls.MapOpenSSLNamesToTLS(opensslNames)
		for _, n := range mapped {
			if _, exists := seen[n]; !exists {
				seen[n] = struct{}{}
				names = append(names, n)
			}
		}
	}

	// ssl_cipher_suites: TLS 1.3 cipher suites (already TLS_* format)
	if suites, ok := cfg["ssl_cipher_suites"]; ok && suites != "" {
		for _, s := range strings.Split(suites, ":") {
			s = strings.TrimSpace(s)
			if s != "" {
				if _, exists := seen[s]; !exists {
					seen[s] = struct{}{}
					names = append(names, s)
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

	if certPath, ok := cfg["ssl_cert"]; ok && certPath != "" {
		resolveCert(certPath)
	}

	if keyPath, ok := cfg["ssl_key"]; ok && keyPath != "" {
		components = append(components, makePrivateKeyComponent(keyPath))
	}

	if caPath, ok := cfg["ssl_ca"]; ok && caPath != "" {
		resolveCert(caPath)
	}

	if clientCA, ok := cfg["ssl_client_ca_file"]; ok && clientCA != "" {
		resolveCert(clientCA)
	}

	// DH parameters
	if dhPath, ok := cfg["ssl_dh"]; ok && dhPath != "" {
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
		"ssl",
		"ssl_cert",
		"ssl_key",
		"ssl_ca",
		"ssl_client_ca_file",
		"ssl_cipher_list",
		"ssl_cipher_suites",
		"ssl_min_protocol",
		"ssl_dh",
		"ssl_prefer_server_ciphers",
		"ssl_curve_list",
		"ssl_verify_client_cert",
	}
	for _, k := range keys {
		if v, ok := cfg[k]; ok && v != "" {
			properties = append(properties, cdx.Property{Name: "theia:dovecot:" + k, Value: v})
		}
	}
	return properties
}
