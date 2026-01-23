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

package redisconf

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
// It scans for Redis configuration files (redis.conf) and extracts TLS settings as CBOM components.
type Plugin struct{}

func NewRedisConfPlugin() (plugins.Plugin, error) { return &Plugin{}, nil }

func (*Plugin) GetName() string { return "Redis Config Plugin" }

func (*Plugin) GetExplanation() string {
	return "Scans for Redis configuration files (redis.conf) and extracts TLS settings (protocols, ciphers, certificates) as CBOM components."
}

func (*Plugin) GetType() plugins.PluginType { return plugins.PluginTypeAppend }

// UpdateBOM walks the filesystem, finds redis.conf files and adds file + protocol components
func (p *Plugin) UpdateBOM(fs filesystem.Filesystem, bom *cdx.BOM) error {
	found := make([]configFinding, 0)
	if err := fs.WalkDir(func(path string) error {
		if isRedisConf(path) {
			exists, err := fs.Exists(path)
			if err != nil {
				return err
			} else if !exists {
				return nil
			}
			rc, err := fs.Open(path)
			if err != nil {
				return nil // skip unreadable files
			}
			defer rc.Close()
			settings, err := parseRedisConf(rc)
			if err != nil {
				log.WithError(err).WithField("path", path).Warn("Failed to parse redis.conf")
				return nil
			}
			// Only include if TLS is enabled (tls-port is set and non-zero)
			if port, ok := settings["tls-port"]; ok && port != "" && port != "0" {
				found = append(found, configFinding{path: path, settings: settings})
				log.WithFields(log.Fields{"file": path}).Info("Redis TLS config detected")
			}
		}
		return nil
	}); err != nil {
		return err
	}

	if len(found) == 0 {
		log.Info("No Redis TLS configuration files found.")
		return nil
	}

	components := make([]cdx.Component, 0)

	for _, f := range found {
		// 1) Add redis.conf file component with properties
		props := extractRelevantProperties(f.settings)

		fileComp := cdx.Component{
			Type:        cdx.ComponentTypeFile,
			Name:        filepath.Base(f.path),
			Description: "Redis TLS configuration",
			BOMRef:      uuid.New().String(),
			Properties:  &props,
			Evidence:    &cdx.Evidence{Occurrences: &[]cdx.EvidenceOccurrence{{Location: f.path}}},
		}
		components = append(components, fileComp)

		// 2) Build protocol + cipher suite components
		versions := detectTLSVersions(f.settings)
		suites := detectCipherSuiteNames(f.settings)

		if len(versions) == 0 || len(suites) == 0 {
			continue
		}
		for _, v := range versions {
			algoComps, protoComp, depMap := tls.BuildTLSProtocolComponents(v, suites, f.path)
			if len(algoComps) == 0 && (protoComp == nil) {
				continue
			}
			components = append(components, algoComps...)
			if protoComp != nil {
				components = append(components, *protoComp)
			}
			if len(depMap) > 0 {
				provcdx.AddDependencies(bom, depMap)
			}
		}

		// 3) Build crypto-material components for cert/key file paths
		cryptoComps, certDeps := buildCryptoMaterialComponents(f.settings, f.path, fs, fileComp.BOMRef)
		components = append(components, cryptoComps...)
		if len(certDeps) > 0 {
			provcdx.AddDependencies(bom, certDeps)
		}
	}

	// Keep deterministic order in BOM
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
	settings map[string]string // directive -> value
}

func isRedisConf(path string) bool {
	name := strings.ToLower(filepath.Base(path))
	return name == "redis.conf" || name == "sentinel.conf"
}

// parseRedisConf parses a Redis configuration file.
// Format: directive value (space-separated, one per line)
// Lines starting with '#' are comments; empty lines are ignored.
// Directives are stored lower-cased.
func parseRedisConf(rc io.Reader) (map[string]string, error) {
	scanner := bufio.NewScanner(rc)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	cfg := make(map[string]string)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Split into directive and value (first space separates them)
		parts := strings.SplitN(line, " ", 2)
		if len(parts) < 2 {
			// directive with no value, store empty
			cfg[strings.ToLower(parts[0])] = ""
			continue
		}
		directive := strings.ToLower(strings.TrimSpace(parts[0]))
		value := strings.TrimSpace(parts[1])
		// Strip surrounding quotes from values
		if len(value) >= 2 && ((value[0] == '"' && value[len(value)-1] == '"') || (value[0] == '\'' && value[len(value)-1] == '\'')) {
			value = value[1 : len(value)-1]
		}
		cfg[directive] = value
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return cfg, nil
}

var tlsVersionRe = regexp.MustCompile(`(?i)TLSv?(\d(?:\.\d)?)`)

func detectTLSVersions(cfg map[string]string) []string {
	versions := make([]string, 0, 2)
	seen := map[string]struct{}{}

	if protocols, ok := cfg["tls-protocols"]; ok && protocols != "" {
		// tls-protocols value is space-separated, e.g. "TLSv1.2 TLSv1.3"
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

	// tls-ciphers: OpenSSL format colon-separated names for TLS <=1.2
	if ciphers, ok := cfg["tls-ciphers"]; ok && ciphers != "" {
		opensslNames := strings.Split(ciphers, ":")
		mapped := tls.MapOpenSSLNamesToTLS(opensslNames)
		for _, n := range mapped {
			if _, exists := seen[n]; !exists {
				seen[n] = struct{}{}
				names = append(names, n)
			}
		}
	}

	// tls-ciphersuites: TLS 1.3 cipher names (already in TLS_* format), colon-separated
	if suites, ok := cfg["tls-ciphersuites"]; ok && suites != "" {
		for _, s := range strings.Split(suites, ":") {
			s = strings.TrimSpace(s)
			if s == "" {
				continue
			}
			if _, exists := seen[s]; !exists {
				seen[s] = struct{}{}
				names = append(names, s)
			}
		}
	}

	sort.Strings(names)
	return names
}

func buildCryptoMaterialComponents(cfg map[string]string, srcPath string, fs filesystem.Filesystem, fileCompBOMRef string) ([]cdx.Component, map[cdx.BOMReference][]string) {
	components := make([]cdx.Component, 0)
	depMap := make(map[cdx.BOMReference][]string)

	// Certificate component for tls-cert-file (try to resolve actual cert)
	if certPath, ok := cfg["tls-cert-file"]; ok && certPath != "" {
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
			components = append(components, cdx.Component{
				Type:   cdx.ComponentTypeCryptographicAsset,
				Name:   filepath.Base(certPath),
				BOMRef: uuid.New().String(),
				CryptoProperties: &cdx.CryptoProperties{
					AssetType:             cdx.CryptoAssetTypeCertificate,
					CertificateProperties: &cdx.CertificateProperties{},
				},
				Evidence: &cdx.Evidence{Occurrences: &[]cdx.EvidenceOccurrence{{Location: certPath}}},
			})
		}
	}

	// Private key component for tls-key-file
	if keyPath, ok := cfg["tls-key-file"]; ok && keyPath != "" {
		components = append(components, cdx.Component{
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
		})
	}

	// CA Certificate component for tls-ca-cert-file (try to resolve actual cert)
	if caPath, ok := cfg["tls-ca-cert-file"]; ok && caPath != "" {
		resolved, certDeps, certRefs := certresolver.ResolveCertificateComponents(fs, caPath)
		if resolved != nil {
			components = append(components, resolved...)
			for k, v := range certDeps {
				depMap[k] = append(depMap[k], v...)
			}
			for _, ref := range certRefs {
				depMap[cdx.BOMReference(fileCompBOMRef)] = append(depMap[cdx.BOMReference(fileCompBOMRef)], ref)
			}
		} else {
			components = append(components, cdx.Component{
				Type:   cdx.ComponentTypeCryptographicAsset,
				Name:   filepath.Base(caPath),
				BOMRef: uuid.New().String(),
				CryptoProperties: &cdx.CryptoProperties{
					AssetType:             cdx.CryptoAssetTypeCertificate,
					CertificateProperties: &cdx.CertificateProperties{},
				},
				Evidence: &cdx.Evidence{Occurrences: &[]cdx.EvidenceOccurrence{{Location: caPath}}},
			})
		}
	}

	return components, depMap
}

func extractRelevantProperties(cfg map[string]string) []cdx.Property {
	properties := make([]cdx.Property, 0)
	keys := []string{
		"tls-protocols",
		"tls-ciphers",
		"tls-ciphersuites",
		"tls-cert-file",
		"tls-key-file",
		"tls-ca-cert-file",
		"tls-prefer-server-ciphers",
		"tls-auth-clients",
	}
	for _, k := range keys {
		if v, ok := cfg[k]; ok && v != "" {
			properties = append(properties, cdx.Property{Name: "theia:redis:" + k, Value: v})
		}
	}
	return properties
}
