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

package mysqlconf

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
// It scans for MySQL/MariaDB configuration files (my.cnf) and extracts TLS/cryptographic settings.
type Plugin struct{}

func NewMySQLConfPlugin() (plugins.Plugin, error) { return &Plugin{}, nil }

func (*Plugin) GetName() string { return "MySQL Config Plugin" }

func (*Plugin) GetExplanation() string {
	return "Scans for MySQL/MariaDB configuration files (my.cnf) and extracts TLS/cryptographic settings as CBOM components."
}

func (*Plugin) GetType() plugins.PluginType { return plugins.PluginTypeAppend }

// UpdateBOM walks the filesystem, finds MySQL/MariaDB config files and adds components to the BOM
func (p *Plugin) UpdateBOM(fs filesystem.Filesystem, bom *cdx.BOM) error {
	found := make([]configFinding, 0)
	if err := fs.WalkDir(func(path string) error {
		if isMySQLConf(path) {
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
			settings, err := parseMySQLConf(rc)
			if err != nil {
				log.WithError(err).WithField("path", path).Warn("Failed to parse MySQL config")
				return nil
			}
			found = append(found, configFinding{path: path, settings: settings})
			log.WithFields(log.Fields{"file": path}).Info("MySQL/MariaDB config detected")
		}
		return nil
	}); err != nil {
		return err
	}

	if len(found) == 0 {
		log.Info("No MySQL/MariaDB configuration files found.")
		return nil
	}

	components := make([]cdx.Component, 0)

	for _, f := range found {
		// 1) Add my.cnf file component with properties
		props := extractRelevantProperties(f.settings)

		fileComp := cdx.Component{
			Type:        cdx.ComponentTypeFile,
			Name:        filepath.Base(f.path),
			Description: "MySQL/MariaDB configuration",
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

		// 3) Build crypto-asset components for certificate and key file paths
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
	settings map[string]map[string]string // section -> key -> val
}

// isMySQLConf checks if the given path is a MySQL/MariaDB configuration file.
func isMySQLConf(path string) bool {
	name := strings.ToLower(filepath.Base(path))
	if name == "my.cnf" || name == "mysqld.cnf" {
		return true
	}
	// Any .cnf file where the path contains mysql or mariadb
	if strings.HasSuffix(name, ".cnf") {
		lowerPath := strings.ToLower(path)
		if strings.Contains(lowerPath, "mysql") || strings.Contains(lowerPath, "mariadb") {
			return true
		}
	}
	return false
}

// normalizeKey converts underscores to hyphens for consistent key lookup.
func normalizeKey(key string) string {
	return strings.ReplaceAll(strings.TrimSpace(key), "_", "-")
}

// parseMySQLConf parses a MySQL/MariaDB INI-style configuration file.
// - Supports [sections]
// - Key=value or key = value pairs
// - Comments with '#' or ';'
// - Directives can use hyphens OR underscores (normalized to hyphens)
// - Recognizes !includedir and !include directives
func parseMySQLConf(rc io.Reader) (map[string]map[string]string, error) {
	scanner := bufio.NewScanner(rc)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	section := "default"
	cfg := map[string]map[string]string{section: {}}

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}

		// Handle !includedir and !include directives (note existence but don't follow)
		if strings.HasPrefix(line, "!includedir") || strings.HasPrefix(line, "!include") {
			continue
		}

		// Section header
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.TrimSpace(line[1 : len(line)-1])
			if _, ok := cfg[section]; !ok {
				cfg[section] = map[string]string{}
			}
			continue
		}

		// Key=value pair
		if i := strings.IndexByte(line, '='); i != -1 {
			key := normalizeKey(line[:i])
			val := strings.TrimSpace(line[i+1:])
			if key != "" {
				cfg[section][key] = val
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return cfg, nil
}

// cryptoDirectives lists the MySQL TLS/crypto directives we care about (normalized with hyphens).
var cryptoDirectives = []string{
	"ssl-ca",
	"ssl-cert",
	"ssl-key",
	"ssl-cipher",
	"tls-version",
	"tls-ciphersuites",
	"ssl-crl",
	"require-secure-transport",
	"ssl-fips-mode",
	"admin-ssl-ca",
	"admin-ssl-cert",
	"admin-ssl-key",
	"admin-ssl-cipher",
	"admin-tls-version",
}

// extractRelevantProperties builds a list of CycloneDX properties from the parsed config.
// It looks in the [mysqld] section first, falling back to other sections.
func extractRelevantProperties(cfg map[string]map[string]string) []cdx.Property {
	properties := make([]cdx.Property, 0)
	preferredSections := []string{"mysqld", "default"}

	// Property name mapping: directive -> property name
	propNames := map[string]string{
		"ssl-ca":                   "theia:mysql:ssl-ca",
		"ssl-cert":                 "theia:mysql:ssl-cert",
		"ssl-key":                  "theia:mysql:ssl-key",
		"ssl-cipher":               "theia:mysql:ssl-cipher",
		"tls-version":              "theia:mysql:tls-version",
		"tls-ciphersuites":         "theia:mysql:tls-ciphersuites",
		"ssl-crl":                  "theia:mysql:ssl-crl",
		"require-secure-transport": "theia:mysql:require-secure-transport",
		"ssl-fips-mode":            "theia:mysql:ssl-fips-mode",
	}

	for _, key := range cryptoDirectives {
		pName, hasProp := propNames[key]
		if !hasProp {
			continue
		}
		if v, ok := getFirstKey(cfg, preferredSections, key); ok && v != "" {
			properties = append(properties, cdx.Property{Name: pName, Value: v})
		}
	}
	return properties
}

// getFirstKey searches for a key in preferred sections first, then falls back to any section.
func getFirstKey(cfg map[string]map[string]string, sections []string, key string) (string, bool) {
	for _, s := range sections {
		if sec, ok := cfg[s]; ok {
			if v, ok2 := sec[key]; ok2 {
				return v, true
			}
		}
	}
	// fallback: search any section deterministically
	secNames := make([]string, 0, len(cfg))
	for s := range cfg {
		secNames = append(secNames, s)
	}
	sort.Strings(secNames)
	for _, s := range secNames {
		if v, ok := cfg[s][key]; ok {
			return v, true
		}
	}
	return "", false
}

var tlsVersionRe = regexp.MustCompile(`(?i)TLSv?(\d(?:\.\d)?)`)

// detectTLSVersions extracts TLS version numbers from the tls-version directive.
// MySQL uses comma-separated values like "TLSv1.2,TLSv1.3".
func detectTLSVersions(cfg map[string]map[string]string) []string {
	versions := make([]string, 0, 2)
	seen := map[string]struct{}{}
	preferredSections := []string{"mysqld", "default"}

	// Check tls-version and admin-tls-version
	for _, key := range []string{"tls-version", "admin-tls-version"} {
		if v, ok := getFirstKey(cfg, preferredSections, key); ok {
			// Split by comma
			parts := strings.Split(v, ",")
			for _, part := range parts {
				part = strings.TrimSpace(part)
				if m := tlsVersionRe.FindStringSubmatch(part); len(m) == 2 {
					ver := m[1]
					if _, ex := seen[ver]; !ex {
						versions = append(versions, ver)
						seen[ver] = struct{}{}
					}
				}
			}
		}
	}
	sort.Strings(versions)
	return versions
}

// buildCryptoMaterialComponents creates CycloneDX crypto-asset components for
// certificate and key file paths found in the [mysqld] section of the config.
// For certificate paths, it attempts to resolve the actual certificate file.
func buildCryptoMaterialComponents(cfg map[string]map[string]string, srcPath string, fs filesystem.Filesystem, fileCompBOMRef string) ([]cdx.Component, map[cdx.BOMReference][]string) {
	components := make([]cdx.Component, 0)
	depMap := make(map[cdx.BOMReference][]string)

	mysqld, ok := cfg["mysqld"]
	if !ok {
		return components, depMap
	}

	certKeys := []string{"ssl-cert", "admin-ssl-cert"}
	keyKeys := []string{"ssl-key", "admin-ssl-key"}
	caKeys := []string{"ssl-ca", "admin-ssl-ca"}

	// Certificate components (try to resolve actual certs)
	for _, k := range certKeys {
		if path, exists := mysqld[k]; exists && path != "" {
			resolved, certDeps, certRefs := certresolver.ResolveCertificateComponents(fs, path)
			if resolved != nil {
				components = append(components, resolved...)
				for dk, dv := range certDeps {
					depMap[dk] = append(depMap[dk], dv...)
				}
				for _, ref := range certRefs {
					depMap[cdx.BOMReference(fileCompBOMRef)] = append(depMap[cdx.BOMReference(fileCompBOMRef)], ref)
				}
			} else {
				components = append(components, cdx.Component{
					Type:   cdx.ComponentTypeCryptographicAsset,
					Name:   filepath.Base(path),
					BOMRef: uuid.New().String(),
					CryptoProperties: &cdx.CryptoProperties{
						AssetType:             cdx.CryptoAssetTypeCertificate,
						CertificateProperties: &cdx.CertificateProperties{},
					},
					Evidence: &cdx.Evidence{Occurrences: &[]cdx.EvidenceOccurrence{{Location: path}}},
				})
			}
		}
	}

	// Private key components
	for _, k := range keyKeys {
		if path, exists := mysqld[k]; exists && path != "" {
			components = append(components, cdx.Component{
				Type:   cdx.ComponentTypeCryptographicAsset,
				Name:   filepath.Base(path),
				BOMRef: uuid.New().String(),
				CryptoProperties: &cdx.CryptoProperties{
					AssetType: cdx.CryptoAssetTypeRelatedCryptoMaterial,
					RelatedCryptoMaterialProperties: &cdx.RelatedCryptoMaterialProperties{
						Type: cdx.RelatedCryptoMaterialTypePrivateKey,
					},
				},
				Evidence: &cdx.Evidence{Occurrences: &[]cdx.EvidenceOccurrence{{Location: path}}},
			})
		}
	}

	// CA certificate components (try to resolve actual certs)
	for _, k := range caKeys {
		if path, exists := mysqld[k]; exists && path != "" {
			resolved, certDeps, certRefs := certresolver.ResolveCertificateComponents(fs, path)
			if resolved != nil {
				components = append(components, resolved...)
				for dk, dv := range certDeps {
					depMap[dk] = append(depMap[dk], dv...)
				}
				for _, ref := range certRefs {
					depMap[cdx.BOMReference(fileCompBOMRef)] = append(depMap[cdx.BOMReference(fileCompBOMRef)], ref)
				}
			} else {
				components = append(components, cdx.Component{
					Type:   cdx.ComponentTypeCryptographicAsset,
					Name:   filepath.Base(path),
					BOMRef: uuid.New().String(),
					CryptoProperties: &cdx.CryptoProperties{
						AssetType:             cdx.CryptoAssetTypeCertificate,
						CertificateProperties: &cdx.CertificateProperties{},
					},
					Evidence: &cdx.Evidence{Occurrences: &[]cdx.EvidenceOccurrence{{Location: path}}},
				})
			}
		}
	}

	return components, depMap
}

// detectCipherSuiteNames extracts TLS cipher suite names from the config.
// It handles:
// - ssl-cipher: colon-separated OpenSSL cipher names -> mapped to TLS_* names
// - tls-ciphersuites: colon-separated TLS 1.3 cipher suite names (already TLS_* format)
func detectCipherSuiteNames(cfg map[string]map[string]string) []string {
	suites := make([]string, 0)
	seen := map[string]struct{}{}
	preferredSections := []string{"mysqld", "default"}

	// Process ssl-cipher (OpenSSL format names, colon-separated)
	for _, key := range []string{"ssl-cipher", "admin-ssl-cipher"} {
		if v, ok := getFirstKey(cfg, preferredSections, key); ok && v != "" {
			opensslNames := strings.Split(v, ":")
			cleaned := make([]string, 0, len(opensslNames))
			for _, n := range opensslNames {
				n = strings.TrimSpace(n)
				if n != "" {
					cleaned = append(cleaned, n)
				}
			}
			mapped := tls.MapOpenSSLNamesToTLS(cleaned)
			for _, m := range mapped {
				if _, ex := seen[m]; !ex {
					seen[m] = struct{}{}
					suites = append(suites, m)
				}
			}
		}
	}

	// Process tls-ciphersuites (already in TLS_* format, colon-separated)
	if v, ok := getFirstKey(cfg, preferredSections, "tls-ciphersuites"); ok && v != "" {
		parts := strings.Split(v, ":")
		for _, p := range parts {
			p = strings.TrimSpace(p)
			if p != "" {
				if _, ex := seen[p]; !ex {
					seen[p] = struct{}{}
					suites = append(suites, p)
				}
			}
		}
	}

	sort.Strings(suites)
	return suites
}
