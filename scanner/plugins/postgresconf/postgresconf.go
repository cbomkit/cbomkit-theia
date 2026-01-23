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

package postgresconf

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
// It scans for PostgreSQL configuration files (postgresql.conf, pg_hba.conf)
// and extracts TLS/cryptographic settings as CBOM components.
type Plugin struct{}

func NewPostgresConfPlugin() (plugins.Plugin, error) { return &Plugin{}, nil }

func (*Plugin) GetName() string { return "PostgreSQL Config Plugin" }

func (*Plugin) GetExplanation() string {
	return "Scans for PostgreSQL configuration files (postgresql.conf, pg_hba.conf) and extracts TLS/cryptographic settings as CBOM components."
}

func (*Plugin) GetType() plugins.PluginType { return plugins.PluginTypeAppend }

// cryptoDirectives lists the postgresql.conf keys that are relevant for cryptographic analysis.
var cryptoDirectives = []string{
	"ssl",
	"ssl_cert_file",
	"ssl_key_file",
	"ssl_ca_file",
	"ssl_crl_file",
	"ssl_ciphers",
	"ssl_prefer_server_ciphers",
	"ssl_ecdh_curve",
	"ssl_min_protocol_version",
	"ssl_max_protocol_version",
	"ssl_dh_params_file",
	"password_encryption",
}

// cryptoAuthMethods are pg_hba.conf auth methods relevant for cryptographic analysis.
var cryptoAuthMethods = map[string]struct{}{
	"scram-sha-256": {},
	"md5":           {},
	"cert":          {},
}

type postgresConfFinding struct {
	path     string
	settings map[string]string
}

type pgHbaConfFinding struct {
	path        string
	authMethods []string
}

// UpdateBOM walks the filesystem, finds PostgreSQL config files and adds components to the BOM.
func (p *Plugin) UpdateBOM(fs filesystem.Filesystem, bom *cdx.BOM) error {
	pgConfs := make([]postgresConfFinding, 0)
	pgHbas := make([]pgHbaConfFinding, 0)

	if err := fs.WalkDir(func(path string) error {
		if !isPostgresConf(path) {
			return nil
		}
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

		baseName := strings.ToLower(filepath.Base(path))
		switch baseName {
		case "postgresql.conf":
			settings, err := parsePostgresConf(rc)
			if err != nil {
				log.WithError(err).WithField("path", path).Warn("Failed to parse postgresql.conf")
				return nil
			}
			pgConfs = append(pgConfs, postgresConfFinding{path: path, settings: settings})
			log.WithFields(log.Fields{"file": path}).Info("PostgreSQL config detected")
		case "pg_hba.conf":
			methods, err := parsePgHbaConf(rc)
			if err != nil {
				log.WithError(err).WithField("path", path).Warn("Failed to parse pg_hba.conf")
				return nil
			}
			pgHbas = append(pgHbas, pgHbaConfFinding{path: path, authMethods: methods})
			log.WithFields(log.Fields{"file": path}).Info("pg_hba.conf detected")
		}
		return nil
	}); err != nil {
		return err
	}

	if len(pgConfs) == 0 && len(pgHbas) == 0 {
		log.Info("No PostgreSQL configuration files found.")
		return nil
	}

	components := make([]cdx.Component, 0)

	for _, f := range pgConfs {
		// 1) Add postgresql.conf file component with crypto properties
		props := extractPostgresProperties(f.settings)
		fileComp := cdx.Component{
			Type:        cdx.ComponentTypeFile,
			Name:        filepath.Base(f.path),
			Description: "PostgreSQL configuration",
			BOMRef:      uuid.New().String(),
			Properties:  &props,
			Evidence:    &cdx.Evidence{Occurrences: &[]cdx.EvidenceOccurrence{{Location: f.path}}},
		}
		components = append(components, fileComp)

		// 2) Build TLS protocol + cipher suite components
		versions := detectPostgresTLSVersions(f.settings)
		suites := detectPostgresCipherSuites(f.settings)

		if len(versions) > 0 && len(suites) > 0 {
			for _, v := range versions {
				algoComps, protoComp, depMap := tls.BuildTLSProtocolComponents(v, suites, f.path)
				if len(algoComps) == 0 && protoComp == nil {
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
		}

		// 3) Add algorithm component for password_encryption if present
		if enc, ok := f.settings["password_encryption"]; ok && enc != "" {
			algoComp := makeHashAlgorithmComponent(enc, f.path)
			components = append(components, algoComp)
		}

		// 4) Add crypto-material components for cert, key, CA, DH params, ECDH curve
		cryptoMaterialComps, certDeps := buildCryptoMaterialComponents(f.settings, f.path, fs, fileComp.BOMRef)
		components = append(components, cryptoMaterialComps...)
		if len(certDeps) > 0 {
			provcdx.AddDependencies(bom, certDeps)
		}
	}

	for _, f := range pgHbas {
		// Add pg_hba.conf file component with auth methods property
		props := []cdx.Property{
			{Name: "theia:postgresql:auth_methods", Value: strings.Join(f.authMethods, ",")},
		}
		fileComp := cdx.Component{
			Type:        cdx.ComponentTypeFile,
			Name:        filepath.Base(f.path),
			Description: "PostgreSQL host-based authentication configuration",
			BOMRef:      uuid.New().String(),
			Properties:  &props,
			Evidence:    &cdx.Evidence{Occurrences: &[]cdx.EvidenceOccurrence{{Location: f.path}}},
		}
		components = append(components, fileComp)
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

func isPostgresConf(path string) bool {
	name := strings.ToLower(filepath.Base(path))
	return name == "postgresql.conf" || name == "pg_hba.conf"
}

// parsePostgresConf parses a postgresql.conf file and returns crypto-relevant key/value pairs.
// Format: key = value (spaces around =), lines starting with # are comments,
// values may be quoted with single quotes.
func parsePostgresConf(rc io.Reader) (map[string]string, error) {
	scanner := bufio.NewScanner(rc)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	settings := make(map[string]string)
	cryptoSet := make(map[string]struct{}, len(cryptoDirectives))
	for _, d := range cryptoDirectives {
		cryptoSet[d] = struct{}{}
	}

	kvRe := regexp.MustCompile(`^\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*(.*)$`)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		matches := kvRe.FindStringSubmatch(line)
		if matches == nil {
			continue
		}
		key := strings.TrimSpace(matches[1])
		val := strings.TrimSpace(matches[2])

		// Strip inline comments (not inside quotes)
		val = stripInlineComment(val)

		// Strip single quotes from value
		val = stripSingleQuotes(val)

		if _, relevant := cryptoSet[key]; relevant {
			settings[key] = val
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return settings, nil
}

// parsePgHbaConf parses a pg_hba.conf file and returns a deduplicated sorted list
// of crypto-relevant authentication methods found.
func parsePgHbaConf(rc io.Reader) ([]string, error) {
	scanner := bufio.NewScanner(rc)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	seen := make(map[string]struct{})
	methods := make([]string, 0)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}

		// Determine method column index based on connection type
		connType := strings.ToLower(fields[0])
		var methodIdx int
		switch connType {
		case "local":
			// local DATABASE USER METHOD [OPTIONS]
			methodIdx = 3
		case "host", "hostssl", "hostnossl", "hostgssenc", "hostnogssenc":
			// host DATABASE USER ADDRESS METHOD [OPTIONS]
			methodIdx = 4
		default:
			continue
		}

		if methodIdx >= len(fields) {
			continue
		}
		method := strings.ToLower(fields[methodIdx])
		if _, isCrypto := cryptoAuthMethods[method]; isCrypto {
			if _, already := seen[method]; !already {
				seen[method] = struct{}{}
				methods = append(methods, method)
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}
	sort.Strings(methods)
	return methods, nil
}

func extractPostgresProperties(settings map[string]string) []cdx.Property {
	properties := make([]cdx.Property, 0, len(settings))
	// Sort keys for deterministic output
	keys := make([]string, 0, len(settings))
	for k := range settings {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		properties = append(properties, cdx.Property{
			Name:  "theia:postgresql:" + k,
			Value: settings[k],
		})
	}
	return properties
}

var pgTLSVersionRe = regexp.MustCompile(`(?i)^TLSv?(\d(?:\.\d)?)$`)

func detectPostgresTLSVersions(settings map[string]string) []string {
	versions := make([]string, 0, 2)
	seen := make(map[string]struct{})
	for _, key := range []string{"ssl_min_protocol_version", "ssl_max_protocol_version"} {
		if v, ok := settings[key]; ok {
			if m := pgTLSVersionRe.FindStringSubmatch(strings.TrimSpace(v)); len(m) == 2 {
				ver := m[1]
				if _, exists := seen[ver]; !exists {
					versions = append(versions, ver)
					seen[ver] = struct{}{}
				}
			}
		}
	}
	sort.Strings(versions)
	return versions
}

func detectPostgresCipherSuites(settings map[string]string) []string {
	ciphers, ok := settings["ssl_ciphers"]
	if !ok || ciphers == "" {
		return nil
	}
	// ssl_ciphers is colon-separated OpenSSL cipher names
	opensslNames := strings.Split(ciphers, ":")
	cleaned := make([]string, 0, len(opensslNames))
	for _, n := range opensslNames {
		n = strings.TrimSpace(n)
		if n != "" {
			cleaned = append(cleaned, n)
		}
	}
	if len(cleaned) == 0 {
		return nil
	}
	// Map OpenSSL names to TLS standard names
	tlsNames := tls.MapOpenSSLNamesToTLS(cleaned)
	return tlsNames
}

func makeHashAlgorithmComponent(algorithm, srcPath string) cdx.Component {
	name := strings.ToUpper(strings.TrimSpace(algorithm))
	ref := uuid.New().String()
	comp := cdx.Component{
		Type:   cdx.ComponentTypeCryptographicAsset,
		Name:   name,
		BOMRef: ref,
		CryptoProperties: &cdx.CryptoProperties{
			AssetType: cdx.CryptoAssetTypeAlgorithm,
			AlgorithmProperties: &cdx.CryptoAlgorithmProperties{
				Primitive: cdx.CryptoPrimitiveHash,
			},
		},
		Evidence: &cdx.Evidence{Occurrences: &[]cdx.EvidenceOccurrence{{Location: srcPath}}},
	}
	return comp
}

// buildCryptoMaterialComponents creates crypto-asset components for certificate,
// key, CA, DH params, and ECDH curve settings found in postgresql.conf.
// For certificate paths, it attempts to resolve the actual certificate file.
func buildCryptoMaterialComponents(cfg map[string]string, srcPath string, fs filesystem.Filesystem, fileCompBOMRef string) ([]cdx.Component, map[cdx.BOMReference][]string) {
	var comps []cdx.Component
	depMap := make(map[cdx.BOMReference][]string)

	// ssl_cert_file -> Certificate component (try to resolve actual cert)
	if path, ok := cfg["ssl_cert_file"]; ok && path != "" {
		resolved, certDeps, certRefs := certresolver.ResolveCertificateComponents(fs, path)
		if resolved != nil {
			comps = append(comps, resolved...)
			for k, v := range certDeps {
				depMap[k] = append(depMap[k], v...)
			}
			for _, ref := range certRefs {
				depMap[cdx.BOMReference(fileCompBOMRef)] = append(depMap[cdx.BOMReference(fileCompBOMRef)], ref)
			}
		} else {
			comps = append(comps, cdx.Component{
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

	// ssl_key_file -> Private key component
	if path, ok := cfg["ssl_key_file"]; ok && path != "" {
		comps = append(comps, cdx.Component{
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

	// ssl_ca_file -> CA Certificate component (try to resolve actual cert)
	if path, ok := cfg["ssl_ca_file"]; ok && path != "" {
		resolved, certDeps, certRefs := certresolver.ResolveCertificateComponents(fs, path)
		if resolved != nil {
			comps = append(comps, resolved...)
			for k, v := range certDeps {
				depMap[k] = append(depMap[k], v...)
			}
			for _, ref := range certRefs {
				depMap[cdx.BOMReference(fileCompBOMRef)] = append(depMap[cdx.BOMReference(fileCompBOMRef)], ref)
			}
		} else {
			comps = append(comps, cdx.Component{
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

	// ssl_dh_params_file -> DH params component
	if path, ok := cfg["ssl_dh_params_file"]; ok && path != "" {
		comps = append(comps, cdx.Component{
			Type:   cdx.ComponentTypeCryptographicAsset,
			Name:   filepath.Base(path),
			BOMRef: uuid.New().String(),
			CryptoProperties: &cdx.CryptoProperties{
				AssetType: cdx.CryptoAssetTypeRelatedCryptoMaterial,
				RelatedCryptoMaterialProperties: &cdx.RelatedCryptoMaterialProperties{
					Type: cdx.RelatedCryptoMaterialTypePublicKey,
				},
			},
			Evidence: &cdx.Evidence{Occurrences: &[]cdx.EvidenceOccurrence{{Location: path}}},
		})
	}

	// ssl_ecdh_curve -> ECDH curve algorithm component
	if curveName, ok := cfg["ssl_ecdh_curve"]; ok && curveName != "" {
		comps = append(comps, cdx.Component{
			Type:   cdx.ComponentTypeCryptographicAsset,
			Name:   curveName,
			BOMRef: uuid.New().String(),
			CryptoProperties: &cdx.CryptoProperties{
				AssetType: cdx.CryptoAssetTypeAlgorithm,
				AlgorithmProperties: &cdx.CryptoAlgorithmProperties{
					Primitive: cdx.CryptoPrimitiveKeyAgree,
				},
			},
			Evidence: &cdx.Evidence{Occurrences: &[]cdx.EvidenceOccurrence{{Location: srcPath}}},
		})
	}

	return comps, depMap
}

func stripSingleQuotes(s string) string {
	if len(s) >= 2 && s[0] == '\'' && s[len(s)-1] == '\'' {
		return s[1 : len(s)-1]
	}
	return s
}

func stripInlineComment(s string) string {
	// Remove trailing comments that are not inside single quotes
	inQuote := false
	for i, ch := range s {
		if ch == '\'' {
			inQuote = !inQuote
		}
		if ch == '#' && !inQuote {
			return strings.TrimSpace(s[:i])
		}
	}
	return s
}
