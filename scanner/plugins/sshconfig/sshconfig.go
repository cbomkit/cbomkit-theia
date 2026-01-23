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

package sshconfig

import (
	"bufio"
	"io"
	"path/filepath"
	"sort"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
	provcdx "github.com/cbomkit/cbomkit-theia/provider/cyclonedx"
	"github.com/cbomkit/cbomkit-theia/provider/filesystem"
	"github.com/cbomkit/cbomkit-theia/scanner/plugins"
	"github.com/cbomkit/cbomkit-theia/scanner/plugins/certresolver"
	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"
)

// SSH algorithm name to descriptive name mappings

var sshCipherMap = map[string]string{
	"chacha20-poly1305@openssh.com": "ChaCha20-Poly1305",
	"aes128-ctr":                    "AES-128-CTR",
	"aes192-ctr":                    "AES-192-CTR",
	"aes256-ctr":                    "AES-256-CTR",
	"aes128-gcm@openssh.com":        "AES-128-GCM",
	"aes256-gcm@openssh.com":        "AES-256-GCM",
	"aes128-cbc":                    "AES-128-CBC",
	"aes192-cbc":                    "AES-192-CBC",
	"aes256-cbc":                    "AES-256-CBC",
	"3des-cbc":                      "3DES-CBC",
}

var sshMACMap = map[string]string{
	"hmac-sha2-256":                 "HMAC-SHA-256",
	"hmac-sha2-512":                 "HMAC-SHA-512",
	"hmac-sha1":                     "HMAC-SHA-1",
	"umac-64@openssh.com":           "UMAC-64",
	"umac-128@openssh.com":          "UMAC-128",
	"hmac-sha2-256-etm@openssh.com": "HMAC-SHA-256-ETM",
	"hmac-sha2-512-etm@openssh.com": "HMAC-SHA-512-ETM",
	"hmac-sha1-etm@openssh.com":     "HMAC-SHA-1-ETM",
	"umac-64-etm@openssh.com":       "UMAC-64-ETM",
	"umac-128-etm@openssh.com":      "UMAC-128-ETM",
}

var sshKexMap = map[string]string{
	"curve25519-sha256":                    "Curve25519-SHA-256",
	"curve25519-sha256@libssh.org":         "Curve25519-SHA-256",
	"ecdh-sha2-nistp256":                   "ECDH-SHA2-NISTP256",
	"ecdh-sha2-nistp384":                   "ECDH-SHA2-NISTP384",
	"ecdh-sha2-nistp521":                   "ECDH-SHA2-NISTP521",
	"diffie-hellman-group-exchange-sha256": "DH-Group-Exchange-SHA256",
	"diffie-hellman-group16-sha512":        "DH-Group16-SHA512",
	"diffie-hellman-group18-sha512":        "DH-Group18-SHA512",
	"diffie-hellman-group14-sha256":        "DH-Group14-SHA256",
	"diffie-hellman-group14-sha1":          "DH-Group14-SHA1",
	"sntrup761x25519-sha512@openssh.com":   "SNTRUP761-X25519-SHA512",
}

var sshHostKeyMap = map[string]string{
	"ssh-ed25519":                        "Ed25519",
	"ssh-ed25519-cert-v01@openssh.com":   "Ed25519-Cert",
	"sk-ssh-ed25519@openssh.com":         "SK-Ed25519",
	"ssh-rsa":                            "RSA",
	"rsa-sha2-256":                       "RSA-SHA2-256",
	"rsa-sha2-512":                       "RSA-SHA2-512",
	"ecdsa-sha2-nistp256":                "ECDSA-SHA2-NISTP256",
	"ecdsa-sha2-nistp384":                "ECDSA-SHA2-NISTP384",
	"ecdsa-sha2-nistp521":                "ECDSA-SHA2-NISTP521",
	"sk-ecdsa-sha2-nistp256@openssh.com": "SK-ECDSA-SHA2-NISTP256",
}

// cryptoDirectives lists the SSH config keywords we extract.
var cryptoDirectives = []string{
	"Ciphers",
	"MACs",
	"KexAlgorithms",
	"HostKeyAlgorithms",
	"PubkeyAcceptedAlgorithms",
	"CASignatureAlgorithms",
	"HostKey",
	"HostCertificate",
	"RequiredRSASize",
	"FingerprintHash",
}

// Plugin implements plugins.Plugin for SSH configuration scanning.
type Plugin struct{}

// NewSSHConfigPlugin creates a new SSH Config Plugin instance.
func NewSSHConfigPlugin() (plugins.Plugin, error) { return &Plugin{}, nil }

func (*Plugin) GetName() string { return "SSH Config Plugin" }

func (*Plugin) GetExplanation() string {
	return "Scans for SSH configuration files (sshd_config, ssh_config) and extracts cryptographic settings (Ciphers, MACs, KexAlgorithms, HostKeyAlgorithms) as CBOM components."
}

func (*Plugin) GetType() plugins.PluginType { return plugins.PluginTypeAppend }

// configFinding holds a parsed SSH config and its file path.
type configFinding struct {
	path     string
	settings map[string][]string // directive -> list of values
}

// UpdateBOM walks the filesystem, finds SSH config files, and adds components to the BOM.
func (p *Plugin) UpdateBOM(fs filesystem.Filesystem, bom *cdx.BOM) error {
	found := make([]configFinding, 0)
	if err := fs.WalkDir(func(path string) error {
		if isSSHConfig(path) {
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
			settings := parseSSHConfig(rc)
			found = append(found, configFinding{path: path, settings: settings})
			log.WithFields(log.Fields{"file": path}).Info("SSH config detected")
		}
		return nil
	}); err != nil {
		return err
	}

	if len(found) == 0 {
		log.Info("No SSH configuration files found.")
		return nil
	}

	components := make([]cdx.Component, 0)

	for _, f := range found {
		// Build properties from parsed settings
		props := buildProperties(f.settings)

		fileComp := cdx.Component{
			Type:        cdx.ComponentTypeFile,
			Name:        filepath.Base(f.path),
			Description: "SSH configuration",
			BOMRef:      uuid.New().String(),
			Properties:  &props,
			Evidence:    &cdx.Evidence{Occurrences: &[]cdx.EvidenceOccurrence{{Location: f.path}}},
		}
		components = append(components, fileComp)

		// Build algorithm components for each crypto directive category
		algComponents := make([]cdx.Component, 0)
		algComponents = append(algComponents, buildAlgorithmComponents(f.settings, "Ciphers", sshCipherMap, cdx.CryptoPrimitiveBlockCipher, f.path)...)
		algComponents = append(algComponents, buildAlgorithmComponents(f.settings, "MACs", sshMACMap, cdx.CryptoPrimitiveMAC, f.path)...)
		algComponents = append(algComponents, buildAlgorithmComponents(f.settings, "KexAlgorithms", sshKexMap, cdx.CryptoPrimitiveKeyAgree, f.path)...)
		algComponents = append(algComponents, buildAlgorithmComponents(f.settings, "HostKeyAlgorithms", sshHostKeyMap, cdx.CryptoPrimitiveSignature, f.path)...)
		components = append(components, algComponents...)

		// Build key material components for HostKey paths
		keyMaterialComponents := buildCryptoMaterialComponents(f.settings, "HostKey", cdx.CryptoAssetTypeRelatedCryptoMaterial)
		components = append(components, keyMaterialComponents...)

		// Build certificate components for HostCertificate paths (try to resolve actual certs)
		certComponents, certDeps := resolveOrPlaceholderCerts(f.settings, "HostCertificate", fs, fileComp.BOMRef)
		components = append(components, certComponents...)
		if len(certDeps) > 0 {
			provcdx.AddDependencies(bom, certDeps)
		}

		// Build SSH protocol component referencing all algorithm components
		algRefs := make([]cdx.BOMReference, 0, len(algComponents))
		for _, ac := range algComponents {
			algRefs = append(algRefs, cdx.BOMReference(ac.BOMRef))
		}
		sshProtocol := cdx.Component{
			Type:   cdx.ComponentTypeCryptographicAsset,
			Name:   "SSH",
			BOMRef: uuid.New().String(),
			CryptoProperties: &cdx.CryptoProperties{
				AssetType: cdx.CryptoAssetTypeProtocol,
				ProtocolProperties: &cdx.CryptoProtocolProperties{
					Type:    cdx.CryptoProtocolTypeSSH,
					Version: "2",
				},
			},
			Evidence: &cdx.Evidence{Occurrences: &[]cdx.EvidenceOccurrence{{Location: f.path}}},
		}
		components = append(components, sshProtocol)

		// Wire up protocol -> algorithm dependency
		dependencyMap := map[cdx.BOMReference][]string{
			cdx.BOMReference(sshProtocol.BOMRef): make([]string, 0, len(algRefs)),
		}
		for _, ref := range algRefs {
			dependencyMap[cdx.BOMReference(sshProtocol.BOMRef)] = append(dependencyMap[cdx.BOMReference(sshProtocol.BOMRef)], string(ref))
		}
		provcdx.AddDependencies(bom, dependencyMap)
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

// isSSHConfig returns true if the given path looks like an SSH configuration file.
func isSSHConfig(path string) bool {
	base := filepath.Base(path)
	if base == "sshd_config" || base == "ssh_config" {
		return true
	}
	// Files with .conf extension under sshd_config.d or ssh_config.d directories
	if filepath.Ext(path) == ".conf" {
		if strings.Contains(path, "sshd_config.d") || strings.Contains(path, "ssh_config.d") {
			return true
		}
	}
	return false
}

// parseSSHConfig parses an SSH config file and returns a map of directive -> values.
// For directives that can appear multiple times (like HostKey), multiple values are accumulated.
// For algorithm list directives, comma-separated values are split into individual entries.
func parseSSHConfig(rc io.Reader) map[string][]string {
	settings := make(map[string][]string)
	scanner := bufio.NewScanner(rc)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	directiveSet := make(map[string]bool)
	for _, d := range cryptoDirectives {
		directiveSet[strings.ToLower(d)] = true
	}

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Handle Match blocks: we just continue parsing directives inside them
		if strings.HasPrefix(strings.ToLower(line), "match ") {
			continue
		}

		// Split into keyword and value (space-separated)
		parts := strings.SplitN(line, " ", 2)
		if len(parts) < 2 {
			continue
		}
		keyword := parts[0]
		value := strings.TrimSpace(parts[1])

		// Check if this is a crypto directive we care about
		if !directiveSet[strings.ToLower(keyword)] {
			continue
		}

		// Normalize keyword to canonical form
		canonical := canonicalDirective(keyword)

		// Handle +/- prefix modifiers on the value (strip them)
		value = strings.TrimPrefix(value, "+")
		value = strings.TrimPrefix(value, "-")
		value = strings.TrimPrefix(value, "^")

		// For algorithm list directives, split by comma
		if isAlgorithmListDirective(canonical) {
			algs := strings.Split(value, ",")
			for _, alg := range algs {
				alg = strings.TrimSpace(alg)
				if alg != "" {
					settings[canonical] = append(settings[canonical], alg)
				}
			}
		} else {
			settings[canonical] = append(settings[canonical], value)
		}
	}

	return settings
}

// canonicalDirective returns the canonical form of an SSH directive keyword.
func canonicalDirective(keyword string) string {
	lower := strings.ToLower(keyword)
	for _, d := range cryptoDirectives {
		if strings.ToLower(d) == lower {
			return d
		}
	}
	return keyword
}

// isAlgorithmListDirective returns true if the directive contains comma-separated algorithm lists.
func isAlgorithmListDirective(directive string) bool {
	switch directive {
	case "Ciphers", "MACs", "KexAlgorithms", "HostKeyAlgorithms",
		"PubkeyAcceptedAlgorithms", "CASignatureAlgorithms":
		return true
	}
	return false
}

// buildProperties creates CycloneDX properties from the parsed SSH config settings.
func buildProperties(settings map[string][]string) []cdx.Property {
	props := make([]cdx.Property, 0)
	// Sort directives for deterministic output
	keys := make([]string, 0, len(settings))
	for k := range settings {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, k := range keys {
		values := settings[k]
		if len(values) == 0 {
			continue
		}
		var propValue string
		if isAlgorithmListDirective(k) {
			propValue = strings.Join(values, ",")
		} else {
			propValue = strings.Join(values, ",")
		}
		props = append(props, cdx.Property{
			Name:  "theia:ssh:" + k,
			Value: propValue,
		})
	}
	return props
}

// buildCryptoMaterialComponents creates CryptographicAsset components for key material or certificates
// from the specified directive in the settings map.
func buildCryptoMaterialComponents(settings map[string][]string, directive string, assetType cdx.CryptoAssetType) []cdx.Component {
	paths, ok := settings[directive]
	if !ok || len(paths) == 0 {
		return nil
	}

	components := make([]cdx.Component, 0, len(paths))
	seen := make(map[string]struct{})

	for _, p := range paths {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if _, dup := seen[p]; dup {
			continue
		}
		seen[p] = struct{}{}

		var comp cdx.Component
		if assetType == cdx.CryptoAssetTypeCertificate {
			comp = cdx.Component{
				Type:   cdx.ComponentTypeCryptographicAsset,
				Name:   filepath.Base(p),
				BOMRef: uuid.New().String(),
				CryptoProperties: &cdx.CryptoProperties{
					AssetType:             cdx.CryptoAssetTypeCertificate,
					CertificateProperties: &cdx.CertificateProperties{},
				},
				Evidence: &cdx.Evidence{Occurrences: &[]cdx.EvidenceOccurrence{{Location: p}}},
			}
		} else {
			comp = cdx.Component{
				Type:   cdx.ComponentTypeCryptographicAsset,
				Name:   filepath.Base(p),
				BOMRef: uuid.New().String(),
				CryptoProperties: &cdx.CryptoProperties{
					AssetType: cdx.CryptoAssetTypeRelatedCryptoMaterial,
					RelatedCryptoMaterialProperties: &cdx.RelatedCryptoMaterialProperties{
						Type: cdx.RelatedCryptoMaterialTypePrivateKey,
					},
				},
				Evidence: &cdx.Evidence{Occurrences: &[]cdx.EvidenceOccurrence{{Location: p}}},
			}
		}
		components = append(components, comp)
	}

	return components
}

// resolveOrPlaceholderCerts attempts to resolve certificate files referenced in the settings.
// For each path found, it tries to read and parse the actual certificate. If successful,
// it returns the full certificate components and a dependency map linking the file component
// to the certificate. Otherwise, it falls back to a placeholder component.
func resolveOrPlaceholderCerts(settings map[string][]string, directive string, fs filesystem.Filesystem, fileCompBOMRef string) ([]cdx.Component, map[cdx.BOMReference][]string) {
	paths, ok := settings[directive]
	if !ok || len(paths) == 0 {
		return nil, nil
	}

	components := make([]cdx.Component, 0)
	depMap := make(map[cdx.BOMReference][]string)
	seen := make(map[string]struct{})

	for _, p := range paths {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if _, dup := seen[p]; dup {
			continue
		}
		seen[p] = struct{}{}

		resolved, certDeps, certRefs := certresolver.ResolveCertificateComponents(fs, p)
		if resolved != nil {
			components = append(components, resolved...)
			for k, v := range certDeps {
				depMap[k] = append(depMap[k], v...)
			}
			for _, ref := range certRefs {
				depMap[cdx.BOMReference(fileCompBOMRef)] = append(depMap[cdx.BOMReference(fileCompBOMRef)], ref)
			}
		} else {
			// Fallback: placeholder certificate component
			components = append(components, cdx.Component{
				Type:   cdx.ComponentTypeCryptographicAsset,
				Name:   filepath.Base(p),
				BOMRef: uuid.New().String(),
				CryptoProperties: &cdx.CryptoProperties{
					AssetType:             cdx.CryptoAssetTypeCertificate,
					CertificateProperties: &cdx.CertificateProperties{},
				},
				Evidence: &cdx.Evidence{Occurrences: &[]cdx.EvidenceOccurrence{{Location: p}}},
			})
		}
	}

	return components, depMap
}

// buildAlgorithmComponents creates CryptographicAsset components for algorithms in a given directive.
func buildAlgorithmComponents(settings map[string][]string, directive string, nameMap map[string]string, primitive cdx.CryptoPrimitive, srcPath string) []cdx.Component {
	algs, ok := settings[directive]
	if !ok || len(algs) == 0 {
		return nil
	}

	components := make([]cdx.Component, 0, len(algs))
	seen := make(map[string]struct{})

	for _, alg := range algs {
		alg = strings.TrimSpace(alg)
		if alg == "" {
			continue
		}
		if _, dup := seen[alg]; dup {
			continue
		}
		seen[alg] = struct{}{}

		displayName := alg
		if mapped, ok := nameMap[alg]; ok {
			displayName = mapped
		}

		// Determine primitive: for chacha20-poly1305, use StreamCipher
		actualPrimitive := primitive
		if directive == "Ciphers" && strings.Contains(strings.ToLower(alg), "chacha20") {
			actualPrimitive = cdx.CryptoPrimitiveStreamCipher
		}

		comp := cdx.Component{
			Type:   cdx.ComponentTypeCryptographicAsset,
			Name:   displayName,
			BOMRef: uuid.New().String(),
			CryptoProperties: &cdx.CryptoProperties{
				AssetType: cdx.CryptoAssetTypeAlgorithm,
				AlgorithmProperties: &cdx.CryptoAlgorithmProperties{
					Primitive: actualPrimitive,
				},
			},
			Evidence: &cdx.Evidence{Occurrences: &[]cdx.EvidenceOccurrence{{Location: srcPath}}},
		}
		components = append(components, comp)
	}

	return components
}
