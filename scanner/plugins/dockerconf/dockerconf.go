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

package dockerconf

import (
	"encoding/json"
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

// Plugin implements plugins.Plugin
// It scans for Docker daemon configuration files (daemon.json) and extracts TLS settings.
type Plugin struct{}

func NewDockerConfPlugin() (plugins.Plugin, error) { return &Plugin{}, nil }

func (*Plugin) GetName() string { return "Docker Config Plugin" }

func (*Plugin) GetExplanation() string {
	return "Scans for Docker daemon configuration files (daemon.json) and extracts TLS settings as CBOM components."
}

func (*Plugin) GetType() plugins.PluginType { return plugins.PluginTypeAppend }

// UpdateBOM walks the filesystem, finds Docker daemon.json files and adds a file component per config
func (p *Plugin) UpdateBOM(fs filesystem.Filesystem, bom *cdx.BOM) error {
	found := make([]configFinding, 0)
	if err := fs.WalkDir(func(path string) error {
		if isDockerConf(path) {
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
			settings, err := parseDockerConf(rc)
			if err != nil {
				log.WithError(err).WithField("path", path).Warn("Failed to parse daemon.json")
				return nil
			}
			found = append(found, configFinding{path: path, settings: settings})
			log.WithFields(log.Fields{"file": path}).Info("Docker daemon config detected")
		}
		return nil
	}); err != nil {
		return err
	}

	if len(found) == 0 {
		log.Info("No Docker daemon configuration files found.")
		return nil
	}

	components := make([]cdx.Component, 0)

	for _, f := range found {
		props := extractProperties(f.settings)

		fileComp := cdx.Component{
			Type:        cdx.ComponentTypeFile,
			Name:        filepath.Base(f.path),
			Description: "Docker daemon configuration",
			BOMRef:      uuid.New().String(),
			Properties:  &props,
			Evidence:    &cdx.Evidence{Occurrences: &[]cdx.EvidenceOccurrence{{Location: f.path}}},
		}
		components = append(components, fileComp)

		// Add crypto-asset components for TLS certificate, key, and CA paths
		// Try to resolve actual certificate files and create dependsOn relationships
		cryptoComponents, certDeps := buildCryptoMaterialComponents(f.settings, f.path, fs, fileComp.BOMRef)
		components = append(components, cryptoComponents...)
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
	settings map[string]interface{}
}

func isDockerConf(path string) bool {
	name := filepath.Base(path)
	if name != "daemon.json" {
		return false
	}
	// The path should contain "docker" to avoid false positives with other daemon.json files
	return strings.Contains(strings.ToLower(path), "docker")
}

// parseDockerConf parses the Docker daemon.json configuration into a generic map.
func parseDockerConf(rc io.Reader) (map[string]interface{}, error) {
	data, err := io.ReadAll(rc)
	if err != nil {
		return nil, err
	}
	var cfg map[string]interface{}
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}

// buildCryptoMaterialComponents extracts TLS certificate, key, and CA paths from
// the Docker daemon config. For certificate paths, it attempts to resolve the actual
// certificate file and generate full X.509 components. Returns the components and
// a dependency map linking the file component to the resolved certificate components.
func buildCryptoMaterialComponents(cfg map[string]interface{}, srcPath string, fs filesystem.Filesystem, fileCompBOMRef string) ([]cdx.Component, map[cdx.BOMReference][]string) {
	var components []cdx.Component
	depMap := make(map[cdx.BOMReference][]string)

	// tlscert -> Certificate component (try to resolve actual cert)
	if v, ok := cfg["tlscert"]; ok {
		if certPath, ok := v.(string); ok && certPath != "" {
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
				// Fallback: placeholder certificate component
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
	}

	// tlskey -> Private key component
	if v, ok := cfg["tlskey"]; ok {
		if keyPath, ok := v.(string); ok && keyPath != "" {
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
	}

	// tlscacert -> CA Certificate component (try to resolve actual cert)
	if v, ok := cfg["tlscacert"]; ok {
		if caPath, ok := v.(string); ok && caPath != "" {
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
				// Fallback: placeholder certificate component
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
	}

	return components, depMap
}

// extractProperties converts Docker daemon TLS settings into CycloneDX properties.
func extractProperties(cfg map[string]interface{}) []cdx.Property {
	properties := make([]cdx.Property, 0)

	// tls (bool)
	if v, ok := cfg["tls"]; ok {
		if b, ok := v.(bool); ok {
			val := "false"
			if b {
				val = "true"
			}
			properties = append(properties, cdx.Property{Name: "theia:docker:tls", Value: val})
		}
	}

	// tlsverify (bool)
	if v, ok := cfg["tlsverify"]; ok {
		if b, ok := v.(bool); ok {
			val := "false"
			if b {
				val = "true"
			}
			properties = append(properties, cdx.Property{Name: "theia:docker:tlsverify", Value: val})
		}
	}

	// tlscacert (string)
	if v, ok := cfg["tlscacert"]; ok {
		if s, ok := v.(string); ok && s != "" {
			properties = append(properties, cdx.Property{Name: "theia:docker:tlscacert", Value: s})
		}
	}

	// tlscert (string)
	if v, ok := cfg["tlscert"]; ok {
		if s, ok := v.(string); ok && s != "" {
			properties = append(properties, cdx.Property{Name: "theia:docker:tlscert", Value: s})
		}
	}

	// tlskey (string)
	if v, ok := cfg["tlskey"]; ok {
		if s, ok := v.(string); ok && s != "" {
			properties = append(properties, cdx.Property{Name: "theia:docker:tlskey", Value: s})
		}
	}

	// insecure-registries ([]string)
	if v, ok := cfg["insecure-registries"]; ok {
		if arr, ok := v.([]interface{}); ok && len(arr) > 0 {
			registries := make([]string, 0, len(arr))
			for _, item := range arr {
				if s, ok := item.(string); ok {
					registries = append(registries, s)
				}
			}
			sort.Strings(registries)
			if len(registries) > 0 {
				properties = append(properties, cdx.Property{
					Name:  "theia:docker:insecure-registries",
					Value: strings.Join(registries, ","),
				})
			}
		}
	}

	return properties
}
