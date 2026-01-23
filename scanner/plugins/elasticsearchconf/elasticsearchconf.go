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

package elasticsearchconf

import (
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
	"gopkg.in/yaml.v3"
)

// Plugin implements plugins.Plugin
// It scans for Elasticsearch configuration files and extracts SSL/TLS settings as CBOM components.
type Plugin struct{}

func NewElasticsearchConfPlugin() (plugins.Plugin, error) { return &Plugin{}, nil }

func (*Plugin) GetName() string { return "Elasticsearch Config Plugin" }

func (*Plugin) GetExplanation() string {
	return "Scans for Elasticsearch configuration files (elasticsearch.yml) and extracts xpack.security TLS settings as CBOM components."
}

func (*Plugin) GetType() plugins.PluginType { return plugins.PluginTypeAppend }

func (p *Plugin) UpdateBOM(fs filesystem.Filesystem, bom *cdx.BOM) error {
	found := make([]configFinding, 0)
	if err := fs.WalkDir(func(path string) error {
		if isElasticsearchConf(path) {
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
			data, err := filesystem.ReadAllAndClose(rc)
			if err != nil {
				log.WithError(err).WithField("path", path).Warn("Failed to read Elasticsearch config")
				return nil
			}
			cfg, err := parseElasticsearchConf(data)
			if err != nil {
				log.WithError(err).WithField("path", path).Warn("Failed to parse Elasticsearch config")
				return nil
			}
			if hasSecuritySSL(cfg) {
				found = append(found, configFinding{path: path, config: cfg})
				log.WithFields(log.Fields{"file": path}).Info("Elasticsearch security config detected")
			}
		}
		return nil
	}); err != nil {
		return err
	}

	if len(found) == 0 {
		log.Info("No Elasticsearch security configuration files found.")
		return nil
	}

	components := make([]cdx.Component, 0)

	for _, f := range found {
		props := buildProperties(f.config)

		fileComp := cdx.Component{
			Type:        cdx.ComponentTypeFile,
			Name:        filepath.Base(f.path),
			Description: "Elasticsearch security configuration",
			BOMRef:      uuid.New().String(),
			Properties:  &props,
			Evidence:    &cdx.Evidence{Occurrences: &[]cdx.EvidenceOccurrence{{Location: f.path}}},
		}
		components = append(components, fileComp)

		// Process transport SSL
		if f.config.Xpack.Security.Transport.SSL.Enabled {
			transportVersions := extractVersions(f.config.Xpack.Security.Transport.SSL.SupportedProtocols)
			transportSuites := f.config.Xpack.Security.Transport.SSL.CipherSuites
			if len(transportVersions) > 0 && len(transportSuites) > 0 {
				for _, v := range transportVersions {
					algoComps, protoComp, depMap := tls.BuildTLSProtocolComponents(v, transportSuites, f.path)
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
			cryptoComps, certDeps := buildTransportCryptoMaterial(f.config.Xpack.Security.Transport.SSL, f.path, fs, fileComp.BOMRef)
			components = append(components, cryptoComps...)
			if len(certDeps) > 0 {
				provcdx.AddDependencies(bom, certDeps)
			}
		}

		// Process HTTP SSL
		if f.config.Xpack.Security.HTTP.SSL.Enabled {
			httpVersions := extractVersions(f.config.Xpack.Security.HTTP.SSL.SupportedProtocols)
			httpSuites := f.config.Xpack.Security.HTTP.SSL.CipherSuites
			if len(httpVersions) > 0 && len(httpSuites) > 0 {
				for _, v := range httpVersions {
					algoComps, protoComp, depMap := tls.BuildTLSProtocolComponents(v, httpSuites, f.path)
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
			cryptoComps, certDeps := buildHTTPCryptoMaterial(f.config.Xpack.Security.HTTP.SSL, f.path, fs, fileComp.BOMRef)
			components = append(components, cryptoComps...)
			if len(certDeps) > 0 {
				provcdx.AddDependencies(bom, certDeps)
			}
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
	path   string
	config esConfig
}

type esConfig struct {
	Xpack struct {
		Security struct {
			Transport struct {
				SSL sslConfig `yaml:"ssl"`
			} `yaml:"transport"`
			HTTP struct {
				SSL sslConfig `yaml:"ssl"`
			} `yaml:"http"`
			FIPSMode struct {
				Enabled bool `yaml:"enabled"`
			} `yaml:"fips_mode"`
		} `yaml:"security"`
	} `yaml:"xpack"`
}

type sslConfig struct {
	Enabled                bool     `yaml:"enabled"`
	VerificationMode       string   `yaml:"verification_mode"`
	Key                    string   `yaml:"key"`
	Certificate            string   `yaml:"certificate"`
	CertificateAuthorities []string `yaml:"certificate_authorities"`
	KeystorePath           string   `yaml:"keystore.path"`
	KeystoreType           string   `yaml:"keystore.type"`
	TruststorePath         string   `yaml:"truststore.path"`
	SupportedProtocols     []string `yaml:"supported_protocols"`
	CipherSuites           []string `yaml:"cipher_suites"`
	ClientAuthentication   string   `yaml:"client_authentication"`
}

func isElasticsearchConf(path string) bool {
	name := strings.ToLower(filepath.Base(path))
	return name == "elasticsearch.yml" || name == "elasticsearch.yaml"
}

func parseElasticsearchConf(data []byte) (esConfig, error) {
	var cfg esConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return esConfig{}, err
	}
	return cfg, nil
}

func hasSecuritySSL(cfg esConfig) bool {
	return cfg.Xpack.Security.Transport.SSL.Enabled || cfg.Xpack.Security.HTTP.SSL.Enabled
}

var tlsVersionRe = regexp.MustCompile(`(?i)TLSv?(\d(?:\.\d)?)`)

func extractVersions(protocols []string) []string {
	versions := make([]string, 0, 4)
	seen := map[string]struct{}{}

	for _, proto := range protocols {
		if m := tlsVersionRe.FindStringSubmatch(proto); len(m) == 2 {
			ver := m[1]
			if _, ex := seen[ver]; !ex {
				versions = append(versions, ver)
				seen[ver] = struct{}{}
			}
		}
	}

	sort.Strings(versions)
	return versions
}

func buildTransportCryptoMaterial(ssl sslConfig, srcPath string, fs filesystem.Filesystem, fileCompBOMRef string) ([]cdx.Component, map[cdx.BOMReference][]string) {
	return buildCryptoMaterialFromSSL(ssl, srcPath, fs, fileCompBOMRef)
}

func buildHTTPCryptoMaterial(ssl sslConfig, srcPath string, fs filesystem.Filesystem, fileCompBOMRef string) ([]cdx.Component, map[cdx.BOMReference][]string) {
	return buildCryptoMaterialFromSSL(ssl, srcPath, fs, fileCompBOMRef)
}

func buildCryptoMaterialFromSSL(ssl sslConfig, srcPath string, fs filesystem.Filesystem, fileCompBOMRef string) ([]cdx.Component, map[cdx.BOMReference][]string) {
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

	if ssl.Certificate != "" {
		resolveCert(ssl.Certificate)
	}

	if ssl.Key != "" {
		components = append(components, makePrivateKeyComponent(ssl.Key))
	}

	for _, caPath := range ssl.CertificateAuthorities {
		if caPath != "" {
			resolveCert(caPath)
		}
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

func buildProperties(cfg esConfig) []cdx.Property {
	props := make([]cdx.Property, 0)

	// Transport SSL properties
	ts := cfg.Xpack.Security.Transport.SSL
	if ts.Enabled {
		props = append(props, cdx.Property{Name: "theia:elasticsearch:transport.ssl.enabled", Value: "true"})
	}
	if ts.Certificate != "" {
		props = append(props, cdx.Property{Name: "theia:elasticsearch:transport.ssl.certificate", Value: ts.Certificate})
	}
	if ts.Key != "" {
		props = append(props, cdx.Property{Name: "theia:elasticsearch:transport.ssl.key", Value: ts.Key})
	}
	if len(ts.CertificateAuthorities) > 0 {
		props = append(props, cdx.Property{Name: "theia:elasticsearch:transport.ssl.certificate_authorities", Value: strings.Join(ts.CertificateAuthorities, ",")})
	}
	if len(ts.SupportedProtocols) > 0 {
		props = append(props, cdx.Property{Name: "theia:elasticsearch:transport.ssl.supported_protocols", Value: strings.Join(ts.SupportedProtocols, ",")})
	}
	if len(ts.CipherSuites) > 0 {
		props = append(props, cdx.Property{Name: "theia:elasticsearch:transport.ssl.cipher_suites", Value: strings.Join(ts.CipherSuites, ":")})
	}
	if ts.VerificationMode != "" {
		props = append(props, cdx.Property{Name: "theia:elasticsearch:transport.ssl.verification_mode", Value: ts.VerificationMode})
	}
	if ts.ClientAuthentication != "" {
		props = append(props, cdx.Property{Name: "theia:elasticsearch:transport.ssl.client_authentication", Value: ts.ClientAuthentication})
	}

	// HTTP SSL properties
	hs := cfg.Xpack.Security.HTTP.SSL
	if hs.Enabled {
		props = append(props, cdx.Property{Name: "theia:elasticsearch:http.ssl.enabled", Value: "true"})
	}
	if hs.Certificate != "" {
		props = append(props, cdx.Property{Name: "theia:elasticsearch:http.ssl.certificate", Value: hs.Certificate})
	}
	if hs.Key != "" {
		props = append(props, cdx.Property{Name: "theia:elasticsearch:http.ssl.key", Value: hs.Key})
	}
	if len(hs.CertificateAuthorities) > 0 {
		props = append(props, cdx.Property{Name: "theia:elasticsearch:http.ssl.certificate_authorities", Value: strings.Join(hs.CertificateAuthorities, ",")})
	}
	if len(hs.SupportedProtocols) > 0 {
		props = append(props, cdx.Property{Name: "theia:elasticsearch:http.ssl.supported_protocols", Value: strings.Join(hs.SupportedProtocols, ",")})
	}
	if len(hs.CipherSuites) > 0 {
		props = append(props, cdx.Property{Name: "theia:elasticsearch:http.ssl.cipher_suites", Value: strings.Join(hs.CipherSuites, ":")})
	}
	if hs.VerificationMode != "" {
		props = append(props, cdx.Property{Name: "theia:elasticsearch:http.ssl.verification_mode", Value: hs.VerificationMode})
	}
	if hs.ClientAuthentication != "" {
		props = append(props, cdx.Property{Name: "theia:elasticsearch:http.ssl.client_authentication", Value: hs.ClientAuthentication})
	}

	// FIPS mode
	if cfg.Xpack.Security.FIPSMode.Enabled {
		props = append(props, cdx.Property{Name: "theia:elasticsearch:fips_mode.enabled", Value: "true"})
	}

	return props
}
