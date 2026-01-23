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

package etcdconf

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
// It scans for etcd configuration files and extracts TLS settings as CBOM components.
type Plugin struct{}

func NewEtcdConfPlugin() (plugins.Plugin, error) { return &Plugin{}, nil }

func (*Plugin) GetName() string { return "etcd Config Plugin" }

func (*Plugin) GetExplanation() string {
	return "Scans for etcd configuration files (etcd.conf.yml) and extracts TLS settings for client and peer transport as CBOM components."
}

func (*Plugin) GetType() plugins.PluginType { return plugins.PluginTypeAppend }

type etcdConfig struct {
	ClientTransportSecurity transportSecurity `yaml:"client-transport-security"`
	PeerTransportSecurity   transportSecurity `yaml:"peer-transport-security"`
}

type transportSecurity struct {
	CertFile       string   `yaml:"cert-file"`
	KeyFile        string   `yaml:"key-file"`
	TrustedCAFile  string   `yaml:"trusted-ca-file"`
	ClientCertAuth bool     `yaml:"client-cert-auth"`
	AutoTLS        bool     `yaml:"auto-tls"`
	CipherSuites   []string `yaml:"cipher-suites"`
	TLSMinVersion  string   `yaml:"tls-min-version"`
	TLSMaxVersion  string   `yaml:"tls-max-version"`
}

type configFinding struct {
	path   string
	config etcdConfig
}

// UpdateBOM walks the filesystem, finds etcd config files and adds components to the BOM
func (p *Plugin) UpdateBOM(fs filesystem.Filesystem, bom *cdx.BOM) error {
	found := make([]configFinding, 0)
	if err := fs.WalkDir(func(path string) error {
		if isEtcdConf(path) {
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
			data, err := filesystem.ReadAllAndClose(rc)
			if err != nil {
				log.WithError(err).WithField("path", path).Warn("Failed to read etcd config")
				return nil
			}
			cfg, err := parseEtcdConf(data)
			if err != nil {
				log.WithError(err).WithField("path", path).Warn("Failed to parse etcd config")
				return nil
			}
			found = append(found, configFinding{path: path, config: cfg})
			log.WithFields(log.Fields{"file": path}).Info("etcd config detected")
		}
		return nil
	}); err != nil {
		return err
	}

	if len(found) == 0 {
		log.Info("No etcd configuration files found.")
		return nil
	}

	components := make([]cdx.Component, 0)

	for _, f := range found {
		// Build properties from client and peer transport security
		props := buildProperties(f.config)

		fileComp := cdx.Component{
			Type:        cdx.ComponentTypeFile,
			Name:        filepath.Base(f.path),
			Description: "etcd configuration",
			BOMRef:      uuid.New().String(),
			Properties:  &props,
			Evidence:    &cdx.Evidence{Occurrences: &[]cdx.EvidenceOccurrence{{Location: f.path}}},
		}
		components = append(components, fileComp)

		// Build TLS protocol components for client transport security
		clientVersions := extractVersions(f.config.ClientTransportSecurity)
		if len(clientVersions) > 0 && len(f.config.ClientTransportSecurity.CipherSuites) > 0 {
			for _, v := range clientVersions {
				algoComps, protoComp, depMap := tls.BuildTLSProtocolComponents(v, f.config.ClientTransportSecurity.CipherSuites, f.path)
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

		// Build TLS protocol components for peer transport security
		peerVersions := extractVersions(f.config.PeerTransportSecurity)
		if len(peerVersions) > 0 && len(f.config.PeerTransportSecurity.CipherSuites) > 0 {
			for _, v := range peerVersions {
				algoComps, protoComp, depMap := tls.BuildTLSProtocolComponents(v, f.config.PeerTransportSecurity.CipherSuites, f.path)
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

		// Build crypto-asset components for certificate, key, and CA paths
		cryptoComps, certDeps := buildCryptoMaterialComponents(f.config, f.path, fs, fileComp.BOMRef)
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

func isEtcdConf(path string) bool {
	name := strings.ToLower(filepath.Base(path))
	switch name {
	case "etcd.conf.yml", "etcd.conf.yaml", "etcd.yaml", "etcd.yml":
		return true
	}
	return false
}

func parseEtcdConf(data []byte) (etcdConfig, error) {
	var cfg etcdConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return etcdConfig{}, err
	}
	return cfg, nil
}

var tlsVersionRe = regexp.MustCompile(`(?i)^TLS(\d(?:\.\d)?)$`)

// parseTLSVersion extracts the version number from strings like "TLS1.2" -> "1.2"
func parseTLSVersion(v string) string {
	m := tlsVersionRe.FindStringSubmatch(strings.TrimSpace(v))
	if len(m) == 2 {
		return m[1]
	}
	return ""
}

func extractVersions(ts transportSecurity) []string {
	versions := make([]string, 0, 2)
	seen := map[string]struct{}{}
	for _, raw := range []string{ts.TLSMinVersion, ts.TLSMaxVersion} {
		if raw == "" {
			continue
		}
		v := parseTLSVersion(raw)
		if v == "" {
			continue
		}
		if _, exists := seen[v]; !exists {
			seen[v] = struct{}{}
			versions = append(versions, v)
		}
	}
	sort.Strings(versions)
	return versions
}

func buildCryptoMaterialComponents(cfg etcdConfig, srcPath string, fs filesystem.Filesystem, fileCompBOMRef string) ([]cdx.Component, map[cdx.BOMReference][]string) {
	components := make([]cdx.Component, 0)
	depMap := make(map[cdx.BOMReference][]string)

	// Helper to resolve a certificate path or fall back to placeholder
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
			components = append(components, makeCertificateComponent(certPath, srcPath))
		}
	}

	// Client transport security crypto materials
	if cfg.ClientTransportSecurity.CertFile != "" {
		resolveCert(cfg.ClientTransportSecurity.CertFile)
	}
	if cfg.ClientTransportSecurity.KeyFile != "" {
		components = append(components, makePrivateKeyComponent(cfg.ClientTransportSecurity.KeyFile, srcPath))
	}
	if cfg.ClientTransportSecurity.TrustedCAFile != "" {
		resolveCert(cfg.ClientTransportSecurity.TrustedCAFile)
	}

	// Peer transport security crypto materials
	if cfg.PeerTransportSecurity.CertFile != "" {
		resolveCert(cfg.PeerTransportSecurity.CertFile)
	}
	if cfg.PeerTransportSecurity.KeyFile != "" {
		components = append(components, makePrivateKeyComponent(cfg.PeerTransportSecurity.KeyFile, srcPath))
	}
	if cfg.PeerTransportSecurity.TrustedCAFile != "" {
		resolveCert(cfg.PeerTransportSecurity.TrustedCAFile)
	}

	return components, depMap
}

func makeCertificateComponent(certPath, srcPath string) cdx.Component {
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

func makePrivateKeyComponent(keyPath, srcPath string) cdx.Component {
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

func buildProperties(cfg etcdConfig) []cdx.Property {
	props := make([]cdx.Property, 0)

	// Client transport security properties
	if cfg.ClientTransportSecurity.CertFile != "" {
		props = append(props, cdx.Property{Name: "theia:etcd:client-cert-file", Value: cfg.ClientTransportSecurity.CertFile})
	}
	if cfg.ClientTransportSecurity.KeyFile != "" {
		props = append(props, cdx.Property{Name: "theia:etcd:client-key-file", Value: cfg.ClientTransportSecurity.KeyFile})
	}
	if cfg.ClientTransportSecurity.TrustedCAFile != "" {
		props = append(props, cdx.Property{Name: "theia:etcd:client-trusted-ca-file", Value: cfg.ClientTransportSecurity.TrustedCAFile})
	}
	if cfg.ClientTransportSecurity.TLSMinVersion != "" {
		props = append(props, cdx.Property{Name: "theia:etcd:client-tls-min-version", Value: cfg.ClientTransportSecurity.TLSMinVersion})
	}
	if cfg.ClientTransportSecurity.TLSMaxVersion != "" {
		props = append(props, cdx.Property{Name: "theia:etcd:client-tls-max-version", Value: cfg.ClientTransportSecurity.TLSMaxVersion})
	}
	if len(cfg.ClientTransportSecurity.CipherSuites) > 0 {
		props = append(props, cdx.Property{Name: "theia:etcd:client-cipher-suites", Value: strings.Join(cfg.ClientTransportSecurity.CipherSuites, ":")})
	}

	// Peer transport security properties
	if cfg.PeerTransportSecurity.CertFile != "" {
		props = append(props, cdx.Property{Name: "theia:etcd:peer-cert-file", Value: cfg.PeerTransportSecurity.CertFile})
	}
	if cfg.PeerTransportSecurity.KeyFile != "" {
		props = append(props, cdx.Property{Name: "theia:etcd:peer-key-file", Value: cfg.PeerTransportSecurity.KeyFile})
	}
	if cfg.PeerTransportSecurity.TrustedCAFile != "" {
		props = append(props, cdx.Property{Name: "theia:etcd:peer-trusted-ca-file", Value: cfg.PeerTransportSecurity.TrustedCAFile})
	}
	if cfg.PeerTransportSecurity.TLSMinVersion != "" {
		props = append(props, cdx.Property{Name: "theia:etcd:peer-tls-min-version", Value: cfg.PeerTransportSecurity.TLSMinVersion})
	}
	if cfg.PeerTransportSecurity.TLSMaxVersion != "" {
		props = append(props, cdx.Property{Name: "theia:etcd:peer-tls-max-version", Value: cfg.PeerTransportSecurity.TLSMaxVersion})
	}
	if len(cfg.PeerTransportSecurity.CipherSuites) > 0 {
		props = append(props, cdx.Property{Name: "theia:etcd:peer-cipher-suites", Value: strings.Join(cfg.PeerTransportSecurity.CipherSuites, ":")})
	}

	return props
}
