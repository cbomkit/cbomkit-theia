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

package apacheconf

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
// It scans for Apache HTTPD configuration files and extracts SSL/TLS settings as CBOM components.
type Plugin struct{}

func NewApacheConfPlugin() (plugins.Plugin, error) { return &Plugin{}, nil }

func (*Plugin) GetName() string { return "Apache HTTPD Config Plugin" }

func (*Plugin) GetExplanation() string {
	return "Scans for Apache HTTPD configuration files and extracts SSL/TLS settings (protocols, ciphers, certificates) as CBOM components."
}

func (*Plugin) GetType() plugins.PluginType { return plugins.PluginTypeAppend }

func (p *Plugin) UpdateBOM(fs filesystem.Filesystem, bom *cdx.BOM) error {
	found := make([]configFinding, 0)
	if err := fs.WalkDir(func(path string) error {
		if isApacheConf(path) {
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
			settings, err := parseApacheConf(rc)
			if err != nil {
				log.WithError(err).WithField("path", path).Warn("Failed to parse Apache config")
				return nil
			}
			if hasSSLDirectives(settings) {
				found = append(found, configFinding{path: path, settings: settings})
				log.WithFields(log.Fields{"file": path}).Info("Apache SSL config detected")
			}
		}
		return nil
	}); err != nil {
		return err
	}

	if len(found) == 0 {
		log.Info("No Apache SSL configuration files found.")
		return nil
	}

	components := make([]cdx.Component, 0)

	for _, f := range found {
		props := extractRelevantProperties(f.settings)

		fileComp := cdx.Component{
			Type:        cdx.ComponentTypeFile,
			Name:        filepath.Base(f.path),
			Description: "Apache HTTPD SSL configuration",
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

func isApacheConf(path string) bool {
	name := strings.ToLower(filepath.Base(path))
	lower := strings.ToLower(path)

	// Direct matches
	switch name {
	case "httpd.conf", "apache2.conf", "ssl.conf":
		return true
	}

	// .conf files under apache/httpd paths
	if strings.HasSuffix(name, ".conf") {
		if strings.Contains(lower, "apache") || strings.Contains(lower, "httpd") {
			return true
		}
	}
	return false
}

// parseApacheConf extracts SSL* directives from an Apache HTTPD config file.
// Handles directive-based format with <VirtualHost>, <IfModule> blocks.
func parseApacheConf(rc io.Reader) (map[string]string, error) {
	scanner := bufio.NewScanner(rc)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	cfg := make(map[string]string)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Skip block opening/closing tags
		if strings.HasPrefix(line, "<") {
			continue
		}

		parts := strings.SplitN(line, " ", 2)
		if len(parts) < 1 {
			continue
		}
		directive := parts[0]
		// Only interested in SSL* directives
		if !strings.HasPrefix(strings.ToUpper(directive), "SSL") {
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
		// Store with original casing for the directive name
		cfg[directive] = value
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return cfg, nil
}

func hasSSLDirectives(cfg map[string]string) bool {
	for k := range cfg {
		if strings.HasPrefix(strings.ToUpper(k), "SSL") {
			return true
		}
	}
	return false
}

// SSLProtocol uses +/- notation: "all -SSLv3 -TLSv1 -TLSv1.1"
var tlsVersionRe = regexp.MustCompile(`(?i)\+?TLSv?(\d(?:\.\d)?)`)

func detectTLSVersions(cfg map[string]string) []string {
	versions := make([]string, 0, 4)
	seen := map[string]struct{}{}

	protocol := ""
	if v, ok := cfg["SSLProtocol"]; ok {
		protocol = v
	}
	if protocol == "" {
		return versions
	}

	// Parse the protocol string: "all -SSLv3 -TLSv1" means exclude those prefixed with -
	// We only add versions that are explicitly included (prefixed with + or no prefix and not -)
	tokens := strings.Fields(protocol)
	allIncluded := false
	excluded := map[string]struct{}{}

	for _, t := range tokens {
		if strings.ToLower(t) == "all" {
			allIncluded = true
			continue
		}
		if strings.HasPrefix(t, "-") {
			if m := tlsVersionRe.FindStringSubmatch(t[1:]); len(m) == 2 {
				excluded[m[1]] = struct{}{}
			}
			continue
		}
		// Explicit inclusion
		raw := strings.TrimPrefix(t, "+")
		if m := tlsVersionRe.FindStringSubmatch(raw); len(m) == 2 {
			if _, ex := seen[m[1]]; !ex {
				versions = append(versions, m[1])
				seen[m[1]] = struct{}{}
			}
		}
	}

	if allIncluded {
		// "all" means TLSv1, TLSv1.1, TLSv1.2, TLSv1.3 (minus excluded)
		for _, v := range []string{"1", "1.1", "1.2", "1.3"} {
			if _, ex := excluded[v]; ex {
				continue
			}
			if _, ex := seen[v]; !ex {
				versions = append(versions, v)
				seen[v] = struct{}{}
			}
		}
	}

	sort.Strings(versions)
	return versions
}

func detectCipherSuiteNames(cfg map[string]string) []string {
	names := make([]string, 0)
	seen := map[string]struct{}{}

	ciphers := ""
	if v, ok := cfg["SSLCipherSuite"]; ok {
		ciphers = v
	}
	if ciphers == "" {
		return names
	}

	opensslNames := strings.Split(ciphers, ":")
	mapped := tls.MapOpenSSLNamesToTLS(opensslNames)
	for _, n := range mapped {
		if _, exists := seen[n]; !exists {
			seen[n] = struct{}{}
			names = append(names, n)
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

	if certPath, ok := cfg["SSLCertificateFile"]; ok && certPath != "" {
		resolveCert(certPath)
	}

	if keyPath, ok := cfg["SSLCertificateKeyFile"]; ok && keyPath != "" {
		components = append(components, makePrivateKeyComponent(keyPath))
	}

	if chainPath, ok := cfg["SSLCertificateChainFile"]; ok && chainPath != "" {
		resolveCert(chainPath)
	}

	if caPath, ok := cfg["SSLCACertificateFile"]; ok && caPath != "" {
		resolveCert(caPath)
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
		"SSLProtocol",
		"SSLCipherSuite",
		"SSLCertificateFile",
		"SSLCertificateKeyFile",
		"SSLCertificateChainFile",
		"SSLCACertificateFile",
		"SSLHonorCipherOrder",
		"SSLCompression",
		"SSLSessionTickets",
		"SSLEngine",
		"SSLVerifyClient",
		"SSLFIPS",
	}
	for _, k := range keys {
		if v, ok := cfg[k]; ok && v != "" {
			properties = append(properties, cdx.Property{Name: "theia:apache:" + k, Value: v})
		}
	}
	return properties
}
