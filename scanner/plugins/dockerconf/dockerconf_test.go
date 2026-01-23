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
	"strings"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/cbomkit/cbomkit-theia/provider/filesystem"
	"github.com/stretchr/testify/assert"
)

func Test_isDockerConf(t *testing.T) {
	tests := []struct {
		path     string
		expected bool
	}{
		{path: "etc/docker/daemon.json", expected: true},
		{path: "/etc/docker/daemon.json", expected: true},
		{path: "home/user/.docker/daemon.json", expected: true},
		{path: "etc/other/daemon.json", expected: false},
		{path: "etc/docker/config.json", expected: false},
		{path: "var/lib/daemon.json", expected: false},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			result := isDockerConf(tt.path)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func Test_parseDockerConf(t *testing.T) {
	content := `{
    "tls": true,
    "tlsverify": true,
    "tlscacert": "/etc/docker/certs/ca.pem",
    "tlscert": "/etc/docker/certs/server-cert.pem",
    "tlskey": "/etc/docker/certs/server-key.pem",
    "hosts": ["tcp://0.0.0.0:2376"],
    "insecure-registries": ["registry.internal:5000"]
}`
	cfg, err := parseDockerConf(strings.NewReader(content))
	assert.NoError(t, err)

	props := extractProperties(cfg)

	m := map[string]string{}
	for _, p := range props {
		m[p.Name] = p.Value
	}

	assert.Equal(t, "true", m["theia:docker:tls"])
	assert.Equal(t, "true", m["theia:docker:tlsverify"])
	assert.Equal(t, "/etc/docker/certs/ca.pem", m["theia:docker:tlscacert"])
	assert.Equal(t, "/etc/docker/certs/server-cert.pem", m["theia:docker:tlscert"])
	assert.Equal(t, "/etc/docker/certs/server-key.pem", m["theia:docker:tlskey"])
	assert.Equal(t, "registry.internal:5000", m["theia:docker:insecure-registries"])
}

func Test_parseDockerConf_tlsDisabled(t *testing.T) {
	content := `{
    "tls": false,
    "tlsverify": false
}`
	cfg, err := parseDockerConf(strings.NewReader(content))
	assert.NoError(t, err)

	props := extractProperties(cfg)

	m := map[string]string{}
	for _, p := range props {
		m[p.Name] = p.Value
	}

	assert.Equal(t, "false", m["theia:docker:tls"])
	assert.Equal(t, "false", m["theia:docker:tlsverify"])
	assert.Empty(t, m["theia:docker:tlscacert"])
	assert.Empty(t, m["theia:docker:tlscert"])
	assert.Empty(t, m["theia:docker:tlskey"])
	assert.Empty(t, m["theia:docker:insecure-registries"])
}

func Test_parseDockerConf_multipleInsecureRegistries(t *testing.T) {
	content := `{
    "insecure-registries": ["registry2.internal:5000", "registry1.internal:5000"]
}`
	cfg, err := parseDockerConf(strings.NewReader(content))
	assert.NoError(t, err)

	props := extractProperties(cfg)

	m := map[string]string{}
	for _, p := range props {
		m[p.Name] = p.Value
	}

	// Registries should be sorted alphabetically and comma-separated
	assert.Equal(t, "registry1.internal:5000,registry2.internal:5000", m["theia:docker:insecure-registries"])
}

func Test_UpdateBOM_adds_components(t *testing.T) {
	fs := filesystem.NewPlainFilesystem("../../../testdata/docker/dir")
	bom := cdx.NewBOM()
	components := make([]cdx.Component, 0)
	bom.Components = &components

	plugin, err := NewDockerConfPlugin()
	assert.NoError(t, err)
	assert.NoError(t, plugin.UpdateBOM(fs, bom))

	assert.NotNil(t, bom.Components)
	assert.GreaterOrEqual(t, len(*bom.Components), 1)

	found := false
	for _, c := range *bom.Components {
		if c.Name == "daemon.json" {
			found = true
			assert.Equal(t, cdx.ComponentTypeFile, c.Type)
			assert.Equal(t, "Docker daemon configuration", c.Description)
			assert.NotNil(t, c.Properties)

			props := map[string]string{}
			for _, p := range *c.Properties {
				props[p.Name] = p.Value
			}

			assert.Equal(t, "true", props["theia:docker:tls"])
			assert.Equal(t, "true", props["theia:docker:tlsverify"])
			assert.Equal(t, "/etc/docker/certs/ca.pem", props["theia:docker:tlscacert"])
			assert.Equal(t, "/etc/docker/certs/server-cert.pem", props["theia:docker:tlscert"])
			assert.Equal(t, "/etc/docker/certs/server-key.pem", props["theia:docker:tlskey"])
			assert.Equal(t, "registry.internal:5000", props["theia:docker:insecure-registries"])

			// Check evidence
			assert.NotNil(t, c.Evidence)
			assert.NotNil(t, c.Evidence.Occurrences)
			assert.GreaterOrEqual(t, len(*c.Evidence.Occurrences), 1)
		}
	}
	assert.True(t, found, "daemon.json component should be present")
}

func Test_UpdateBOM_resolves_certificates_and_adds_dependsOn(t *testing.T) {
	// Use a test directory that has actual cert files at the referenced paths
	fs := filesystem.NewPlainFilesystem("../../../testdata/docker-with-certs/dir")
	bom := cdx.NewBOM()
	components := make([]cdx.Component, 0)
	bom.Components = &components

	plugin, err := NewDockerConfPlugin()
	assert.NoError(t, err)
	assert.NoError(t, plugin.UpdateBOM(fs, bom))

	assert.NotNil(t, bom.Components)

	// Find the daemon.json file component
	var fileCompBOMRef string
	for _, c := range *bom.Components {
		if c.Name == "daemon.json" && c.Type == cdx.ComponentTypeFile {
			fileCompBOMRef = c.BOMRef
			break
		}
	}
	assert.NotEmpty(t, fileCompBOMRef, "daemon.json file component should exist")

	// Find resolved certificate components (should have CertificateProperties with SubjectName filled)
	var certBOMRefs []string
	for _, c := range *bom.Components {
		if c.CryptoProperties != nil &&
			c.CryptoProperties.AssetType == cdx.CryptoAssetTypeCertificate &&
			c.CryptoProperties.CertificateProperties != nil &&
			c.CryptoProperties.CertificateProperties.SubjectName != "" {
			certBOMRefs = append(certBOMRefs, c.BOMRef)
		}
	}
	assert.NotEmpty(t, certBOMRefs, "should have resolved certificate components with SubjectName filled")

	// Verify algorithm components were generated (from cert resolution)
	var algorithmComps []cdx.Component
	for _, c := range *bom.Components {
		if c.CryptoProperties != nil && c.CryptoProperties.AssetType == cdx.CryptoAssetTypeAlgorithm {
			algorithmComps = append(algorithmComps, c)
		}
	}
	assert.NotEmpty(t, algorithmComps, "should have algorithm components from resolved certificates")

	// Verify dependsOn relationship exists from file component to certificate components
	assert.NotNil(t, bom.Dependencies, "BOM should have dependencies")
	foundDep := false
	for _, dep := range *bom.Dependencies {
		if dep.Ref == fileCompBOMRef {
			foundDep = true
			assert.NotNil(t, dep.Dependencies)
			// Each resolved cert BOMRef should be in the dependencies
			for _, certRef := range certBOMRefs {
				assert.Contains(t, *dep.Dependencies, certRef,
					"file component should dependOn resolved certificate %s", certRef)
			}
		}
	}
	assert.True(t, foundDep, "should have a dependency entry for the file component")
}

func Test_UpdateBOM_fallback_when_cert_not_found(t *testing.T) {
	// Use the original test directory where cert paths don't exist on filesystem
	fs := filesystem.NewPlainFilesystem("../../../testdata/docker/dir")
	bom := cdx.NewBOM()
	components := make([]cdx.Component, 0)
	bom.Components = &components

	plugin, err := NewDockerConfPlugin()
	assert.NoError(t, err)
	assert.NoError(t, plugin.UpdateBOM(fs, bom))

	assert.NotNil(t, bom.Components)

	// Should have placeholder certificate components (empty CertificateProperties)
	var placeholderCerts []cdx.Component
	for _, c := range *bom.Components {
		if c.CryptoProperties != nil &&
			c.CryptoProperties.AssetType == cdx.CryptoAssetTypeCertificate &&
			c.CryptoProperties.CertificateProperties != nil &&
			c.CryptoProperties.CertificateProperties.SubjectName == "" {
			placeholderCerts = append(placeholderCerts, c)
		}
	}
	assert.NotEmpty(t, placeholderCerts, "should have placeholder certificate components when files not found")

	// Should NOT have dependencies (since certs couldn't be resolved)
	if bom.Dependencies != nil {
		for _, dep := range *bom.Dependencies {
			// No dependency should point from file component to certs
			for _, c := range *bom.Components {
				if c.Name == "daemon.json" && c.Type == cdx.ComponentTypeFile {
					if dep.Ref == c.BOMRef {
						t.Error("file component should not have dependencies when certs are not resolved")
					}
				}
			}
		}
	}
}
