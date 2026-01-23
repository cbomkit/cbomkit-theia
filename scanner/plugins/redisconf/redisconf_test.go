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
	"os"
	"strings"
	testing "testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/cbomkit/cbomkit-theia/provider/filesystem"
	"github.com/stretchr/testify/assert"
)

func Test_isRedisConf(t *testing.T) {
	tests := []struct {
		path     string
		expected bool
	}{
		{"redis.conf", true},
		{"sentinel.conf", true},
		{"/etc/redis/redis.conf", true},
		{"/etc/redis/sentinel.conf", true},
		{"Redis.conf", true},
		{"REDIS.CONF", true},
		{"Sentinel.Conf", true},
		{"other.conf", false},
		{"redis.cnf", false},
		{"redis.conf.bak", false},
		{"myredis.conf", false},
		{"", false},
	}
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			assert.Equal(t, tt.expected, isRedisConf(tt.path))
		})
	}
}

func Test_parseRedisConf(t *testing.T) {
	content := `# Redis configuration file

port 6379
tls-port 6380

# TLS configuration
tls-cert-file /etc/redis/tls/redis.crt
tls-key-file /etc/redis/tls/redis.key
tls-ca-cert-file /etc/redis/tls/ca.crt

tls-protocols "TLSv1.2 TLSv1.3"
tls-ciphers ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384
tls-ciphersuites TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256

tls-prefer-server-ciphers yes
tls-auth-clients optional
tls-replication yes
tls-cluster yes
`
	cfg, err := parseRedisConf(strings.NewReader(content))
	assert.NoError(t, err)

	assert.Equal(t, "6379", cfg["port"])
	assert.Equal(t, "6380", cfg["tls-port"])
	assert.Equal(t, "/etc/redis/tls/redis.crt", cfg["tls-cert-file"])
	assert.Equal(t, "/etc/redis/tls/redis.key", cfg["tls-key-file"])
	assert.Equal(t, "/etc/redis/tls/ca.crt", cfg["tls-ca-cert-file"])
	assert.Equal(t, "TLSv1.2 TLSv1.3", cfg["tls-protocols"])
	assert.Equal(t, "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384", cfg["tls-ciphers"])
	assert.Equal(t, "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256", cfg["tls-ciphersuites"])
	assert.Equal(t, "yes", cfg["tls-prefer-server-ciphers"])
	assert.Equal(t, "optional", cfg["tls-auth-clients"])
	assert.Equal(t, "yes", cfg["tls-replication"])
	assert.Equal(t, "yes", cfg["tls-cluster"])

	// Test properties extraction
	props := extractRelevantProperties(cfg)
	m := map[string]string{}
	for _, p := range props {
		m[p.Name] = p.Value
	}
	assert.Equal(t, "TLSv1.2 TLSv1.3", m["theia:redis:tls-protocols"])
	assert.Equal(t, "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384", m["theia:redis:tls-ciphers"])
	assert.Equal(t, "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256", m["theia:redis:tls-ciphersuites"])
	assert.Equal(t, "/etc/redis/tls/redis.crt", m["theia:redis:tls-cert-file"])
	assert.Equal(t, "/etc/redis/tls/redis.key", m["theia:redis:tls-key-file"])
	assert.Equal(t, "/etc/redis/tls/ca.crt", m["theia:redis:tls-ca-cert-file"])
	assert.Equal(t, "yes", m["theia:redis:tls-prefer-server-ciphers"])
	assert.Equal(t, "optional", m["theia:redis:tls-auth-clients"])

	// Test TLS version detection
	versions := detectTLSVersions(cfg)
	assert.Contains(t, versions, "1.2")
	assert.Contains(t, versions, "1.3")

	// Test cipher suite detection
	suites := detectCipherSuiteNames(cfg)
	assert.Contains(t, suites, "TLS_AES_256_GCM_SHA384")
	assert.Contains(t, suites, "TLS_CHACHA20_POLY1305_SHA256")
}

func Test_UpdateBOM_resolves_certs_and_adds_dependsOn(t *testing.T) {
	// Use a test directory with actual cert files at the referenced paths
	fs := filesystem.NewPlainFilesystem("../../../testdata/redis-with-certs/dir")
	bom := cdx.NewBOM()
	components := make([]cdx.Component, 0)
	bom.Components = &components

	plugin, err := NewRedisConfPlugin()
	assert.NoError(t, err)
	assert.NoError(t, plugin.UpdateBOM(fs, bom))

	assert.NotNil(t, bom.Components)

	// Find the redis.conf file component
	var fileCompBOMRef string
	for _, c := range *bom.Components {
		if c.Name == "redis.conf" && c.Type == cdx.ComponentTypeFile {
			fileCompBOMRef = c.BOMRef
			break
		}
	}
	assert.NotEmpty(t, fileCompBOMRef, "redis.conf file component should exist")

	// Find resolved certificate components
	var certBOMRefs []string
	for _, c := range *bom.Components {
		if c.CryptoProperties != nil &&
			c.CryptoProperties.AssetType == cdx.CryptoAssetTypeCertificate &&
			c.CryptoProperties.CertificateProperties != nil &&
			c.CryptoProperties.CertificateProperties.SubjectName != "" {
			certBOMRefs = append(certBOMRefs, c.BOMRef)
		}
	}
	assert.NotEmpty(t, certBOMRefs, "should have resolved certificate components")

	// Verify dependsOn relationship
	assert.NotNil(t, bom.Dependencies, "BOM should have dependencies")
	foundDep := false
	for _, dep := range *bom.Dependencies {
		if dep.Ref == fileCompBOMRef {
			foundDep = true
			assert.NotNil(t, dep.Dependencies)
			for _, certRef := range certBOMRefs {
				assert.Contains(t, *dep.Dependencies, certRef,
					"file component should dependOn resolved certificate")
			}
		}
	}
	assert.True(t, foundDep, "should have a dependency from redis.conf to resolved certs")
}

func Test_UpdateBOM_adds_components(t *testing.T) {
	fs := filesystem.NewPlainFilesystem("../../../testdata/redis/dir")
	bom := cdx.NewBOM()
	components := make([]cdx.Component, 0)
	bom.Components = &components

	plugin, err := NewRedisConfPlugin()
	assert.NoError(t, err)
	assert.NoError(t, plugin.UpdateBOM(fs, bom))

	assert.NotNil(t, bom.Components)
	assert.GreaterOrEqual(t, len(*bom.Components), 1)

	err = cdx.NewBOMEncoder(os.Stdout, cdx.BOMFileFormatJSON).SetPretty(true).Encode(bom)
	if err != nil {
		t.Fail()
		return
	}

	found := false
	for _, c := range *bom.Components {
		if c.Name == "redis.conf" {
			found = true
			assert.Equal(t, cdx.ComponentTypeFile, c.Type)
			assert.NotNil(t, c.Properties)
			props := map[string]string{}
			for _, p := range *c.Properties {
				props[p.Name] = p.Value
			}
			assert.Equal(t, "TLSv1.2 TLSv1.3", props["theia:redis:tls-protocols"])
			assert.Equal(t, "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384", props["theia:redis:tls-ciphers"])
			assert.Equal(t, "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256", props["theia:redis:tls-ciphersuites"])
			assert.Equal(t, "/etc/redis/tls/redis.crt", props["theia:redis:tls-cert-file"])
			assert.Equal(t, "/etc/redis/tls/redis.key", props["theia:redis:tls-key-file"])
			assert.Equal(t, "/etc/redis/tls/ca.crt", props["theia:redis:tls-ca-cert-file"])
			assert.Equal(t, "yes", props["theia:redis:tls-prefer-server-ciphers"])
			assert.Equal(t, "optional", props["theia:redis:tls-auth-clients"])
		}
	}
	assert.True(t, found, "redis.conf component should be present")
}
