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

package dovecotconf

import (
	"strings"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/cbomkit/cbomkit-theia/provider/filesystem"
	"github.com/stretchr/testify/assert"
)

func Test_isDovecotConf(t *testing.T) {
	tests := []struct {
		path   string
		expect bool
	}{
		{"dovecot.conf", true},
		{"/etc/dovecot/dovecot.conf", true},
		{"/etc/dovecot/conf.d/10-ssl.conf", true},
		{"/etc/dovecot/conf.d/10-auth.conf", true},
		{"redis.conf", false},
		{"/etc/nginx/nginx.conf", false},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			assert.Equal(t, tt.expect, isDovecotConf(tt.path))
		})
	}
}

func Test_parseDovecotConf(t *testing.T) {
	content := `
ssl = required

ssl_cert = </etc/dovecot/ssl/server.crt
ssl_key = </etc/dovecot/ssl/server.key
ssl_ca = </etc/dovecot/ssl/ca.crt

ssl_min_protocol = TLSv1.2
ssl_cipher_list = ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384
ssl_cipher_suites = TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256
ssl_prefer_server_ciphers = yes
ssl_dh = </etc/dovecot/ssl/dh.pem
`
	cfg, err := parseDovecotConf(strings.NewReader(content))
	assert.NoError(t, err)

	assert.Equal(t, "required", cfg["ssl"])
	assert.Equal(t, "/etc/dovecot/ssl/server.crt", cfg["ssl_cert"])
	assert.Equal(t, "/etc/dovecot/ssl/server.key", cfg["ssl_key"])
	assert.Equal(t, "/etc/dovecot/ssl/ca.crt", cfg["ssl_ca"])
	assert.Equal(t, "TLSv1.2", cfg["ssl_min_protocol"])
	assert.Equal(t, "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384", cfg["ssl_cipher_list"])
	assert.Equal(t, "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256", cfg["ssl_cipher_suites"])
	assert.Equal(t, "/etc/dovecot/ssl/dh.pem", cfg["ssl_dh"])

	// Test version detection (min = 1.2 implies 1.2 and 1.3)
	versions := detectTLSVersions(cfg)
	assert.Contains(t, versions, "1.2")
	assert.Contains(t, versions, "1.3")

	// Test cipher suite detection
	suites := detectCipherSuiteNames(cfg)
	assert.Contains(t, suites, "TLS_AES_256_GCM_SHA384")
	assert.Contains(t, suites, "TLS_CHACHA20_POLY1305_SHA256")

	// Test properties
	props := extractRelevantProperties(cfg)
	propMap := map[string]string{}
	for _, p := range props {
		propMap[p.Name] = p.Value
	}
	assert.Equal(t, "required", propMap["theia:dovecot:ssl"])
	assert.Equal(t, "/etc/dovecot/ssl/server.crt", propMap["theia:dovecot:ssl_cert"])
	assert.Equal(t, "TLSv1.2", propMap["theia:dovecot:ssl_min_protocol"])
}

func Test_UpdateBOM_adds_components(t *testing.T) {
	fs := filesystem.NewPlainFilesystem("../../../testdata/dovecot/dir")
	bom := cdx.NewBOM()
	components := make([]cdx.Component, 0)
	bom.Components = &components

	plugin, err := NewDovecotConfPlugin()
	assert.NoError(t, err)
	assert.Equal(t, "Dovecot Config Plugin", plugin.GetName())
	assert.NotEmpty(t, plugin.GetExplanation())

	assert.NoError(t, plugin.UpdateBOM(fs, bom))

	assert.NotNil(t, bom.Components)
	assert.GreaterOrEqual(t, len(*bom.Components), 1)

	found := false
	for _, c := range *bom.Components {
		if c.Name == "10-ssl.conf" && c.Type == cdx.ComponentTypeFile {
			found = true
			assert.NotNil(t, c.Properties)
			props := map[string]string{}
			for _, p := range *c.Properties {
				props[p.Name] = p.Value
			}
			assert.Equal(t, "required", props["theia:dovecot:ssl"])
			assert.Equal(t, "/etc/dovecot/ssl/server.crt", props["theia:dovecot:ssl_cert"])
			assert.Equal(t, "/etc/dovecot/ssl/server.key", props["theia:dovecot:ssl_key"])
			assert.Equal(t, "TLSv1.2", props["theia:dovecot:ssl_min_protocol"])
			assert.Contains(t, props["theia:dovecot:ssl_cipher_list"], "ECDHE-ECDSA-AES256-GCM-SHA384")
		}
	}
	assert.True(t, found, "10-ssl.conf component should be present")
}
