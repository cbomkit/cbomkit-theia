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

package haproxyconf

import (
	"strings"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/cbomkit/cbomkit-theia/provider/filesystem"
	"github.com/stretchr/testify/assert"
)

func Test_isHAProxyConf(t *testing.T) {
	tests := []struct {
		path   string
		expect bool
	}{
		{"haproxy.cfg", true},
		{"/etc/haproxy/haproxy.cfg", true},
		{"/etc/haproxy/conf.d/frontend.cfg", true},
		{"other.cfg", false},
		{"haproxy.conf", false},
		{"/etc/nginx/nginx.conf", false},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			assert.Equal(t, tt.expect, isHAProxyConf(tt.path))
		})
	}
}

func Test_parseHAProxyConf(t *testing.T) {
	content := `
global
    ssl-default-bind-ciphers ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384
    ssl-default-bind-ciphersuites TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256
    ssl-default-bind-options ssl-min-ver TLSv1.2 no-tls-tickets
    ssl-dh-param-file /etc/haproxy/dhparam.pem

frontend https
    bind *:443 ssl crt /etc/haproxy/certs/server.pem ca-file /etc/haproxy/certs/ca.pem
`
	cfg, err := parseHAProxyConf(strings.NewReader(content))
	assert.NoError(t, err)

	assert.Equal(t, "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384", cfg["ssl-default-bind-ciphers"])
	assert.Equal(t, "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256", cfg["ssl-default-bind-ciphersuites"])
	assert.Contains(t, cfg["ssl-default-bind-options"], "ssl-min-ver TLSv1.2")
	assert.Equal(t, "/etc/haproxy/dhparam.pem", cfg["ssl-dh-param-file"])
	assert.Equal(t, "/etc/haproxy/certs/server.pem", cfg["bind:crt"])
	assert.Equal(t, "/etc/haproxy/certs/ca.pem", cfg["bind:ca-file"])

	// Test version detection from options
	versions := detectTLSVersions(cfg)
	assert.Contains(t, versions, "1.2")

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
	assert.Equal(t, "/etc/haproxy/dhparam.pem", propMap["theia:haproxy:ssl-dh-param-file"])
	assert.Equal(t, "/etc/haproxy/certs/server.pem", propMap["theia:haproxy:bind:crt"])
}

func Test_UpdateBOM_adds_components(t *testing.T) {
	fs := filesystem.NewPlainFilesystem("../../../testdata/haproxy/dir")
	bom := cdx.NewBOM()
	components := make([]cdx.Component, 0)
	bom.Components = &components

	plugin, err := NewHAProxyConfPlugin()
	assert.NoError(t, err)
	assert.Equal(t, "HAProxy Config Plugin", plugin.GetName())

	assert.NoError(t, plugin.UpdateBOM(fs, bom))

	assert.NotNil(t, bom.Components)
	assert.GreaterOrEqual(t, len(*bom.Components), 1)

	found := false
	for _, c := range *bom.Components {
		if c.Name == "haproxy.cfg" && c.Type == cdx.ComponentTypeFile {
			found = true
			assert.NotNil(t, c.Properties)
			props := map[string]string{}
			for _, p := range *c.Properties {
				props[p.Name] = p.Value
			}
			assert.Contains(t, props["theia:haproxy:ssl-default-bind-ciphers"], "ECDHE-ECDSA-AES256-GCM-SHA384")
			assert.Contains(t, props["theia:haproxy:ssl-default-bind-ciphersuites"], "TLS_AES_256_GCM_SHA384")
		}
	}
	assert.True(t, found, "haproxy.cfg component should be present")
}
