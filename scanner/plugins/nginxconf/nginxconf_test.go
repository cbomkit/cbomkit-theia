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

package nginxconf

import (
	"strings"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/cbomkit/cbomkit-theia/provider/filesystem"
	"github.com/stretchr/testify/assert"
)

func Test_isNginxConf(t *testing.T) {
	tests := []struct {
		path   string
		expect bool
	}{
		{"nginx.conf", true},
		{"/etc/nginx/nginx.conf", true},
		{"/etc/nginx/conf.d/ssl.conf", true},
		{"/etc/nginx/sites-available/mysite.conf", true},
		{"ssl.conf", true},
		{"NGINX.CONF", true},
		{"other.conf", false},
		{"nginx.txt", false},
		{"/etc/apache2/apache2.conf", false},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			assert.Equal(t, tt.expect, isNginxConf(tt.path))
		})
	}
}

func Test_parseNginxConf(t *testing.T) {
	content := `
worker_processes auto;

http {
    server {
        listen 443 ssl;
        ssl_protocols TLSv1.2 TLSv1.3;
        ssl_ciphers ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;
        ssl_certificate /etc/nginx/ssl/server.crt;
        ssl_certificate_key /etc/nginx/ssl/server.key;
        ssl_prefer_server_ciphers on;
        ssl_ecdh_curve secp384r1;
    }
}
`
	cfg, err := parseNginxConf(strings.NewReader(content))
	assert.NoError(t, err)

	assert.Equal(t, "TLSv1.2 TLSv1.3", cfg["ssl_protocols"])
	assert.Equal(t, "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384", cfg["ssl_ciphers"])
	assert.Equal(t, "/etc/nginx/ssl/server.crt", cfg["ssl_certificate"])
	assert.Equal(t, "/etc/nginx/ssl/server.key", cfg["ssl_certificate_key"])
	assert.Equal(t, "on", cfg["ssl_prefer_server_ciphers"])
	assert.Equal(t, "secp384r1", cfg["ssl_ecdh_curve"])

	// Test version detection
	versions := detectTLSVersions(cfg)
	assert.Contains(t, versions, "1.2")
	assert.Contains(t, versions, "1.3")

	// Test properties
	props := extractRelevantProperties(cfg)
	propMap := map[string]string{}
	for _, p := range props {
		propMap[p.Name] = p.Value
	}
	assert.Equal(t, "TLSv1.2 TLSv1.3", propMap["theia:nginx:ssl_protocols"])
	assert.Equal(t, "/etc/nginx/ssl/server.crt", propMap["theia:nginx:ssl_certificate"])
	assert.Equal(t, "/etc/nginx/ssl/server.key", propMap["theia:nginx:ssl_certificate_key"])
}

func Test_UpdateBOM_adds_components(t *testing.T) {
	fs := filesystem.NewPlainFilesystem("../../../testdata/nginx/dir")
	bom := cdx.NewBOM()
	components := make([]cdx.Component, 0)
	bom.Components = &components

	plugin, err := NewNginxConfPlugin()
	assert.NoError(t, err)
	assert.Equal(t, "Nginx Config Plugin", plugin.GetName())
	assert.NotEmpty(t, plugin.GetExplanation())

	assert.NoError(t, plugin.UpdateBOM(fs, bom))

	assert.NotNil(t, bom.Components)
	assert.GreaterOrEqual(t, len(*bom.Components), 1)

	// Find the nginx.conf file component
	found := false
	for _, c := range *bom.Components {
		if c.Name == "nginx.conf" && c.Type == cdx.ComponentTypeFile {
			found = true
			assert.NotNil(t, c.Properties)
			props := map[string]string{}
			for _, p := range *c.Properties {
				props[p.Name] = p.Value
			}
			assert.Equal(t, "TLSv1.2 TLSv1.3", props["theia:nginx:ssl_protocols"])
			assert.Contains(t, props["theia:nginx:ssl_ciphers"], "ECDHE-ECDSA-AES256-GCM-SHA384")
			assert.Equal(t, "/etc/nginx/ssl/server.crt", props["theia:nginx:ssl_certificate"])
			assert.Equal(t, "/etc/nginx/ssl/server.key", props["theia:nginx:ssl_certificate_key"])
			assert.Equal(t, "on", props["theia:nginx:ssl_prefer_server_ciphers"])
			assert.Equal(t, "on", props["theia:nginx:ssl_stapling"])
		}
	}
	assert.True(t, found, "nginx.conf component should be present")
}
