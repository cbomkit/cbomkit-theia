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
	"strings"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/cbomkit/cbomkit-theia/provider/filesystem"
	"github.com/stretchr/testify/assert"
)

func Test_isApacheConf(t *testing.T) {
	tests := []struct {
		path   string
		expect bool
	}{
		{"httpd.conf", true},
		{"apache2.conf", true},
		{"ssl.conf", true},
		{"/etc/httpd/conf/httpd.conf", true},
		{"/etc/apache2/sites-available/mysite.conf", true},
		{"/etc/apache2/mods-enabled/ssl.conf", true},
		{"nginx.conf", false},
		{"httpd.txt", false},
		{"/etc/redis/redis.conf", false},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			assert.Equal(t, tt.expect, isApacheConf(tt.path))
		})
	}
}

func Test_parseApacheConf(t *testing.T) {
	content := `
<IfModule mod_ssl.c>
    SSLEngine on
    SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1
    SSLCipherSuite ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384
    SSLHonorCipherOrder on
    SSLCertificateFile /etc/apache2/ssl/server.crt
    SSLCertificateKeyFile /etc/apache2/ssl/server.key
    SSLCACertificateFile /etc/apache2/ssl/ca.crt
    SSLCompression off
</IfModule>
`
	cfg, err := parseApacheConf(strings.NewReader(content))
	assert.NoError(t, err)

	assert.Equal(t, "on", cfg["SSLEngine"])
	assert.Equal(t, "all -SSLv3 -TLSv1 -TLSv1.1", cfg["SSLProtocol"])
	assert.Equal(t, "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384", cfg["SSLCipherSuite"])
	assert.Equal(t, "/etc/apache2/ssl/server.crt", cfg["SSLCertificateFile"])
	assert.Equal(t, "/etc/apache2/ssl/server.key", cfg["SSLCertificateKeyFile"])
	assert.Equal(t, "/etc/apache2/ssl/ca.crt", cfg["SSLCACertificateFile"])

	// Test version detection with "all -SSLv3 -TLSv1 -TLSv1.1" => TLSv1.2, TLSv1.3
	versions := detectTLSVersions(cfg)
	assert.Contains(t, versions, "1.2")
	assert.Contains(t, versions, "1.3")
	assert.NotContains(t, versions, "1")
	assert.NotContains(t, versions, "1.1")
}

func Test_UpdateBOM_adds_components(t *testing.T) {
	fs := filesystem.NewPlainFilesystem("../../../testdata/apache/dir")
	bom := cdx.NewBOM()
	components := make([]cdx.Component, 0)
	bom.Components = &components

	plugin, err := NewApacheConfPlugin()
	assert.NoError(t, err)
	assert.Equal(t, "Apache HTTPD Config Plugin", plugin.GetName())
	assert.NotEmpty(t, plugin.GetExplanation())

	assert.NoError(t, plugin.UpdateBOM(fs, bom))

	assert.NotNil(t, bom.Components)
	assert.GreaterOrEqual(t, len(*bom.Components), 1)

	found := false
	for _, c := range *bom.Components {
		if c.Name == "ssl.conf" && c.Type == cdx.ComponentTypeFile {
			found = true
			assert.NotNil(t, c.Properties)
			props := map[string]string{}
			for _, p := range *c.Properties {
				props[p.Name] = p.Value
			}
			assert.Equal(t, "all -SSLv3 -TLSv1 -TLSv1.1", props["theia:apache:SSLProtocol"])
			assert.Contains(t, props["theia:apache:SSLCipherSuite"], "ECDHE-ECDSA-AES256-GCM-SHA384")
			assert.Equal(t, "/etc/apache2/ssl/server.crt", props["theia:apache:SSLCertificateFile"])
			assert.Equal(t, "/etc/apache2/ssl/server.key", props["theia:apache:SSLCertificateKeyFile"])
			assert.Equal(t, "on", props["theia:apache:SSLHonorCipherOrder"])
		}
	}
	assert.True(t, found, "ssl.conf component should be present")
}
