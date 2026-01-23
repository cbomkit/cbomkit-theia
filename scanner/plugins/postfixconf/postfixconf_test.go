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

package postfixconf

import (
	"strings"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/cbomkit/cbomkit-theia/provider/filesystem"
	"github.com/stretchr/testify/assert"
)

func Test_isPostfixConf(t *testing.T) {
	tests := []struct {
		path   string
		expect bool
	}{
		{"/etc/postfix/main.cf", true},
		{"main.cf", false}, // needs postfix in path
		{"/etc/redis/redis.conf", false},
		{"/etc/postfix/master.cf", false}, // only main.cf
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			assert.Equal(t, tt.expect, isPostfixConf(tt.path))
		})
	}
}

func Test_parsePostfixConf(t *testing.T) {
	content := `# Postfix TLS settings

smtpd_tls_cert_file = /etc/postfix/ssl/server.crt
smtpd_tls_key_file = /etc/postfix/ssl/server.key
smtpd_tls_CAfile = /etc/postfix/ssl/ca.crt
smtpd_tls_security_level = may
smtpd_tls_protocols = !SSLv2, !SSLv3, TLSv1.2, TLSv1.3
smtpd_tls_mandatory_protocols = !SSLv2, !SSLv3, !TLSv1, !TLSv1.1
smtpd_tls_ciphers = high
tls_high_cipherlist = ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384
tls_preempt_cipherlist = yes
smtp_tls_protocols = !SSLv2, !SSLv3, TLSv1.2, TLSv1.3
`
	cfg, err := parsePostfixConf(strings.NewReader(content))
	assert.NoError(t, err)

	assert.Equal(t, "/etc/postfix/ssl/server.crt", cfg["smtpd_tls_cert_file"])
	assert.Equal(t, "/etc/postfix/ssl/server.key", cfg["smtpd_tls_key_file"])
	assert.Equal(t, "/etc/postfix/ssl/ca.crt", cfg["smtpd_tls_CAfile"])
	assert.Equal(t, "may", cfg["smtpd_tls_security_level"])
	assert.Equal(t, "high", cfg["smtpd_tls_ciphers"])
	assert.Equal(t, "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384", cfg["tls_high_cipherlist"])

	// Test version detection
	versions := detectTLSVersions(cfg, "smtpd_tls_protocols")
	assert.Contains(t, versions, "1.2")
	assert.Contains(t, versions, "1.3")

	// Test properties
	props := extractRelevantProperties(cfg)
	propMap := map[string]string{}
	for _, p := range props {
		propMap[p.Name] = p.Value
	}
	assert.Equal(t, "/etc/postfix/ssl/server.crt", propMap["theia:postfix:smtpd_tls_cert_file"])
	assert.Equal(t, "may", propMap["theia:postfix:smtpd_tls_security_level"])
}

func Test_parsePostfixConf_continuation_lines(t *testing.T) {
	content := `smtpd_tls_protocols = !SSLv2, !SSLv3,
    TLSv1.2, TLSv1.3
smtpd_tls_cert_file = /etc/postfix/ssl/server.crt
`
	cfg, err := parsePostfixConf(strings.NewReader(content))
	assert.NoError(t, err)

	// Continuation lines should be joined
	assert.Contains(t, cfg["smtpd_tls_protocols"], "TLSv1.2")
	assert.Contains(t, cfg["smtpd_tls_protocols"], "TLSv1.3")
	assert.Equal(t, "/etc/postfix/ssl/server.crt", cfg["smtpd_tls_cert_file"])
}

func Test_UpdateBOM_adds_components(t *testing.T) {
	fs := filesystem.NewPlainFilesystem("../../../testdata/postfix/dir")
	bom := cdx.NewBOM()
	components := make([]cdx.Component, 0)
	bom.Components = &components

	plugin, err := NewPostfixConfPlugin()
	assert.NoError(t, err)
	assert.Equal(t, "Postfix Config Plugin", plugin.GetName())
	assert.NotEmpty(t, plugin.GetExplanation())

	assert.NoError(t, plugin.UpdateBOM(fs, bom))

	assert.NotNil(t, bom.Components)
	assert.GreaterOrEqual(t, len(*bom.Components), 1)

	found := false
	for _, c := range *bom.Components {
		if c.Name == "main.cf" && c.Type == cdx.ComponentTypeFile {
			found = true
			assert.NotNil(t, c.Properties)
			props := map[string]string{}
			for _, p := range *c.Properties {
				props[p.Name] = p.Value
			}
			assert.Equal(t, "/etc/postfix/ssl/server.crt", props["theia:postfix:smtpd_tls_cert_file"])
			assert.Equal(t, "/etc/postfix/ssl/server.key", props["theia:postfix:smtpd_tls_key_file"])
			assert.Equal(t, "/etc/postfix/ssl/ca.crt", props["theia:postfix:smtpd_tls_CAfile"])
			assert.Equal(t, "may", props["theia:postfix:smtpd_tls_security_level"])
			assert.Contains(t, props["theia:postfix:tls_high_cipherlist"], "ECDHE-ECDSA-AES256-GCM-SHA384")
		}
	}
	assert.True(t, found, "main.cf component should be present")
}
