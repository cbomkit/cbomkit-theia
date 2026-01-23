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

package mysqlconf

import (
	"os"
	"strings"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/cbomkit/cbomkit-theia/provider/filesystem"
	"github.com/stretchr/testify/assert"
)

func Test_isMySQLConf(t *testing.T) {
	tests := []struct {
		path     string
		expected bool
	}{
		{"my.cnf", true},
		{"My.cnf", true},
		{"MY.CNF", true},
		{"mysqld.cnf", true},
		{"Mysqld.cnf", true},
		{"/etc/mysql/conf.d/custom.cnf", true},
		{"/etc/mysql/my.cnf", true},
		{"etc/mariadb/conf.d/server.cnf", true},
		{"/etc/mariadb/mariadb.cnf", true},
		{"openssl.cnf", false},
		{"/etc/something/other.cnf", false},
		{"/etc/nginx/nginx.conf", false},
		{"my.ini", false},
		{"random.txt", false},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			result := isMySQLConf(tt.path)
			assert.Equal(t, tt.expected, result, "isMySQLConf(%q) = %v, want %v", tt.path, result, tt.expected)
		})
	}
}

func Test_parseMySQLConf(t *testing.T) {
	content := `
# MySQL configuration file
; Another comment style
[mysqld]
port = 3306
datadir = /var/lib/mysql

# SSL/TLS configuration
ssl-ca = /etc/mysql/ssl/ca.pem
ssl_cert = /etc/mysql/ssl/server-cert.pem
ssl-key = /etc/mysql/ssl/server-key.pem
ssl-cipher = ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384
tls_version = TLSv1.2,TLSv1.3
tls-ciphersuites = TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256
require_secure_transport = ON
ssl-fips-mode = OFF
ssl-crl = /etc/mysql/ssl/crl.pem

!includedir /etc/mysql/conf.d/

[client]
ssl-ca = /etc/mysql/ssl/ca.pem
ssl-cert = /etc/mysql/ssl/client-cert.pem
ssl-key = /etc/mysql/ssl/client-key.pem
`
	cfg, err := parseMySQLConf(strings.NewReader(content))
	assert.NoError(t, err)
	assert.NotNil(t, cfg)

	// Check [mysqld] section values (underscores normalized to hyphens)
	mysqld, ok := cfg["mysqld"]
	assert.True(t, ok, "mysqld section should exist")
	assert.Equal(t, "3306", mysqld["port"])
	assert.Equal(t, "/var/lib/mysql", mysqld["datadir"])
	assert.Equal(t, "/etc/mysql/ssl/ca.pem", mysqld["ssl-ca"])
	assert.Equal(t, "/etc/mysql/ssl/server-cert.pem", mysqld["ssl-cert"])
	assert.Equal(t, "/etc/mysql/ssl/server-key.pem", mysqld["ssl-key"])
	assert.Equal(t, "ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384", mysqld["ssl-cipher"])
	assert.Equal(t, "TLSv1.2,TLSv1.3", mysqld["tls-version"])
	assert.Equal(t, "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256", mysqld["tls-ciphersuites"])
	assert.Equal(t, "ON", mysqld["require-secure-transport"])
	assert.Equal(t, "OFF", mysqld["ssl-fips-mode"])
	assert.Equal(t, "/etc/mysql/ssl/crl.pem", mysqld["ssl-crl"])

	// Check [client] section
	client, ok := cfg["client"]
	assert.True(t, ok, "client section should exist")
	assert.Equal(t, "/etc/mysql/ssl/ca.pem", client["ssl-ca"])
	assert.Equal(t, "/etc/mysql/ssl/client-cert.pem", client["ssl-cert"])
	assert.Equal(t, "/etc/mysql/ssl/client-key.pem", client["ssl-key"])

	// Extract properties and verify
	props := extractRelevantProperties(cfg)
	m := map[string]string{}
	for _, p := range props {
		m[p.Name] = p.Value
	}
	assert.Equal(t, "/etc/mysql/ssl/ca.pem", m["theia:mysql:ssl-ca"])
	assert.Equal(t, "/etc/mysql/ssl/server-cert.pem", m["theia:mysql:ssl-cert"])
	assert.Equal(t, "/etc/mysql/ssl/server-key.pem", m["theia:mysql:ssl-key"])
	assert.Equal(t, "ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384", m["theia:mysql:ssl-cipher"])
	assert.Equal(t, "TLSv1.2,TLSv1.3", m["theia:mysql:tls-version"])
	assert.Equal(t, "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256", m["theia:mysql:tls-ciphersuites"])
	assert.Equal(t, "ON", m["theia:mysql:require-secure-transport"])
	assert.Equal(t, "OFF", m["theia:mysql:ssl-fips-mode"])
	assert.Equal(t, "/etc/mysql/ssl/crl.pem", m["theia:mysql:ssl-crl"])
}

func Test_parseMySQLConf_detectVersions(t *testing.T) {
	content := `
[mysqld]
tls-version = TLSv1.2,TLSv1.3
`
	cfg, err := parseMySQLConf(strings.NewReader(content))
	assert.NoError(t, err)

	versions := detectTLSVersions(cfg)
	assert.Contains(t, versions, "1.2")
	assert.Contains(t, versions, "1.3")
	assert.Len(t, versions, 2)
}

func Test_parseMySQLConf_detectCipherSuites(t *testing.T) {
	content := `
[mysqld]
tls-ciphersuites = TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256
`
	cfg, err := parseMySQLConf(strings.NewReader(content))
	assert.NoError(t, err)

	suites := detectCipherSuiteNames(cfg)
	assert.Contains(t, suites, "TLS_AES_256_GCM_SHA384")
	assert.Contains(t, suites, "TLS_CHACHA20_POLY1305_SHA256")
}

func Test_UpdateBOM_adds_components(t *testing.T) {
	fs := filesystem.NewPlainFilesystem("../../../testdata/mysql/dir")
	bom := cdx.NewBOM()
	components := make([]cdx.Component, 0)
	bom.Components = &components

	plugin, err := NewMySQLConfPlugin()
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
		if c.Name == "my.cnf" {
			found = true
			assert.NotNil(t, c.Properties)
			props := map[string]string{}
			for _, p := range *c.Properties {
				props[p.Name] = p.Value
			}
			assert.Equal(t, "/etc/mysql/ssl/ca.pem", props["theia:mysql:ssl-ca"])
			assert.Equal(t, "/etc/mysql/ssl/server-cert.pem", props["theia:mysql:ssl-cert"])
			assert.Equal(t, "/etc/mysql/ssl/server-key.pem", props["theia:mysql:ssl-key"])
			assert.Equal(t, "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384", props["theia:mysql:ssl-cipher"])
			assert.Equal(t, "TLSv1.2,TLSv1.3", props["theia:mysql:tls-version"])
			assert.Equal(t, "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256", props["theia:mysql:tls-ciphersuites"])
			assert.Equal(t, "ON", props["theia:mysql:require-secure-transport"])
			assert.Equal(t, "OFF", props["theia:mysql:ssl-fips-mode"])
		}
	}
	assert.True(t, found, "my.cnf component should be present")
}
