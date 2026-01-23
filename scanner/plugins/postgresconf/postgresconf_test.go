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

package postgresconf

import (
	"strings"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/cbomkit/cbomkit-theia/provider/filesystem"
	"github.com/stretchr/testify/assert"
)

func Test_isPostgresConf(t *testing.T) {
	tests := []struct {
		path     string
		expected bool
	}{
		{"postgresql.conf", true},
		{"pg_hba.conf", true},
		{"/etc/postgresql/14/main/postgresql.conf", true},
		{"/etc/postgresql/14/main/pg_hba.conf", true},
		{"PostgreSQL.conf", true},
		{"openssl.cnf", false},
		{"pg_ident.conf", false},
		{"some_other.conf", false},
		{"/var/lib/postgresql/data/postgresql.conf", true},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			result := isPostgresConf(tt.path)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func Test_parsePostgresConf(t *testing.T) {
	content := `
# PostgreSQL configuration
listen_addresses = '*'
port = 5432

# SSL configuration
ssl = on
ssl_cert_file = '/etc/postgresql/server.crt'
ssl_key_file = '/etc/postgresql/server.key'
ssl_ca_file = '/etc/postgresql/ca.crt'
ssl_crl_file = '/etc/postgresql/root.crl'
ssl_ciphers = 'ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384'
ssl_prefer_server_ciphers = on
ssl_ecdh_curve = 'prime256v1'
ssl_min_protocol_version = 'TLSv1.2'
ssl_max_protocol_version = 'TLSv1.3'
ssl_dh_params_file = '/etc/postgresql/dh2048.pem'
password_encryption = 'scram-sha-256'
`
	settings, err := parsePostgresConf(strings.NewReader(content))
	assert.NoError(t, err)

	assert.Equal(t, "on", settings["ssl"])
	assert.Equal(t, "/etc/postgresql/server.crt", settings["ssl_cert_file"])
	assert.Equal(t, "/etc/postgresql/server.key", settings["ssl_key_file"])
	assert.Equal(t, "/etc/postgresql/ca.crt", settings["ssl_ca_file"])
	assert.Equal(t, "/etc/postgresql/root.crl", settings["ssl_crl_file"])
	assert.Equal(t, "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384", settings["ssl_ciphers"])
	assert.Equal(t, "on", settings["ssl_prefer_server_ciphers"])
	assert.Equal(t, "prime256v1", settings["ssl_ecdh_curve"])
	assert.Equal(t, "TLSv1.2", settings["ssl_min_protocol_version"])
	assert.Equal(t, "TLSv1.3", settings["ssl_max_protocol_version"])
	assert.Equal(t, "/etc/postgresql/dh2048.pem", settings["ssl_dh_params_file"])
	assert.Equal(t, "scram-sha-256", settings["password_encryption"])

	// Non-crypto directives should not be captured
	_, hasPort := settings["port"]
	assert.False(t, hasPort)
	_, hasListen := settings["listen_addresses"]
	assert.False(t, hasListen)
}

func Test_parsePostgresConf_inline_comments(t *testing.T) {
	content := `
ssl = on # enable SSL
ssl_min_protocol_version = 'TLSv1.2' # minimum version
password_encryption = 'scram-sha-256' # strong hash
`
	settings, err := parsePostgresConf(strings.NewReader(content))
	assert.NoError(t, err)

	assert.Equal(t, "on", settings["ssl"])
	assert.Equal(t, "TLSv1.2", settings["ssl_min_protocol_version"])
	assert.Equal(t, "scram-sha-256", settings["password_encryption"])
}

func Test_parsePgHbaConf(t *testing.T) {
	content := `
# TYPE  DATABASE        USER            ADDRESS                 METHOD
local   all             all                                     peer
hostssl all             all             0.0.0.0/0               scram-sha-256
hostssl all             all             ::/0                    scram-sha-256
host    all             all             127.0.0.1/32            md5
hostssl replication     replication     0.0.0.0/0               cert
host    all             all             192.168.1.0/24          trust
`
	methods, err := parsePgHbaConf(strings.NewReader(content))
	assert.NoError(t, err)

	// Should find cert, md5, scram-sha-256 (sorted, deduplicated)
	assert.Equal(t, []string{"cert", "md5", "scram-sha-256"}, methods)
}

func Test_parsePgHbaConf_no_crypto_methods(t *testing.T) {
	content := `
# TYPE  DATABASE        USER            ADDRESS                 METHOD
local   all             all                                     peer
host    all             all             127.0.0.1/32            trust
`
	methods, err := parsePgHbaConf(strings.NewReader(content))
	assert.NoError(t, err)
	assert.Empty(t, methods)
}

func Test_detectPostgresTLSVersions(t *testing.T) {
	settings := map[string]string{
		"ssl_min_protocol_version": "TLSv1.2",
		"ssl_max_protocol_version": "TLSv1.3",
	}
	versions := detectPostgresTLSVersions(settings)
	assert.Equal(t, []string{"1.2", "1.3"}, versions)
}

func Test_detectPostgresTLSVersions_single(t *testing.T) {
	settings := map[string]string{
		"ssl_min_protocol_version": "TLSv1.2",
	}
	versions := detectPostgresTLSVersions(settings)
	assert.Equal(t, []string{"1.2"}, versions)
}

func Test_extractPostgresProperties(t *testing.T) {
	settings := map[string]string{
		"ssl":                      "on",
		"ssl_min_protocol_version": "TLSv1.2",
		"password_encryption":      "scram-sha-256",
	}
	props := extractPostgresProperties(settings)
	m := make(map[string]string)
	for _, p := range props {
		m[p.Name] = p.Value
	}
	assert.Equal(t, "on", m["theia:postgresql:ssl"])
	assert.Equal(t, "TLSv1.2", m["theia:postgresql:ssl_min_protocol_version"])
	assert.Equal(t, "scram-sha-256", m["theia:postgresql:password_encryption"])
}

func Test_UpdateBOM_adds_components(t *testing.T) {
	fs := filesystem.NewPlainFilesystem("../../../testdata/postgresql/dir")
	bom := cdx.NewBOM()
	components := make([]cdx.Component, 0)
	bom.Components = &components

	plugin, err := NewPostgresConfPlugin()
	assert.NoError(t, err)
	assert.NoError(t, plugin.UpdateBOM(fs, bom))

	assert.NotNil(t, bom.Components)
	assert.GreaterOrEqual(t, len(*bom.Components), 2, "should have at least postgresql.conf and pg_hba.conf components")

	// Check postgresql.conf component
	foundPostgresConf := false
	foundPgHba := false
	for _, c := range *bom.Components {
		if c.Name == "postgresql.conf" {
			foundPostgresConf = true
			assert.Equal(t, cdx.ComponentTypeFile, c.Type)
			assert.NotNil(t, c.Properties)
			props := make(map[string]string)
			for _, p := range *c.Properties {
				props[p.Name] = p.Value
			}
			assert.Equal(t, "on", props["theia:postgresql:ssl"])
			assert.Equal(t, "/etc/postgresql/server.crt", props["theia:postgresql:ssl_cert_file"])
			assert.Equal(t, "/etc/postgresql/server.key", props["theia:postgresql:ssl_key_file"])
			assert.Equal(t, "/etc/postgresql/ca.crt", props["theia:postgresql:ssl_ca_file"])
			assert.Equal(t, "TLSv1.2", props["theia:postgresql:ssl_min_protocol_version"])
			assert.Equal(t, "TLSv1.3", props["theia:postgresql:ssl_max_protocol_version"])
			assert.Equal(t, "scram-sha-256", props["theia:postgresql:password_encryption"])
			assert.Contains(t, props["theia:postgresql:ssl_ciphers"], "ECDHE-ECDSA-AES256-GCM-SHA384")
		}
		if c.Name == "pg_hba.conf" {
			foundPgHba = true
			assert.Equal(t, cdx.ComponentTypeFile, c.Type)
			assert.NotNil(t, c.Properties)
			props := make(map[string]string)
			for _, p := range *c.Properties {
				props[p.Name] = p.Value
			}
			assert.Contains(t, props["theia:postgresql:auth_methods"], "scram-sha-256")
			assert.Contains(t, props["theia:postgresql:auth_methods"], "cert")
			assert.Contains(t, props["theia:postgresql:auth_methods"], "md5")
		}
	}
	assert.True(t, foundPostgresConf, "postgresql.conf component should be present")
	assert.True(t, foundPgHba, "pg_hba.conf component should be present")

	// Check that a password_encryption algorithm component was created
	foundHashAlgo := false
	for _, c := range *bom.Components {
		if c.Type == cdx.ComponentTypeCryptographicAsset && c.CryptoProperties != nil {
			if c.CryptoProperties.AssetType == cdx.CryptoAssetTypeAlgorithm &&
				c.CryptoProperties.AlgorithmProperties != nil &&
				c.CryptoProperties.AlgorithmProperties.Primitive == cdx.CryptoPrimitiveHash &&
				c.Name == "SCRAM-SHA-256" {
				foundHashAlgo = true
			}
		}
	}
	assert.True(t, foundHashAlgo, "SCRAM-SHA-256 hash algorithm component should be present")
}
