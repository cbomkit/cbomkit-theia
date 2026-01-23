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

package elasticsearchconf

import (
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/cbomkit/cbomkit-theia/provider/filesystem"
	"github.com/stretchr/testify/assert"
)

func Test_isElasticsearchConf(t *testing.T) {
	tests := []struct {
		path   string
		expect bool
	}{
		{"elasticsearch.yml", true},
		{"elasticsearch.yaml", true},
		{"/etc/elasticsearch/elasticsearch.yml", true},
		{"ELASTICSEARCH.YML", true},
		{"kibana.yml", false},
		{"elastic.yml", false},
		{"elasticsearch.conf", false},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			assert.Equal(t, tt.expect, isElasticsearchConf(tt.path))
		})
	}
}

func Test_parseElasticsearchConf(t *testing.T) {
	content := []byte(`
xpack:
  security:
    transport:
      ssl:
        enabled: true
        verification_mode: full
        key: /etc/elasticsearch/certs/transport.key
        certificate: /etc/elasticsearch/certs/transport.crt
        certificate_authorities:
          - /etc/elasticsearch/certs/ca.crt
        supported_protocols:
          - TLSv1.2
          - TLSv1.3
        cipher_suites:
          - TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
          - TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
        client_authentication: required
    http:
      ssl:
        enabled: true
        key: /etc/elasticsearch/certs/http.key
        certificate: /etc/elasticsearch/certs/http.crt
        supported_protocols:
          - TLSv1.2
        cipher_suites:
          - TLS_AES_256_GCM_SHA384
    fips_mode:
      enabled: true
`)

	cfg, err := parseElasticsearchConf(content)
	assert.NoError(t, err)

	// Transport SSL
	assert.True(t, cfg.Xpack.Security.Transport.SSL.Enabled)
	assert.Equal(t, "full", cfg.Xpack.Security.Transport.SSL.VerificationMode)
	assert.Equal(t, "/etc/elasticsearch/certs/transport.key", cfg.Xpack.Security.Transport.SSL.Key)
	assert.Equal(t, "/etc/elasticsearch/certs/transport.crt", cfg.Xpack.Security.Transport.SSL.Certificate)
	assert.Equal(t, []string{"/etc/elasticsearch/certs/ca.crt"}, cfg.Xpack.Security.Transport.SSL.CertificateAuthorities)
	assert.Equal(t, []string{"TLSv1.2", "TLSv1.3"}, cfg.Xpack.Security.Transport.SSL.SupportedProtocols)
	assert.Equal(t, []string{"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"}, cfg.Xpack.Security.Transport.SSL.CipherSuites)
	assert.Equal(t, "required", cfg.Xpack.Security.Transport.SSL.ClientAuthentication)

	// HTTP SSL
	assert.True(t, cfg.Xpack.Security.HTTP.SSL.Enabled)
	assert.Equal(t, "/etc/elasticsearch/certs/http.crt", cfg.Xpack.Security.HTTP.SSL.Certificate)

	// FIPS mode
	assert.True(t, cfg.Xpack.Security.FIPSMode.Enabled)

	// Test version extraction
	versions := extractVersions(cfg.Xpack.Security.Transport.SSL.SupportedProtocols)
	assert.Contains(t, versions, "1.2")
	assert.Contains(t, versions, "1.3")

	// Test properties
	props := buildProperties(cfg)
	propMap := map[string]string{}
	for _, p := range props {
		propMap[p.Name] = p.Value
	}
	assert.Equal(t, "true", propMap["theia:elasticsearch:transport.ssl.enabled"])
	assert.Equal(t, "/etc/elasticsearch/certs/transport.crt", propMap["theia:elasticsearch:transport.ssl.certificate"])
	assert.Equal(t, "/etc/elasticsearch/certs/transport.key", propMap["theia:elasticsearch:transport.ssl.key"])
	assert.Equal(t, "full", propMap["theia:elasticsearch:transport.ssl.verification_mode"])
	assert.Equal(t, "true", propMap["theia:elasticsearch:http.ssl.enabled"])
	assert.Equal(t, "true", propMap["theia:elasticsearch:fips_mode.enabled"])
}

func Test_UpdateBOM_adds_components(t *testing.T) {
	fs := filesystem.NewPlainFilesystem("../../../testdata/elasticsearch/dir")
	bom := cdx.NewBOM()
	components := make([]cdx.Component, 0)
	bom.Components = &components

	plugin, err := NewElasticsearchConfPlugin()
	assert.NoError(t, err)
	assert.Equal(t, "Elasticsearch Config Plugin", plugin.GetName())
	assert.NotEmpty(t, plugin.GetExplanation())

	assert.NoError(t, plugin.UpdateBOM(fs, bom))

	assert.NotNil(t, bom.Components)
	assert.GreaterOrEqual(t, len(*bom.Components), 1)

	found := false
	for _, c := range *bom.Components {
		if c.Name == "elasticsearch.yml" && c.Type == cdx.ComponentTypeFile {
			found = true
			assert.NotNil(t, c.Properties)
			props := map[string]string{}
			for _, p := range *c.Properties {
				props[p.Name] = p.Value
			}
			assert.Equal(t, "true", props["theia:elasticsearch:transport.ssl.enabled"])
			assert.Equal(t, "/etc/elasticsearch/certs/transport.crt", props["theia:elasticsearch:transport.ssl.certificate"])
			assert.Equal(t, "/etc/elasticsearch/certs/transport.key", props["theia:elasticsearch:transport.ssl.key"])
			assert.Contains(t, props["theia:elasticsearch:transport.ssl.cipher_suites"], "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384")
			assert.Equal(t, "true", props["theia:elasticsearch:http.ssl.enabled"])
		}
	}
	assert.True(t, found, "elasticsearch.yml component should be present")
}
