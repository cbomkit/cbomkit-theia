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

package etcdconf

import (
	"os"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/cbomkit/cbomkit-theia/provider/filesystem"
	"github.com/stretchr/testify/assert"
)

func Test_isEtcdConf(t *testing.T) {
	tests := []struct {
		path   string
		expect bool
	}{
		{"etcd.conf.yml", true},
		{"etcd.conf.yaml", true},
		{"etcd.yaml", true},
		{"etcd.yml", true},
		{"/etc/etcd/etcd.conf.yml", true},
		{"/some/path/etcd.yaml", true},
		{"ETCD.CONF.YML", true},
		{"Etcd.Conf.Yaml", true},
		{"ETCD.YML", true},
		{"notanetcd.yml", false},
		{"etcd.conf.json", false},
		{"etcd.toml", false},
		{"something_else.yaml", false},
		{"myetcd.conf.yml", false},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			assert.Equal(t, tt.expect, isEtcdConf(tt.path))
		})
	}
}

func Test_parseEtcdConf(t *testing.T) {
	content := []byte(`
name: 'node1'
data-dir: '/var/lib/etcd'

client-transport-security:
  cert-file: '/etc/etcd/pki/server.crt'
  key-file: '/etc/etcd/pki/server.key'
  trusted-ca-file: '/etc/etcd/pki/ca.crt'
  client-cert-auth: true
  auto-tls: false
  cipher-suites:
    - TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
    - TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
    - TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
  tls-min-version: 'TLS1.2'
  tls-max-version: 'TLS1.3'

peer-transport-security:
  cert-file: '/etc/etcd/pki/peer.crt'
  key-file: '/etc/etcd/pki/peer.key'
  trusted-ca-file: '/etc/etcd/pki/ca.crt'
  client-cert-auth: true
  auto-tls: false
  cipher-suites:
    - TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
    - TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
  tls-min-version: 'TLS1.2'
  tls-max-version: 'TLS1.3'
`)

	cfg, err := parseEtcdConf(content)
	assert.NoError(t, err)

	// Client transport security assertions
	assert.Equal(t, "/etc/etcd/pki/server.crt", cfg.ClientTransportSecurity.CertFile)
	assert.Equal(t, "/etc/etcd/pki/server.key", cfg.ClientTransportSecurity.KeyFile)
	assert.Equal(t, "/etc/etcd/pki/ca.crt", cfg.ClientTransportSecurity.TrustedCAFile)
	assert.True(t, cfg.ClientTransportSecurity.ClientCertAuth)
	assert.False(t, cfg.ClientTransportSecurity.AutoTLS)
	assert.Equal(t, []string{
		"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
		"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
		"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
	}, cfg.ClientTransportSecurity.CipherSuites)
	assert.Equal(t, "TLS1.2", cfg.ClientTransportSecurity.TLSMinVersion)
	assert.Equal(t, "TLS1.3", cfg.ClientTransportSecurity.TLSMaxVersion)

	// Peer transport security assertions
	assert.Equal(t, "/etc/etcd/pki/peer.crt", cfg.PeerTransportSecurity.CertFile)
	assert.Equal(t, "/etc/etcd/pki/peer.key", cfg.PeerTransportSecurity.KeyFile)
	assert.Equal(t, "/etc/etcd/pki/ca.crt", cfg.PeerTransportSecurity.TrustedCAFile)
	assert.True(t, cfg.PeerTransportSecurity.ClientCertAuth)
	assert.False(t, cfg.PeerTransportSecurity.AutoTLS)
	assert.Equal(t, []string{
		"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
		"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
	}, cfg.PeerTransportSecurity.CipherSuites)
	assert.Equal(t, "TLS1.2", cfg.PeerTransportSecurity.TLSMinVersion)
	assert.Equal(t, "TLS1.3", cfg.PeerTransportSecurity.TLSMaxVersion)

	// Test TLS version parsing
	versions := extractVersions(cfg.ClientTransportSecurity)
	assert.Contains(t, versions, "1.2")
	assert.Contains(t, versions, "1.3")

	// Test properties generation
	props := buildProperties(cfg)
	propMap := map[string]string{}
	for _, p := range props {
		propMap[p.Name] = p.Value
	}
	assert.Equal(t, "/etc/etcd/pki/server.crt", propMap["theia:etcd:client-cert-file"])
	assert.Equal(t, "/etc/etcd/pki/server.key", propMap["theia:etcd:client-key-file"])
	assert.Equal(t, "/etc/etcd/pki/ca.crt", propMap["theia:etcd:client-trusted-ca-file"])
	assert.Equal(t, "TLS1.2", propMap["theia:etcd:client-tls-min-version"])
	assert.Equal(t, "TLS1.3", propMap["theia:etcd:client-tls-max-version"])
	assert.Equal(t, "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", propMap["theia:etcd:client-cipher-suites"])
	assert.Equal(t, "/etc/etcd/pki/peer.crt", propMap["theia:etcd:peer-cert-file"])
	assert.Equal(t, "/etc/etcd/pki/peer.key", propMap["theia:etcd:peer-key-file"])
	assert.Equal(t, "/etc/etcd/pki/ca.crt", propMap["theia:etcd:peer-trusted-ca-file"])
	assert.Equal(t, "TLS1.2", propMap["theia:etcd:peer-tls-min-version"])
	assert.Equal(t, "TLS1.3", propMap["theia:etcd:peer-tls-max-version"])
	assert.Equal(t, "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", propMap["theia:etcd:peer-cipher-suites"])
}

func Test_UpdateBOM_resolves_certs_and_adds_dependsOn(t *testing.T) {
	// Use a test directory with actual cert files at the referenced paths
	fs := filesystem.NewPlainFilesystem("../../../testdata/etcd-with-certs/dir")
	bom := cdx.NewBOM()
	components := make([]cdx.Component, 0)
	bom.Components = &components

	plugin, err := NewEtcdConfPlugin()
	assert.NoError(t, err)
	assert.NoError(t, plugin.UpdateBOM(fs, bom))

	assert.NotNil(t, bom.Components)

	// Find the etcd.conf.yml file component
	var fileCompBOMRef string
	for _, c := range *bom.Components {
		if c.Name == "etcd.conf.yml" && c.Type == cdx.ComponentTypeFile {
			fileCompBOMRef = c.BOMRef
			break
		}
	}
	assert.NotEmpty(t, fileCompBOMRef, "etcd.conf.yml file component should exist")

	// Find resolved certificate components (SubjectName should be filled)
	var certBOMRefs []string
	for _, c := range *bom.Components {
		if c.CryptoProperties != nil &&
			c.CryptoProperties.AssetType == cdx.CryptoAssetTypeCertificate &&
			c.CryptoProperties.CertificateProperties != nil &&
			c.CryptoProperties.CertificateProperties.SubjectName != "" {
			certBOMRefs = append(certBOMRefs, c.BOMRef)
		}
	}
	// etcd has 4 cert paths (client cert, client CA, peer cert, peer CA)
	// but CA cert is same file (/etc/etcd/pki/ca.crt), each will be resolved independently
	assert.GreaterOrEqual(t, len(certBOMRefs), 2, "should have resolved certificate components")

	// Verify dependsOn relationship from file component to certs
	assert.NotNil(t, bom.Dependencies, "BOM should have dependencies")
	foundDep := false
	for _, dep := range *bom.Dependencies {
		if dep.Ref == fileCompBOMRef {
			foundDep = true
			assert.NotNil(t, dep.Dependencies)
			assert.GreaterOrEqual(t, len(*dep.Dependencies), 2,
				"file component should depend on multiple resolved certificates")
		}
	}
	assert.True(t, foundDep, "should have a dependency from etcd.conf.yml to resolved certs")
}

func Test_UpdateBOM_adds_components(t *testing.T) {
	fs := filesystem.NewPlainFilesystem("../../../testdata/etcd/dir")
	bom := cdx.NewBOM()
	components := make([]cdx.Component, 0)
	bom.Components = &components

	plugin, err := NewEtcdConfPlugin()
	assert.NoError(t, err)
	assert.Equal(t, "etcd Config Plugin", plugin.GetName())
	assert.NotEmpty(t, plugin.GetExplanation())

	assert.NoError(t, plugin.UpdateBOM(fs, bom))

	assert.NotNil(t, bom.Components)
	assert.GreaterOrEqual(t, len(*bom.Components), 1)

	err = cdx.NewBOMEncoder(os.Stdout, cdx.BOMFileFormatJSON).SetPretty(true).Encode(bom)
	if err != nil {
		t.Fail()
		return
	}

	// Find the etcd.conf.yml file component
	found := false
	for _, c := range *bom.Components {
		if c.Name == "etcd.conf.yml" && c.Type == cdx.ComponentTypeFile {
			found = true
			assert.NotNil(t, c.Properties)
			props := map[string]string{}
			for _, p := range *c.Properties {
				props[p.Name] = p.Value
			}
			assert.Equal(t, "/etc/etcd/pki/server.crt", props["theia:etcd:client-cert-file"])
			assert.Equal(t, "/etc/etcd/pki/server.key", props["theia:etcd:client-key-file"])
			assert.Equal(t, "/etc/etcd/pki/ca.crt", props["theia:etcd:client-trusted-ca-file"])
			assert.Equal(t, "TLS1.2", props["theia:etcd:client-tls-min-version"])
			assert.Equal(t, "TLS1.3", props["theia:etcd:client-tls-max-version"])
			assert.Contains(t, props["theia:etcd:client-cipher-suites"], "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384")
			assert.Equal(t, "/etc/etcd/pki/peer.crt", props["theia:etcd:peer-cert-file"])
			assert.Equal(t, "/etc/etcd/pki/peer.key", props["theia:etcd:peer-key-file"])
			assert.Equal(t, "/etc/etcd/pki/ca.crt", props["theia:etcd:peer-trusted-ca-file"])
			assert.Equal(t, "TLS1.2", props["theia:etcd:peer-tls-min-version"])
			assert.Equal(t, "TLS1.3", props["theia:etcd:peer-tls-max-version"])
			assert.Contains(t, props["theia:etcd:peer-cipher-suites"], "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384")
		}
	}
	assert.True(t, found, "etcd.conf.yml component should be present")
}
