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

package sshconfig

import (
	"strings"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/cbomkit/cbomkit-theia/provider/filesystem"
	"github.com/stretchr/testify/assert"
)

func Test_isSSHConfig(t *testing.T) {
	tests := []struct {
		path     string
		expected bool
	}{
		{"etc/ssh/sshd_config", true},
		{"etc/ssh/ssh_config", true},
		{"/etc/ssh/sshd_config", true},
		{"/etc/ssh/ssh_config", true},
		{"sshd_config", true},
		{"ssh_config", true},
		{"etc/ssh/sshd_config.d/custom.conf", true},
		{"etc/ssh/ssh_config.d/custom.conf", true},
		{"/etc/ssh/sshd_config.d/50-hardening.conf", true},
		{"/etc/ssh/ssh_config.d/10-defaults.conf", true},
		{"etc/ssh/sshd_config.d/noext", false},
		{"etc/ssh/somefile.conf", false},
		{"etc/ssh/sshd_config.bak", false},
		{"random_file.txt", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			result := isSSHConfig(tt.path)
			assert.Equal(t, tt.expected, result, "isSSHConfig(%q)", tt.path)
		})
	}
}

func Test_parseSSHConfig(t *testing.T) {
	content := `# SSH server configuration
Port 22
Protocol 2

HostKey /etc/ssh/ssh_host_ed25519_key
HostKey /etc/ssh/ssh_host_rsa_key
HostCertificate /etc/ssh/ssh_host_ed25519_key-cert.pub

Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr
MACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,umac-128-etm@openssh.com
KexAlgorithms sntrup761x25519-sha512@openssh.com,curve25519-sha256,ecdh-sha2-nistp384
HostKeyAlgorithms ssh-ed25519,rsa-sha2-512,rsa-sha2-256

PubkeyAcceptedAlgorithms ssh-ed25519,rsa-sha2-512,rsa-sha2-256
CASignatureAlgorithms ssh-ed25519,rsa-sha2-512

RequiredRSASize 3072
FingerprintHash sha256

Match User admin
    Ciphers aes256-gcm@openssh.com
`

	settings := parseSSHConfig(strings.NewReader(content))

	// HostKey should have two entries
	assert.Equal(t, []string{"/etc/ssh/ssh_host_ed25519_key", "/etc/ssh/ssh_host_rsa_key"}, settings["HostKey"])

	// HostCertificate
	assert.Equal(t, []string{"/etc/ssh/ssh_host_ed25519_key-cert.pub"}, settings["HostCertificate"])

	// Ciphers: 4 from global + 1 from Match block
	assert.Contains(t, settings["Ciphers"], "chacha20-poly1305@openssh.com")
	assert.Contains(t, settings["Ciphers"], "aes256-gcm@openssh.com")
	assert.Contains(t, settings["Ciphers"], "aes128-gcm@openssh.com")
	assert.Contains(t, settings["Ciphers"], "aes256-ctr")

	// MACs
	assert.Equal(t, []string{
		"hmac-sha2-256-etm@openssh.com",
		"hmac-sha2-512-etm@openssh.com",
		"umac-128-etm@openssh.com",
	}, settings["MACs"])

	// KexAlgorithms
	assert.Equal(t, []string{
		"sntrup761x25519-sha512@openssh.com",
		"curve25519-sha256",
		"ecdh-sha2-nistp384",
	}, settings["KexAlgorithms"])

	// HostKeyAlgorithms
	assert.Equal(t, []string{
		"ssh-ed25519",
		"rsa-sha2-512",
		"rsa-sha2-256",
	}, settings["HostKeyAlgorithms"])

	// PubkeyAcceptedAlgorithms
	assert.Equal(t, []string{
		"ssh-ed25519",
		"rsa-sha2-512",
		"rsa-sha2-256",
	}, settings["PubkeyAcceptedAlgorithms"])

	// CASignatureAlgorithms
	assert.Equal(t, []string{
		"ssh-ed25519",
		"rsa-sha2-512",
	}, settings["CASignatureAlgorithms"])

	// RequiredRSASize
	assert.Equal(t, []string{"3072"}, settings["RequiredRSASize"])

	// FingerprintHash
	assert.Equal(t, []string{"sha256"}, settings["FingerprintHash"])

	// Non-crypto directives should not be captured
	_, hasPort := settings["Port"]
	assert.False(t, hasPort)
	_, hasProtocol := settings["Protocol"]
	assert.False(t, hasProtocol)
}

func Test_parseSSHConfig_with_modifiers(t *testing.T) {
	content := `Ciphers +aes128-cbc,aes192-cbc
MACs -hmac-sha1
KexAlgorithms ^curve25519-sha256
`
	settings := parseSSHConfig(strings.NewReader(content))

	assert.Contains(t, settings["Ciphers"], "aes128-cbc")
	assert.Contains(t, settings["Ciphers"], "aes192-cbc")
	assert.Contains(t, settings["MACs"], "hmac-sha1")
	assert.Contains(t, settings["KexAlgorithms"], "curve25519-sha256")
}

func Test_UpdateBOM_adds_components(t *testing.T) {
	fs := filesystem.NewPlainFilesystem("../../../testdata/ssh/dir")
	bom := cdx.NewBOM()
	components := make([]cdx.Component, 0)
	bom.Components = &components

	plugin, err := NewSSHConfigPlugin()
	assert.NoError(t, err)
	assert.NoError(t, plugin.UpdateBOM(fs, bom))

	assert.NotNil(t, bom.Components)
	assert.GreaterOrEqual(t, len(*bom.Components), 1, "Should have at least one component")

	// Find the file component
	var fileComp *cdx.Component
	for i := range *bom.Components {
		c := &(*bom.Components)[i]
		if c.Type == cdx.ComponentTypeFile && c.Name == "sshd_config" {
			fileComp = c
			break
		}
	}
	assert.NotNil(t, fileComp, "sshd_config file component should be present")

	// Verify properties
	assert.NotNil(t, fileComp.Properties)
	props := map[string]string{}
	for _, p := range *fileComp.Properties {
		props[p.Name] = p.Value
	}
	assert.Equal(t, "chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr", props["theia:ssh:Ciphers"])
	assert.Equal(t, "hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,umac-128-etm@openssh.com", props["theia:ssh:MACs"])
	assert.Equal(t, "sntrup761x25519-sha512@openssh.com,curve25519-sha256,ecdh-sha2-nistp384", props["theia:ssh:KexAlgorithms"])
	assert.Equal(t, "ssh-ed25519,rsa-sha2-512,rsa-sha2-256", props["theia:ssh:HostKeyAlgorithms"])
	assert.Equal(t, "3072", props["theia:ssh:RequiredRSASize"])
	assert.Equal(t, "sha256", props["theia:ssh:FingerprintHash"])

	// Verify evidence
	assert.NotNil(t, fileComp.Evidence)
	assert.NotNil(t, fileComp.Evidence.Occurrences)
	assert.Equal(t, "sshd_config", (*fileComp.Evidence.Occurrences)[0].Location)

	// Verify algorithm components exist
	cipherCount := 0
	macCount := 0
	kexCount := 0
	hostkeyCount := 0
	for _, c := range *bom.Components {
		if c.Type != cdx.ComponentTypeCryptographicAsset {
			continue
		}
		if c.CryptoProperties == nil || c.CryptoProperties.AlgorithmProperties == nil {
			continue
		}
		switch c.CryptoProperties.AlgorithmProperties.Primitive {
		case cdx.CryptoPrimitiveBlockCipher:
			cipherCount++
		case cdx.CryptoPrimitiveStreamCipher:
			cipherCount++ // chacha20 counted as cipher too
		case cdx.CryptoPrimitiveMAC:
			macCount++
		case cdx.CryptoPrimitiveKeyAgree:
			kexCount++
		case cdx.CryptoPrimitiveSignature:
			hostkeyCount++
		}
	}
	assert.Equal(t, 4, cipherCount, "Should have 4 cipher algorithm components (including chacha20 as stream cipher)")
	assert.Equal(t, 3, macCount, "Should have 3 MAC algorithm components")
	assert.Equal(t, 3, kexCount, "Should have 3 KEX algorithm components")
	assert.Equal(t, 3, hostkeyCount, "Should have 3 host key algorithm components")

	// Verify specific algorithm names are mapped correctly
	algoNames := make(map[string]bool)
	for _, c := range *bom.Components {
		if c.Type == cdx.ComponentTypeCryptographicAsset {
			algoNames[c.Name] = true
		}
	}
	assert.True(t, algoNames["ChaCha20-Poly1305"], "ChaCha20-Poly1305 should be present")
	assert.True(t, algoNames["AES-256-GCM"], "AES-256-GCM should be present")
	assert.True(t, algoNames["HMAC-SHA-256-ETM"], "HMAC-SHA-256-ETM should be present")
	assert.True(t, algoNames["Curve25519-SHA-256"], "Curve25519-SHA-256 should be present")
	assert.True(t, algoNames["Ed25519"], "Ed25519 should be present")
}
