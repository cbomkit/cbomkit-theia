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

package certresolver

import (
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/cbomkit/cbomkit-theia/provider/filesystem"
	"github.com/stretchr/testify/assert"
)

func TestResolveCertificateComponents_ValidCert(t *testing.T) {
	fs := filesystem.NewPlainFilesystem("testdata")

	components, depMap, certRefs := ResolveCertificateComponents(fs, "certs/server.pem")

	assert.NotNil(t, components, "should return components for a valid certificate")
	assert.NotEmpty(t, components, "should have at least one component")
	assert.NotNil(t, certRefs, "should return certificate BOMRefs")
	assert.NotEmpty(t, certRefs, "should have at least one cert BOMRef")

	// Verify we got a certificate component
	foundCert := false
	for _, comp := range components {
		if comp.CryptoProperties != nil && comp.CryptoProperties.AssetType == cdx.CryptoAssetTypeCertificate {
			foundCert = true
			assert.Equal(t, "Linagora CA", comp.Name)
			assert.NotNil(t, comp.CryptoProperties.CertificateProperties)
			assert.Equal(t, "Linagora CA", comp.CryptoProperties.CertificateProperties.SubjectName)
			assert.Equal(t, "Linagora CA", comp.CryptoProperties.CertificateProperties.IssuerName)
			assert.NotEmpty(t, comp.CryptoProperties.CertificateProperties.NotValidBefore)
			assert.NotEmpty(t, comp.CryptoProperties.CertificateProperties.NotValidAfter)
			assert.NotEmpty(t, comp.BOMRef)
			// Verify it's in certRefs
			assert.Contains(t, certRefs, comp.BOMRef)
		}
	}
	assert.True(t, foundCert, "should contain a certificate component")

	// Verify we got algorithm components (SHA256WithRSA -> SHA256 + RSA)
	foundAlgorithm := false
	for _, comp := range components {
		if comp.CryptoProperties != nil && comp.CryptoProperties.AssetType == cdx.CryptoAssetTypeAlgorithm {
			foundAlgorithm = true
		}
	}
	assert.True(t, foundAlgorithm, "should contain algorithm components")

	// Verify we got a public key component
	foundKey := false
	for _, comp := range components {
		if comp.CryptoProperties != nil && comp.CryptoProperties.AssetType == cdx.CryptoAssetTypeRelatedCryptoMaterial {
			foundKey = true
		}
	}
	assert.True(t, foundKey, "should contain a public key component")

	// Verify dependency map has internal cert dependencies (signature algorithm deps)
	assert.NotNil(t, depMap)
}

func TestResolveCertificateComponents_FileNotFound(t *testing.T) {
	fs := filesystem.NewPlainFilesystem("testdata")

	components, depMap, certRefs := ResolveCertificateComponents(fs, "certs/nonexistent.pem")

	assert.Nil(t, components)
	assert.Nil(t, depMap)
	assert.Nil(t, certRefs)
}

func TestResolveCertificateComponents_InvalidCert(t *testing.T) {
	fs := filesystem.NewPlainFilesystem("testdata")

	components, depMap, certRefs := ResolveCertificateComponents(fs, "certs/invalid.pem")

	assert.Nil(t, components)
	assert.Nil(t, depMap)
	assert.Nil(t, certRefs)
}

func TestResolveCertificateComponents_EmptyPath(t *testing.T) {
	fs := filesystem.NewPlainFilesystem("testdata")

	components, depMap, certRefs := ResolveCertificateComponents(fs, "")

	assert.Nil(t, components)
	assert.Nil(t, depMap)
	assert.Nil(t, certRefs)
}

func TestResolveCertificateComponents_CertRefMatchesBOMRef(t *testing.T) {
	fs := filesystem.NewPlainFilesystem("testdata")

	components, _, certRefs := ResolveCertificateComponents(fs, "certs/server.pem")

	assert.NotEmpty(t, certRefs)

	// Each certRef should correspond to a certificate component's BOMRef
	for _, ref := range certRefs {
		found := false
		for _, comp := range components {
			if comp.BOMRef == ref {
				found = true
				assert.Equal(t, cdx.CryptoAssetTypeCertificate, comp.CryptoProperties.AssetType,
					"certRef should point to a certificate component")
			}
		}
		assert.True(t, found, "certRef %s should match a component BOMRef", ref)
	}
}
