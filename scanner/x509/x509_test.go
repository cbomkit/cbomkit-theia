// Copyright 2024 PQCA
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

package x509

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRegistryLoading(t *testing.T) {
	registry, err := GetRegistry()
	require.NoError(t, err)
	require.NotNil(t, registry)

	t.Run("traditional algorithms present", func(t *testing.T) {
		for _, key := range []string{
			"SHA256WithRSA", "SHA384WithRSA", "SHA512WithRSA",
			"ECDSAWithSHA256", "ECDSAWithSHA384", "ECDSAWithSHA512",
			"Ed25519", "RSA", "DSA", "ECDSA",
			"SHA256", "SHA384", "SHA512",
		} {
			entry, found := registry.LookupByKey(key)
			assert.True(t, found, "expected registry key %s to exist", key)
			assert.NotEmpty(t, entry.OID, "expected OID for %s", key)
			assert.NotEmpty(t, entry.Name, "expected Name for %s", key)
		}
	})

	t.Run("PQC algorithms present", func(t *testing.T) {
		for _, key := range []string{
			"ML-DSA-44", "ML-DSA-65", "ML-DSA-87",
			"ML-KEM-512", "ML-KEM-768", "ML-KEM-1024",
			"SLH-DSA-SHA2-128s", "SLH-DSA-SHA2-128f",
			"SLH-DSA-SHAKE-256s", "SLH-DSA-SHAKE-256f",
		} {
			entry, found := registry.LookupByKey(key)
			assert.True(t, found, "expected registry key %s to exist", key)
			assert.NotEmpty(t, entry.OID, "expected OID for %s", key)
			assert.NotEmpty(t, entry.NistStandard, "expected NistStandard for %s", key)
		}
	})

	t.Run("hybrid algorithms present", func(t *testing.T) {
		for _, key := range []string{
			"ML-DSA-44-RSA2048-PSS-SHA256",
			"ML-DSA-65-Ed25519",
			"ML-DSA-87-ECDSA-P384-SHA512",
		} {
			entry, found := registry.LookupByKey(key)
			assert.True(t, found, "expected registry key %s to exist", key)
			assert.Equal(t, "hybrid", entry.Type)
			assert.Contains(t, entry.Components, "pqc")
			assert.Contains(t, entry.Components, "traditional")
		}
	})

	t.Run("OID lookup works", func(t *testing.T) {
		// ML-DSA-65 has a unique OID
		entries, found := registry.LookupByOID("2.16.840.1.101.3.4.3.18")
		assert.True(t, found)
		assert.Len(t, entries, 1)
		assert.Equal(t, "ML-DSA-65", entries[0].Name)
	})

	t.Run("PSS OID lookup returns multiple entries", func(t *testing.T) {
		entries, found := registry.LookupByOID("1.2.840.113549.1.1.10")
		assert.True(t, found)
		assert.Greater(t, len(entries), 1, "PSS OID should map to multiple entries")
	})

	t.Run("PSS hash disambiguation", func(t *testing.T) {
		entry, found := registry.LookupPSSByHashOID("2.16.840.1.101.3.4.2.1") // SHA-256
		assert.True(t, found)
		assert.Equal(t, "SHA256WithRSAPSS", entry.Name)

		entry, found = registry.LookupPSSByHashOID("2.16.840.1.101.3.4.2.2") // SHA-384
		assert.True(t, found)
		assert.Equal(t, "SHA384WithRSAPSS", entry.Name)
	})

	t.Run("component references are valid", func(t *testing.T) {
		for key, entry := range registry.Algorithms {
			for role, ref := range entry.Components {
				_, found := registry.LookupByKey(ref)
				assert.True(t, found, "algorithm %s references component %s=%s which doesn't exist", key, role, ref)
			}
		}
	})
}

func TestASN1ExtractAlgorithmOIDs(t *testing.T) {
	t.Run("extract from ECDSA-SHA256 certificate", func(t *testing.T) {
		// Create a real ECDSA-SHA256 certificate for testing
		der := createTestCert(t, x509.ECDSAWithSHA256)
		oids, err := extractAlgorithmOIDs(der)
		require.NoError(t, err)
		assert.Equal(t, "1.2.840.10045.4.3.2", oids.SignatureAlgorithm) // ECDSA-SHA256
		assert.Equal(t, "1.2.840.10045.2.1", oids.PublicKeyAlgorithm)  // ECDSA
	})

	t.Run("extract from PQC certificate", func(t *testing.T) {
		// Create a synthetic certificate with ML-DSA-65 signature algorithm OID
		der := createSyntheticPQCCert(t, asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 18}) // ML-DSA-65
		oids, err := extractAlgorithmOIDs(der)
		require.NoError(t, err)
		assert.Equal(t, "2.16.840.1.101.3.4.3.18", oids.SignatureAlgorithm)
	})

	t.Run("invalid DER returns error", func(t *testing.T) {
		_, err := extractAlgorithmOIDs([]byte{0x00, 0x01, 0x02})
		assert.Error(t, err)
	})
}

func TestBuildAlgorithmComponent(t *testing.T) {
	t.Run("standalone signature algorithm", func(t *testing.T) {
		entry := AlgorithmEntry{
			OID:             "2.16.840.1.101.3.4.3.18",
			Name:            "ML-DSA-65",
			Type:            "standalone",
			Primitive:       "signature",
			CryptoFunctions: []string{"sign"},
			ParameterSetIdentifier: "65",
		}
		comp := buildAlgorithmComponent(entry, "/test/cert.pem")

		assert.Equal(t, "ML-DSA-65", comp.Name)
		assert.Equal(t, cdx.ComponentTypeCryptographicAsset, comp.Type)
		assert.Equal(t, cdx.CryptoAssetTypeAlgorithm, comp.CryptoProperties.AssetType)
		assert.Equal(t, "2.16.840.1.101.3.4.3.18", comp.CryptoProperties.OID)
		assert.Equal(t, cdx.CryptoPrimitiveSignature, comp.CryptoProperties.AlgorithmProperties.Primitive)
		assert.Equal(t, "65", comp.CryptoProperties.AlgorithmProperties.ParameterSetIdentifier)
		assert.Contains(t, *comp.CryptoProperties.AlgorithmProperties.CryptoFunctions, cdx.CryptoFunctionSign)
	})

	t.Run("standalone KEM algorithm", func(t *testing.T) {
		entry := AlgorithmEntry{
			OID:             "2.16.840.1.101.3.4.4.2",
			Name:            "ML-KEM-768",
			Type:            "standalone",
			Primitive:       "kem",
			CryptoFunctions: []string{"encapsulate", "decapsulate"},
			ParameterSetIdentifier: "768",
		}
		comp := buildAlgorithmComponent(entry, "/test/cert.pem")

		assert.Equal(t, cdx.CryptoPrimitiveKEM, comp.CryptoProperties.AlgorithmProperties.Primitive)
		assert.Contains(t, *comp.CryptoProperties.AlgorithmProperties.CryptoFunctions, cdx.CryptoFunctionEncapsulate)
		assert.Contains(t, *comp.CryptoProperties.AlgorithmProperties.CryptoFunctions, cdx.CryptoFunctionDecapsulate)
	})

	t.Run("hash algorithm", func(t *testing.T) {
		entry := AlgorithmEntry{
			OID:             "2.16.840.1.101.3.4.2.1",
			Name:            "SHA256",
			Type:            "standalone",
			Primitive:       "hash",
			CryptoFunctions: []string{"digest"},
			ParameterSetIdentifier: "256",
		}
		comp := buildAlgorithmComponent(entry, "/test/cert.pem")

		assert.Equal(t, cdx.CryptoPrimitiveHash, comp.CryptoProperties.AlgorithmProperties.Primitive)
		assert.Contains(t, *comp.CryptoProperties.AlgorithmProperties.CryptoFunctions, cdx.CryptoFunctionDigest)
	})

	t.Run("algorithm with padding", func(t *testing.T) {
		entry := AlgorithmEntry{
			OID:       "1.2.840.113549.1.1.11",
			Name:      "SHA256WithRSA",
			Type:      "composite",
			Primitive: "signature",
			Padding:   "PKCS1v15",
		}
		comp := buildAlgorithmComponent(entry, "/test/cert.pem")
		assert.Equal(t, cdx.CryptoPaddingPKCS1v15, comp.CryptoProperties.AlgorithmProperties.Padding)
	})

	t.Run("algorithm with curve", func(t *testing.T) {
		entry := AlgorithmEntry{
			OID:       "1.3.101.112",
			Name:      "Ed25519",
			Type:      "standalone",
			Primitive: "signature",
			Curve:     "Ed25519",
		}
		comp := buildAlgorithmComponent(entry, "/test/cert.pem")
		assert.Equal(t, "Ed25519", comp.CryptoProperties.AlgorithmProperties.Curve)
	})
}

func TestBuildSignatureResultFromEntry(t *testing.T) {
	registry, err := GetRegistry()
	require.NoError(t, err)

	t.Run("composite algorithm produces hash and signature", func(t *testing.T) {
		entry, found := registry.LookupByKey("SHA256WithRSA")
		require.True(t, found)

		result, err := buildSignatureResultFromEntry(registry, entry, "/test/cert.pem")
		require.NoError(t, err)

		assert.NotNil(t, result.hashAndSignature)
		assert.Equal(t, "SHA256WithRSA", result.hashAndSignature.Name)
		assert.NotNil(t, result.hash)
		assert.Equal(t, "SHA256", result.hash.Name)
		assert.NotNil(t, result.signature)
		assert.Equal(t, "RSA", result.signature.Name)
	})

	t.Run("standalone algorithm has no sub-components", func(t *testing.T) {
		entry, found := registry.LookupByKey("Ed25519")
		require.True(t, found)

		result, err := buildSignatureResultFromEntry(registry, entry, "/test/cert.pem")
		require.NoError(t, err)

		assert.NotNil(t, result.hashAndSignature)
		assert.Equal(t, "Ed25519", result.hashAndSignature.Name)
		assert.Nil(t, result.hash)
		assert.Nil(t, result.signature)
	})

	t.Run("PQC standalone algorithm", func(t *testing.T) {
		entry, found := registry.LookupByKey("ML-DSA-65")
		require.True(t, found)

		result, err := buildSignatureResultFromEntry(registry, entry, "/test/cert.pem")
		require.NoError(t, err)

		assert.NotNil(t, result.hashAndSignature)
		assert.Equal(t, "ML-DSA-65", result.hashAndSignature.Name)
		assert.Equal(t, "2.16.840.1.101.3.4.3.18", result.hashAndSignature.CryptoProperties.OID)
		assert.Nil(t, result.hash)
		assert.Nil(t, result.signature)
	})

	t.Run("hybrid algorithm produces PQC and traditional sub-components", func(t *testing.T) {
		entry, found := registry.LookupByKey("ML-DSA-65-Ed25519")
		require.True(t, found)

		result, err := buildSignatureResultFromEntry(registry, entry, "/test/cert.pem")
		require.NoError(t, err)

		assert.NotNil(t, result.hashAndSignature)
		assert.Equal(t, "ML-DSA-65-Ed25519", result.hashAndSignature.Name)
		// hash field holds PQC component in hybrid case
		assert.NotNil(t, result.hash)
		assert.Equal(t, "ML-DSA-65", result.hash.Name)
		// signature field holds traditional component in hybrid case
		assert.NotNil(t, result.signature)
		assert.Equal(t, "Ed25519", result.signature.Name)
	})
}

func TestGenerateCdxComponentsRegression(t *testing.T) {
	t.Run("ECDSA-SHA256 certificate produces correct components", func(t *testing.T) {
		der := createTestCert(t, x509.ECDSAWithSHA256)
		certs, err := ParseCertificatesToX509CertificateWithMetadata(der, "test.pem")
		require.NoError(t, err)
		require.Len(t, certs, 1)

		components, deps, err := GenerateCdxComponents(certs[0])
		require.NoError(t, err)
		require.NotNil(t, components)
		require.NotNil(t, deps)

		// Should have: ECDSA (sig sub-comp), SHA256 (hash sub-comp), ECDSAWithSHA256 (composite),
		// ECDSA (pubkey alg), ECDSA public key, certificate = 6 components
		assert.Len(t, *components, 6)

		// Find the certificate component
		var certComp *cdx.Component
		for i := range *components {
			if (*components)[i].CryptoProperties.AssetType == cdx.CryptoAssetTypeCertificate {
				certComp = &(*components)[i]
				break
			}
		}
		require.NotNil(t, certComp)
		assert.Equal(t, "test.example.com", certComp.Name)
		assert.NotEmpty(t, string(certComp.CryptoProperties.CertificateProperties.SignatureAlgorithmRef))
		assert.NotEmpty(t, string(certComp.CryptoProperties.CertificateProperties.SubjectPublicKeyRef))

		// Find the signature algorithm component
		var sigAlgComp *cdx.Component
		for i := range *components {
			if (*components)[i].BOMRef == string(certComp.CryptoProperties.CertificateProperties.SignatureAlgorithmRef) {
				sigAlgComp = &(*components)[i]
				break
			}
		}
		require.NotNil(t, sigAlgComp)
		assert.Equal(t, "ECDSAWithSHA256", sigAlgComp.Name)
		assert.Equal(t, "1.2.840.10045.4.3.2", sigAlgComp.CryptoProperties.OID)
	})

	t.Run("Ed25519 certificate has no hash sub-component", func(t *testing.T) {
		der := createTestCertEd25519(t)
		certs, err := ParseCertificatesToX509CertificateWithMetadata(der, "test-ed25519.pem")
		require.NoError(t, err)
		require.Len(t, certs, 1)

		components, deps, err := GenerateCdxComponents(certs[0])
		require.NoError(t, err)
		require.NotNil(t, components)

		// Ed25519: standalone sig alg + pubkey alg + public key + certificate = 4
		// (no hash or sig sub-components)
		assert.Len(t, *components, 4)

		// No dependencies for Ed25519 (standalone, no sub-components)
		assert.Empty(t, *deps)
	})
}

func TestUnknownAlgorithmHandling(t *testing.T) {
	t.Run("unknown OID produces generic component", func(t *testing.T) {
		comp := buildUnknownAlgorithmComponent("1.2.3.4.5.6.7.8.9", "/test/cert.pem")
		assert.Equal(t, "Unknown (1.2.3.4.5.6.7.8.9)", comp.Name)
		assert.Equal(t, "1.2.3.4.5.6.7.8.9", comp.CryptoProperties.OID)
		assert.Equal(t, cdx.CryptoAssetTypeAlgorithm, comp.CryptoProperties.AssetType)
	})
}

// createTestCert creates a self-signed test certificate with the given signature algorithm.
func createTestCert(t *testing.T, sigAlg x509.SignatureAlgorithm) []byte {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "test.example.com",
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour * 24 * 365),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		SignatureAlgorithm:    sigAlg,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	return der
}

// createTestCertEd25519 creates a self-signed Ed25519 test certificate.
func createTestCertEd25519(t *testing.T) []byte {
	t.Helper()

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "test-ed25519.example.com",
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour * 24 * 365),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		SignatureAlgorithm:    x509.PureEd25519,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, pub, priv)
	require.NoError(t, err)
	return der
}

// createSyntheticPQCCert creates a minimal DER-encoded certificate structure
// with the given signature algorithm OID. This is NOT a valid cryptographic certificate,
// but it has a valid ASN1 structure for testing OID extraction.
func createSyntheticPQCCert(t *testing.T, sigAlgOID asn1.ObjectIdentifier) []byte {
	t.Helper()

	// Build a minimal X.509 certificate ASN1 structure
	algID := asn1AlgorithmIdentifier{Algorithm: sigAlgOID}
	pubKeyAlgID := asn1AlgorithmIdentifier{Algorithm: sigAlgOID} // Use same OID for pubkey alg

	tbs := asn1TBSCertificate{
		Version:   asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: mustMarshal(t, 2)},
		SerialNumber: big.NewInt(1),
		Signature: algID,
		Issuer:    asn1.RawValue{FullBytes: mustMarshalSequence(t, pkix.RDNSequence{{{Type: asn1.ObjectIdentifier{2, 5, 4, 3}, Value: "Test PQC CA"}}})},
		Validity:  asn1.RawValue{FullBytes: mustMarshalSequence(t, []time.Time{time.Now(), time.Now().Add(time.Hour * 24 * 365)})},
		Subject:   asn1.RawValue{FullBytes: mustMarshalSequence(t, pkix.RDNSequence{{{Type: asn1.ObjectIdentifier{2, 5, 4, 3}, Value: "Test PQC Cert"}}})},
		PublicKeyInfo: asn1SubjectPublicKeyInfo{
			Algorithm: pubKeyAlgID,
			PublicKey: asn1.BitString{Bytes: []byte{0x00}, BitLength: 8},
		},
	}

	cert := asn1Certificate{
		TBSCertificate:     tbs,
		SignatureAlgorithm: algID,
		Signature:          asn1.BitString{Bytes: []byte{0x00}, BitLength: 8},
	}

	der, err := asn1.Marshal(cert)
	require.NoError(t, err)
	return der
}

func mustMarshal(t *testing.T, val interface{}) []byte {
	t.Helper()
	data, err := asn1.Marshal(val)
	require.NoError(t, err)
	return data
}

func mustMarshalSequence(t *testing.T, val interface{}) []byte {
	t.Helper()
	data, err := asn1.Marshal(val)
	require.NoError(t, err)
	return data
}
