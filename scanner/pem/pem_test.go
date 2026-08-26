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

package pem

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/stretchr/testify/assert"
)

func TestGenerateCdxComponentsLegacyEncryptedRSAKey(t *testing.T) {
	raw := []byte("-----BEGIN RSA PRIVATE KEY-----\n" +
		"Proc-Type: 4,ENCRYPTED\n" +
		"DEK-Info: DES-EDE3-CBC,BA26229A1653B7FF\n\n" +
		"2i5PgUsjTMVjyLog9C0BgFyMOBAujM3zwSAr4W2vsIjMHY2Rm4gtLQ0hIhc8dGWH\n" +
		"-----END RSA PRIVATE KEY-----")

	block, _ := pem.Decode(raw)
	if block == nil {
		t.Fatal("failed to decode test PEM block")
	}

	components, err := GenerateCdxComponents(block)
	if err != nil {
		t.Fatalf("expected no error for a recognized encrypted key, got: %v", err)
	}
	assert.Len(t, components, 2)

	props := components[0].CryptoProperties.RelatedCryptoMaterialProperties
	assert.Equal(t, cdx.RelatedCryptoMaterialTypePrivateKey, props.Type)
	assert.NotNil(t, props.SecuredBy)
	assert.Equal(t, "Software", props.SecuredBy.Mechanism)
	assert.Equal(t, cdx.BOMReference(components[1].BOMRef), props.SecuredBy.AlgorithmRef)

	cipher := components[1]
	assert.Equal(t, "DES-EDE3-CBC", cipher.Name)
	assert.Equal(t, cdx.CryptoPrimitiveBlockCipher, cipher.CryptoProperties.AlgorithmProperties.Primitive)
	assert.Equal(t, cdx.CryptoAlgorithmModeCBC, cipher.CryptoProperties.AlgorithmProperties.Mode)
}

func TestGenerateCdxComponentsPKCS8EncryptedKey(t *testing.T) {
	// EncryptedPrivateKeyInfo using PBES2 with PBKDF2 and aes-256-CBC-PAD, generated via
	// `openssl genpkey -algorithm RSA | openssl pkcs8 -topk8 -v2 aes-256-cbc`.
	raw := []byte("-----BEGIN ENCRYPTED PRIVATE KEY-----\n" +
		"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\n" +
		"-----END ENCRYPTED PRIVATE KEY-----")

	block, _ := pem.Decode(raw)
	if block == nil {
		t.Fatal("failed to decode test PEM block")
	}

	components, err := GenerateCdxComponents(block)
	if err != nil {
		t.Fatalf("expected no error for a recognized encrypted key, got: %v", err)
	}
	assert.Len(t, components, 3)

	props := components[0].CryptoProperties.RelatedCryptoMaterialProperties
	assert.Equal(t, cdx.RelatedCryptoMaterialTypePrivateKey, props.Type)
	assert.NotNil(t, props.SecuredBy)
	assert.Equal(t, "Software", props.SecuredBy.Mechanism)
	assert.Equal(t, cdx.BOMReference(components[1].BOMRef), props.SecuredBy.AlgorithmRef)

	cipher := components[1]
	assert.Equal(t, "AES-256-CBC", cipher.Name)
	assert.Equal(t, cdx.CryptoPrimitiveBlockCipher, cipher.CryptoProperties.AlgorithmProperties.Primitive)
	assert.Equal(t, cdx.CryptoAlgorithmModeCBC, cipher.CryptoProperties.AlgorithmProperties.Mode)

	kdf := components[2]
	assert.Equal(t, "PBKDF2-HMAC-SHA256", kdf.Name)
	assert.Equal(t, cdx.CryptoPrimitiveKDF, kdf.CryptoProperties.AlgorithmProperties.Primitive)
}

func TestGenerateCdxComponentsPKCS8EncryptedKeyOmittedPRFDefaultsToSHA1(t *testing.T) {
	// PBKDF2-params generated with `openssl pkcs8 -topk8 -v2 aes-256-cbc -v2prf hmacWithSHA1`.
	// OpenSSL omits the prf field entirely here since HMAC-SHA1 is the RFC 8018 default,
	// so this exercises the fallback rather than an explicit HMAC-SHA1 AlgorithmIdentifier.
	raw := []byte("-----BEGIN ENCRYPTED PRIVATE KEY-----\n" +
		"MIIFJzBRBgkqhkiG9w0BBQ0wRDAjBgkqhkiG9w0BBQwwFgQQre5HmYmLBhc8S/7I\n" +
		"9arQsgICCAAwHQYJYIZIAWUDBAEqBBDScJ/U2h4vdioLThjCKI5rBIIE0JwPnWOI\n" +
		"NcD1LGwji659l5x9v8lDVnm/vVXb/+LO/IjcLVvYL2ICKmO7Tw1RhKC1Gwcbzcw/\n" +
		"rCXfT2BA3H/enWTR9vnEmDpMS3Ux8m3C19F7MswXqbjXQTtDAPBAwd2ZI/Wgd8fu\n" +
		"myRqWH+mII7Y/RWviyBz9v8k58iU7j3ITgjvtjtCDHPoxexKkP4WMKf/MvNJ+Z5R\n" +
		"QHxLFIe0oxd2nT8BAX23BVGIW9sfgJH0I0rIxD+8UUirSUSXOhZOj7Hqovbof/hk\n" +
		"QNxMkdfipJx8FkoTr4fDumuf2NC/mMC1mwPDIIlKirTSeYvAxFKeLoNPD43L0kIm\n" +
		"zwdCejqat5iuKHiXGaYmMWCcdBJ82y6K5HzM/UBNimWtZPEVcvvmSDfMKckw/65r\n" +
		"1x2hibtY2XTicWNvCHOInZTArfXAd1Chniq/kAT2rk+NZ9VxDFxB30Kqx2W0YuJJ\n" +
		"dns+L2OWv9Ft9OY5SziE4UcSiaGLViIV1O2jb7kTBrgyZ2uD78ZgIVdQLCb2E3Ut\n" +
		"RRQGGeNtjPqm/SnBpru25+QENFonDKkbQhUQDWVqQSSDT+44CCWckq2N4UxysJ49\n" +
		"ypgAPmw61taA1RfclWGhuDZBVIPElqeyMnPMyJkkShunlEC16F4eTvFmNVC4P+Hg\n" +
		"6k3y15kw0Lq6eE66jdKMHkpw6TyFJhiR0acbltkI/duQT6a0DVoZCCbbQU3YeSeU\n" +
		"fKW8LopWnrY2tIH6Tq5P0rIJrTvvxpI5SM3QPr3uYQzf0JhoAFPjLiL+ZHJww5z5\n" +
		"klR24hbJGnDq6ja4j/5GH3Bq4SPYAuWkc14Fbvpq347PcsgSLHUfeBk9+fTHLUCG\n" +
		"wNOIU0f8F1iJCZDIOK4aNT3wNmB13sw1VGtf3khF+8rYIcSu5eYvG4f6R+N3TN0E\n" +
		"Mu0UbYpCVhNQfoEKk+7vpMLf3Wj51NxzjUgWz3CcTcuKjk9YXKBuW2GrCE0a1j+c\n" +
		"IHpZzDy669DX16H0eMLndRCRzTgnJhy+abKjV3N1DjFbu7BxI8i56mkSJF35B00t\n" +
		"p/ig1XU6N5mdqqQMhD6tjUg2vnXtBjPqaICQTUbEDFUjBaf1gAOuZU9TrhjsKQoR\n" +
		"J7MfeTQCyuyQzT0ccTaB8gR/IMyoSavOtVPuzpM9Mr+ZJr7wqUWlSPTzjiQxn9yT\n" +
		"dDqe3oYWwDgi5NdFpGBNAqCgyudQ3ceongfho+HFRmRSGpbV09iKOzcsO4zWFVaI\n" +
		"G/LGeqiDqZSogECcoF4IaQ3u8yiYNxWaLU87M9WDAPT6G398Ul2fdCBBO/q6Q4PF\n" +
		"J28DHp/uzaFUQNCYcmIfu4IJDQyPdAlZeMLPtSm95SEI5O21AzzyWMIi4vLmO3JB\n" +
		"dFruCgamnS6cyk5JZ8ckvIQOgez2SYE0oL9yjKt44YHZmCQGpmhoUK0i8jopXCNl\n" +
		"lLPcWsJ7moL+9uaZv103ouTiajQX8z32zDjUgfhAPOLvva4KWP3VNviscyVnmi4I\n" +
		"Y3EtlIBXQlCQ1aH8jhlUciotWiy4nWRLSoy2v2xOyRfqQE8FpLf2CT6suR9vdXtb\n" +
		"3jVHscY0U/BvhTFukhTaN3UY0Wzy01oLNMZUA8Wk3/k+mfZ8JslABqDIhEPraLtk\n" +
		"l37ov9OYhy40GeI6fFJbfePsU5YSCTb1OMu4\n" +
		"-----END ENCRYPTED PRIVATE KEY-----")

	block, _ := pem.Decode(raw)
	if block == nil {
		t.Fatal("failed to decode test PEM block")
	}

	components, err := GenerateCdxComponents(block)
	if err != nil {
		t.Fatalf("expected no error for a recognized encrypted key, got: %v", err)
	}
	assert.Len(t, components, 3)
	props := components[0].CryptoProperties.RelatedCryptoMaterialProperties
	assert.NotNil(t, props.SecuredBy)
	assert.Equal(t, "Software", props.SecuredBy.Mechanism)
	assert.Equal(t, cdx.BOMReference(components[1].BOMRef), props.SecuredBy.AlgorithmRef)
	assert.Equal(t, "AES-256-CBC", components[1].Name)
	assert.Equal(t, "PBKDF2-HMAC-SHA1", components[2].Name)
}

func TestGenerateCdxComponentsPKCS8LegacyDirectPBEScheme(t *testing.T) {
	// A direct (non-PBES2) legacy PKCS12 PBE scheme, generated with
	// `openssl pkcs8 -topk8 -v1 PBE-SHA1-3DES`. The mechanism should resolve straight from
	// the outer AlgorithmIdentifier without attempting to unwrap PBES2-shaped parameters.
	raw := []byte("-----BEGIN ENCRYPTED PRIVATE KEY-----\n" +
		"MIIE6jAcBgoqhkiG9w0BDAEDMA4ECHbp5eKBDosLAgIIAASCBMgNBtgzt65+T78J\n" +
		"BQk67jAalv8xmXFJwU2LlWcRc139OYSsuX9t5d0M7PovI6EUnThn/A/uKTHkuC01\n" +
		"fep+BG9QaVwQMWMHsfmUv0zhAgjZK42vHdXOWzgqf4lziJcfbdPh7GqGX65qsUv+\n" +
		"vW/5ObCfwFhtOEawfpBypz3q9l5pgsctPtCK0aaOoMHdE+utjxxs+9ttuW+FzJzC\n" +
		"QUvH5Ujw/sfLbbI4jY0x7qxwU1U4UBq/n1KZSp67w3sVg9O1nD9Ruh+cnl+7e0ib\n" +
		"bRh/MuLx5J+eYj9eEdtL1M/UiGcGLDLG7SWxGnTKmdMPcdYyYVCJJS3LGo9WKMcF\n" +
		"4hTR7snq+3guuNDaqpBtoLyZXGRNoyvM2Uq0t5qfjMVU9HvgKzwXBJ4GSNMObVPQ\n" +
		"4uNM8hN714tx/HdkblCw/56Uxt3YlGHR6MEXDvUlOPJI1wj8SF3TuIPpn4SMvUky\n" +
		"M9AKYowIls1pWBD6tMzGCihW0dsHUeGiS/3ctKVTA1uw9U9Tjo1bBfCOlPDJ9vO9\n" +
		"RUPVN2Ea0wilFtB6I9+pmNrlCju5cfiQK0403v4PQZhwZ87oWIpJgCG48jVISA76\n" +
		"XyFTcAoZIMadteFslaAe8Ks+DBVOnL4wvl2A9UjYLHLihx3dy1fIiTvvDP27mVDG\n" +
		"aSm63bl63I+AoBR2+3BCgAZaekIpjKdAO5Ld9VsdhDDV0nxhBZSYH/ioSTW2PCwn\n" +
		"obpFDatUWER09aYgbHyr2LJQ1EBCMwyEuqmxtq1XBGKStMQjn6CDhVc5ith6S/1J\n" +
		"tr2LpJQsDbVMXmd84vFJZXJ8Pc7qI9yHZ3S6VK96/K65OxcH4qxX5awXaH4AfTTf\n" +
		"1WPreDjHlfSw/ivGaRcc31tTYdzyXZu1VjsJDkr+xm46Cox5BlRxPYbi2o7+NbuV\n" +
		"M4pwk6l4e7lxaEwCw/XG2z0nQoYA/7sJrsF8b11l20X6fVEqRqLxi0SE0PKdIEH5\n" +
		"TsF70B00W/IumH0aOOoWs4zeoUvyRkwkXSP6j2pGvvNLNOLx6HG1ePyYMQP3lYRZ\n" +
		"C8c60quVLUMJP0iol9YDNaQMjWMEXXeiLSwvnILNFjY4/6xusVrvqKV6bfpc7DCD\n" +
		"24GP71Ug7KoTn2GMFq96nmuOyeuW8T0YPEjC/gnt9ZqhPFJzOMfWBqptJX4/tpws\n" +
		"9P0VVQvQePmKERXrnXeSiauETeLSvnAGmjbvyZMbnasMxAwOe1wssN/9sGPChkv7\n" +
		"oA0mW7TNUh4vPYYk5QKAIo1gTt3VuZ7++aTmYZcPnJxAE4l/NmKMucZv95xnZSXU\n" +
		"KomM9RLeHPJPa0wGJ3DoDKduKJHGQqyUdvNihdcwl9jSrAH1Qn8hmpvprEoz+hrk\n" +
		"wThiGFL6yQeK8+e9kLS0HUQvyUCTv8dmT+C7kc3LHmZG93pHQuT2/0yuJ9/bN4qu\n" +
		"eWXjpslP8zfozfBk5qv2Nl+pbeYBaG6CAmVcCSyPqBw3ISLGN+OQazHVvY2Yi+bI\n" +
		"yMrNlOQ3jjaJ+zmBTZqg7w4tAr5mG3D6wjb185egcnf51AJuqJSkvmPeXrDnaH/R\n" +
		"ehdCdHwWGPCartWe7WqQU1bYWr0B9Duo+Vhu5kVbm9az4qICnWV/SATjVnG8Au9U\n" +
		"tqmMaSdIspQb9HGd7Cg=\n" +
		"-----END ENCRYPTED PRIVATE KEY-----")

	block, _ := pem.Decode(raw)
	if block == nil {
		t.Fatal("failed to decode test PEM block")
	}

	components, err := GenerateCdxComponents(block)
	if err != nil {
		t.Fatalf("expected no error for a recognized encrypted key, got: %v", err)
	}
	// The encrypted-key component, plus separate cipher and KDF components: PKCS#12 Appendix B
	// schemes fuse a KDF and a cipher into one OID, but the identity of each is still known and
	// should be reported as two distinct algorithm components, not one fused/mistyped one.
	assert.Len(t, components, 3)
	props := components[0].CryptoProperties.RelatedCryptoMaterialProperties
	assert.NotNil(t, props.SecuredBy)
	assert.Equal(t, "Software", props.SecuredBy.Mechanism)
	assert.Equal(t, cdx.BOMReference(components[1].BOMRef), props.SecuredBy.AlgorithmRef)

	cipher := components[1]
	assert.Equal(t, "DES-EDE3-CBC", cipher.Name)
	assert.Equal(t, cdx.CryptoPrimitiveBlockCipher, cipher.CryptoProperties.AlgorithmProperties.Primitive)
	assert.Equal(t, cdx.CryptoAlgorithmModeCBC, cipher.CryptoProperties.AlgorithmProperties.Mode)

	kdf := components[2]
	assert.Equal(t, "PKCS#12 KDF-SHA1", kdf.Name)
	assert.Equal(t, cdx.CryptoPrimitiveKDF, kdf.CryptoProperties.AlgorithmProperties.Primitive)
}

// pbeWithSHAAnd128BitRC4 fuses a stream cipher (RC4) into its OID, unlike every other legacy PBE
// scheme, which fuses a block cipher. Its cipher component must be tagged CryptoPrimitiveStreamCipher,
// not CryptoPrimitiveBlockCipher. The EncryptedPrivateKeyInfo DER is built directly via asn1.Marshal
// (rather than a captured openssl fixture) since only the outer AlgorithmIdentifier OID matters here.
func TestGenerateCdxComponentsPKCS8LegacyRC4Scheme(t *testing.T) {
	type pbeParameter struct {
		Salt           []byte
		IterationCount int
	}
	type encryptedPrivateKeyInfo struct {
		Algorithm pkix.AlgorithmIdentifier
		Encrypted []byte
	}

	params, err := asn1.Marshal(pbeParameter{Salt: []byte{1, 2, 3, 4, 5, 6, 7, 8}, IterationCount: 2048})
	if err != nil {
		t.Fatalf("failed to marshal PBEParameter: %v", err)
	}
	der, err := asn1.Marshal(encryptedPrivateKeyInfo{
		Algorithm: pkix.AlgorithmIdentifier{
			Algorithm:  asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 1, 1}, // pbeWithSHAAnd128BitRC4
			Parameters: asn1.RawValue{FullBytes: params},
		},
		Encrypted: []byte{0xAA, 0xBB, 0xCC, 0xDD},
	})
	if err != nil {
		t.Fatalf("failed to marshal EncryptedPrivateKeyInfo: %v", err)
	}

	components := pkcs8EncryptionComponents(der)
	assert.Len(t, components, 3)

	cipher := components[1]
	assert.Equal(t, "RC4-128", cipher.Name)
	assert.Equal(t, cdx.CryptoPrimitiveStreamCipher, cipher.CryptoProperties.AlgorithmProperties.Primitive)
	assert.Empty(t, cipher.CryptoProperties.AlgorithmProperties.Mode)

	kdf := components[2]
	assert.Equal(t, "PKCS#12 KDF-SHA1", kdf.Name)
	assert.Equal(t, cdx.CryptoPrimitiveKDF, kdf.CryptoProperties.AlgorithmProperties.Primitive)
}

// pbeWithSHA1AndRC2-CBC (RFC 8018 §6.1 PBES1) is one of the four PBES1/PKCS#12 gaps previously
// missing from the OID table, falling back to a raw dotted-OID placeholder name. DER built via
// asn1.Marshal since legacyPBEComponents never inspects Parameters, only the outer OID.
func TestGenerateCdxComponentsPKCS8PBES1RC2Scheme(t *testing.T) {
	type encryptedPrivateKeyInfo struct {
		Algorithm pkix.AlgorithmIdentifier
		Encrypted []byte
	}

	der, err := asn1.Marshal(encryptedPrivateKeyInfo{
		Algorithm: pkix.AlgorithmIdentifier{
			Algorithm: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 11}, // pbeWithSHA1AndRC2-CBC
		},
		Encrypted: []byte{0xAA, 0xBB, 0xCC, 0xDD},
	})
	if err != nil {
		t.Fatalf("failed to marshal EncryptedPrivateKeyInfo: %v", err)
	}

	components := pkcs8EncryptionComponents(der)
	assert.Len(t, components, 3)

	cipher := components[1]
	assert.Equal(t, "RC2-CBC", cipher.Name)
	assert.Equal(t, cdx.CryptoPrimitiveBlockCipher, cipher.CryptoProperties.AlgorithmProperties.Primitive)
	assert.Equal(t, cdx.CryptoAlgorithmModeCBC, cipher.CryptoProperties.AlgorithmProperties.Mode)

	kdf := components[2]
	assert.Equal(t, "PBKDF1-SHA1", kdf.Name)
	assert.Equal(t, cdx.CryptoPrimitiveKDF, kdf.CryptoProperties.AlgorithmProperties.Primitive)
}

// AES-128-OFB is one of the AES-CFB/OFB cipher-scheme OIDs previously missing from the PBES2
// cipher table. DER built via asn1.Marshal to exercise the full PBES2 KDF/cipher unwrap path.
func TestGenerateCdxComponentsPKCS8PBES2AESOFBCipher(t *testing.T) {
	type pbes2Params struct {
		KDF    pkix.AlgorithmIdentifier
		Cipher pkix.AlgorithmIdentifier
	}
	type encryptedPrivateKeyInfo struct {
		Algorithm pkix.AlgorithmIdentifier
		Encrypted []byte
	}

	saltDER, err := asn1.Marshal([]byte{1, 2, 3, 4, 5, 6, 7, 8})
	if err != nil {
		t.Fatalf("failed to marshal salt: %v", err)
	}
	kdfParams, err := asn1.Marshal(pbkdf2Params{
		Salt:           asn1.RawValue{FullBytes: saltDER},
		IterationCount: 2048,
		PRF:            pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 9}}, // HMAC-SHA256
	})
	if err != nil {
		t.Fatalf("failed to marshal PBKDF2-params: %v", err)
	}
	ivDER, err := asn1.Marshal(make([]byte, 16))
	if err != nil {
		t.Fatalf("failed to marshal IV: %v", err)
	}
	schemeParams, err := asn1.Marshal(pbes2Params{
		KDF: pkix.AlgorithmIdentifier{
			Algorithm:  asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 12}, // PBKDF2
			Parameters: asn1.RawValue{FullBytes: kdfParams},
		},
		Cipher: pkix.AlgorithmIdentifier{
			Algorithm:  asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 3}, // AES-128-OFB
			Parameters: asn1.RawValue{FullBytes: ivDER},
		},
	})
	if err != nil {
		t.Fatalf("failed to marshal PBES2-params: %v", err)
	}
	der, err := asn1.Marshal(encryptedPrivateKeyInfo{
		Algorithm: pkix.AlgorithmIdentifier{
			Algorithm:  asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 13}, // PBES2
			Parameters: asn1.RawValue{FullBytes: schemeParams},
		},
		Encrypted: []byte{0xAA, 0xBB, 0xCC, 0xDD},
	})
	if err != nil {
		t.Fatalf("failed to marshal EncryptedPrivateKeyInfo: %v", err)
	}

	components := pkcs8EncryptionComponents(der)
	assert.Len(t, components, 3)

	cipher := components[1]
	assert.Equal(t, "AES-128-OFB", cipher.Name)
	assert.Equal(t, cdx.CryptoPrimitiveBlockCipher, cipher.CryptoProperties.AlgorithmProperties.Primitive)
	assert.Equal(t, cdx.CryptoAlgorithmModeOFB, cipher.CryptoProperties.AlgorithmProperties.Mode)

	kdf := components[2]
	assert.Equal(t, "PBKDF2-HMAC-SHA256", kdf.Name)
	assert.Equal(t, cdx.CryptoPrimitiveKDF, kdf.CryptoProperties.AlgorithmProperties.Primitive)
}

func TestGenerateCdxComponentsUnencryptedMalformedKeyStillErrors(t *testing.T) {
	// A block recognized as an RSA private key that fails to parse for reasons other than
	// encryption (e.g. corrupted key material) must still surface as an error, unchanged.
	raw := []byte("-----BEGIN RSA PRIVATE KEY-----\n" +
		"MAA=\n" +
		"-----END RSA PRIVATE KEY-----")

	block, _ := pem.Decode(raw)
	if block == nil {
		t.Fatal("failed to decode test PEM block")
	}

	_, err := GenerateCdxComponents(block)
	assert.Error(t, err)
}

func TestGenerateCdxComponentsOpenSSHPassphraseProtectedKey(t *testing.T) {
	// Generated with: ssh-keygen -t ed25519 -N testpassphrase -C "" -f id_ed25519
	raw := []byte("-----BEGIN OPENSSH PRIVATE KEY-----\n" +
		"b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABBP9T2L6v\n" +
		"A4w3OyEHctq1TkAAAAGAAAAAEAAAAzAAAAC3NzaC1lZDI1NTE5AAAAIJv1oucckQBNTvBJ\n" +
		"0wWhQDQzAMnGrii5VNlW1OgxCy2jAAAAkFy5+5SOjbvYfbO99XJYoLwN6jJ26J6GQjjJ56\n" +
		"hwb3tLrcYTEQvLSC1n/rTF9mAp7k+X6Vw9I8M+CT40LzidTiPklIb93LugCub4hsNF88GH\n" +
		"DQeuQfIfFs2J3vdwb5OQ8805LQi2L1NEB/buHGBzuigSeKg7qzyfWcagXqVPWWgbkogDAY\n" +
		"VgHG4i9Ak2G+wwLg==\n" +
		"-----END OPENSSH PRIVATE KEY-----")

	block, _ := pem.Decode(raw)
	if block == nil {
		t.Fatal("failed to decode test PEM block")
	}

	components, err := GenerateCdxComponents(block)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assert.Len(t, components, 4)

	cipher := components[1]
	assert.Equal(t, "AES-256-CTR", cipher.Name)
	assert.Equal(t, cdx.CryptoPrimitiveBlockCipher, cipher.CryptoProperties.AlgorithmProperties.Primitive)
	assert.Equal(t, cdx.CryptoAlgorithmModeCTR, cipher.CryptoProperties.AlgorithmProperties.Mode)

	kdf := components[2]
	assert.Equal(t, "bcrypt", kdf.Name)
	assert.Equal(t, cdx.CryptoPrimitiveKDF, kdf.CryptoProperties.AlgorithmProperties.Primitive)

	key := components[0]
	assert.Equal(t, cdx.CryptoAssetTypeRelatedCryptoMaterial, key.CryptoProperties.AssetType)
	assert.Equal(t, cdx.RelatedCryptoMaterialTypePrivateKey, key.CryptoProperties.RelatedCryptoMaterialProperties.Type)
	assert.Equal(t, cdx.BOMReference(cipher.BOMRef), key.CryptoProperties.RelatedCryptoMaterialProperties.SecuredBy.AlgorithmRef)

	pubKey := components[3]
	assert.Equal(t, "ED25519", pubKey.Name)
	assert.Equal(t, cdx.CryptoAssetTypeRelatedCryptoMaterial, pubKey.CryptoProperties.AssetType)
	assert.Equal(t, cdx.RelatedCryptoMaterialTypePublicKey, pubKey.CryptoProperties.RelatedCryptoMaterialProperties.Type)
}

// chacha20-poly1305@openssh.com is an AEAD construction with no applicable CryptoAlgorithmMode, so
// its extra detail is carried in ParameterSetIdentifier/CryptoFunctions instead.
func TestGenerateCdxComponentsOpenSSHChaCha20Poly1305(t *testing.T) {
	// Generated with: ssh-keygen -t ed25519 -N testpassphrase -Z chacha20-poly1305@openssh.com -C "" -f id_ed25519
	raw := []byte("-----BEGIN OPENSSH PRIVATE KEY-----\n" +
		"b3BlbnNzaC1rZXktdjEAAAAAHWNoYWNoYTIwLXBvbHkxMzA1QG9wZW5zc2guY29tAAAABm\n" +
		"JjcnlwdAAAABgAAAAQm7/o2GzGJpuJLhCPlLU/sQAAABgAAAABAAAAMwAAAAtzc2gtZWQy\n" +
		"NTUxOQAAACA4QVdzvb4HCqCZj4tXu7S0hIboW57NfXUcX07lYAeYOgAAAIjMByPI6RD6cK\n" +
		"8Nonbb0y4H0T2nX3wE9BvtUSkXGHD4W3SuYTGVSLHAS+2JUFriSzhSFbQTQUpTb2OlYSr1\n" +
		"/rJ9hLF35XVa2nt0DGD8IIA3muW2Dz/mW60ny+nBCUw0YIZ3VEb7EZLEUWZOXL3wOy8BJW\n" +
		"0lvw8bYXJruIE+ThGcML65RSBi013vs1hBBlFC83KijtS5SVW2Aw==\n" +
		"-----END OPENSSH PRIVATE KEY-----")

	block, _ := pem.Decode(raw)
	if block == nil {
		t.Fatal("failed to decode test PEM block")
	}

	components, err := GenerateCdxComponents(block)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assert.Len(t, components, 4)

	cipher := components[1]
	assert.Equal(t, "ChaCha20-Poly1305", cipher.Name)
	assert.Equal(t, cdx.CryptoPrimitiveAE, cipher.CryptoProperties.AlgorithmProperties.Primitive)
	assert.Equal(t, "512-bit key (two 256-bit ChaCha20 subkeys: payload+MAC, length field), 64-bit sequence-number nonce, 128-bit tag", cipher.CryptoProperties.AlgorithmProperties.ParameterSetIdentifier)
	if assert.NotNil(t, cipher.CryptoProperties.AlgorithmProperties.CryptoFunctions) {
		assert.ElementsMatch(t,
			[]cdx.CryptoFunction{cdx.CryptoFunctionEncrypt, cdx.CryptoFunctionDecrypt, cdx.CryptoFunctionTag},
			*cipher.CryptoProperties.AlgorithmProperties.CryptoFunctions)
	}

	pubKey := components[3]
	assert.Equal(t, "ED25519", pubKey.Name)
}

// Some tools mislabel a PKCS8 EncryptedPrivateKeyInfo as "PRIVATE KEY" instead of the standard
// "ENCRYPTED PRIVATE KEY". x509.ParsePKCS8PrivateKey then fails, but the content is still
// recognizably encrypted PKCS8 (its outer SEQUENCE decodes as AlgorithmIdentifier+OCTET STRING,
// not the version-INTEGER-first shape of a real PrivateKeyInfo), so it should still be enriched
// rather than falling back to a generic secret.
func TestGenerateCdxComponentsMislabeledEncryptedPKCS8Key(t *testing.T) {
	// Same DER as TestGenerateCdxComponentsPKCS8EncryptedKey, wrapped in a "PRIVATE KEY" label.
	raw := []byte("-----BEGIN PRIVATE KEY-----\n" +
		"MIIFNTBfBgkqhkiG9w0BBQ0wUjAxBgkqhkiG9w0BBQwwJAQQpSWo8bNANk2fHXl2\n" +
		"PVxCsAICCAAwDAYIKoZIhvcNAgkFADAdBglghkgBZQMEASoEEGJ+KfImD/Z6emMe\n" +
		"gVedeoUEggTQkG2fi3wPe9kHM1EyWlnu/sTu6fh/h3fYHQXTD7NFG3QZaQDsyfbO\n" +
		"PEl0G6zxMLb1LcEcPNHy6dO9CbzaBtlsQKUCtj8CiCzjjRB8mUEjq4zwT4+yfEP1\n" +
		"Djd0P7Eb4LF7sOINwA9KTQEL4lBYKddjSB9XD2mfHWNqNxQK4aF7cfRj81NDhi9G\n" +
		"NIhdrGbMXCWAUn3bd0ARwf05/yiOIWtmr6VjnC2KOjngbx4eXRHBkxtI9YnY31/I\n" +
		"M4nJWxpbjVI2fNpSf1xJLYszvIKakttWlUyTGvEsFCq4NUvLdPSGx4ITtotD2GHj\n" +
		"AQctLYP/3I6SM1P+mKsEaSEgVpJ0gkLPzwDZS23YRgp6DQxqW0rNk+seqzmDF5o+\n" +
		"Do2Eu2HhpRHB3lXOZ8KZzC3X6UJzMtYeEq74iRFSs3hwxXHpEJJpKOL9o5l+0eQ7\n" +
		"RnjI05x74RKTo4+8xo4b+9VttSfh7+zbPCLxJ6oiom/mJiATIr4RB2Uu2KmziOGs\n" +
		"WwtvDe8So4SDaH/n/ryGzZ3XTFlwjCM7qGWIbK5RkasMGd/NsJ7zaj7fB9BO2E92\n" +
		"pkjsVnjVIYk1RwOWTb2bcxt5j6qRtNwhnSFQlP7OdrsY2gpT0fhaPkX3c+ben9pN\n" +
		"29VU+62e02gXuVnQHgfm7RefGWRVPin57dpYfI9xTfQmyJeyTtngDLqLtYcOEe3p\n" +
		"8Eplict39vt59465CxhdeTZhq4/jyPNIXdw1hM4gNHT36j3orbdjK8zWeAEEgaGd\n" +
		"RRCJOdrCgQPbK7/VHkc0JGxaLbFDqSp0bH6Iz5Zcyf1agGcWqjFcESr/RiePM7Cg\n" +
		"kPQGr64PCJ2BTEZH58WOIgXID0sKZp+qkjC9UDpkxbeFIMxRGZJflAiqopD7mO3S\n" +
		"xu/VXvxkhkUp+skBLI8B5rlI2PUvj68BQW2zJ8o/iKT9L0lf18teszhyo0V00stY\n" +
		"nA/6h9UVEKY5NA9DvksiZP4dUbDlsXcNefi6PK8SRtI7oX0LZFgft5DlAN5MAW/q\n" +
		"6psPYB++imvuV7f65wmr8uWFBWqgii/7oPUPhmrf+tW7jTAzafyZLBUMCeGyp25O\n" +
		"p12y1V3Ec/wlSZ/+T0bsEwR6tycI55GzLx9DEMdtVjwK2YsxV9cIqbiBmdTJ5AH2\n" +
		"zZqyTnIlyIyun1fntRvn/+O87DGytMGZWEv+1XbGdne8c2xZJK5ltqQKLph2qsoM\n" +
		"8EbJhReVxZ9jkCRkNCdspCvY1bELVHU/VFhPSSJTbO4C0hYNvzPxQQYsh9tXZioF\n" +
		"TXvlPMVsbHRJdOAgseUNI2x5/ZRou4DWcklorWR7bXUJC4IUS9zlRnkyfSy0kLMi\n" +
		"ku4OBOAxCvwXzx9E/qL3LPz5mODisv5SNSSTWcYGCDiRH3sZ8e6nEsHB0deBndx8\n" +
		"uEQ7Xk/a3jNFeNq9PIH1zf9xx+YEd0UesuhXWaNR2oDbaI7vU97uINmW1UsOOh3p\n" +
		"ldR3U1KkccxFjgETr0Yh4EzxP1ulcuLE2n444Wlg55POOocILofgZdOlpPC1WLpI\n" +
		"HflB1TXRe8oRTYqmBUWe3/1A7ovx76aVKZo1sqkHAkC2lp4MaV+V+UaHVeVUDqW3\n" +
		"pqcP4PIRXJ/RQowYxrggwnIlPvsbB+xi1rMA7x4MxH+7XMiprxJvxiw=\n" +
		"-----END PRIVATE KEY-----")

	block, _ := pem.Decode(raw)
	if block == nil {
		t.Fatal("failed to decode test PEM block")
	}
	assert.Equal(t, "PRIVATE KEY", block.Type)

	components, err := GenerateCdxComponents(block)
	if err != nil {
		t.Fatalf("expected no error for a mislabeled encrypted key, got: %v", err)
	}
	assert.Len(t, components, 3)
	assert.Equal(t, cdx.CryptoAssetTypeRelatedCryptoMaterial, components[0].CryptoProperties.AssetType)
	assert.Equal(t, cdx.RelatedCryptoMaterialTypePrivateKey, components[0].CryptoProperties.RelatedCryptoMaterialProperties.Type)
}

// A "PRIVATE KEY" block that is neither a valid PrivateKeyInfo nor shaped like an
// EncryptedPrivateKeyInfo is genuinely malformed, not encrypted, and must still surface as an
// error rather than being misidentified as an encrypted key.
func TestGenerateCdxComponentsUnencryptedMalformedPKCS8KeyStillErrors(t *testing.T) {
	raw := []byte("-----BEGIN PRIVATE KEY-----\n" +
		"MAA=\n" +
		"-----END PRIVATE KEY-----")

	block, _ := pem.Decode(raw)
	if block == nil {
		t.Fatal("failed to decode test PEM block")
	}

	_, err := GenerateCdxComponents(block)
	assert.Error(t, err)
}
