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
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"slices"
	"strings"

	"github.com/cbomkit/cbomkit-theia/scanner/key"

	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

// Filter that describes which PEMBlockTypes to allow
type Filter struct {
	FilterType TypeFilterType
	List       []BlockType
}

// TypeFilterType Used to specify whether a filter is an allow- or blocklist
type TypeFilterType bool

const (
	TypeAllowlist TypeFilterType = true  // Allowlist
	TypeBlocklist TypeFilterType = false // Blocklist
)

// BlockType A not complete list of PEMBlockTypes that can be detected currently
type BlockType string

const (
	BlockTypeCertificate         BlockType = "CERTIFICATE"
	BlockTypePrivateKey          BlockType = "PRIVATE KEY"
	BlockTypeEncryptedPrivateKey BlockType = "ENCRYPTED PRIVATE KEY"
	BlockTypePublicKey           BlockType = "PUBLIC KEY"
	BlockTypeECPrivateKey        BlockType = "EC PRIVATE KEY"
	BlockTypeRSAPrivateKey       BlockType = "RSA PRIVATE KEY"
	BlockTypeRSAPublicKey        BlockType = "RSA PUBLIC KEY"
	BlockTypeOPENSSHPrivateKey   BlockType = "OPENSSH PRIVATE KEY"
)

// pbkdf2Params mirrors RFC 8018's PBKDF2-params. PRF defaults to HMAC-SHA1 per the RFC
// when omitted, which is why it is optional here rather than required.
type pbkdf2Params struct {
	Salt           asn1.RawValue
	IterationCount int
	KeyLength      int                      `asn1:"optional"`
	PRF            pkix.AlgorithmIdentifier `asn1:"optional"`
}

// encryptionAlgorithmOIDNames maps OIDs used in PKCS8/PKCS12 password-based encryption
// (PBES2, its KDFs and PBKDF2 PRFs, its cipher schemes, and legacy direct PBE schemes) to
// human-readable names. OIDs are globally unique, so sharing one table across these
// categories cannot cause a collision.
var encryptionAlgorithmOIDNames = map[string]string{
	// PBES2 (RFC 8018) and its KDFs
	"1.2.840.113549.1.5.13":  "PBES2",
	"1.2.840.113549.1.5.12":  "PBKDF2",
	"1.3.6.1.4.1.11591.4.11": "scrypt",

	// PBKDF2 pseudo-random functions (RFC 8018)
	"1.2.840.113549.2.7":  "HMAC-SHA1",
	"1.2.840.113549.2.8":  "HMAC-SHA224",
	"1.2.840.113549.2.9":  "HMAC-SHA256",
	"1.2.840.113549.2.10": "HMAC-SHA384",
	"1.2.840.113549.2.11": "HMAC-SHA512",
	"1.2.840.113549.2.12": "HMAC-SHA512-224",
	"1.2.840.113549.2.13": "HMAC-SHA512-256",

	// PBES2 cipher schemes
	"2.16.840.1.101.3.4.1.2":  "AES-128-CBC",
	"2.16.840.1.101.3.4.1.22": "AES-192-CBC",
	"2.16.840.1.101.3.4.1.42": "AES-256-CBC",
	"2.16.840.1.101.3.4.1.6":  "AES-128-GCM",
	"2.16.840.1.101.3.4.1.26": "AES-192-GCM",
	"2.16.840.1.101.3.4.1.46": "AES-256-GCM",
	"1.2.840.113549.3.7":      "DES-EDE3-CBC",
	"1.3.14.3.2.7":            "DES-CBC",

	// Legacy direct (non-PBES2) PKCS5/PKCS12 password-based encryption schemes
	"1.2.840.113549.1.5.3":    "pbeWithMD5AndDES-CBC",
	"1.2.840.113549.1.5.10":   "pbeWithSHA1AndDES-CBC",
	"1.2.840.113549.1.12.1.1": "pbeWithSHAAnd128BitRC4",
	"1.2.840.113549.1.12.1.2": "pbeWithSHAAnd40BitRC4",
	"1.2.840.113549.1.12.1.3": "pbeWithSHAAnd3-KeyTripleDES-CBC",
	"1.2.840.113549.1.12.1.4": "pbeWithSHAAnd2-KeyTripleDES-CBC",
	"1.2.840.113549.1.12.1.5": "pbeWithSHAAnd128BitRC2-CBC",
	"1.2.840.113549.1.12.1.6": "pbeWithSHAAnd40BitRC2-CBC",
}

// ParsePEMToBlocksWithTypeFilter Just like ParsePEMToBlocksWithTypes but uses a filter for filtering
func ParsePEMToBlocksWithTypeFilter(raw []byte, filter Filter) map[*pem.Block]BlockType {
	blocksWithType := parsePEMToBlocksWithTypes(raw)
	filteredBlocksWithType := make(map[*pem.Block]BlockType)

	for block, t := range blocksWithType {
		if slices.Contains(filter.List, t) == bool(filter.FilterType) {
			filteredBlocksWithType[block] = t
		}
	}
	return filteredBlocksWithType
}

// GenerateCdxComponents Generate cyclone-go components from a block containing a key
func GenerateCdxComponents(block *pem.Block) ([]cdx.Component, error) {
	switch BlockType(block.Type) {
	case BlockTypePrivateKey:
		rawKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return []cdx.Component{}, err
		}
		return key.GenerateCdxComponents([]any{rawKey})
	case BlockTypeEncryptedPrivateKey:
		return pkcs8EncryptionComponents(block.Bytes), nil
	case BlockTypeECPrivateKey:
		rawKey, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			if components, encrypted := legacyEncryptionComponents(block.Headers); encrypted {
				return components, nil
			}
			return []cdx.Component{}, err
		}
		return key.GenerateCdxComponents([]any{rawKey, &rawKey.PublicKey})
	case BlockTypeRSAPrivateKey:
		rawKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			if components, encrypted := legacyEncryptionComponents(block.Headers); encrypted {
				return components, nil
			}
			return []cdx.Component{}, err
		}
		return key.GenerateCdxComponents([]any{rawKey, &rawKey.PublicKey})
	case BlockTypePublicKey:
		rawKey, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return []cdx.Component{}, err
		}
		return key.GenerateCdxComponents([]any{rawKey})
	case BlockTypeRSAPublicKey:
		rawKey, err := x509.ParsePKCS1PublicKey(block.Bytes)
		if err != nil {
			return []cdx.Component{}, err
		}
		return key.GenerateCdxComponents([]any{rawKey})
	case BlockTypeOPENSSHPrivateKey:
		rawKey, err := ssh.ParseRawPrivateKey(pem.EncodeToMemory(block))
		if err != nil {
			return []cdx.Component{}, err
		}
		return key.GenerateCdxComponents([]any{rawKey})
	default:
		return []cdx.Component{}, fmt.Errorf("could not generate component from PEM. Block type is unknown or not a key")
	}
}

// oidName looks up a human-readable name for an OID, falling back to its dotted form.
func oidName(oid asn1.ObjectIdentifier) string {
	if name, ok := encryptionAlgorithmOIDNames[oid.String()]; ok {
		return name
	}
	return oid.String()
}

// legacyEncryptionComponents reports whether a PEM block carries the legacy OpenSSL
// "Proc-Type: 4,ENCRYPTED" / "DEK-Info: <cipher>,<iv>" headers, and if so, builds the
// encrypted-key component together with a standalone algorithm component for its cipher.
func legacyEncryptionComponents(headers map[string]string) (components []cdx.Component, encrypted bool) {
	procType, ok := headers["Proc-Type"]
	if !ok || !strings.Contains(procType, "ENCRYPTED") {
		return nil, false
	}
	cipherName := "PEM legacy encryption,Cipher Unknown"
	if dekInfo, ok := headers["DEK-Info"]; ok {
		if cipher, _, _ := strings.Cut(dekInfo, ","); cipher != "" {
			cipherName = cipher
		}
	}
	return encryptedPrivateKeyComponents(cipherName), true
}

// pkcs8EncryptionComponents inspects the outer EncryptedPrivateKeyInfo ASN.1 structure of a
// standard PKCS8 "ENCRYPTED PRIVATE KEY" block to identify the encryption scheme in use, and
// builds the encrypted-key component together with algorithm components describing it.
func pkcs8EncryptionComponents(der []byte) []cdx.Component {
	var info struct {
		Algorithm pkix.AlgorithmIdentifier
		Encrypted asn1.RawValue
	}
	if _, err := asn1.Unmarshal(der, &info); err != nil {
		log.WithError(err).Debug("Could not parse EncryptedPrivateKeyInfo; recording as generic encrypted private key")
		return encryptedPrivateKeyComponents("PKCS#8 encrypted private key")
	}

	oid := info.Algorithm.Algorithm.String()
	name, ok := encryptionAlgorithmOIDNames[oid]
	if !ok {
		return encryptedPrivateKeyComponents(fmt.Sprintf("PKCS#8 encrypted private key (%s)", oid))
	}
	if name != "PBES2" {
		// legacyPBEEncryptionComponents builds components for the pre-PBES2 password-based encryption
		// schemes: RFC 8018 §6.1 PBES1 ("pbeWithMD5AndDES-CBC", "pbeWithSHA1AndDES-CBC") and the PKCS#12
		// Appendix B schemes ("pbeWithSHAAnd..."). Both fuse the cipher and KDF into a single OID, so
		// unlike PBES2 they can't be split into separate cipher/KDF algorithm components.
		return encryptedPrivateKeyComponents(name)
	}
	return pbes2EncryptionComponents(name, info.Algorithm.Parameters.FullBytes)
}

// pbes2EncryptionComponents builds components for PBES2 (RFC 8018 §6.2), which names its cipher
// (encryptionScheme) and KDF (keyDerivationFunc) as separate AlgorithmIdentifiers, unwrapped here
// into their own algorithm components.
func pbes2EncryptionComponents(name string, params []byte) []cdx.Component {
	var scheme struct {
		KDF    pkix.AlgorithmIdentifier
		Cipher pkix.AlgorithmIdentifier
	}
	if _, err := asn1.Unmarshal(params, &scheme); err != nil {
		log.WithError(err).Debug("Could not parse PBES2-params; recording as generic PBES2 encryption")
		return encryptedPrivateKeyComponents(name)
	}
	cipherComponent := makeAlgorithmComponent(oidName(scheme.Cipher.Algorithm), cdx.CryptoPrimitiveBlockCipher)
	keyComponent := newEncryptedPrivateKeyComponent(cdx.BOMReference(cipherComponent.BOMRef))
	kdfComponent := pbes2KDFComponent(scheme.KDF)
	return []cdx.Component{keyComponent, cipherComponent, kdfComponent}
}

// pbes2KDFComponent builds the algorithm component for a PBES2 keyDerivationFunc. When the KDF
// is PBKDF2 (RFC 8018 §5.2), its PBKDF2-params are unwrapped to recover the PRF hash and fold it
// into the component name; any other KDF (e.g. scrypt) is named as-is.
func pbes2KDFComponent(kdfAlg pkix.AlgorithmIdentifier) cdx.Component {
	kdfName := oidName(kdfAlg.Algorithm)
	if kdfName != "PBKDF2" {
		return makeAlgorithmComponent(kdfName, cdx.CryptoPrimitiveKDF)
	}

	var kdf pbkdf2Params
	if _, err := asn1.Unmarshal(kdfAlg.Parameters.FullBytes, &kdf); err != nil {
		log.WithError(err).Debug("Could not parse PBKDF2-params; omitting PRF from KDF component name")
		return makeAlgorithmComponent(kdfName, cdx.CryptoPrimitiveKDF)
	}
	prfName := "HMAC-SHA1" // RFC 8018 default when the prf field is omitted
	if len(kdf.PRF.Algorithm) > 0 {
		prfName = oidName(kdf.PRF.Algorithm)
	}
	return makeAlgorithmComponent(fmt.Sprintf("%s-%s", kdfName, prfName), cdx.CryptoPrimitiveKDF)
}

// encryptedPrivateKeyComponents builds the encrypted-key component together with a single
// algorithm component for a named cipher, for the cases where the cipher can't be separated
// from its KDF (legacy PEM headers, legacy direct PKCS5/PKCS12 schemes) or the scheme couldn't
// be parsed at all.
func encryptedPrivateKeyComponents(cipherName string) []cdx.Component {
	cipherComponent := makeAlgorithmComponent(cipherName, cdx.CryptoPrimitiveBlockCipher)
	keyComponent := newEncryptedPrivateKeyComponent(cdx.BOMReference(cipherComponent.BOMRef))
	return []cdx.Component{keyComponent, cipherComponent}
}

// makeAlgorithmComponent builds a standalone cryptographic-asset "algorithm" component for a
// resolved algorithm name,its own generated BOMRef so other components can reference it via an *Ref field.
func makeAlgorithmComponent(name string, primitive cdx.CryptoPrimitive) cdx.Component {
	comp := cdx.Component{
		Name:   name,
		Type:   cdx.ComponentTypeCryptographicAsset,
		BOMRef: uuid.New().String(),
		CryptoProperties: &cdx.CryptoProperties{
			AssetType:           cdx.CryptoAssetTypeAlgorithm,
			AlgorithmProperties: &cdx.CryptoAlgorithmProperties{Primitive: primitive},
		},
	}
	if primitive == cdx.CryptoPrimitiveBlockCipher {
		upper := strings.ToUpper(name)
		switch {
		case strings.Contains(upper, "GCM"):
			comp.CryptoProperties.AlgorithmProperties.Mode = cdx.CryptoAlgorithmModeGCM
		case strings.Contains(upper, "CBC"):
			comp.CryptoProperties.AlgorithmProperties.Mode = cdx.CryptoAlgorithmModeCBC
		}
	}
	return comp
}

// newEncryptedPrivateKeyComponent builds a related-crypto-material component for a private key
// whose contents are encrypted and therefore cannot be parsed into key material. Mechanism
// records the protection category per the CycloneDX spec's examples ("HSM", "TPM", "SGX",
// "Software", "None") — this package only ever detects software/password-based encryption — and
// AlgorithmRef points at the cipher component that actually encrypts the key bytes.
func newEncryptedPrivateKeyComponent(cipherRef cdx.BOMReference) cdx.Component {
	return cdx.Component{
		Name: "encrypted-private-key",
		Type: cdx.ComponentTypeCryptographicAsset,
		CryptoProperties: &cdx.CryptoProperties{
			AssetType: cdx.CryptoAssetTypeRelatedCryptoMaterial,
			RelatedCryptoMaterialProperties: &cdx.RelatedCryptoMaterialProperties{
				Type:   cdx.RelatedCryptoMaterialTypePrivateKey,
				Format: "PEM",
				SecuredBy: &cdx.SecuredBy{
					Mechanism:    "Software",
					AlgorithmRef: cipherRef,
				},
			},
		},
	}
}

// Parse the []byte of a PEM file to a map containing the *pem.Block and a PEMBlockType for each block
func parsePEMToBlocksWithTypes(raw []byte) map[*pem.Block]BlockType {
	blocks := parsePEMToBlocks(raw)

	blocksWithType := make(map[*pem.Block]BlockType, len(blocks))

	for _, block := range blocks {
		blocksWithType[block] = BlockType(block.Type)
	}
	return blocksWithType
}

func parsePEMToBlocks(raw []byte) []*pem.Block {
	rest := raw
	var blocks []*pem.Block
	for len(rest) != 0 {
		var newBlock *pem.Block
		newBlock, rest = pem.Decode(rest)
		if newBlock != nil {
			blocks = append(blocks, newBlock)
		} else {
			break
		}
	}
	return blocks
}
