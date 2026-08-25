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
	"bytes"
	"crypto/ed25519"
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

// encryptionAlgorithmOIDNames maps OIDs used in PKCS8 PBES2 password-based encryption (PBES2
// itself, its KDFs and PBKDF2 PRFs) to human-readable names. OIDs are globally unique, so sharing
// one table across these categories cannot cause a collision. PBES2 cipher schemes are looked up
// via pbes2CipherSchemes instead, since those also need an explicit mode rather than an inferred one.
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
}

// pbes2CipherScheme names a PBES2 (RFC 8018 §6.2) encryptionScheme OID and its cipher mode. The
// mode is carried here rather than inferred from the name, since it's already known precisely
// from which OID matched.
type pbes2CipherScheme struct {
	name string
	mode cdx.CryptoAlgorithmMode
}

var pbes2CipherSchemes = map[string]pbes2CipherScheme{
	"2.16.840.1.101.3.4.1.2":  {name: "AES-128-CBC", mode: cdx.CryptoAlgorithmModeCBC},
	"2.16.840.1.101.3.4.1.22": {name: "AES-192-CBC", mode: cdx.CryptoAlgorithmModeCBC},
	"2.16.840.1.101.3.4.1.42": {name: "AES-256-CBC", mode: cdx.CryptoAlgorithmModeCBC},
	"2.16.840.1.101.3.4.1.6":  {name: "AES-128-GCM", mode: cdx.CryptoAlgorithmModeGCM},
	"2.16.840.1.101.3.4.1.26": {name: "AES-192-GCM", mode: cdx.CryptoAlgorithmModeGCM},
	"2.16.840.1.101.3.4.1.46": {name: "AES-256-GCM", mode: cdx.CryptoAlgorithmModeGCM},
	"2.16.840.1.101.3.4.1.3":  {name: "AES-128-OFB", mode: cdx.CryptoAlgorithmModeOFB},
	"2.16.840.1.101.3.4.1.23": {name: "AES-192-OFB", mode: cdx.CryptoAlgorithmModeOFB},
	"2.16.840.1.101.3.4.1.43": {name: "AES-256-OFB", mode: cdx.CryptoAlgorithmModeOFB},
	"2.16.840.1.101.3.4.1.4":  {name: "AES-128-CFB", mode: cdx.CryptoAlgorithmModeCFB},
	"2.16.840.1.101.3.4.1.24": {name: "AES-192-CFB", mode: cdx.CryptoAlgorithmModeCFB},
	"2.16.840.1.101.3.4.1.44": {name: "AES-256-CFB", mode: cdx.CryptoAlgorithmModeCFB},
	"1.2.840.113549.3.7":      {name: "DES-EDE3-CBC", mode: cdx.CryptoAlgorithmModeCBC},
	"1.3.14.3.2.7":            {name: "DES-CBC", mode: cdx.CryptoAlgorithmModeCBC},
}

// legacyPBEScheme describes a legacy (non-PBES2) password-based encryption OID: either RFC 8018
// §6.1 PBES1 ("pbeWithMD5AndDES-CBC", "pbeWithSHA1AndDES-CBC") or a PKCS#12 Appendix B scheme
// ("pbeWithSHAAnd..."). Both fuse their KDF and cipher into a single OID rather than naming them
// as separate AlgorithmIdentifiers the way PBES2 does, so the split has to be hardcoded here.
// cipherMode is empty for stream ciphers, which have no block mode.
type legacyPBEScheme struct {
	kdfName         string
	cipherName      string
	cipherPrimitive cdx.CryptoPrimitive
	cipherMode      cdx.CryptoAlgorithmMode
}

var legacyPBESchemes = map[string]legacyPBEScheme{
	// RFC 8018 §6.1 PBES1: PBKDF1 (parameterized by hash) with DES-CBC or RC2-CBC. PBES1 fixes
	// RC2's effective key length rather than naming it, unlike the PKCS#12 RC2 variants below.
	"1.2.840.113549.1.5.1":  {kdfName: "PBKDF1-MD2", cipherName: "DES-CBC", cipherPrimitive: cdx.CryptoPrimitiveBlockCipher, cipherMode: cdx.CryptoAlgorithmModeCBC},
	"1.2.840.113549.1.5.3":  {kdfName: "PBKDF1-MD5", cipherName: "DES-CBC", cipherPrimitive: cdx.CryptoPrimitiveBlockCipher, cipherMode: cdx.CryptoAlgorithmModeCBC},
	"1.2.840.113549.1.5.10": {kdfName: "PBKDF1-SHA1", cipherName: "DES-CBC", cipherPrimitive: cdx.CryptoPrimitiveBlockCipher, cipherMode: cdx.CryptoAlgorithmModeCBC},
	"1.2.840.113549.1.5.4":  {kdfName: "PBKDF1-MD2", cipherName: "RC2-CBC", cipherPrimitive: cdx.CryptoPrimitiveBlockCipher, cipherMode: cdx.CryptoAlgorithmModeCBC},
	"1.2.840.113549.1.5.6":  {kdfName: "PBKDF1-MD5", cipherName: "RC2-CBC", cipherPrimitive: cdx.CryptoPrimitiveBlockCipher, cipherMode: cdx.CryptoAlgorithmModeCBC},
	"1.2.840.113549.1.5.11": {kdfName: "PBKDF1-SHA1", cipherName: "RC2-CBC", cipherPrimitive: cdx.CryptoPrimitiveBlockCipher, cipherMode: cdx.CryptoAlgorithmModeCBC},

	// PKCS#12 Appendix B: the PKCS#12 KDF (always SHA1-based) with the named cipher. RC4 is a
	// stream cipher; the DES/RC2 variants are all block ciphers run in CBC mode.
	"1.2.840.113549.1.12.1.1": {kdfName: "PKCS#12 KDF-SHA1", cipherName: "RC4-128", cipherPrimitive: cdx.CryptoPrimitiveStreamCipher},
	"1.2.840.113549.1.12.1.2": {kdfName: "PKCS#12 KDF-SHA1", cipherName: "RC4-40", cipherPrimitive: cdx.CryptoPrimitiveStreamCipher},
	"1.2.840.113549.1.12.1.3": {kdfName: "PKCS#12 KDF-SHA1", cipherName: "DES-EDE3-CBC", cipherPrimitive: cdx.CryptoPrimitiveBlockCipher, cipherMode: cdx.CryptoAlgorithmModeCBC},
	"1.2.840.113549.1.12.1.4": {kdfName: "PKCS#12 KDF-SHA1", cipherName: "DES-EDE2-CBC", cipherPrimitive: cdx.CryptoPrimitiveBlockCipher, cipherMode: cdx.CryptoAlgorithmModeCBC},
	"1.2.840.113549.1.12.1.5": {kdfName: "PKCS#12 KDF-SHA1", cipherName: "RC2-128-CBC", cipherPrimitive: cdx.CryptoPrimitiveBlockCipher, cipherMode: cdx.CryptoAlgorithmModeCBC},
	"1.2.840.113549.1.12.1.6": {kdfName: "PKCS#12 KDF-SHA1", cipherName: "RC2-40-CBC", cipherPrimitive: cdx.CryptoPrimitiveBlockCipher, cipherMode: cdx.CryptoAlgorithmModeCBC},
}

// opensshCipherScheme names an OpenSSH "openssh-key-v1" ciphername (see cipher.c in
// openssh-portable) and its primitive/mode. Unlike PBES1/PBES2, OpenSSH's own key format already
// carries the cipher and KDF (bcrypt) as separate named fields, so no fused-scheme split is needed.
// parameterSetIdentifier and cryptoFunctions are only populated for AEAD ciphers, which have no
// block-cipher mode to record but do have other CycloneDX-modeled parameters worth capturing.
type opensshCipherScheme struct {
	name                   string
	primitive              cdx.CryptoPrimitive
	mode                   cdx.CryptoAlgorithmMode
	parameterSetIdentifier string
	cryptoFunctions        []cdx.CryptoFunction
}

var opensshCipherSchemes = map[string]opensshCipherScheme{
	// blowfish-cbc, cast128-cbc, rijndael-cbc@lysator.liu.se and the arcfour variants were removed
	// from OpenSSH's own cipher list well before this change, but keys generated by older OpenSSH
	// releases, or by other tools sharing this on-disk format, may still carry them. Key sizes below
	// are taken from OpenSSH's cipher.c ciphers[] table (key_len field, in bytes): blowfish-cbc=16,
	// cast128-cbc=16, rijndael-cbc@lysator.liu.se=32 (an alias for aes256-cbc, sharing its EVP cipher),
	// arcfour=16, arcfour128=16 (plus a 1536-byte keystream discard), arcfour256=32 (same discard).
	"blowfish-cbc":                {name: "Blowfish-128-CBC", primitive: cdx.CryptoPrimitiveBlockCipher, mode: cdx.CryptoAlgorithmModeCBC},
	"cast128-cbc":                 {name: "CAST-128-CBC", primitive: cdx.CryptoPrimitiveBlockCipher, mode: cdx.CryptoAlgorithmModeCBC},
	"rijndael-cbc@lysator.liu.se": {name: "AES-256-CBC", primitive: cdx.CryptoPrimitiveBlockCipher, mode: cdx.CryptoAlgorithmModeCBC},
	"arcfour":                     {name: "RC4-128", primitive: cdx.CryptoPrimitiveStreamCipher},
	"arcfour128":                  {name: "RC4-128", primitive: cdx.CryptoPrimitiveStreamCipher, parameterSetIdentifier: "1536-byte keystream discard"},
	"arcfour256":                  {name: "RC4-256", primitive: cdx.CryptoPrimitiveStreamCipher, parameterSetIdentifier: "1536-byte keystream discard"},
	"3des-cbc":                    {name: "DES-EDE3-CBC", primitive: cdx.CryptoPrimitiveBlockCipher, mode: cdx.CryptoAlgorithmModeCBC},
	"aes128-cbc":                  {name: "AES-128-CBC", primitive: cdx.CryptoPrimitiveBlockCipher, mode: cdx.CryptoAlgorithmModeCBC},
	"aes192-cbc":                  {name: "AES-192-CBC", primitive: cdx.CryptoPrimitiveBlockCipher, mode: cdx.CryptoAlgorithmModeCBC},
	"aes256-cbc":                  {name: "AES-256-CBC", primitive: cdx.CryptoPrimitiveBlockCipher, mode: cdx.CryptoAlgorithmModeCBC},
	"aes128-ctr":                  {name: "AES-128-CTR", primitive: cdx.CryptoPrimitiveBlockCipher, mode: cdx.CryptoAlgorithmModeCTR},
	"aes192-ctr":                  {name: "AES-192-CTR", primitive: cdx.CryptoPrimitiveBlockCipher, mode: cdx.CryptoAlgorithmModeCTR},
	"aes256-ctr":                  {name: "AES-256-CTR", primitive: cdx.CryptoPrimitiveBlockCipher, mode: cdx.CryptoAlgorithmModeCTR},
	// OpenSSH's cipher.c gives both GCM ciphers a 12-byte (96-bit) IV and 16-byte (128-bit) auth
	// tag. The 96-bit nonce's construction (a 4-byte fixed field plus an 8-byte per-packet
	// invocation counter, rather than a random nonce) is specified by RFC 5647 (AES-GCM for SSH),
	// not the C source itself.
	"aes128-gcm@openssh.com": {
		name:                   "AES-128-GCM",
		primitive:              cdx.CryptoPrimitiveBlockCipher,
		mode:                   cdx.CryptoAlgorithmModeGCM,
		parameterSetIdentifier: "96-bit nonce (RFC 5647: 4-byte fixed field + 8-byte invocation counter), 128-bit tag",
		cryptoFunctions:        []cdx.CryptoFunction{cdx.CryptoFunctionEncrypt, cdx.CryptoFunctionDecrypt, cdx.CryptoFunctionTag},
	},
	"aes256-gcm@openssh.com": {
		name:                   "AES-256-GCM",
		primitive:              cdx.CryptoPrimitiveBlockCipher,
		mode:                   cdx.CryptoAlgorithmModeGCM,
		parameterSetIdentifier: "96-bit nonce (RFC 5647: 4-byte fixed field + 8-byte invocation counter), 128-bit tag",
		cryptoFunctions:        []cdx.CryptoFunction{cdx.CryptoFunctionEncrypt, cdx.CryptoFunctionDecrypt, cdx.CryptoFunctionTag},
	},
	// OpenSSH's construction (cipher-chachapoly.c) splits a 512-bit key into two independent
	// 256-bit ChaCha20 subkeys: one encrypts the packet payload and generates the Poly1305 key,
	// the other separately encrypts the packet length field; the 64-bit packet sequence number is
	// used as the nonce for both, rather than a random or counter-based nonce. The 128-bit tag
	// covers the encrypted length field plus ciphertext.
	"chacha20-poly1305@openssh.com": {
		name:                   "ChaCha20-Poly1305",
		primitive:              cdx.CryptoPrimitiveAE,
		parameterSetIdentifier: "512-bit key (two 256-bit ChaCha20 subkeys: payload+MAC, length field), 64-bit sequence-number nonce, 128-bit tag",
		cryptoFunctions:        []cdx.CryptoFunction{cdx.CryptoFunctionEncrypt, cdx.CryptoFunctionDecrypt, cdx.CryptoFunctionTag},
	},
}

// opensshKeyMagic is the fixed header of the OpenSSH "openssh-key-v1" private key wire format. See
// https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.key.
const opensshKeyMagic = "openssh-key-v1\x00"

// opensshEncryptionComponents inspects the header of an OpenSSH "openssh-key-v1" private key
// (block.Bytes of an "OPENSSH PRIVATE KEY" PEM block) to identify its cipher and KDF. Unlike
// ssh.ParseRawPrivateKey, this only reads the plaintext header fields (ciphername, kdfname) that
// precede the encrypted key material, so it works without the passphrase.
func opensshEncryptionComponents(keyBytes []byte) []cdx.Component {
	if !bytes.HasPrefix(keyBytes, []byte(opensshKeyMagic)) {
		return encryptedPrivateKeyComponents("OpenSSH encrypted private key", cdx.CryptoPrimitiveUnknown, "")
	}

	var header struct {
		CipherName   string
		KdfName      string
		KdfOpts      string
		NumKeys      uint32
		PubKey       []byte
		PrivKeyBlock []byte
		Rest         []byte `ssh:"rest"`
	}
	if err := ssh.Unmarshal(keyBytes[len(opensshKeyMagic):], &header); err != nil {
		log.WithError(err).Debug("Could not parse OpenSSH private key header; recording as generic encrypted private key")
		return encryptedPrivateKeyComponents("OpenSSH encrypted private key", cdx.CryptoPrimitiveUnknown, "")
	}

	var cipherComponent cdx.Component
	if cipher, ok := opensshCipherSchemes[header.CipherName]; ok {
		cipherComponent = makeAlgorithmComponent(cipher.name, cipher.primitive, cipher.mode)
		if cipher.parameterSetIdentifier != "" {
			cipherComponent.CryptoProperties.AlgorithmProperties.ParameterSetIdentifier = cipher.parameterSetIdentifier
		}
		if len(cipher.cryptoFunctions) > 0 {
			cipherComponent.CryptoProperties.AlgorithmProperties.CryptoFunctions = &cipher.cryptoFunctions
		}
	} else {
		cipherComponent = makeAlgorithmComponent(header.CipherName, cdx.CryptoPrimitiveUnknown, "")
	}
	keyComponent := newEncryptedPrivateKeyComponent(cdx.BOMReference(cipherComponent.BOMRef))
	kdfComponent := makeAlgorithmComponent(header.KdfName, cdx.CryptoPrimitiveKDF, "")
	components := []cdx.Component{keyComponent, cipherComponent, kdfComponent}

	if pubKeyComponent, ok := opensshPublicKeyComponent(header.PubKey); ok {
		components = append(components, pubKeyComponent)
	}
	return components
}

// opensshPublicKeyComponent parses the plaintext public key blob embedded in an OpenSSH
// "openssh-key-v1" private key header (stored unencrypted specifically so implementations can
// identify the key type without a passphrase, per PROTOCOL.key) and builds a CBOM component
// describing the underlying asymmetric key algorithm. It returns ok=false if the blob can't be
// parsed or its key type isn't one key.GenerateCdxComponent knows how to describe.
func opensshPublicKeyComponent(pubKeyBytes []byte) (cdx.Component, bool) {
	sshPubKey, err := ssh.ParsePublicKey(pubKeyBytes)
	if err != nil {
		log.WithError(err).Debug("Could not parse OpenSSH public key header; omitting key type metadata")
		return cdx.Component{}, false
	}

	cryptoPubKey, ok := sshPubKey.(ssh.CryptoPublicKey)
	if !ok {
		return cdx.Component{}, false
	}

	rawPubKey := cryptoPubKey.CryptoPublicKey()
	if edPubKey, ok := rawPubKey.(ed25519.PublicKey); ok {
		rawPubKey = &edPubKey
	}

	component, err := key.GenerateCdxComponent(rawPubKey)
	if err != nil {
		log.WithError(err).Debug("Could not describe OpenSSH public key algorithm; omitting key type metadata")
		return cdx.Component{}, false
	}
	return *component, true
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
			if looksLikeEncryptedPKCS8(block.Bytes) {
				return pkcs8EncryptionComponents(block.Bytes), nil
			}
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
			if _, ok := err.(*ssh.PassphraseMissingError); ok {
				return opensshEncryptionComponents(block.Bytes), nil
			}
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
	primitive := cdx.CryptoPrimitiveUnknown
	var mode cdx.CryptoAlgorithmMode
	if dekInfo, ok := headers["DEK-Info"]; ok {
		if cipher, _, _ := strings.Cut(dekInfo, ","); cipher != "" {
			cipherName = cipher
			primitive = cdx.CryptoPrimitiveBlockCipher
			mode = cipherModeFromName(cipher)
		}
	}
	return encryptedPrivateKeyComponents(cipherName, primitive, mode), true
}

// cipherModeFromName infers a block-cipher mode from an OpenSSL DEK-Info cipher spec string (e.g.
// "AES-256-CBC", "DES-EDE3-CBC"). Unlike the OID-keyed lookups elsewhere in this file, DEK-Info
// values are arbitrary free text with no structured table to resolve them against, so this is the
// one place a substring match on the name is unavoidable. Unrecognized suffixes leave the mode unset.
func cipherModeFromName(name string) cdx.CryptoAlgorithmMode {
	upper := strings.ToUpper(name)
	switch {
	case strings.Contains(upper, "GCM"):
		return cdx.CryptoAlgorithmModeGCM
	case strings.Contains(upper, "CBC"):
		return cdx.CryptoAlgorithmModeCBC
	case strings.Contains(upper, "OFB"):
		return cdx.CryptoAlgorithmModeOFB
	case strings.Contains(upper, "CFB"):
		return cdx.CryptoAlgorithmModeCFB
	case strings.Contains(upper, "CTR"):
		return cdx.CryptoAlgorithmModeCTR
	case strings.Contains(upper, "ECB"):
		return cdx.CryptoAlgorithmModeECB
	}
	return ""
}

// pkcs8EncryptedPrivateKeyInfo mirrors PKCS8's EncryptedPrivateKeyInfo (RFC 5958 §3): SEQUENCE {
// encryptionAlgorithm AlgorithmIdentifier, encryptedData OCTET STRING }. Its first field is a
// SEQUENCE (AlgorithmIdentifier), unlike PrivateKeyInfo's first field, which is an INTEGER
// (version) — so successfully decoding into this shape is a reasonable signal that DER content is
// encrypted PKCS8, even when it arrived in a PEM block labeled "PRIVATE KEY" rather than
// "ENCRYPTED PRIVATE KEY" (some tools mislabel it this way).
type pkcs8EncryptedPrivateKeyInfo struct {
	Algorithm pkix.AlgorithmIdentifier
	Encrypted asn1.RawValue
}

// looksLikeEncryptedPKCS8 reports whether der decodes as pkcs8EncryptedPrivateKeyInfo, used to
// distinguish a mislabeled encrypted PKCS8 key from genuinely malformed key material before
// treating x509.ParsePKCS8PrivateKey's failure as encryption rather than corruption.
func looksLikeEncryptedPKCS8(der []byte) bool {
	var info pkcs8EncryptedPrivateKeyInfo
	_, err := asn1.Unmarshal(der, &info)
	return err == nil
}

// pkcs8EncryptionComponents inspects the outer EncryptedPrivateKeyInfo ASN.1 structure of a
// standard PKCS8 encrypted private key (whether from an "ENCRYPTED PRIVATE KEY" block, or a
// mislabeled "PRIVATE KEY" block that looksLikeEncryptedPKCS8 confirmed is actually encrypted) to
// identify the encryption scheme in use, and builds the encrypted-key component together with
// algorithm components describing it.
func pkcs8EncryptionComponents(der []byte) []cdx.Component {
	var info pkcs8EncryptedPrivateKeyInfo
	if _, err := asn1.Unmarshal(der, &info); err != nil {
		log.WithError(err).Debug("Could not parse EncryptedPrivateKeyInfo; recording as generic encrypted private key")
		return encryptedPrivateKeyComponents("PKCS#8 encrypted private key", cdx.CryptoPrimitiveUnknown, "")
	}

	oid := info.Algorithm.Algorithm.String()
	if scheme, ok := legacyPBESchemes[oid]; ok {
		return legacyPBEComponents(scheme)
	}

	name, ok := encryptionAlgorithmOIDNames[oid]
	if !ok {
		return encryptedPrivateKeyComponents(fmt.Sprintf("PKCS#8 encrypted private key (%s)", oid), cdx.CryptoPrimitiveUnknown, "")
	}
	if name != "PBES2" {
		//Defensive code,will not reach here for well formed input, it will protect from malformed input where the outer OID happens to collide with one of those inner-only OIDs.
		return encryptedPrivateKeyComponents(name, cdx.CryptoPrimitiveUnknown, "")
	}
	return pbes2EncryptionComponents(name, info.Algorithm.Parameters.FullBytes)
}

// legacyPBEComponents builds separate cipher and KDF algorithm components for a legacy
// (non-PBES2) password-based encryption scheme, mirroring how pbes2EncryptionComponents splits
// PBES2's own explicit cipher/KDF AlgorithmIdentifiers.
func legacyPBEComponents(scheme legacyPBEScheme) []cdx.Component {
	cipherComponent := makeAlgorithmComponent(scheme.cipherName, scheme.cipherPrimitive, scheme.cipherMode)
	keyComponent := newEncryptedPrivateKeyComponent(cdx.BOMReference(cipherComponent.BOMRef))
	kdfComponent := makeAlgorithmComponent(scheme.kdfName, cdx.CryptoPrimitiveKDF, "")
	return []cdx.Component{keyComponent, cipherComponent, kdfComponent}
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
		return encryptedPrivateKeyComponents(name, cdx.CryptoPrimitiveUnknown, "")
	}

	var cipherComponent cdx.Component
	if cipher, ok := pbes2CipherSchemes[scheme.Cipher.Algorithm.String()]; ok {
		cipherComponent = makeAlgorithmComponent(cipher.name, cdx.CryptoPrimitiveBlockCipher, cipher.mode)
	} else {
		cipherComponent = makeAlgorithmComponent(scheme.Cipher.Algorithm.String(), cdx.CryptoPrimitiveUnknown, "")
	}
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
		return makeAlgorithmComponent(kdfName, cdx.CryptoPrimitiveKDF, "")
	}

	var kdf pbkdf2Params
	if _, err := asn1.Unmarshal(kdfAlg.Parameters.FullBytes, &kdf); err != nil {
		log.WithError(err).Debug("Could not parse PBKDF2-params; omitting PRF from KDF component name")
		return makeAlgorithmComponent(kdfName, cdx.CryptoPrimitiveKDF, "")
	}
	prfName := "HMAC-SHA1" // RFC 8018 default when the prf field is omitted
	if len(kdf.PRF.Algorithm) > 0 {
		prfName = oidName(kdf.PRF.Algorithm)
	}
	return makeAlgorithmComponent(fmt.Sprintf("%s-%s", kdfName, prfName), cdx.CryptoPrimitiveKDF, "")
}

// encryptedPrivateKeyComponents builds the encrypted-key component together with a single
// algorithm component for a resolved cipher name, or a placeholder name (tagged
// CryptoPrimitiveUnknown) for the cases where the scheme couldn't be identified or parsed at all.
func encryptedPrivateKeyComponents(cipherName string, primitive cdx.CryptoPrimitive, mode cdx.CryptoAlgorithmMode) []cdx.Component {
	cipherComponent := makeAlgorithmComponent(cipherName, primitive, mode)
	keyComponent := newEncryptedPrivateKeyComponent(cdx.BOMReference(cipherComponent.BOMRef))
	return []cdx.Component{keyComponent, cipherComponent}
}

// makeAlgorithmComponent builds a standalone cryptographic-asset "algorithm" component for a
// resolved algorithm name and mode (mode may be empty when not applicable), with its own
// generated BOMRef so other components can reference it via an *Ref field.
func makeAlgorithmComponent(name string, primitive cdx.CryptoPrimitive, mode cdx.CryptoAlgorithmMode) cdx.Component {
	comp := cdx.Component{
		Name:   name,
		Type:   cdx.ComponentTypeCryptographicAsset,
		BOMRef: uuid.New().String(),
		CryptoProperties: &cdx.CryptoProperties{
			AssetType:           cdx.CryptoAssetTypeAlgorithm,
			AlgorithmProperties: &cdx.CryptoAlgorithmProperties{Primitive: primitive},
		},
	}
	if mode != "" {
		comp.CryptoProperties.AlgorithmProperties.Mode = mode
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
		Name:   "encrypted-private-key",
		Type:   cdx.ComponentTypeCryptographicAsset,
		BOMRef: uuid.New().String(),
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
