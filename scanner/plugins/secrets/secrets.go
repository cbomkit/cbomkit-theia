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

package secrets

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"regexp"
	"strings"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"

	"github.com/cbomkit/cbomkit-theia/provider/filesystem"
	"github.com/cbomkit/cbomkit-theia/scanner/key"
	"github.com/cbomkit/cbomkit-theia/scanner/pem"
	"github.com/cbomkit/cbomkit-theia/scanner/plugins"
	"github.com/cbomkit/cbomkit-theia/scanner/x509"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/detect"
	"github.com/zricethezav/gitleaks/v8/report"
)

// extendedGitleaksConfig is gitleaks' built-in default ruleset (via `[extend] useDefault = true`)
// plus cbomkit-theia's own additional path-only rules (e.g. flagging bare public-key/cert files
// that the default ruleset's "private-key" rule doesn't cover).
//
//go:embed gitleaks.toml
var extendedGitleaksConfig string

// newDetector builds a gitleaks detector from extendedGitleaksConfig. This mirrors
// detect.NewDetectorDefaultConfig, which does the same thing but with gitleaks' bare default
// config string instead of our extended one.
func newDetector() (*detect.Detector, error) {
	viper.SetConfigType("toml")
	if err := viper.ReadConfig(strings.NewReader(extendedGitleaksConfig)); err != nil {
		return nil, err
	}
	var vc config.ViperConfig
	if err := viper.Unmarshal(&vc); err != nil {
		return nil, err
	}
	cfg, err := vc.Translate()
	if err != nil {
		return nil, err
	}
	return detect.NewDetector(cfg), nil
}

// pathFallbackRuleContentCounterparts maps the rule ID of a path-only fallback rule (which
// flags a file by extension alone, catching raw-DER key material with no PEM text markers) to
// the content-based rule ID(s) that supersede it whenever the same file also matches on content.
var pathFallbackRuleContentCounterparts = map[string][]string{
	"public-key-file": {"pem-public-key", "openssh-public-key", "ssh2-public-key"},
	"csr-file":        {"pem-csr"},
}

func NewSecretsPlugin() (plugins.Plugin, error) {
	return &Plugin{}, nil
}

type Plugin struct{}

func (*Plugin) GetName() string {
	return "Secret Detection Plugin"
}

func (*Plugin) GetExplanation() string {
	return "Find Secrets & Keys"
}

func (*Plugin) GetType() plugins.PluginType {
	return plugins.PluginTypeAppend
}

type findingWithMetadata struct {
	report.Finding
	raw []byte
}

func (*Plugin) UpdateBOM(fs filesystem.Filesystem, bom *cdx.BOM) error {
	detector, err := newDetector()
	if err != nil {
		return err
	}
	// Detect findings
	components := make([]cdx.Component, 0)
	if err := fs.WalkDir(func(path string) error {
		// Skip large files
		maxFileSize := viper.GetInt64("keys.max_file_size")
		if maxFileSize <= 0 {
			maxFileSize = 1024 * 1024 // Default to 1MB
		}

		readCloser, err := fs.Open(path)
		if err != nil {
			return nil // skip and continue
		}
		defer readCloser.Close()

		limitReader := io.LimitReader(readCloser, maxFileSize+1)
		content, err := io.ReadAll(limitReader)
		if err != nil {
			log.WithField("path", path).Warn("Unable to read file")
			return nil
		}

		// Skip large files
		if int64(len(content)) > maxFileSize {
			log.Warnf("Skipping large file: %s (exceeds limit of %d bytes)", path, maxFileSize)
			return nil
		}

		fragment := detect.Fragment{Raw: string(content), FilePath: path}
		findings := detector.Detect(fragment)

		// A path-only fallback rule (e.g. "csr-file") and its content-based counterpart
		// (e.g. "pem-csr") can both match the same file - the fallback exists only to catch
		// raw-DER files the content regex can't see. When the content rule also matched, skip
		// the fallback's finding so it doesn't add a redundant generic-secret component.
		matchedRuleIDs := make(map[string]bool, len(findings))
		for _, finding := range findings {
			matchedRuleIDs[finding.RuleID] = true
		}

		for _, finding := range findings {
			if contentRuleIDs, ok := pathFallbackRuleContentCounterparts[finding.RuleID]; ok {
				superseded := false
				for _, contentRuleID := range contentRuleIDs {
					if matchedRuleIDs[contentRuleID] {
						superseded = true
						break
					}
				}
				if superseded {
					continue
				}
			}

			findingMeta := findingWithMetadata{
				Finding: finding,
				raw:     content,
			}
			log.WithFields(log.Fields{
				"type": finding.RuleID, "file": finding.File,
			}).Info("Secret detected")

			// Create CDX Components
			currentComponents, err := findingMeta.getComponents()
			if err != nil {
				log.WithError(err).Warn("Could not add secret finding to BOM component")
				continue
			}
			components = append(components, currentComponents...)
		}
		return nil
	}); err != nil {
		log.WithError(err).Error("Error while trying to scan for secrets")
		return err
	}

	if len(components) == 0 {
		log.Info("No secrets found.")
		return nil
	}

	// Write  bom
	*bom.Components = append(*bom.Components, components...)
	return nil
}

func (finding findingWithMetadata) getComponents() ([]cdx.Component, error) {
	switch finding.RuleID {
	case "private-key":
		return finding.getPrivateKeyComponent()
	case "pem-public-key":
		return finding.getPEMPublicKeyComponent()
	case "pem-csr":
		return finding.getCSRComponent()
	case "openssh-public-key":
		return finding.getOpenSSHPublicKeyComponent()
	case "ssh2-public-key":
		return finding.getSSH2PublicKeyComponent()
	case "pgp-public-key":
		return finding.getPGPPublicKeyComponent()
	case "wireguard-public-key":
		return finding.getWireGuardPublicKeyComponent()
	case "wireguard-private-key":
		return finding.getWireGuardPrivateKeyComponent()
	case "jwk":
		return finding.getJWKComponent()
	}
	return []cdx.Component{finding.getGenericSecretComponent()}, nil
}

// annotateComponents appends finding's description onto each component's existing description
// (joined by ";", or set outright if the component has none) and attaches an Evidence occurrence
// pointing at finding's location. Used to tag every component derived from a single finding.
func (finding findingWithMetadata) annotateComponents(components []cdx.Component) {
	for i := range components {
		if description := components[i].Description; description != "" {
			components[i].Description = strings.Join([]string{description, finding.Description}, ";")
		} else {
			components[i].Description = finding.Description
		}
		components[i].Evidence = &cdx.Evidence{
			Occurrences: &[]cdx.EvidenceOccurrence{
				{
					Location: finding.File,
					Line:     &finding.StartLine,
				},
			},
		}
	}
}

func (finding findingWithMetadata) getPrivateKeyComponent() ([]cdx.Component, error) {
	// Filter for private keys only
	privateKeyFilter := pem.Filter{
		FilterType: pem.TypeAllowlist,
		List: []pem.BlockType{
			pem.BlockTypePrivateKey,
			pem.BlockTypeEncryptedPrivateKey,
			pem.BlockTypeRSAPrivateKey,
			pem.BlockTypeECPrivateKey,
			pem.BlockTypeDSAPrivateKey,
			pem.BlockTypeOPENSSHPrivateKey,
		},
	}

	// Parse PEM blocks
	blocks := pem.ParsePEMToBlocksWithTypeFilter(finding.raw, privateKeyFilter)
	if len(blocks) == 0 {
		return []cdx.Component{finding.getGenericSecretComponent()}, nil
	}

	log.Infof("Found %d private key(s) in %s", len(blocks), finding.File)

	components := make([]cdx.Component, 0)
	for block := range blocks {
		currentComponents, err := pem.GenerateCdxComponents(block)
		if err != nil {
			// The PEM block is a recognized private-key type (e.g. encrypted, or otherwise
			// undecodable), but its contents could not be parsed into key material. Still
			// record it as a generic secret rather than dropping a confirmed finding.
			log.WithError(err).WithField("path", finding.File).Warn("Found private key PEM block but could not parse its key material; recording as generic secret")
			components = append(components, finding.getGenericSecretComponent())
			continue
		}

		finding.annotateComponents(currentComponents)
		components = append(components, currentComponents...)
	}
	return components, nil
}

func (finding findingWithMetadata) getCSRComponent() ([]cdx.Component, error) {
	// Filter for certificate signing requests only
	csrFilter := pem.Filter{
		FilterType: pem.TypeAllowlist,
		List: []pem.BlockType{
			pem.BlockTypeCertificateRequest,
			pem.BlockTypeLegacyCertificateRequest,
		},
	}

	blocks := pem.ParsePEMToBlocksWithTypeFilter(finding.raw, csrFilter)
	if len(blocks) == 0 {
		return []cdx.Component{finding.getGenericSecretComponent()}, nil
	}

	log.Infof("Found %d certificate signing request(s) in %s", len(blocks), finding.File)

	components := make([]cdx.Component, 0)
	for block := range blocks {
		currentComponents, err := pem.GenerateCdxComponents(block)
		if err != nil {
			log.WithError(err).WithField("path", finding.File).Warn("Found CSR PEM block but could not parse it; recording as generic secret")
			components = append(components, finding.getGenericSecretComponent())
			continue
		}

		finding.annotateComponents(currentComponents)
		components = append(components, currentComponents...)
	}
	return components, nil
}

func (finding findingWithMetadata) getPEMPublicKeyComponent() ([]cdx.Component, error) {
	// Filter for public keys only
	publicKeyFilter := pem.Filter{
		FilterType: pem.TypeAllowlist,
		List: []pem.BlockType{
			pem.BlockTypePublicKey,
			pem.BlockTypeRSAPublicKey,
		},
	}

	// Parse PEM blocks
	blocks := pem.ParsePEMToBlocksWithTypeFilter(finding.raw, publicKeyFilter)
	if len(blocks) == 0 {
		return []cdx.Component{finding.getGenericSecretComponent()}, nil
	}

	log.Infof("Found %d public key(s) in %s", len(blocks), finding.File)

	components := make([]cdx.Component, 0)
	for block := range blocks {
		currentComponents, err := pem.GenerateCdxComponents(block)
		if err != nil {
			// The PEM block is a recognized public-key type, but its contents could not be
			// parsed into key material. Still record it as a generic secret rather than
			// dropping a confirmed finding.
			log.WithError(err).WithField("path", finding.File).Warn("Found public key PEM block but could not parse its key material; recording as generic secret")
			components = append(components, finding.getGenericSecretComponent())
			continue
		}

		finding.annotateComponents(currentComponents)
		components = append(components, currentComponents...)
	}
	return components, nil
}

func (finding findingWithMetadata) getOpenSSHPublicKeyComponent() ([]cdx.Component, error) {
	components := pem.ParseOpenSSHAuthorizedKeyComponents(finding.raw)
	if len(components) == 0 {
		return []cdx.Component{finding.getGenericSecretComponent()}, nil
	}

	log.Infof("Found %d OpenSSH public key(s) in %s", len(components), finding.File)

	finding.annotateComponents(components)
	return components, nil
}

func (finding findingWithMetadata) getSSH2PublicKeyComponent() ([]cdx.Component, error) {
	components := pem.ParseSSH2PublicKeyComponents(finding.raw)
	if len(components) == 0 {
		return []cdx.Component{finding.getGenericSecretComponent()}, nil
	}

	log.Infof("Found %d SSH2 public key(s) in %s", len(components), finding.File)

	finding.annotateComponents(components)
	return components, nil
}

// wireguardPublicKeyRegexp captures the base64-encoded Curve25519 key from a WireGuard config
// "PublicKey = ..." line. WireGuard public and private keys are structurally identical raw
// 32-byte X25519 keys, so only the "PublicKey" label (as opposed to "PrivateKey") distinguishes
// them - matching on the label is required, not optional.
var wireguardPublicKeyRegexp = regexp.MustCompile(`(?i)PublicKey\s*=\s*([A-Za-z0-9+/]{43}=)`)

// wireguardPrivateKeyRegexp is the "PrivateKey" counterpart to wireguardPublicKeyRegexp - same
// raw 32-byte X25519 key shape, distinguished only by the "PrivateKey" label.
var wireguardPrivateKeyRegexp = regexp.MustCompile(`(?i)PrivateKey\s*=\s*([A-Za-z0-9+/]{43}=)`)

func (finding findingWithMetadata) getPGPPublicKeyComponent() ([]cdx.Component, error) {
	components := parsePGPPublicKeyComponents(finding.raw)
	if len(components) == 0 {
		return []cdx.Component{finding.getGenericSecretComponent()}, nil
	}

	log.Infof("Found %d OpenPGP public key(s) in %s", len(components), finding.File)

	finding.annotateComponents(components)
	return components, nil
}

// parsePGPPublicKeyComponents parses a single ASCII-armored OpenPGP public key block (as
// produced by e.g. `gpg --export --armor`) and builds a component per primary/subkey it can
// describe. Keys using algorithms unsupported by golang.org/x/crypto/openpgp (e.g. modern
// EdDSA/Ed25519 primary keys) are silently skipped rather than failing the whole keyring.
func parsePGPPublicKeyComponents(raw []byte) []cdx.Component {
	block, err := armor.Decode(bytes.NewReader(raw))
	if err != nil || block.Type != openpgp.PublicKeyType {
		return nil
	}

	entityList, err := openpgp.ReadKeyRing(block.Body)
	if err != nil {
		return nil
	}

	components := make([]cdx.Component, 0)
	for _, entity := range entityList {
		if entity.PrimaryKey != nil {
			if component, err := key.GenerateCdxComponent(entity.PrimaryKey.PublicKey); err == nil {
				components = append(components, *component)
			}
		}
		for _, subkey := range entity.Subkeys {
			if subkey.PublicKey == nil {
				continue
			}
			if component, err := key.GenerateCdxComponent(subkey.PublicKey.PublicKey); err == nil {
				components = append(components, *component)
			}
		}
	}
	return components
}

func (finding findingWithMetadata) getWireGuardPublicKeyComponent() ([]cdx.Component, error) {
	matches := wireguardPublicKeyRegexp.FindAllStringSubmatch(string(finding.raw), -1)

	components := make([]cdx.Component, 0, len(matches))
	for _, match := range matches {
		keyBytes, err := base64.StdEncoding.DecodeString(match[1])
		if err != nil || len(keyBytes) != 32 {
			continue
		}
		pubKey, err := ecdh.X25519().NewPublicKey(keyBytes)
		if err != nil {
			continue
		}
		component, err := key.GenerateCdxComponent(pubKey)
		if err != nil {
			continue
		}
		components = append(components, *component)
	}

	if len(components) == 0 {
		return []cdx.Component{finding.getGenericSecretComponent()}, nil
	}

	finding.annotateComponents(components)
	log.Infof("Found %d WireGuard public key(s) in %s", len(components), finding.File)
	return components, nil
}

func (finding findingWithMetadata) getWireGuardPrivateKeyComponent() ([]cdx.Component, error) {
	matches := wireguardPrivateKeyRegexp.FindAllStringSubmatch(string(finding.raw), -1)

	components := make([]cdx.Component, 0, len(matches))
	for _, match := range matches {
		keyBytes, err := base64.StdEncoding.DecodeString(match[1])
		if err != nil || len(keyBytes) != 32 {
			continue
		}
		privKey, err := ecdh.X25519().NewPrivateKey(keyBytes)
		if err != nil {
			continue
		}
		component, err := key.GenerateCdxComponent(privKey)
		if err != nil {
			continue
		}
		components = append(components, *component)
	}

	if len(components) == 0 {
		return []cdx.Component{finding.getGenericSecretComponent()}, nil
	}

	finding.annotateComponents(components)
	log.Infof("Found %d WireGuard private key(s) in %s", len(components), finding.File)
	return components, nil
}

// jwk covers the RFC 7517 JSON Web Key fields needed to reconstruct a Go key for the algorithms
// key.GenerateCdxComponent knows how to describe (RSA, EC P-256/P-384/P-521, OKP Ed25519/X25519),
// plus "oct" symmetric keys (reported directly as secret-key material, since
// key.GenerateCdxComponent has no notion of a raw symmetric key), and the common parameters
// (section 4) that describe the key rather than form part of it.
type jwk struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	N   string `json:"n"`
	E   string `json:"e"`
	X   string `json:"x"`
	Y   string `json:"y"`
	D   string `json:"d"`
	K   string `json:"k"`

	Use     string   `json:"use"`
	KeyOps  []string `json:"key_ops"`
	Alg     string   `json:"alg"`
	Kid     string   `json:"kid"`
	X5u     string   `json:"x5u"`
	X5c     []string `json:"x5c"`
	X5t     string   `json:"x5t"`
	X5tS256 string   `json:"x5t#S256"`
}

type jwkSet struct {
	Keys []jwk `json:"keys"`
}

// isPrivate reports whether k carries private key material ("d", per RFC 7517 sections 6.2/6.3)
// rather than only a public key. A JWK with "d" set describes a private key even though its
// kty ("RSA"/"EC"/"OKP") is shared with the public-key form.
func (k jwk) isPrivate() bool {
	return k.D != ""
}

func (finding findingWithMetadata) getJWKComponent() ([]cdx.Component, error) {
	components := make([]cdx.Component, 0)
	for _, k := range parseJWKs(finding.raw) {
		var component cdx.Component
		if k.Kty == "oct" {
			c, err := k.toSecretKeyComponent()
			if err != nil {
				log.WithError(err).WithField("path", finding.File).Debug("Could not parse JWK symmetric key")
				continue
			}
			component = c
		} else {
			parsedKey, err := k.toKey()
			if err != nil {
				log.WithError(err).WithField("path", finding.File).Debug("Could not parse JWK key")
				continue
			}
			c, err := key.GenerateCdxComponent(parsedKey)
			if err != nil {
				continue
			}
			component = *c
		}

		k.annotateCommonParams(&component)
		components = append(components, component)
		components = append(components, k.x5cComponents(finding.File)...)
	}

	if len(components) == 0 {
		return []cdx.Component{finding.getGenericSecretComponent()}, nil
	}

	finding.annotateComponents(components)
	log.Infof("Found %d JWK key(s) in %s", len(components), finding.File)
	return components, nil
}

// parseJWKs parses raw as either a single JWK object or a JWK Set ({"keys": [...]}). It returns
// nil if raw is neither (e.g. the match was inside a larger, unrelated JSON document).
func parseJWKs(raw []byte) []jwk {
	var set jwkSet
	if err := json.Unmarshal(raw, &set); err == nil && len(set.Keys) > 0 {
		return set.Keys
	}

	var single jwk
	if err := json.Unmarshal(raw, &single); err == nil && single.Kty != "" {
		return []jwk{single}
	}
	return nil
}

// toKey reconstructs the Go key described by a JWK's base64url-encoded fields, returning a
// private key type (compatible with key.GenerateCdxComponent) when k carries private key
// material, and a public key type otherwise.
func (k jwk) toKey() (any, error) {
	switch k.Kty {
	case "RSA":
		n, err := base64.RawURLEncoding.DecodeString(k.N)
		if err != nil {
			return nil, err
		}
		e, err := base64.RawURLEncoding.DecodeString(k.E)
		if err != nil {
			return nil, err
		}
		pub := rsa.PublicKey{
			N: new(big.Int).SetBytes(n),
			E: int(new(big.Int).SetBytes(e).Int64()),
		}
		if !k.isPrivate() {
			return &pub, nil
		}
		d, err := base64.RawURLEncoding.DecodeString(k.D)
		if err != nil {
			return nil, err
		}
		return &rsa.PrivateKey{PublicKey: pub, D: new(big.Int).SetBytes(d)}, nil
	case "EC":
		var curve elliptic.Curve
		switch k.Crv {
		case "P-256":
			curve = elliptic.P256()
		case "P-384":
			curve = elliptic.P384()
		case "P-521":
			curve = elliptic.P521()
		default:
			return nil, fmt.Errorf("unsupported EC curve: %s", k.Crv)
		}
		x, err := base64.RawURLEncoding.DecodeString(k.X)
		if err != nil {
			return nil, err
		}
		y, err := base64.RawURLEncoding.DecodeString(k.Y)
		if err != nil {
			return nil, err
		}
		pub := ecdsa.PublicKey{Curve: curve, X: new(big.Int).SetBytes(x), Y: new(big.Int).SetBytes(y)}
		if !k.isPrivate() {
			return &pub, nil
		}
		d, err := base64.RawURLEncoding.DecodeString(k.D)
		if err != nil {
			return nil, err
		}
		return &ecdsa.PrivateKey{PublicKey: pub, D: new(big.Int).SetBytes(d)}, nil
	case "OKP":
		x, err := base64.RawURLEncoding.DecodeString(k.X)
		if err != nil {
			return nil, err
		}
		switch k.Crv {
		case "Ed25519":
			if !k.isPrivate() {
				pub := ed25519.PublicKey(x)
				return &pub, nil
			}
			d, err := base64.RawURLEncoding.DecodeString(k.D)
			if err != nil {
				return nil, err
			}
			// JWK stores only the 32-byte Ed25519 seed in "d"; Go's ed25519.PrivateKey is the
			// 64-byte seed||publicKey expanded form.
			priv := make([]byte, 0, len(d)+len(x))
			priv = append(priv, d...)
			priv = append(priv, x...)
			return ed25519.PrivateKey(priv), nil
		case "X25519":
			if !k.isPrivate() {
				return ecdh.X25519().NewPublicKey(x)
			}
			d, err := base64.RawURLEncoding.DecodeString(k.D)
			if err != nil {
				return nil, err
			}
			return ecdh.X25519().NewPrivateKey(d)
		default:
			return nil, fmt.Errorf("unsupported OKP curve: %s", k.Crv)
		}
	default:
		return nil, fmt.Errorf("unsupported JWK key type: %s", k.Kty)
	}
}

// toSecretKeyComponent builds a component for an "oct" (symmetric) JWK, whose raw key bytes
// live in "k". key.GenerateCdxComponent has no case for a bare symmetric key, so this is built
// directly rather than routed through it.
func (k jwk) toSecretKeyComponent() (cdx.Component, error) {
	raw, err := base64.RawURLEncoding.DecodeString(k.K)
	if err != nil {
		return cdx.Component{}, err
	}

	size := len(raw) * 8
	return cdx.Component{
		Name: fmt.Sprintf("oct-%d", size),
		Type: cdx.ComponentTypeCryptographicAsset,
		CryptoProperties: &cdx.CryptoProperties{
			AssetType: cdx.CryptoAssetTypeRelatedCryptoMaterial,
			RelatedCryptoMaterialProperties: &cdx.RelatedCryptoMaterialProperties{
				Type: cdx.RelatedCryptoMaterialTypeSecretKey,
				Size: &size,
			},
		},
	}, nil
}

// annotateCommonParams sets the CDX fields that correspond to the RFC 7517 JWK common parameters
// (section 4) describing the key rather than forming part of it: "kid" becomes the related-crypto-
// material ID, "x5t"/"x5t#S256" become its fingerprint (SHA-256 preferred when both are present),
// and "use"/"key_ops"/"alg"/"x5u" become generic properties, since CycloneDX has no dedicated
// field for them. A no-op if component has no RelatedCryptoMaterialProperties to annotate (e.g.
// a key type toKey/toSecretKeyComponent could not build).
func (k jwk) annotateCommonParams(component *cdx.Component) {
	if component.CryptoProperties == nil || component.CryptoProperties.RelatedCryptoMaterialProperties == nil {
		return
	}
	related := component.CryptoProperties.RelatedCryptoMaterialProperties

	if k.Kid != "" {
		related.ID = k.Kid
	}
	if fingerprint := k.fingerprint(); fingerprint != nil {
		related.Fingerprint = fingerprint
	}

	properties := make([]cdx.Property, 0, 4)
	if k.Use != "" {
		properties = append(properties, cdx.Property{Name: "jwk:use", Value: k.Use})
	}
	if len(k.KeyOps) > 0 {
		properties = append(properties, cdx.Property{Name: "jwk:key_ops", Value: strings.Join(k.KeyOps, ",")})
	}
	if k.Alg != "" {
		properties = append(properties, cdx.Property{Name: "jwk:alg", Value: k.Alg})
	}
	if k.X5u != "" {
		properties = append(properties, cdx.Property{Name: "jwk:x5u", Value: k.X5u})
	}
	if len(properties) > 0 {
		component.Properties = &properties
	}
}

// fingerprint decodes the JWK's "x5t#S256" (preferred) or "x5t" certificate thumbprint -
// base64url-encoded per RFC 7517 sections 4.8/4.9 - into a CDX Hash.
func (k jwk) fingerprint() *cdx.Hash {
	if k.X5tS256 != "" {
		if raw, err := base64.RawURLEncoding.DecodeString(k.X5tS256); err == nil {
			return &cdx.Hash{Algorithm: cdx.HashAlgoSHA256, Value: hex.EncodeToString(raw)}
		}
	}
	if k.X5t != "" {
		if raw, err := base64.RawURLEncoding.DecodeString(k.X5t); err == nil {
			return &cdx.Hash{Algorithm: cdx.HashAlgoSHA1, Value: hex.EncodeToString(raw)}
		}
	}
	return nil
}

// x5cComponents parses each certificate in the JWK's "x5c" chain - base64-encoded (not
// base64url-encoded) DER, per RFC 7517 section 4.7 - and builds the same certificate/public-key/
// algorithm component graph the certificates plugin builds for PEM/DER certificate files.
func (k jwk) x5cComponents(path string) []cdx.Component {
	components := make([]cdx.Component, 0, len(k.X5c))
	for _, encoded := range k.X5c {
		der, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			log.WithError(err).WithField("path", path).Debug("Could not decode JWK x5c certificate")
			continue
		}
		certs, err := x509.ParseCertificatesToX509CertificateWithMetadata(der, path)
		if err != nil {
			log.WithError(err).WithField("path", path).Debug("Could not parse JWK x5c certificate")
			continue
		}
		for _, cert := range certs {
			certComponents, _, err := x509.GenerateCdxComponents(cert)
			if err != nil {
				log.WithError(err).WithField("path", path).Debug("Could not generate CDX components for JWK x5c certificate")
				continue
			}
			components = append(components, *certComponents...)
		}
	}
	return components
}

func (finding findingWithMetadata) getGenericSecretComponent() cdx.Component {
	return cdx.Component{
		Name:        finding.RuleID,
		Description: finding.Description,
		Type:        cdx.ComponentTypeCryptographicAsset,
		CryptoProperties: &cdx.CryptoProperties{
			AssetType: cdx.CryptoAssetTypeRelatedCryptoMaterial,
			RelatedCryptoMaterialProperties: &cdx.RelatedCryptoMaterialProperties{
				Type: getRelatedCryptoAssetTypeFromRuleID(finding.RuleID),
			},
		},
		Evidence: &cdx.Evidence{
			Occurrences: &[]cdx.EvidenceOccurrence{
				{
					Location: finding.File,
					Line:     &finding.StartLine,
				},
			},
		},
	}
}

func getRelatedCryptoAssetTypeFromRuleID(id string) cdx.RelatedCryptoMaterialType {
	switch {
	case strings.Contains(id, "private-key"):
		return cdx.RelatedCryptoMaterialTypePrivateKey
	case strings.Contains(id, "token") ||
		strings.Contains(id, "jwt"):
		return cdx.RelatedCryptoMaterialTypeToken
	case strings.Contains(id, "key") || id == "jwk":
		return cdx.RelatedCryptoMaterialTypeKey
	case strings.Contains(id, "password"):
		return cdx.RelatedCryptoMaterialTypePassword
	default:
		return cdx.RelatedCryptoMaterialTypeUnknown
	}
}
