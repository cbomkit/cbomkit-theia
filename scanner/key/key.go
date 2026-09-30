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

package key

import (
	"crypto/dsa"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"fmt"
	"math/big"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/cbomkit/cbomkit-theia/scanner/errors"
	"github.com/google/uuid"
)

func GenerateCdxComponents(keys []any) ([]cdx.Component, error) {
	components := make([]cdx.Component, 0)
	for _, key := range keys {
		component, err := GenerateCdxComponent(key)
		if err != nil {
			return nil, err
		}
		components = append(components, *component)
	}
	return components, nil
}

func GenerateCdxComponent(key any) (*cdx.Component, error) {
	switch key := key.(type) {
	case *rsa.PublicKey:
		return getRSAPublicKeyComponent(key), nil
	case *dsa.PublicKey:
		return getDSAPublicKeyComponent(key), nil
	case *dsa.PrivateKey:
		return getDSAPrivateKeyComponent(key), nil
	case *ecdsa.PublicKey:
		return getECDSAPublicKeyComponent(key), nil
	case *ed25519.PublicKey:
		return getED25519PublicKeyComponent(key), nil
	case *ecdh.PublicKey:
		return getECDHPublicKeyComponent(key), nil
	case *rsa.PrivateKey:
		return getRSAPrivateKeyComponent(key), nil
	case *ecdsa.PrivateKey:
		return getECDSAPrivateKeyComponent(key), nil
	case ed25519.PrivateKey:
		return getED25519PrivateKeyComponent(), nil
	case *ecdh.PrivateKey:
		return getECDHPrivateKeyComponent(), nil
	default:
		return nil, errors.ErrUnknownKeyAlgorithm
	}
}

func getGenericKeyComponent() *cdx.Component {
	return &cdx.Component{
		Type:   cdx.ComponentTypeCryptographicAsset,
		BOMRef: uuid.New().String(),
		CryptoProperties: &cdx.CryptoProperties{
			AssetType: cdx.CryptoAssetTypeRelatedCryptoMaterial,
			RelatedCryptoMaterialProperties: &cdx.RelatedCryptoMaterialProperties{
				Type:   cdx.RelatedCryptoMaterialTypeKey,
				Format: "PEM",
			},
		},
	}
}

func getGenericPublicKeyComponent() *cdx.Component {
	c := getGenericKeyComponent()
	c.CryptoProperties.RelatedCryptoMaterialProperties.Type = cdx.RelatedCryptoMaterialTypePublicKey
	return c
}

func getGenericPrivateKeyComponent() *cdx.Component {
	c := getGenericKeyComponent()
	c.CryptoProperties.RelatedCryptoMaterialProperties.Type = cdx.RelatedCryptoMaterialTypePrivateKey
	return c
}

func getRSAPublicKeyComponent(key *rsa.PublicKey) *cdx.Component {
	c := getGenericPublicKeyComponent()
	size := key.Size() * 8 // byte
	c.Name = fmt.Sprintf("RSA-%v", size)
	c.CryptoProperties.RelatedCryptoMaterialProperties.Size = &size
	c.CryptoProperties.OID = "1.2.840.113549.1.1.1"
	keyValue, err := x509.MarshalPKIXPublicKey(key)
	if err == nil {
		c.CryptoProperties.RelatedCryptoMaterialProperties.Value = base64.StdEncoding.EncodeToString(keyValue)
	}
	return c
}

func getRSAPrivateKeyComponent(key *rsa.PrivateKey) *cdx.Component {
	c := getGenericPrivateKeyComponent()
	c.Name = "RSA"
	size := key.PublicKey.Size() * 8 // byte
	c.Name = fmt.Sprintf("RSA-%v", size)
	c.CryptoProperties.RelatedCryptoMaterialProperties.Size = &size
	c.CryptoProperties.OID = "1.2.840.113549.1.1.1"
	return c
}

func getECDSAPublicKeyComponent(key *ecdsa.PublicKey) *cdx.Component {
	c := getGenericPublicKeyComponent()
	c.Name = "ECDSA"
	c.CryptoProperties.OID = "1.2.840.10045.2.1"
	keyValue, err := x509.MarshalPKIXPublicKey(key)
	if err == nil {
		c.CryptoProperties.RelatedCryptoMaterialProperties.Value = base64.StdEncoding.EncodeToString(keyValue)
	}
	return c
}

func getECDSAPrivateKeyComponent(key *ecdsa.PrivateKey) *cdx.Component {
	c := getGenericPrivateKeyComponent()
	c.Name = "ECDSA"
	c.Description = fmt.Sprintf("Curve: %v", key.Curve.Params().Name)
	return c
}

func getED25519PublicKeyComponent(key *ed25519.PublicKey) *cdx.Component {
	c := getGenericPublicKeyComponent()
	c.Name = "ED25519"
	size := len([]byte(*key)) * 8
	c.CryptoProperties.RelatedCryptoMaterialProperties.Size = &size
	keyValue, err := x509.MarshalPKIXPublicKey(key)
	if err == nil {
		c.CryptoProperties.RelatedCryptoMaterialProperties.Value = base64.StdEncoding.EncodeToString(keyValue)
	}
	return c
}

func getED25519PrivateKeyComponent() *cdx.Component {
	c := getGenericPrivateKeyComponent()
	c.Name = "ED25519"
	return c
}

func getECDHPublicKeyComponent(key *ecdh.PublicKey) *cdx.Component {
	c := getGenericPublicKeyComponent()
	c.Name = "ECDH"
	size := len(key.Bytes()) * 8
	c.CryptoProperties.RelatedCryptoMaterialProperties.Size = &size
	c.CryptoProperties.OID = "1.2.840.10045.2.1"
	keyValue, err := x509.MarshalPKIXPublicKey(key)
	if err == nil {
		c.CryptoProperties.RelatedCryptoMaterialProperties.Value = base64.StdEncoding.EncodeToString(keyValue)
	}
	return c
}

func getECDHPrivateKeyComponent() *cdx.Component {
	c := getGenericPrivateKeyComponent()
	c.Name = "ECDH"
	return c
}

func getDSAPublicKeyComponent(key *dsa.PublicKey) *cdx.Component {
	c := getGenericPublicKeyComponent()
	c.Name = "DSA"
	size := key.Y.BitLen()
	c.CryptoProperties.RelatedCryptoMaterialProperties.Size = &size
	c.CryptoProperties.OID = "1.2.840.10040.4.1"
	if keyValue, err := marshalDSAPublicKey(key); err == nil {
		c.CryptoProperties.RelatedCryptoMaterialProperties.Value = base64.StdEncoding.EncodeToString(keyValue)
	}
	return c
}

func getDSAPrivateKeyComponent(key *dsa.PrivateKey) *cdx.Component {
	c := getGenericPrivateKeyComponent()
	c.Name = "DSA"
	size := key.Y.BitLen()
	c.CryptoProperties.RelatedCryptoMaterialProperties.Size = &size
	c.CryptoProperties.OID = "1.2.840.10040.4.1"
	return c
}

// dsaAlgorithmParameters mirrors RFC 3279's Dss-Parms.
type dsaAlgorithmParameters struct {
	P, Q, G *big.Int
}

type dsaAlgorithmIdentifier struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters dsaAlgorithmParameters
}

// dsaPublicKeyInfo mirrors RFC 5280's SubjectPublicKeyInfo, specialized to a DSA
// AlgorithmIdentifier.
type dsaPublicKeyInfo struct {
	Algorithm dsaAlgorithmIdentifier
	PublicKey asn1.BitString
}

// marshalDSAPublicKey builds the PKIX, ASN.1 DER SubjectPublicKeyInfo encoding of a DSA public
// key by hand. crypto/x509.MarshalPKIXPublicKey (unlike ParsePKIXPublicKey) does not support DSA,
// so there is no standard-library function to reuse here.
func marshalDSAPublicKey(key *dsa.PublicKey) ([]byte, error) {
	y, err := asn1.Marshal(key.Y)
	if err != nil {
		return nil, err
	}
	return asn1.Marshal(dsaPublicKeyInfo{
		Algorithm: dsaAlgorithmIdentifier{
			Algorithm:  asn1.ObjectIdentifier{1, 2, 840, 10040, 4, 1},
			Parameters: dsaAlgorithmParameters{P: key.P, Q: key.Q, G: key.G},
		},
		PublicKey: asn1.BitString{Bytes: y, BitLength: len(y) * 8},
	})
}
