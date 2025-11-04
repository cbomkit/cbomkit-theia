package key

import (
	"crypto/dsa"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"fmt"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/IBM/cbomkit-theia/scanner/errors"
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
	c.CryptoProperties.OID = "1.3.14.3.2.12"
	return c
}
