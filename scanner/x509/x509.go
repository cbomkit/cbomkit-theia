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
	"crypto/x509"
	"fmt"
	"path/filepath"
        "strings"
	"time"

	"github.com/IBM/cbomkit-theia/scanner/errors"
	"github.com/IBM/cbomkit-theia/scanner/key"

	"github.com/google/uuid"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

// CertificateWithMetadata An X.509 certificate with additional metadata that is not part of the x509.Certificate struct
type CertificateWithMetadata struct {
	*x509.Certificate
	path   string
	format string
}

// NewX509CertificateWithMetadata Create a new x509CertificateWithMetadata from a x509.Certificate and a path
func NewX509CertificateWithMetadata(cert *x509.Certificate, path string) (*CertificateWithMetadata, error) {
	if cert == nil {
		return nil, fmt.Errorf("certificate is nil")
	}
	return &CertificateWithMetadata{
		cert,
		path,
		"X.509",
	}, nil
}

// ParseCertificatesToX509CertificateWithMetadata Convenience function to parse der bytes into a slice of x509CertificateWithMetadata
func ParseCertificatesToX509CertificateWithMetadata(der []byte, path string) ([]*CertificateWithMetadata, error) {
	certs, err := x509.ParseCertificates(der)
	if err != nil {
		return make([]*CertificateWithMetadata, 0), err
	}

	certsWithMetadata := make([]*CertificateWithMetadata, 0, len(certs))

	for _, cert := range certs {
		certWithMetadata, err := NewX509CertificateWithMetadata(cert, path)
		if err != nil {
			return certsWithMetadata, err
		}
		certsWithMetadata = append(certsWithMetadata, certWithMetadata)
	}

	return certsWithMetadata, err
}

func GenerateCdxComponents(certificateWithMetadata *CertificateWithMetadata) (*[]cdx.Component, *map[cdx.BOMReference][]string, error) {
	// Creating BOM Components
	components := make([]cdx.Component, 0)
	dependencyMap := make(map[cdx.BOMReference][]string)

	// model the certificate algorithm as cdx component
	certificate := certificateWithMetadata.getCertificateComponent()
	// model the algorithm with which the issuer signed the certificate as a cdx component graph.
	// For example, a SHA256-RSA-signed cert results in (1) "SHA256-RSA", (2) "RSA", and (3) "SHA256" components,
	// with a dependency that (1) dependsOn (2) and (3).
	signatureAlgorithm, err := certificateWithMetadata.getSignatureAlgorithmComponent()
	if err != nil {
		return nil, nil, err
	}
	if signatureAlgorithm.hashAndSignature != nil {
		if signatureAlgorithm.signature != nil {
			dependencyMap[cdx.BOMReference(signatureAlgorithm.hashAndSignature.BOMRef)] = append(dependencyMap[cdx.BOMReference(signatureAlgorithm.hashAndSignature.BOMRef)], signatureAlgorithm.signature.BOMRef)
			components = append(components, *signatureAlgorithm.signature)
		}
		if signatureAlgorithm.hash != nil {
			dependencyMap[cdx.BOMReference(signatureAlgorithm.hashAndSignature.BOMRef)] = append(dependencyMap[cdx.BOMReference(signatureAlgorithm.hashAndSignature.BOMRef)], signatureAlgorithm.hash.BOMRef)
			components = append(components, *signatureAlgorithm.hash)
		}
		certificate.CryptoProperties.CertificateProperties.SignatureAlgorithmRef = cdx.BOMReference(signatureAlgorithm.hashAndSignature.BOMRef)
		components = append(components, *signatureAlgorithm.hashAndSignature)
	}
	// model the algorithm corresponding to the public key on the certificate
	publicKeyAlgorithm, err := certificateWithMetadata.getPublicKeyAlgorithmComponent()
	if err != nil {
		return nil, nil, err
	}
	components = append(components, publicKeyAlgorithm)
	// model the public key
	publicKey, err := certificateWithMetadata.getPublicKeyComponent()
	if err != nil {
		return nil, nil, err
	}
	// add dependency to public key algorithm
	publicKey.CryptoProperties.RelatedCryptoMaterialProperties.AlgorithmRef = cdx.BOMReference(publicKeyAlgorithm.BOMRef)
	// add certificate dependency to public key
	certificate.CryptoProperties.CertificateProperties.SubjectPublicKeyRef = cdx.BOMReference(publicKey.BOMRef)
	components = append(components, publicKey)
	components = append(components, certificate)

	return &components, &dependencyMap, nil
}

// Generate the CycloneDX component for the certificate
func (x509CertificateWithMetadata *CertificateWithMetadata) getCertificateComponent() cdx.Component {
	return cdx.Component{
		Type:   cdx.ComponentTypeCryptographicAsset,
		Name:   x509CertificateWithMetadata.Subject.CommonName,
		BOMRef: uuid.New().String(),
		CryptoProperties: &cdx.CryptoProperties{
			AssetType: cdx.CryptoAssetTypeCertificate,
			CertificateProperties: &cdx.CertificateProperties{
				SubjectName:          x509CertificateWithMetadata.Subject.CommonName,
				IssuerName:           x509CertificateWithMetadata.Issuer.CommonName,
				NotValidBefore:       x509CertificateWithMetadata.NotBefore.Format(time.RFC3339),
				NotValidAfter:        x509CertificateWithMetadata.NotAfter.Format(time.RFC3339),
				CertificateFormat:    x509CertificateWithMetadata.format,
				CertificateExtension: strings.TrimPrefix(filepath.Ext(x509CertificateWithMetadata.path), "."),
			},
		},
		Evidence: &cdx.Evidence{
			Occurrences: &[]cdx.EvidenceOccurrence{
				{
					Location: x509CertificateWithMetadata.path,
				}},
		},
	}
}

type signatureAlgorithmResult struct {
	hashAndSignature *cdx.Component // the composite signature algorithm, e.g. "SHA256-RSA"
	hash             *cdx.Component // the hash algorithm (if present), e.g. "SHA256"
	signature        *cdx.Component // the signature algorithm, e.g "RSA"

}

// Generate the CycloneDX components for the algorithm used by the issuer to sign this certificate
func (x509CertificateWithMetadata *CertificateWithMetadata) getSignatureAlgorithmComponent() (signatureAlgorithmResult, error) {
	path := x509CertificateWithMetadata.path
	hashAndSignature := getGenericSignatureAlgorithmComponent(path)
	hashAndSignature.Name = x509CertificateWithMetadata.SignatureAlgorithm.String()
	switch x509CertificateWithMetadata.SignatureAlgorithm {
	case x509.MD2WithRSA:
		hashAndSignature.CryptoProperties.AlgorithmProperties.Padding = cdx.CryptoPaddingPKCS1v15
		hashAndSignature.CryptoProperties.OID = "1.2.840.113549.1.1.2"
		hash := getMD2AlgorithmComponent(path)
		signature := getRSASignatureAlgorithmComponent(path)

		return signatureAlgorithmResult{
			hashAndSignature: &hashAndSignature,
			hash:             &hash,
			signature:        &signature,
		}, nil
	case x509.MD5WithRSA:
		hashAndSignature.CryptoProperties.AlgorithmProperties.Padding = cdx.CryptoPaddingPKCS1v15
		hashAndSignature.CryptoProperties.OID = "1.2.840.113549.1.1.4"
		hash := getMD5AlgorithmComponent(path)
		signature := getRSASignatureAlgorithmComponent(path)

		return signatureAlgorithmResult{
			hashAndSignature: &hashAndSignature,
			hash:             &hash,
			signature:        &signature,
		}, nil
	case x509.SHA1WithRSA:
		hashAndSignature.CryptoProperties.AlgorithmProperties.ParameterSetIdentifier = "160"
		hashAndSignature.CryptoProperties.AlgorithmProperties.Padding = cdx.CryptoPaddingPKCS1v15
		hashAndSignature.CryptoProperties.OID = "1.2.840.113549.1.1.5"
		hash := getSHA1AlgorithmComponent(path)
		signature := getRSASignatureAlgorithmComponent(path)

		return signatureAlgorithmResult{
			hashAndSignature: &hashAndSignature,
			hash:             &hash,
			signature:        &signature,
		}, nil
	case x509.SHA256WithRSA:
		hashAndSignature.CryptoProperties.AlgorithmProperties.ParameterSetIdentifier = "256"
		hashAndSignature.CryptoProperties.AlgorithmProperties.Padding = cdx.CryptoPaddingPKCS1v15
		hashAndSignature.CryptoProperties.OID = "1.2.840.113549.1.1.11"
		hash := getSHA256AlgorithmComponent(path)
		signature := getRSASignatureAlgorithmComponent(path)

		return signatureAlgorithmResult{
			hashAndSignature: &hashAndSignature,
			hash:             &hash,
			signature:        &signature,
		}, nil
	case x509.SHA384WithRSA:
		hashAndSignature.CryptoProperties.AlgorithmProperties.ParameterSetIdentifier = "384"
		hashAndSignature.CryptoProperties.AlgorithmProperties.Padding = cdx.CryptoPaddingPKCS1v15
		hashAndSignature.CryptoProperties.OID = "1.2.840.113549.1.1.12"
		hash := getSHA384AlgorithmComponent(path)
		signature := getRSASignatureAlgorithmComponent(path)

		return signatureAlgorithmResult{
			hashAndSignature: &hashAndSignature,
			hash:             &hash,
			signature:        &signature,
		}, nil
	case x509.SHA512WithRSA:
		hashAndSignature.CryptoProperties.AlgorithmProperties.ParameterSetIdentifier = "512"
		hashAndSignature.CryptoProperties.AlgorithmProperties.Padding = cdx.CryptoPaddingPKCS1v15
		hashAndSignature.CryptoProperties.OID = "1.2.840.113549.1.1.13"
		hash := getSHA512AlgorithmComponent(path)
		signature := getRSASignatureAlgorithmComponent(path)

		return signatureAlgorithmResult{
			hashAndSignature: &hashAndSignature,
			hash:             &hash,
			signature:        &signature,
		}, nil
	case x509.DSAWithSHA1:
		hashAndSignature.CryptoProperties.AlgorithmProperties.ParameterSetIdentifier = "160"
		hashAndSignature.CryptoProperties.OID = "1.2.840.10040.4.3"
		hash := getSHA1AlgorithmComponent(path)
		signature := getDSAAlgorithmComponent(path)

		return signatureAlgorithmResult{
			hashAndSignature: &hashAndSignature,
			hash:             &hash,
			signature:        &signature,
		}, nil
	case x509.DSAWithSHA256:
		hashAndSignature.CryptoProperties.AlgorithmProperties.ParameterSetIdentifier = "256"
		hashAndSignature.CryptoProperties.OID = "2.16.840.1.101.3.4.3.2"
		hash := getSHA256AlgorithmComponent(path)
		signature := getDSAAlgorithmComponent(path)

		return signatureAlgorithmResult{
			hashAndSignature: &hashAndSignature,
			hash:             &hash,
			signature:        &signature,
		}, nil
	case x509.ECDSAWithSHA1:
		hashAndSignature.CryptoProperties.AlgorithmProperties.ParameterSetIdentifier = "160"
		hashAndSignature.CryptoProperties.OID = "1.2.840.10045.4.1"
		hash := getSHA1AlgorithmComponent(path)
		signature := getECDSAAlgorithmComponent(path)

		return signatureAlgorithmResult{
			hashAndSignature: &hashAndSignature,
			hash:             &hash,
			signature:        &signature,
		}, nil
	case x509.ECDSAWithSHA256:
		hashAndSignature.CryptoProperties.AlgorithmProperties.ParameterSetIdentifier = "256"
		hashAndSignature.CryptoProperties.OID = "1.2.840.10045.4.3.2"
		hash := getSHA256AlgorithmComponent(path)
		signature := getECDSAAlgorithmComponent(path)

		return signatureAlgorithmResult{
			hashAndSignature: &hashAndSignature,
			hash:             &hash,
			signature:        &signature,
		}, nil
	case x509.ECDSAWithSHA384:
		hashAndSignature.CryptoProperties.AlgorithmProperties.ParameterSetIdentifier = "384"
		hashAndSignature.CryptoProperties.OID = "1.2.840.10045.4.3.3"
		hash := getSHA384AlgorithmComponent(path)
		signature := getECDSAAlgorithmComponent(path)

		return signatureAlgorithmResult{
			hashAndSignature: &hashAndSignature,
			hash:             &hash,
			signature:        &signature,
		}, nil
	case x509.ECDSAWithSHA512:
		hashAndSignature.CryptoProperties.AlgorithmProperties.ParameterSetIdentifier = "512"
		hashAndSignature.CryptoProperties.OID = "1.2.840.10045.4.3.4"
		hash := getSHA512AlgorithmComponent(path)
		signature := getECDSAAlgorithmComponent(path)

		return signatureAlgorithmResult{
			hashAndSignature: &hashAndSignature,
			hash:             &hash,
			signature:        &signature,
		}, nil
	case x509.SHA256WithRSAPSS:
		hashAndSignature.CryptoProperties.AlgorithmProperties.ParameterSetIdentifier = "256"
		hashAndSignature.CryptoProperties.AlgorithmProperties.Padding = cdx.CryptoPaddingOther
		hashAndSignature.CryptoProperties.OID = "1.2.840.113549.1.1.10"
		hash := getSHA256AlgorithmComponent(path)
		signature := getRSASignatureAlgorithmComponent(path)

		return signatureAlgorithmResult{
			hashAndSignature: &hashAndSignature,
			hash:             &hash,
			signature:        &signature,
		}, nil
	case x509.SHA384WithRSAPSS:
		hashAndSignature.CryptoProperties.AlgorithmProperties.ParameterSetIdentifier = "384"
		hashAndSignature.CryptoProperties.AlgorithmProperties.Padding = cdx.CryptoPaddingOther
		hashAndSignature.CryptoProperties.OID = "1.2.840.113549.1.1.10"
		hash := getSHA384AlgorithmComponent(path)
		signature := getRSASignatureAlgorithmComponent(path)

		return signatureAlgorithmResult{
			hashAndSignature: &hashAndSignature,
			hash:             &hash,
			signature:        &signature,
		}, nil
	case x509.SHA512WithRSAPSS:
		hashAndSignature.CryptoProperties.AlgorithmProperties.ParameterSetIdentifier = "512"
		hashAndSignature.CryptoProperties.AlgorithmProperties.Padding = cdx.CryptoPaddingOther
		hashAndSignature.CryptoProperties.OID = "1.2.840.113549.1.1.10"
		hash := getSHA512AlgorithmComponent(path)
		signature := getRSASignatureAlgorithmComponent(path)

		return signatureAlgorithmResult{
			hashAndSignature: &hashAndSignature,
			hash:             &hash,
			signature:        &signature,
		}, nil
	case x509.PureEd25519:
		// Since there is no hash, Ed25519 *is* the composite hashAndSignature algorithm
		hashAndSignature = getEd25519AlgorithmComponent(path)
		return signatureAlgorithmResult{
			hashAndSignature: &hashAndSignature,
			hash:             nil, // No hash, see: https://datatracker.ietf.org/doc/html/rfc8032#section-4
			signature:        nil,
		}, nil
	default:
		return signatureAlgorithmResult{
			hashAndSignature: nil,
			hash:             nil,
			signature:        nil,
		}, errors.ErrX509UnknownAlgorithm
	}
}

// Generate the CycloneDX component for the public key
func (x509CertificateWithMetadata *CertificateWithMetadata) getPublicKeyComponent() (cdx.Component, error) {
	component, err := key.GenerateCdxComponent(x509CertificateWithMetadata.PublicKey)
	if err != nil {
		return cdx.Component{}, err
	}

	component.Evidence = &cdx.Evidence{
		Occurrences: &[]cdx.EvidenceOccurrence{
			{Location: x509CertificateWithMetadata.path},
		},
	}
	return *component, nil
}

// Generate the CycloneDX component for the algorithm corresponding to the public key on this certificate
func (x509CertificateWithMetadata *CertificateWithMetadata) getPublicKeyAlgorithmComponent() (cdx.Component, error) {
	switch x509CertificateWithMetadata.PublicKeyAlgorithm {
	case x509.RSA:
		keyUsage := x509CertificateWithMetadata.KeyUsage
		// If the Key Usage extension is present, includes a signature usage,
		// and does not include "KeyEncipherment", we conclude it is a signature-only RSA key.
		if keyUsage != 0 &&
			(keyUsage&x509.KeyUsageDigitalSignature+
				keyUsage&x509.KeyUsageCRLSign+
				keyUsage&x509.KeyUsageCertSign > 0) &&
			(keyUsage&x509.KeyUsageKeyEncipherment == 0) {
			return getRSASignatureAlgorithmComponent(x509CertificateWithMetadata.path), nil

		}
		return getRSAPKEAlgorithmComponent(x509CertificateWithMetadata.path), nil
	case x509.DSA:
		return getDSAAlgorithmComponent(x509CertificateWithMetadata.path), nil
	case x509.ECDSA:
		return getECDSAAlgorithmComponent(x509CertificateWithMetadata.path), nil
	case x509.Ed25519:
		return getEd25519AlgorithmComponent(x509CertificateWithMetadata.path), nil
	default:
		return cdx.Component{}, errors.ErrX509UnknownAlgorithm
	}
}

func getMD2AlgorithmComponent(path string) cdx.Component {
	comp := getGenericHashAlgorithmComponent(path)
	comp.Name = "MD2"
	comp.CryptoProperties.AlgorithmProperties.ParameterSetIdentifier = "2"
	comp.CryptoProperties.AlgorithmProperties.Padding = cdx.CryptoPaddingOther
	return comp
}

func getMD5AlgorithmComponent(path string) cdx.Component {
	comp := getGenericHashAlgorithmComponent(path)
	comp.Name = "MD5"
	comp.CryptoProperties.AlgorithmProperties.ParameterSetIdentifier = "5"
	return comp
}

func getSHA1AlgorithmComponent(path string) cdx.Component {
	comp := getGenericHashAlgorithmComponent(path)
	comp.Name = "SHA1"
	comp.CryptoProperties.AlgorithmProperties.ParameterSetIdentifier = "1"
	return comp
}

func getSHA256AlgorithmComponent(path string) cdx.Component {
	comp := getGenericHashAlgorithmComponent(path)
	comp.Name = "SHA256"
	comp.CryptoProperties.AlgorithmProperties.ParameterSetIdentifier = "256"
	return comp
}

func getSHA384AlgorithmComponent(path string) cdx.Component {
	comp := getGenericHashAlgorithmComponent(path)
	comp.Name = "SHA384"
	comp.CryptoProperties.AlgorithmProperties.ParameterSetIdentifier = "384"
	return comp
}

func getSHA512AlgorithmComponent(path string) cdx.Component {
	comp := getGenericHashAlgorithmComponent(path)
	comp.Name = "SHA512"
	comp.CryptoProperties.AlgorithmProperties.ParameterSetIdentifier = "512"
	return comp
}

func getRSASignatureAlgorithmComponent(path string) cdx.Component {
	comp := getGenericSignatureAlgorithmComponent(path)
	comp.Name = "RSA"
	comp.CryptoProperties.OID = "1.2.840.113549.1.1.1"
	return comp
}

func getRSAPKEAlgorithmComponent(path string) cdx.Component {
	comp := getGenericPublicKeyAlgorithmComponent(path)
	comp.Name = "RSA"
	comp.CryptoProperties.AlgorithmProperties.Primitive = cdx.CryptoPrimitivePKE
	comp.CryptoProperties.AlgorithmProperties.CryptoFunctions = &[]cdx.CryptoFunction{cdx.CryptoFunctionEncapsulate, cdx.CryptoFunctionDecapsulate, cdx.CryptoFunctionSign}
	comp.CryptoProperties.OID = "1.2.840.113549.1.1.1"
	return comp
}

func getDSAAlgorithmComponent(path string) cdx.Component {
	comp := getGenericSignatureAlgorithmComponent(path)
	comp.Name = "DSA"
	comp.CryptoProperties.OID = "1.2.840.10040.4.1"
	return comp
}

func getECDSAAlgorithmComponent(path string) cdx.Component {
	comp := getGenericSignatureAlgorithmComponent(path)
	comp.Name = "ECDSA"
	comp.CryptoProperties.OID = "1.2.840.10045.2.1"
	return comp
}

func getEd25519AlgorithmComponent(path string) cdx.Component {
	comp := getGenericSignatureAlgorithmComponent(path)
	comp.Name = "Ed25519"
	comp.CryptoProperties.AlgorithmProperties.Curve = "Ed25519" // https://datatracker.ietf.org/doc/html/rfc8032
	comp.CryptoProperties.OID = "1.3.101.112"
	return comp
}

// Generate a generic CycloneDX component a public key algorithm.
// NOTE: This generic  component does not include the primitive or cryptoFunctions fields, since these may be KeyUsage dependent.
func getGenericPublicKeyAlgorithmComponent(path string) cdx.Component {
	return cdx.Component{
		Type:   cdx.ComponentTypeCryptographicAsset,
		BOMRef: uuid.New().String(),
		CryptoProperties: &cdx.CryptoProperties{
			AssetType:           cdx.CryptoAssetTypeAlgorithm,
			AlgorithmProperties: &cdx.CryptoAlgorithmProperties{},
		},
		Evidence: &cdx.Evidence{
			Occurrences: &[]cdx.EvidenceOccurrence{
				{
					Location: path,
				}},
		},
	}
}

// Generate a generic CycloneDX component for a signature algorithm
func getGenericSignatureAlgorithmComponent(path string) cdx.Component {
	comp := getGenericPublicKeyAlgorithmComponent(path)
	comp.CryptoProperties.AlgorithmProperties.Primitive = cdx.CryptoPrimitiveSignature
	comp.CryptoProperties.AlgorithmProperties.CryptoFunctions = &[]cdx.CryptoFunction{cdx.CryptoFunctionSign}
	return comp
}

// Generate a generic CycloneDX component for a hash algorithm
func getGenericHashAlgorithmComponent(path string) cdx.Component {
	return cdx.Component{
		Type:   cdx.ComponentTypeCryptographicAsset,
		BOMRef: uuid.New().String(),
		CryptoProperties: &cdx.CryptoProperties{
			AssetType: cdx.CryptoAssetTypeAlgorithm,
			AlgorithmProperties: &cdx.CryptoAlgorithmProperties{
				Primitive:       cdx.CryptoPrimitiveHash,
				CryptoFunctions: &[]cdx.CryptoFunction{cdx.CryptoFunctionDigest},
			},
		},
		Evidence: &cdx.Evidence{
			Occurrences: &[]cdx.EvidenceOccurrence{
				{
					Location: path,
				}},
		},
	}
}
