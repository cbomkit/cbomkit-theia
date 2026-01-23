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
	"log"
	"path/filepath"
	"strings"
	"time"

	"github.com/cbomkit/cbomkit-theia/scanner/errors"
	"github.com/cbomkit/cbomkit-theia/scanner/key"

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
	hashAndSignature *cdx.Component // the composite/hybrid/standalone signature algorithm
	hash             *cdx.Component // the hash algorithm (if present), e.g. "SHA256"
	signature        *cdx.Component // the signature algorithm, e.g "RSA"
}

// x509SigAlgToRegistryKey maps a crypto/x509 SignatureAlgorithm enum to the corresponding OID registry key.
var x509SigAlgToRegistryKey = map[x509.SignatureAlgorithm]string{
	x509.MD2WithRSA:      "MD2WithRSA",
	x509.MD5WithRSA:      "MD5WithRSA",
	x509.SHA1WithRSA:     "SHA1WithRSA",
	x509.SHA256WithRSA:   "SHA256WithRSA",
	x509.SHA384WithRSA:   "SHA384WithRSA",
	x509.SHA512WithRSA:   "SHA512WithRSA",
	x509.DSAWithSHA1:     "DSAWithSHA1",
	x509.DSAWithSHA256:   "DSAWithSHA256",
	x509.ECDSAWithSHA1:   "ECDSAWithSHA1",
	x509.ECDSAWithSHA256: "ECDSAWithSHA256",
	x509.ECDSAWithSHA384: "ECDSAWithSHA384",
	x509.ECDSAWithSHA512: "ECDSAWithSHA512",
	x509.SHA256WithRSAPSS: "SHA256WithRSAPSS",
	x509.SHA384WithRSAPSS: "SHA384WithRSAPSS",
	x509.SHA512WithRSAPSS: "SHA512WithRSAPSS",
	x509.PureEd25519:     "Ed25519",
}

// getSignatureAlgorithmComponent generates CycloneDX components for the certificate's signature algorithm.
// It first attempts to use the x509 package's algorithm identification, falling back to
// raw ASN1 OID extraction for unknown algorithms (e.g., PQC).
func (x509CertificateWithMetadata *CertificateWithMetadata) getSignatureAlgorithmComponent() (signatureAlgorithmResult, error) {
	registry, err := GetRegistry()
	if err != nil {
		return signatureAlgorithmResult{}, fmt.Errorf("failed to load OID registry: %w", err)
	}

	path := x509CertificateWithMetadata.path

	// Try to resolve via x509 enum first
	if registryKey, found := x509SigAlgToRegistryKey[x509CertificateWithMetadata.SignatureAlgorithm]; found {
		return buildSignatureResult(registry, registryKey, path)
	}

	// Fallback: parse raw ASN1 to extract the algorithm OID
	if x509CertificateWithMetadata.SignatureAlgorithm == x509.UnknownSignatureAlgorithm {
		oids, err := extractAlgorithmOIDs(x509CertificateWithMetadata.Raw)
		if err != nil {
			return signatureAlgorithmResult{}, fmt.Errorf("failed to extract algorithm OIDs via ASN1: %w", err)
		}

		// Handle RSA-PSS disambiguation
		if oids.SignatureAlgorithm == "1.2.840.113549.1.1.10" && oids.PSSHashAlgorithm != "" {
			entry, found := registry.LookupPSSByHashOID(oids.PSSHashAlgorithm)
			if found {
				return buildSignatureResultFromEntry(registry, entry, path)
			}
		}

		// Look up by OID
		entry, found := registry.LookupByOIDUnambiguous(oids.SignatureAlgorithm)
		if found {
			return buildSignatureResultFromEntry(registry, entry, path)
		}

		// Unknown OID: create a generic component with the raw OID
		log.Printf("Warning: unknown signature algorithm OID: %s", oids.SignatureAlgorithm)
		comp := buildUnknownAlgorithmComponent(oids.SignatureAlgorithm, path)
		return signatureAlgorithmResult{hashAndSignature: &comp}, nil
	}

	return signatureAlgorithmResult{}, errors.ErrX509UnknownAlgorithm
}

// buildSignatureResult builds signature algorithm components from a registry key.
func buildSignatureResult(registry *OIDRegistry, registryKey string, path string) (signatureAlgorithmResult, error) {
	entry, found := registry.LookupByKey(registryKey)
	if !found {
		return signatureAlgorithmResult{}, fmt.Errorf("registry key not found: %s", registryKey)
	}
	return buildSignatureResultFromEntry(registry, entry, path)
}

// buildSignatureResultFromEntry builds signature algorithm components from an AlgorithmEntry.
func buildSignatureResultFromEntry(registry *OIDRegistry, entry AlgorithmEntry, path string) (signatureAlgorithmResult, error) {
	switch entry.Type {
	case "standalone":
		// Standalone signature algorithm (e.g., Ed25519, ML-DSA-65)
		comp := buildAlgorithmComponent(entry, path)
		return signatureAlgorithmResult{hashAndSignature: &comp}, nil

	case "composite":
		// Composite algorithm (e.g., SHA256WithRSA) — has hash + signature sub-components
		parent := buildAlgorithmComponent(entry, path)

		var hashComp, sigComp *cdx.Component
		if hashKey, ok := entry.Components["hash"]; ok {
			if hashEntry, found := registry.LookupByKey(hashKey); found {
				h := buildAlgorithmComponent(hashEntry, path)
				hashComp = &h
			}
		}
		if sigKey, ok := entry.Components["signature"]; ok {
			if sigEntry, found := registry.LookupByKey(sigKey); found {
				s := buildAlgorithmComponent(sigEntry, path)
				sigComp = &s
			}
		}

		return signatureAlgorithmResult{
			hashAndSignature: &parent,
			hash:             hashComp,
			signature:        sigComp,
		}, nil

	case "hybrid":
		// Hybrid algorithm (e.g., ML-DSA-65-ECDSA-P256) — has PQC + traditional sub-components
		parent := buildAlgorithmComponent(entry, path)

		var pqcComp, tradComp *cdx.Component
		if pqcKey, ok := entry.Components["pqc"]; ok {
			if pqcEntry, found := registry.LookupByKey(pqcKey); found {
				p := buildAlgorithmComponent(pqcEntry, path)
				pqcComp = &p
			}
		}
		if tradKey, ok := entry.Components["traditional"]; ok {
			if tradEntry, found := registry.LookupByKey(tradKey); found {
				t := buildAlgorithmComponent(tradEntry, path)
				tradComp = &t
			}
		}

		// For hybrid algorithms, sub-components are treated like hash+signature
		// in terms of the dependency graph
		return signatureAlgorithmResult{
			hashAndSignature: &parent,
			hash:             pqcComp,
			signature:        tradComp,
		}, nil

	default:
		return signatureAlgorithmResult{}, fmt.Errorf("unsupported algorithm type: %s", entry.Type)
	}
}

// Generate the CycloneDX component for the public key.
// Falls back to a generic component if the key type is not recognized (e.g., PQC keys).
func (x509CertificateWithMetadata *CertificateWithMetadata) getPublicKeyComponent() (cdx.Component, error) {
	component, err := key.GenerateCdxComponent(x509CertificateWithMetadata.PublicKey)
	if err != nil {
		// For unknown key types (PQC), create a generic public key component
		// using the raw SubjectPublicKeyInfo from the certificate
		return x509CertificateWithMetadata.buildGenericPublicKeyComponent(), nil
	}

	component.Evidence = &cdx.Evidence{
		Occurrences: &[]cdx.EvidenceOccurrence{
			{Location: x509CertificateWithMetadata.path},
		},
	}
	return *component, nil
}

// buildGenericPublicKeyComponent creates a public key component for key types
// not supported by Go's crypto library (e.g., PQC keys).
func (x509CertificateWithMetadata *CertificateWithMetadata) buildGenericPublicKeyComponent() cdx.Component {
	size := len(x509CertificateWithMetadata.RawSubjectPublicKeyInfo) * 8
	return cdx.Component{
		Type:   cdx.ComponentTypeCryptographicAsset,
		Name:   x509CertificateWithMetadata.PublicKeyAlgorithm.String(),
		BOMRef: uuid.New().String(),
		CryptoProperties: &cdx.CryptoProperties{
			AssetType: cdx.CryptoAssetTypeRelatedCryptoMaterial,
			RelatedCryptoMaterialProperties: &cdx.RelatedCryptoMaterialProperties{
				Type:   cdx.RelatedCryptoMaterialTypePublicKey,
				Size:   &size,
				Format: "DER",
			},
		},
		Evidence: &cdx.Evidence{
			Occurrences: &[]cdx.EvidenceOccurrence{
				{Location: x509CertificateWithMetadata.path},
			},
		},
	}
}

// getPublicKeyAlgorithmComponent generates the CycloneDX component for the public key algorithm.
// It uses the x509 package's identification first, falling back to ASN1 OID extraction for unknown algorithms.
func (x509CertificateWithMetadata *CertificateWithMetadata) getPublicKeyAlgorithmComponent() (cdx.Component, error) {
	registry, err := GetRegistry()
	if err != nil {
		return cdx.Component{}, fmt.Errorf("failed to load OID registry: %w", err)
	}

	path := x509CertificateWithMetadata.path

	switch x509CertificateWithMetadata.PublicKeyAlgorithm {
	case x509.RSA:
		keyUsage := x509CertificateWithMetadata.KeyUsage
		// If the Key Usage extension is present, includes a signature usage,
		// and does not include "KeyEncipherment", we conclude it is a signature-only RSA key.
		registryKey := "RSA-PKE"
		if keyUsage != 0 &&
			(keyUsage&x509.KeyUsageDigitalSignature+
				keyUsage&x509.KeyUsageCRLSign+
				keyUsage&x509.KeyUsageCertSign > 0) &&
			(keyUsage&x509.KeyUsageKeyEncipherment == 0) {
			registryKey = "RSA"
		}
		entry, found := registry.LookupByKey(registryKey)
		if !found {
			return cdx.Component{}, fmt.Errorf("registry key not found: %s", registryKey)
		}
		return buildAlgorithmComponent(entry, path), nil

	case x509.DSA:
		entry, found := registry.LookupByKey("DSA")
		if !found {
			return cdx.Component{}, fmt.Errorf("registry key not found: DSA")
		}
		return buildAlgorithmComponent(entry, path), nil

	case x509.ECDSA:
		entry, found := registry.LookupByKey("ECDSA")
		if !found {
			return cdx.Component{}, fmt.Errorf("registry key not found: ECDSA")
		}
		return buildAlgorithmComponent(entry, path), nil

	case x509.Ed25519:
		entry, found := registry.LookupByKey("Ed25519")
		if !found {
			return cdx.Component{}, fmt.Errorf("registry key not found: Ed25519")
		}
		return buildAlgorithmComponent(entry, path), nil

	default:
		// Unknown public key algorithm — fall back to ASN1 parsing
		oids, err := extractAlgorithmOIDs(x509CertificateWithMetadata.Raw)
		if err != nil {
			return cdx.Component{}, fmt.Errorf("failed to extract algorithm OIDs via ASN1: %w", err)
		}

		entry, found := registry.LookupByOIDUnambiguous(oids.PublicKeyAlgorithm)
		if found {
			return buildAlgorithmComponent(entry, path), nil
		}

		// Unknown OID
		log.Printf("Warning: unknown public key algorithm OID: %s", oids.PublicKeyAlgorithm)
		return buildUnknownAlgorithmComponent(oids.PublicKeyAlgorithm, path), nil
	}
}

// buildAlgorithmComponent creates a CycloneDX component from an AlgorithmEntry.
func buildAlgorithmComponent(entry AlgorithmEntry, path string) cdx.Component {
	comp := cdx.Component{
		Type:   cdx.ComponentTypeCryptographicAsset,
		Name:   entry.Name,
		BOMRef: uuid.New().String(),
		CryptoProperties: &cdx.CryptoProperties{
			AssetType:           cdx.CryptoAssetTypeAlgorithm,
			OID:                 entry.OID,
			AlgorithmProperties: &cdx.CryptoAlgorithmProperties{},
		},
		Evidence: &cdx.Evidence{
			Occurrences: &[]cdx.EvidenceOccurrence{
				{Location: path},
			},
		},
	}

	// Set primitive
	switch entry.Primitive {
	case "signature":
		comp.CryptoProperties.AlgorithmProperties.Primitive = cdx.CryptoPrimitiveSignature
	case "hash":
		comp.CryptoProperties.AlgorithmProperties.Primitive = cdx.CryptoPrimitiveHash
	case "pke":
		comp.CryptoProperties.AlgorithmProperties.Primitive = cdx.CryptoPrimitivePKE
	case "kem":
		comp.CryptoProperties.AlgorithmProperties.Primitive = cdx.CryptoPrimitiveKEM
	}

	// Set crypto functions
	if len(entry.CryptoFunctions) > 0 {
		functions := make([]cdx.CryptoFunction, 0, len(entry.CryptoFunctions))
		for _, fn := range entry.CryptoFunctions {
			switch fn {
			case "sign":
				functions = append(functions, cdx.CryptoFunctionSign)
			case "digest":
				functions = append(functions, cdx.CryptoFunctionDigest)
			case "encapsulate":
				functions = append(functions, cdx.CryptoFunctionEncapsulate)
			case "decapsulate":
				functions = append(functions, cdx.CryptoFunctionDecapsulate)
			}
		}
		comp.CryptoProperties.AlgorithmProperties.CryptoFunctions = &functions
	}

	// Set padding
	if entry.Padding != "" {
		switch entry.Padding {
		case "PKCS1v15":
			comp.CryptoProperties.AlgorithmProperties.Padding = cdx.CryptoPaddingPKCS1v15
		case "PSS", "Other":
			comp.CryptoProperties.AlgorithmProperties.Padding = cdx.CryptoPaddingOther
		}
	}

	// Set parameter set identifier
	if entry.ParameterSetIdentifier != "" {
		comp.CryptoProperties.AlgorithmProperties.ParameterSetIdentifier = entry.ParameterSetIdentifier
	}

	// Set curve
	if entry.Curve != "" {
		comp.CryptoProperties.AlgorithmProperties.Curve = entry.Curve
	}

	return comp
}

// buildUnknownAlgorithmComponent creates a generic component for an algorithm with an unknown OID.
func buildUnknownAlgorithmComponent(oid string, path string) cdx.Component {
	return cdx.Component{
		Type:   cdx.ComponentTypeCryptographicAsset,
		Name:   fmt.Sprintf("Unknown (%s)", oid),
		BOMRef: uuid.New().String(),
		CryptoProperties: &cdx.CryptoProperties{
			AssetType:           cdx.CryptoAssetTypeAlgorithm,
			OID:                 oid,
			AlgorithmProperties: &cdx.CryptoAlgorithmProperties{},
		},
		Evidence: &cdx.Evidence{
			Occurrences: &[]cdx.EvidenceOccurrence{
				{Location: path},
			},
		},
	}
}
