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
	"encoding/asn1"
	"fmt"
	"math/big"
)

// Minimal ASN1 structures for extracting algorithm OIDs from X.509 certificates.
// These are only used when Go's crypto/x509 cannot identify the algorithm (PQC fallback).

type asn1AlgorithmIdentifier struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

type asn1SubjectPublicKeyInfo struct {
	Algorithm asn1AlgorithmIdentifier
	PublicKey asn1.BitString
}

type asn1TBSCertificate struct {
	Raw           asn1.RawContent
	Version       asn1.RawValue `asn1:"optional,explicit,tag:0"`
	SerialNumber  *big.Int
	Signature     asn1AlgorithmIdentifier
	Issuer        asn1.RawValue
	Validity      asn1.RawValue
	Subject       asn1.RawValue
	PublicKeyInfo asn1SubjectPublicKeyInfo
}

type asn1Certificate struct {
	TBSCertificate     asn1TBSCertificate
	SignatureAlgorithm asn1AlgorithmIdentifier
	Signature          asn1.BitString
}

// AlgorithmOIDs holds the extracted algorithm OIDs from a certificate.
type AlgorithmOIDs struct {
	SignatureAlgorithm string
	PublicKeyAlgorithm string
	// PSSHashAlgorithm is set if the signature algorithm is RSA-PSS and the hash can be determined from parameters.
	PSSHashAlgorithm string
}

// extractAlgorithmOIDs parses raw DER-encoded certificate bytes to extract algorithm OIDs.
// This is used as a fallback when crypto/x509 returns UnknownSignatureAlgorithm or UnknownPublicKeyAlgorithm.
func extractAlgorithmOIDs(derBytes []byte) (*AlgorithmOIDs, error) {
	var cert asn1Certificate
	rest, err := asn1.Unmarshal(derBytes, &cert)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate ASN1 structure: %w", err)
	}
	if len(rest) > 0 {
		return nil, fmt.Errorf("trailing data after certificate ASN1 structure")
	}

	result := &AlgorithmOIDs{
		SignatureAlgorithm: cert.SignatureAlgorithm.Algorithm.String(),
		PublicKeyAlgorithm: cert.TBSCertificate.PublicKeyInfo.Algorithm.Algorithm.String(),
	}

	// If signature algorithm is RSA-PSS (1.2.840.113549.1.1.10), try to extract the hash OID from parameters
	if result.SignatureAlgorithm == "1.2.840.113549.1.1.10" {
		hashOID, err := extractPSSHashOID(cert.SignatureAlgorithm.Parameters)
		if err == nil {
			result.PSSHashAlgorithm = hashOID
		}
	}

	return result, nil
}

// pssParameters represents the RSA-PSS AlgorithmIdentifier parameters (RSASSA-PSS-params).
// See RFC 4055, Section 3.1
type pssParameters struct {
	HashAlgorithm    asn1AlgorithmIdentifier `asn1:"optional,explicit,tag:0"`
	MaskGenAlgorithm asn1AlgorithmIdentifier `asn1:"optional,explicit,tag:1"`
	SaltLength       int                     `asn1:"optional,explicit,tag:2,default:20"`
	TrailerField     int                     `asn1:"optional,explicit,tag:3,default:1"`
}

// extractPSSHashOID extracts the hash algorithm OID from RSA-PSS parameters.
func extractPSSHashOID(params asn1.RawValue) (string, error) {
	if len(params.FullBytes) == 0 {
		return "", fmt.Errorf("no PSS parameters present")
	}

	var pssParams pssParameters
	_, err := asn1.Unmarshal(params.FullBytes, &pssParams)
	if err != nil {
		return "", fmt.Errorf("failed to parse PSS parameters: %w", err)
	}

	if len(pssParams.HashAlgorithm.Algorithm) == 0 {
		// Default is SHA-1 per RFC 4055
		return "1.3.14.3.2.26", nil
	}

	return pssParams.HashAlgorithm.Algorithm.String(), nil
}
