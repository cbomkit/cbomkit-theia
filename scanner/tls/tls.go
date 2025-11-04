// Copyright 2025 IBM
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

package tls

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/google/uuid"
)

// BuildTLSProtocolComponents constructs a TLS protocol component and its dependency map.
//
// Inputs:
//   - version: TLS version string (e.g., "1.2", "1.3").
//   - suiteNames: TLS cipher suite names like "TLS_AES_128_GCM_SHA256".
//   - srcPath: evidence location for the protocol/algorithms.
//
// Output:
//   - algoComps: algorithm components referenced by the cipher suites (deduplicated, deterministic order).
//   - proto: TLS protocol component (nil if no recognized suites).
//   - depMap: dependencies mapping (protocol → algorithms; signature → hash heuristic).
func BuildTLSProtocolComponents(version string, suiteNames []string, srcPath string) ([]cdx.Component, *cdx.Component, map[cdx.BOMReference][]string) {
	// Load DB lazily
	if err := loadCipherSuitesDB(); err != nil {
		return nil, nil, nil
	}

	algoComps := make([]cdx.Component, 0)
	algoRefSet := map[string]struct{}{}
	refOrder := make([]cdx.BOMReference, 0)
	cipherSuites := make([]cdx.CipherSuite, 0)

	// deterministic order over provided names
	sortedNames := make([]string, 0, len(suiteNames))
	sortedNames = append(sortedNames, suiteNames...)
	sort.Strings(sortedNames)

	for _, name := range sortedNames {
		cs, ok := cipherSuiteDB.byName[name]
		if !ok {
			continue
		}
		// Build identifiers from hex bytes
		identifiers := make([]string, 0)
		if cs.HexByte1 != "" && cs.HexByte2 != "" {
			identifiers = append(identifiers, cs.HexByte1, cs.HexByte2)
		}

		// Extract algorithms from the cipher suite fields
		algRefsForSuite := make([]cdx.BOMReference, 0)
		algs := extractAlgorithmsFromSuite(cs)
		for _, a := range algs {
			comp := makeAlgorithmComponent(a, srcPath)
			if comp.BOMRef == "" {
				continue
			}
			if _, seen := algoRefSet[comp.BOMRef]; !seen {
				algoRefSet[comp.BOMRef] = struct{}{}
				algoComps = append(algoComps, comp)
				refOrder = append(refOrder, cdx.BOMReference(comp.BOMRef))
			}
			algRefsForSuite = append(algRefsForSuite, cdx.BOMReference(comp.BOMRef))
		}
		cipherSuites = append(cipherSuites, cdx.CipherSuite{
			Name:        name,
			Algorithms:  &algRefsForSuite,
			Identifiers: &identifiers,
		})
	}

	if len(cipherSuites) == 0 {
		return nil, nil, nil
	}

	// protocol component
	protoRef := cdx.BOMReference(uuid.New().String())
	protoName := "TLSv" + version
	refsCopy := make([]cdx.BOMReference, len(refOrder))
	copy(refsCopy, refOrder)
	proto := cdx.Component{
		Type:   cdx.ComponentTypeCryptographicAsset,
		Name:   protoName,
		BOMRef: string(protoRef),
		CryptoProperties: &cdx.CryptoProperties{
			AssetType: cdx.CryptoAssetTypeProtocol,
			ProtocolProperties: &cdx.CryptoProtocolProperties{
				Type:           cdx.CryptoProtocolTypeTLS,
				Version:        version,
				CipherSuites:   &cipherSuites,
				CryptoRefArray: &refsCopy,
			},
		},
		Evidence: &cdx.Evidence{Occurrences: &[]cdx.EvidenceOccurrence{{Location: srcPath}}},
	}

	// dependencies: protocol depends on all algorithms; and the composed signature depends on hash if applicable
	depMap := make(map[cdx.BOMReference][]string)
	if len(refOrder) > 0 {
		depMap[protoRef] = make([]string, 0, len(refOrder))
		for _, r := range refOrder {
			depMap[protoRef] = append(depMap[protoRef], string(r))
		}
	}
	// add signature->hash dependency heuristically
	for _, comp := range algoComps {
		if comp.CryptoProperties != nil && comp.CryptoProperties.AlgorithmProperties != nil {
			if strings.Contains(strings.ToUpper(comp.Name), "WITH") {
				parts := strings.Split(strings.ToUpper(comp.Name), "WITH")
				if len(parts) >= 1 {
					depMap[cdx.BOMReference(comp.BOMRef)] = append(depMap[cdx.BOMReference(comp.BOMRef)], uuid.New().String())
				}
			}
		}
	}

	return algoComps, &proto, depMap
}

// --- Embedded cipher suites DB and helpers ---

//go:embed ciphersuites.json
var embeddedCipherSuites []byte

var (
	cipherSuiteOnce sync.Once
	cipherSuiteDB   *cipherDB
	cipherSuiteErr  error
)

type cipherDB struct {
	Ciphersuites []map[string]cipherSuite `json:"ciphersuites"`
	byName       map[string]*cipherSuite
}

type cipherSuite struct {
	GnuTLSName      string   `json:"gnutls_name"`
	OpenSSLName     string   `json:"openssl_name"`
	HexByte1        string   `json:"hex_byte_1"`
	HexByte2        string   `json:"hex_byte_2"`
	ProtocolVersion string   `json:"protocol_version"`
	KexAlgorithm    string   `json:"kex_algorithm"`
	AuthAlgorithm   string   `json:"auth_algorithm"`
	EncAlgorithm    string   `json:"enc_algorithm"`
	HashAlgorithm   string   `json:"hash_algorithm"`
	Security        string   `json:"security"`
	TLSVersion      []string `json:"tls_version"`
}

func loadCipherSuitesDB() error {
	cipherSuiteOnce.Do(func() {
		if len(embeddedCipherSuites) == 0 {
			cipherSuiteErr = fmt.Errorf("embedded ciphersuites.json is empty")
			return
		}
		db := &cipherDB{}
		if err := json.Unmarshal(embeddedCipherSuites, db); err != nil {
			cipherSuiteErr = err
			return
		}
		db.byName = make(map[string]*cipherSuite)
		for i := range db.Ciphersuites {
			csMap := db.Ciphersuites[i]
			for name, cs := range csMap {
				// Store a copy of the cipher suite with the name as key
				csCopy := cs
				db.byName[name] = &csCopy
			}
		}
		cipherSuiteDB = db
	})
	return cipherSuiteErr
}

func extractAlgorithmsFromSuite(cs *cipherSuite) []string {
	algs := make([]string, 0)
	seen := make(map[string]struct{})
	if cs.KexAlgorithm != "" && cs.KexAlgorithm != "-" {
		kex := strings.TrimSpace(cs.KexAlgorithm)
		if _, ok := seen[kex]; !ok {
			algs = append(algs, kex)
			seen[kex] = struct{}{}
		}
	}
	if cs.EncAlgorithm != "" && cs.EncAlgorithm != "-" {
		enc := strings.TrimSpace(cs.EncAlgorithm)
		if _, ok := seen[enc]; !ok {
			algs = append(algs, enc)
			seen[enc] = struct{}{}
		}
	}
	if cs.HashAlgorithm != "" && cs.HashAlgorithm != "-" {
		hash := strings.TrimSpace(cs.HashAlgorithm)
		if _, ok := seen[hash]; !ok {
			algs = append(algs, hash)
			seen[hash] = struct{}{}
		}
	}
	if cs.AuthAlgorithm != "" && cs.AuthAlgorithm != "-" && cs.AuthAlgorithm != "anon" {
		auth := strings.TrimSpace(cs.AuthAlgorithm)
		if _, ok := seen[auth]; !ok {
			algs = append(algs, auth)
			seen[auth] = struct{}{}
		}
	}
	return algs
}

func makeAlgorithmComponent(name, srcPath string) cdx.Component {
	upper := strings.ToUpper(name)
	ref := uuid.New().String()
	comp := cdx.Component{Type: cdx.ComponentTypeCryptographicAsset, Name: normalizedAlgoName(upper), BOMRef: ref,
		CryptoProperties: &cdx.CryptoProperties{AssetType: cdx.CryptoAssetTypeAlgorithm, AlgorithmProperties: &cdx.CryptoAlgorithmProperties{}},
		Evidence:         &cdx.Evidence{Occurrences: &[]cdx.EvidenceOccurrence{{Location: srcPath}}},
	}
	ap := comp.CryptoProperties.AlgorithmProperties
	// Primitive + details
	switch {
	case strings.HasPrefix(upper, "AES"):
		ap.Primitive = cdx.CryptoPrimitiveBlockCipher
		if strings.Contains(upper, "GCM") {
			ap.Mode = cdx.CryptoAlgorithmModeGCM
		} else if strings.Contains(upper, "CBC") {
			ap.Mode = cdx.CryptoAlgorithmModeCBC
		}
	case strings.HasPrefix(upper, "SHA"):
		ap.Primitive = cdx.CryptoPrimitiveHash
		if i := strings.IndexAny(upper, "0123456789"); i != -1 {
			ap.ParameterSetIdentifier = upper[i:]
		}
	case strings.HasSuffix(upper, "WITHRSA") || strings.HasSuffix(upper, "WITHDSA") || strings.HasSuffix(upper, "WITHECDSA"):
		ap.Primitive = cdx.CryptoPrimitiveSignature
	case upper == "DH" || upper == "ECDH":
		ap.Primitive = cdx.CryptoPrimitiveKeyAgree
	}
	// Known OIDs (limited, mirror opensslconf)
	switch upper {
	case "DH":
		comp.CryptoProperties.OID = "1.2.840.113549.1.3.1"
	case "SHA256WITHDSA":
		comp.CryptoProperties.OID = "2.16.840.1.101.3.4.3.2"
	}
	return comp
}

func normalizedAlgoName(upper string) string {
	// e.g., AES256-CBC, SHA256, SHA256withDSA
	if strings.HasPrefix(upper, "AES") {
		size := ""
		if i := strings.IndexAny(upper, "0123456789"); i != -1 {
			size = upper[i:]
		}
		return fmt.Sprintf("AES%s", size)
	}
	if strings.HasPrefix(upper, "SHA") {
		// plain hash or signature naming
		if strings.Contains(upper, "WITH") {
			parts := strings.Split(upper, "WITH")
			return parts[0] + "with" + strings.Title(strings.ToLower(parts[1]))
		}
		return upper
	}
	return upper
}
