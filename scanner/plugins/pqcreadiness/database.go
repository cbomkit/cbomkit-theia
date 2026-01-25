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

package pqcreadiness

import (
	_ "embed"
	"encoding/json"
	"regexp"
	"strconv"
	"strings"
)

//go:embed algorithms.json
var algorithmsJSON []byte

//go:embed pqc_oids.json
var pqcOIDsJSON []byte

// AlgorithmDatabase contains the classical algorithm vulnerability mappings
type AlgorithmDatabase struct {
	Version            string                         `json:"version"`
	LastUpdated        string                         `json:"lastUpdated"`
	ClassicalAlgorithms map[string]ClassicalAlgorithm `json:"classicalAlgorithms"`
}

// ClassicalAlgorithm represents a classical cryptographic algorithm
type ClassicalAlgorithm struct {
	Family                 string                     `json:"family"`
	Primitive              string                     `json:"primitive"`
	QuantumStatus          string                     `json:"quantumStatus"`
	PrimaryThreat          string                     `json:"primaryThreat"`
	KeySizeMapping         map[string]SecurityMapping `json:"keySizeMapping"`
	CurveMapping           map[string]SecurityMapping `json:"curveMapping"`
	FixedSecurityLevel     *SecurityMapping           `json:"fixedSecurityLevel"`
	OIDs                   []string                   `json:"oids"`
	RecommendedReplacements []string                  `json:"recommendedReplacements"`
	Notes                  string                     `json:"notes"`
}

// SecurityMapping contains security level information
type SecurityMapping struct {
	ClassicalBits int `json:"classicalBits"`
	QuantumBits   int `json:"quantumBits"`
	NISTLevel     int `json:"nistLevel"`
}

// PQCOIDDatabase contains the PQC algorithm OID mappings
type PQCOIDDatabase struct {
	Version           string                   `json:"version"`
	LastUpdated       string                   `json:"lastUpdated"`
	Source            string                   `json:"source"`
	PQCAlgorithms     map[string]PQCAlgorithmDef `json:"pqcAlgorithms"`
	HybridSchemes     map[string]HybridScheme    `json:"hybridSchemes"`
	PQCNamePatterns   []string                   `json:"pqcNamePatterns"`
	HybridNamePatterns []string                  `json:"hybridNamePatterns"`

	// Compiled patterns for efficient matching
	pqcPatterns    []*regexp.Regexp
	hybridPatterns []*regexp.Regexp
	oidToAlgorithm map[string]*PQCAlgorithmInfo
}

// PQCAlgorithmDef defines a PQC algorithm family
type PQCAlgorithmDef struct {
	StandardName   string                      `json:"standardName"`
	Family         string                      `json:"family"`
	Primitive      string                      `json:"primitive"`
	BaseOID        string                      `json:"baseOID"`
	ParameterSets  map[string]PQCParameterSet  `json:"parameterSets"`
}

// PQCParameterSet defines a specific parameter set
type PQCParameterSet struct {
	OID            string `json:"oid"`
	NISTLevel      int    `json:"nistLevel"`
	PublicKeySize  int    `json:"publicKeySize"`
	CiphertextSize int    `json:"ciphertextSize"`
	SignatureSize  int    `json:"signatureSize"`
	ClassicalBits  int    `json:"classicalBits"`
	QuantumBits    int    `json:"quantumBits"`
}

// HybridScheme defines a hybrid PQC+classical scheme
type HybridScheme struct {
	DisplayName       string   `json:"displayName"`
	Components        []string `json:"components"`
	OID               string   `json:"oid"`
	NISTLevel         int      `json:"nistLevel"`
	IsHybrid          bool     `json:"isHybrid"`
	ClassicalComponent string  `json:"classicalComponent"`
	PQCComponent      string   `json:"pqcComponent"`
	ClassicalBits     int      `json:"classicalBits"`
	QuantumBits       int      `json:"quantumBits"`
}

// PQCAlgorithmInfo contains resolved PQC algorithm information
type PQCAlgorithmInfo struct {
	Name               string
	Family             string
	StandardName       string
	ParameterSet       string
	OID                string
	NISTLevel          int
	Primitive          string
	IsHybrid           bool
	ClassicalComponent string
	ClassicalBits      int
	QuantumBits        int
}

// loadAlgorithmDatabase loads the classical algorithm database
func loadAlgorithmDatabase() (*AlgorithmDatabase, error) {
	var db AlgorithmDatabase
	if err := json.Unmarshal(algorithmsJSON, &db); err != nil {
		return nil, err
	}
	return &db, nil
}

// loadPQCOIDDatabase loads the PQC OID database
func loadPQCOIDDatabase() (*PQCOIDDatabase, error) {
	var db PQCOIDDatabase
	if err := json.Unmarshal(pqcOIDsJSON, &db); err != nil {
		return nil, err
	}

	// Compile name patterns
	db.pqcPatterns = make([]*regexp.Regexp, 0, len(db.PQCNamePatterns))
	for _, pattern := range db.PQCNamePatterns {
		if re, err := regexp.Compile("(?i)" + pattern); err == nil {
			db.pqcPatterns = append(db.pqcPatterns, re)
		}
	}

	db.hybridPatterns = make([]*regexp.Regexp, 0, len(db.HybridNamePatterns))
	for _, pattern := range db.HybridNamePatterns {
		if re, err := regexp.Compile("(?i)" + pattern); err == nil {
			db.hybridPatterns = append(db.hybridPatterns, re)
		}
	}

	// Build OID lookup map
	db.oidToAlgorithm = make(map[string]*PQCAlgorithmInfo)

	// Add PQC algorithms
	for familyName, algDef := range db.PQCAlgorithms {
		for paramSetName, paramSet := range algDef.ParameterSets {
			info := &PQCAlgorithmInfo{
				Name:          paramSetName,
				Family:        familyName,
				StandardName:  algDef.StandardName,
				ParameterSet:  paramSetName,
				OID:           paramSet.OID,
				NISTLevel:     paramSet.NISTLevel,
				Primitive:     algDef.Primitive,
				IsHybrid:      false,
				ClassicalBits: paramSet.ClassicalBits,
				QuantumBits:   paramSet.QuantumBits,
			}
			db.oidToAlgorithm[paramSet.OID] = info
		}
	}

	// Add hybrid schemes
	for name, hybrid := range db.HybridSchemes {
		info := &PQCAlgorithmInfo{
			Name:               hybrid.DisplayName,
			Family:             "hybrid",
			StandardName:       "",
			ParameterSet:       name,
			OID:                hybrid.OID,
			NISTLevel:          hybrid.NISTLevel,
			Primitive:          "kem",
			IsHybrid:           true,
			ClassicalComponent: hybrid.ClassicalComponent,
			ClassicalBits:      hybrid.ClassicalBits,
			QuantumBits:        hybrid.QuantumBits,
		}
		db.oidToAlgorithm[hybrid.OID] = info
	}

	return &db, nil
}

// Lookup finds vulnerability information for an algorithm
func (db *AlgorithmDatabase) Lookup(algName, oid string, keySize int, curve string) *AlgorithmVulnerability {
	upperName := strings.ToUpper(algName)

	// Try direct name match
	for name, alg := range db.ClassicalAlgorithms {
		if strings.Contains(upperName, strings.ToUpper(name)) {
			return db.buildVulnerability(name, &alg, keySize, curve)
		}
	}

	// Try OID match
	for name, alg := range db.ClassicalAlgorithms {
		for _, algOID := range alg.OIDs {
			if oid != "" && strings.HasPrefix(oid, algOID) {
				return db.buildVulnerability(name, &alg, keySize, curve)
			}
		}
	}

	return nil
}

func (db *AlgorithmDatabase) buildVulnerability(name string, alg *ClassicalAlgorithm, keySize int, curve string) *AlgorithmVulnerability {
	vuln := &AlgorithmVulnerability{
		AlgorithmName:          name,
		AlgorithmFamily:        alg.Family,
		QuantumStatus:          QuantumVulnerabilityStatus(alg.QuantumStatus),
		PrimaryThreat:          QuantumThreat(alg.PrimaryThreat),
		RecommendedReplacement: alg.RecommendedReplacements,
		Notes:                  alg.Notes,
	}

	// Determine security level based on key size or curve
	if alg.FixedSecurityLevel != nil {
		vuln.ClassicalSecurityBits = alg.FixedSecurityLevel.ClassicalBits
		vuln.QuantumSecurityBits = alg.FixedSecurityLevel.QuantumBits
		vuln.NISTQuantumLevel = alg.FixedSecurityLevel.NISTLevel
	} else if keySize > 0 && alg.KeySizeMapping != nil {
		keySizeStr := strconv.Itoa(keySize)
		if mapping, ok := alg.KeySizeMapping[keySizeStr]; ok {
			vuln.ClassicalSecurityBits = mapping.ClassicalBits
			vuln.QuantumSecurityBits = mapping.QuantumBits
			vuln.NISTQuantumLevel = mapping.NISTLevel
			vuln.AlgorithmName = name + "-" + keySizeStr
		} else {
			// Find closest key size
			vuln.ClassicalSecurityBits = db.findClosestKeySize(alg.KeySizeMapping, keySize)
		}
	} else if curve != "" && alg.CurveMapping != nil {
		normalizedCurve := normalizeCurveName(curve)
		if mapping, ok := alg.CurveMapping[normalizedCurve]; ok {
			vuln.ClassicalSecurityBits = mapping.ClassicalBits
			vuln.QuantumSecurityBits = mapping.QuantumBits
			vuln.NISTQuantumLevel = mapping.NISTLevel
			vuln.AlgorithmName = name + "-" + normalizedCurve
		}
	}

	return vuln
}

func (db *AlgorithmDatabase) findClosestKeySize(mapping map[string]SecurityMapping, keySize int) int {
	closest := 0
	closestDiff := int(^uint(0) >> 1) // Max int

	for keySizeStr, m := range mapping {
		if size, err := strconv.Atoi(keySizeStr); err == nil {
			diff := abs(size - keySize)
			if diff < closestDiff {
				closestDiff = diff
				closest = m.ClassicalBits
			}
		}
	}

	return closest
}

func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}

func normalizeCurveName(curve string) string {
	upper := strings.ToUpper(curve)
	switch upper {
	case "SECP256R1", "PRIME256V1":
		return "P-256"
	case "SECP384R1":
		return "P-384"
	case "SECP521R1":
		return "P-521"
	default:
		return upper
	}
}

// LookupByOID finds a PQC algorithm by its OID
func (db *PQCOIDDatabase) LookupByOID(oid string) *PQCAlgorithmInfo {
	if info, ok := db.oidToAlgorithm[oid]; ok {
		return info
	}

	// Try prefix match for OID hierarchies
	for storedOID, info := range db.oidToAlgorithm {
		if strings.HasPrefix(oid, storedOID) || strings.HasPrefix(storedOID, oid) {
			return info
		}
	}

	return nil
}

// LookupByName finds a PQC algorithm by name pattern
func (db *PQCOIDDatabase) LookupByName(name string) *PQCAlgorithmInfo {
	upperName := strings.ToUpper(name)

	// Check for exact parameter set matches
	for _, algDef := range db.PQCAlgorithms {
		for paramSetName, paramSet := range algDef.ParameterSets {
			if strings.Contains(upperName, strings.ToUpper(paramSetName)) {
				return &PQCAlgorithmInfo{
					Name:          paramSetName,
					Family:        algDef.Family,
					StandardName:  algDef.StandardName,
					ParameterSet:  paramSetName,
					OID:           paramSet.OID,
					NISTLevel:     paramSet.NISTLevel,
					Primitive:     algDef.Primitive,
					IsHybrid:      false,
					ClassicalBits: paramSet.ClassicalBits,
					QuantumBits:   paramSet.QuantumBits,
				}
			}
		}
	}

	// Check hybrid schemes
	for hybridName, hybrid := range db.HybridSchemes {
		if strings.Contains(upperName, strings.ToUpper(hybridName)) {
			return &PQCAlgorithmInfo{
				Name:               hybrid.DisplayName,
				Family:             "hybrid",
				ParameterSet:       hybridName,
				OID:                hybrid.OID,
				NISTLevel:          hybrid.NISTLevel,
				Primitive:          "kem",
				IsHybrid:           true,
				ClassicalComponent: hybrid.ClassicalComponent,
				ClassicalBits:      hybrid.ClassicalBits,
				QuantumBits:        hybrid.QuantumBits,
			}
		}
	}

	return nil
}

// IsPQCName checks if a name matches PQC algorithm patterns
func (db *PQCOIDDatabase) IsPQCName(name string) bool {
	for _, re := range db.pqcPatterns {
		if re.MatchString(name) {
			return true
		}
	}
	return false
}

// IsHybridName checks if a name matches hybrid scheme patterns
func (db *PQCOIDDatabase) IsHybridName(name string) bool {
	for _, re := range db.hybridPatterns {
		if re.MatchString(name) {
			return true
		}
	}
	return false
}
