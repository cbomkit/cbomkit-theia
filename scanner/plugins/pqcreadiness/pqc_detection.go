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
	"fmt"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

// PQCDetectionResult contains the result of PQC algorithm detection
type PQCDetectionResult struct {
	Algorithm          *PQCAlgorithmInfo
	DetectionMethod    string  // "oid", "name-pattern", "config"
	Confidence         float64 // 0.0-1.0
	IsHybridDeployment bool
	HybridPartner      string // Classical algorithm in hybrid
}

// detectPQCAlgorithm checks if a component uses a PQC algorithm
func (plugin *Plugin) detectPQCAlgorithm(component *cdx.Component) *PQCDetectionResult {
	// First try OID detection (highest confidence)
	if oid := extractOID(component); oid != "" {
		if info := plugin.pqcOIDDB.LookupByOID(oid); info != nil {
			return &PQCDetectionResult{
				Algorithm:          info,
				DetectionMethod:    "oid",
				Confidence:         1.0,
				IsHybridDeployment: info.IsHybrid,
				HybridPartner:      info.ClassicalComponent,
			}
		}
	}

	// Try name-based detection
	name := component.Name
	if name != "" {
		// Check for PQC algorithm names
		if info := plugin.pqcOIDDB.LookupByName(name); info != nil {
			return &PQCDetectionResult{
				Algorithm:          info,
				DetectionMethod:    "name-pattern",
				Confidence:         0.9,
				IsHybridDeployment: info.IsHybrid,
				HybridPartner:      info.ClassicalComponent,
			}
		}

		// Check if name matches PQC patterns
		if plugin.pqcOIDDB.IsPQCName(name) {
			return &PQCDetectionResult{
				Algorithm: &PQCAlgorithmInfo{
					Name:      name,
					Family:    "pqc-unknown",
					NISTLevel: 0,
					IsHybrid:  plugin.pqcOIDDB.IsHybridName(name),
				},
				DetectionMethod:    "name-pattern",
				Confidence:         0.7,
				IsHybridDeployment: plugin.pqcOIDDB.IsHybridName(name),
			}
		}
	}

	// Check crypto properties for PQC indicators
	if component.CryptoProperties != nil {
		if algProps := component.CryptoProperties.AlgorithmProperties; algProps != nil {
			paramSet := algProps.ParameterSetIdentifier
			if paramSet != "" && plugin.pqcOIDDB.IsPQCName(paramSet) {
				if info := plugin.pqcOIDDB.LookupByName(paramSet); info != nil {
					return &PQCDetectionResult{
						Algorithm:          info,
						DetectionMethod:    "crypto-properties",
						Confidence:         0.85,
						IsHybridDeployment: info.IsHybrid,
						HybridPartner:      info.ClassicalComponent,
					}
				}
			}
		}
	}

	return nil
}

// enrichWithPQC adds PQC-related properties to a component
func (plugin *Plugin) enrichWithPQC(component *cdx.Component, result *PQCDetectionResult) {
	if component.Properties == nil {
		component.Properties = &[]cdx.Property{}
	}

	props := []cdx.Property{
		{
			Name:  "theia:pqc:is-pqc-algorithm",
			Value: "true",
		},
		{
			Name:  "theia:pqc:algorithm-family",
			Value: result.Algorithm.Family,
		},
		{
			Name:  "theia:pqc:detection-method",
			Value: result.DetectionMethod,
		},
		{
			Name:  "theia:pqc:detection-confidence",
			Value: fmt.Sprintf("%.2f", result.Confidence),
		},
	}

	// Set quantum status based on whether it's hybrid or pure PQC
	if result.IsHybridDeployment {
		props = append(props, cdx.Property{
			Name:  "theia:pqc:quantum-status",
			Value: string(HybridTransitional),
		})
		props = append(props, cdx.Property{
			Name:  "theia:pqc:is-hybrid",
			Value: "true",
		})
		if result.HybridPartner != "" {
			props = append(props, cdx.Property{
				Name:  "theia:pqc:hybrid-classical-component",
				Value: result.HybridPartner,
			})
		}
	} else {
		props = append(props, cdx.Property{
			Name:  "theia:pqc:quantum-status",
			Value: string(QuantumSafe),
		})
		props = append(props, cdx.Property{
			Name:  "theia:pqc:is-hybrid",
			Value: "false",
		})
	}

	// Add standard name if available
	if result.Algorithm.StandardName != "" {
		props = append(props, cdx.Property{
			Name:  "theia:pqc:standard",
			Value: result.Algorithm.StandardName,
		})
	}

	// Add NIST level
	if result.Algorithm.NISTLevel > 0 {
		props = append(props, cdx.Property{
			Name:  "theia:pqc:nist-quantum-level",
			Value: fmt.Sprintf("%d", result.Algorithm.NISTLevel),
		})
	}

	// Add security bits
	if result.Algorithm.ClassicalBits > 0 {
		props = append(props, cdx.Property{
			Name:  "theia:pqc:classical-security-bits",
			Value: fmt.Sprintf("%d", result.Algorithm.ClassicalBits),
		})
	}
	if result.Algorithm.QuantumBits > 0 {
		props = append(props, cdx.Property{
			Name:  "theia:pqc:quantum-security-bits",
			Value: fmt.Sprintf("%d", result.Algorithm.QuantumBits),
		})
	}

	// Add quantum threat (none for PQC)
	props = append(props, cdx.Property{
		Name:  "theia:pqc:quantum-threat",
		Value: string(ThreatNone),
	})

	*component.Properties = append(*component.Properties, props...)
}

// detectPQCInName checks if a string contains PQC algorithm indicators
func detectPQCInName(name string) (isPQC bool, isHybrid bool, family string) {
	lowerName := strings.ToLower(name)

	// PQC algorithm families
	pqcFamilies := map[string]string{
		"kyber":     "ML-KEM",
		"ml-kem":    "ML-KEM",
		"mlkem":     "ML-KEM",
		"dilithium": "ML-DSA",
		"ml-dsa":    "ML-DSA",
		"mldsa":     "ML-DSA",
		"sphincs":   "SLH-DSA",
		"slh-dsa":   "SLH-DSA",
		"falcon":    "FN-DSA",
		"fn-dsa":    "FN-DSA",
	}

	// Check for PQC families
	for pattern, familyName := range pqcFamilies {
		if strings.Contains(lowerName, pattern) {
			isPQC = true
			family = familyName
			break
		}
	}

	// Check for hybrid patterns
	hybridPatterns := []string{
		"x25519kyber", "x25519_kyber", "x25519-kyber",
		"p256kyber", "p256_kyber", "p256-kyber",
		"p384kyber", "p384_kyber", "p384-kyber",
		"ecdh+", "ecdh-", "ecdh_",
	}

	for _, pattern := range hybridPatterns {
		if strings.Contains(lowerName, pattern) {
			isHybrid = true
			if !isPQC {
				isPQC = true
				family = "hybrid"
			}
			break
		}
	}

	return
}
