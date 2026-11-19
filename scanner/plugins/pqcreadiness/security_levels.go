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
	"strconv"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

// SecurityLevel represents computed security levels for a cryptographic component
type SecurityLevel struct {
	ClassicalBits         int     // Classical (pre-quantum) security bits
	QuantumBits           int     // Post-quantum security bits
	NISTLevel             int     // NIST quantum security level (0-5)
	EffectiveSecurityBits int     // Minimum of classical/quantum considering threats
	Confidence            float64 // How confident we are in this assessment
}

// calculateSecurityLevel computes security levels for a component
func (plugin *Plugin) calculateSecurityLevel(component *cdx.Component) *SecurityLevel {
	level := &SecurityLevel{
		Confidence: 1.0,
	}

	// First check if we already have security bits from vulnerability classification
	if component.Properties != nil {
		for _, prop := range *component.Properties {
			switch prop.Name {
			case "theia:pqc:classical-security-bits":
				if bits, err := strconv.Atoi(prop.Value); err == nil {
					level.ClassicalBits = bits
				}
			case "theia:pqc:quantum-security-bits":
				if bits, err := strconv.Atoi(prop.Value); err == nil {
					level.QuantumBits = bits
				}
			case "theia:pqc:nist-quantum-level":
				if l, err := strconv.Atoi(prop.Value); err == nil {
					level.NISTLevel = l
				}
			}
		}
	}

	// If we already have computed values, just calculate effective security
	if level.ClassicalBits > 0 || level.QuantumBits > 0 {
		level.calculateEffectiveSecurityBits()
		return level
	}

	// Otherwise, try to compute from algorithm information
	algName := extractAlgorithmName(component)
	keySize := extractKeySize(component)
	curve := extractCurve(component)

	// Look up in database
	if vuln := plugin.algorithmDB.Lookup(algName, "", keySize, curve); vuln != nil {
		level.ClassicalBits = vuln.ClassicalSecurityBits
		level.QuantumBits = vuln.QuantumSecurityBits
		level.NISTLevel = vuln.NISTQuantumLevel
		level.calculateEffectiveSecurityBits()
		return level
	}

	// Use inference
	inferredVuln := plugin.inferVulnerability(algName, keySize, curve, component)
	if inferredVuln != nil {
		level.ClassicalBits = inferredVuln.ClassicalSecurityBits
		level.QuantumBits = inferredVuln.QuantumSecurityBits
		level.NISTLevel = inferredVuln.NISTQuantumLevel
		level.Confidence = 0.7 // Lower confidence for inferred values
	}

	level.calculateEffectiveSecurityBits()
	return level
}

// calculateEffectiveSecurityBits determines the effective security level
func (level *SecurityLevel) calculateEffectiveSecurityBits() {
	// Effective security is the minimum of classical and quantum
	// For quantum-vulnerable algorithms, quantum bits is 0
	if level.QuantumBits == 0 {
		level.EffectiveSecurityBits = 0 // Quantum-vulnerable
	} else if level.ClassicalBits == 0 {
		level.EffectiveSecurityBits = level.QuantumBits
	} else {
		level.EffectiveSecurityBits = min(level.ClassicalBits, level.QuantumBits)
	}
}

// setSecurityLevels adds security level properties to a component
func (plugin *Plugin) setSecurityLevels(component *cdx.Component, level *SecurityLevel) {
	if component.Properties == nil {
		component.Properties = &[]cdx.Property{}
	}

	// Check if properties already exist and update them
	existingProps := make(map[string]bool)
	for _, prop := range *component.Properties {
		existingProps[prop.Name] = true
	}

	props := []cdx.Property{}

	if !existingProps["theia:pqc:classical-security-bits"] && level.ClassicalBits > 0 {
		props = append(props, cdx.Property{
			Name:  "theia:pqc:classical-security-bits",
			Value: fmt.Sprintf("%d", level.ClassicalBits),
		})
	}

	if !existingProps["theia:pqc:quantum-security-bits"] {
		props = append(props, cdx.Property{
			Name:  "theia:pqc:quantum-security-bits",
			Value: fmt.Sprintf("%d", level.QuantumBits),
		})
	}

	if !existingProps["theia:pqc:nist-quantum-level"] {
		props = append(props, cdx.Property{
			Name:  "theia:pqc:nist-quantum-level",
			Value: fmt.Sprintf("%d", level.NISTLevel),
		})
	}

	// Always add effective security bits
	props = append(props, cdx.Property{
		Name:  "theia:pqc:effective-security-bits",
		Value: fmt.Sprintf("%d", level.EffectiveSecurityBits),
	})

	// Add confidence if not perfect
	if level.Confidence < 1.0 {
		props = append(props, cdx.Property{
			Name:  "theia:pqc:security-level-confidence",
			Value: fmt.Sprintf("%.2f", level.Confidence),
		})
	}

	*component.Properties = append(*component.Properties, props...)
}

// GetSecurityClassification returns a human-readable security classification
func (level *SecurityLevel) GetSecurityClassification() string {
	switch {
	case level.EffectiveSecurityBits == 0:
		return "quantum-vulnerable"
	case level.EffectiveSecurityBits < 80:
		return "weak"
	case level.EffectiveSecurityBits < 112:
		return "legacy"
	case level.EffectiveSecurityBits < 128:
		return "acceptable"
	case level.EffectiveSecurityBits < 192:
		return "strong"
	case level.EffectiveSecurityBits < 256:
		return "very-strong"
	default:
		return "maximum"
	}
}

// GetNISTLevelDescription returns a description for the NIST security level
func GetNISTLevelDescription(level int) string {
	switch level {
	case 0:
		return "Not quantum-safe (broken by quantum computers)"
	case 1:
		return "At least as hard to break as AES-128 (NIST Level 1)"
	case 2:
		return "At least as hard to break as SHA-256/AES-128 (NIST Level 2)"
	case 3:
		return "At least as hard to break as AES-192 (NIST Level 3)"
	case 4:
		return "At least as hard to break as SHA-384/AES-192 (NIST Level 4)"
	case 5:
		return "At least as hard to break as AES-256 (NIST Level 5)"
	default:
		return "Unknown NIST level"
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
