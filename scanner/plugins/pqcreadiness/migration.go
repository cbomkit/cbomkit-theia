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
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

// MigrationGuidance contains recommendations for migrating to PQC
type MigrationGuidance struct {
	RecommendedReplacements []string
	MigrationPath           string // "direct", "hybrid-transition", "requires-analysis"
	BlockingFactors         []string
	Notes                   string
	Urgency                 string // "immediate", "soon", "planned", "monitor"
}

// generateMigrationGuidance creates migration recommendations for a component
func (plugin *Plugin) generateMigrationGuidance(component *cdx.Component) *MigrationGuidance {
	guidance := &MigrationGuidance{
		RecommendedReplacements: []string{},
		BlockingFactors:         []string{},
	}

	// Check if already using PQC
	if isPQCComponent(component) {
		guidance.MigrationPath = "none-required"
		guidance.Notes = "Component already uses post-quantum cryptography"
		guidance.Urgency = "monitor"
		return guidance
	}

	// Get quantum status and existing recommendations
	quantumStatus := getQuantumStatus(component)
	existingReplacements := getExistingReplacements(component)

	if len(existingReplacements) > 0 {
		guidance.RecommendedReplacements = existingReplacements
	} else {
		// Generate recommendations based on algorithm type
		guidance.RecommendedReplacements = plugin.generateReplacementRecommendations(component)
	}

	// Determine migration path based on quantum status
	switch quantumStatus {
	case QuantumVulnerable:
		guidance.MigrationPath = determineVulnerableMigrationPath(component)
		guidance.Urgency = "soon"
	case QuantumPartiallySecure:
		guidance.MigrationPath = "key-size-upgrade"
		guidance.Urgency = "planned"
		guidance.Notes = "Consider upgrading to larger key sizes for Grover resistance"
	case HybridTransitional:
		guidance.MigrationPath = "complete-transition"
		guidance.Urgency = "planned"
		guidance.Notes = "Currently using hybrid scheme; plan transition to pure PQC when ecosystem matures"
	default:
		guidance.MigrationPath = "requires-analysis"
		guidance.Urgency = "monitor"
	}

	// Check for blocking factors
	guidance.BlockingFactors = identifyMigrationBlockers(component)

	// Adjust urgency based on blocking factors
	if len(guidance.BlockingFactors) > 0 && guidance.Urgency == "soon" {
		guidance.Notes = "Migration complexity increased due to: " + strings.Join(guidance.BlockingFactors, ", ")
	}

	return guidance
}

// isPQCComponent checks if component already uses PQC
func isPQCComponent(component *cdx.Component) bool {
	if component.Properties == nil {
		return false
	}
	for _, prop := range *component.Properties {
		if prop.Name == "theia:pqc:is-pqc-algorithm" && prop.Value == "true" {
			return true
		}
		if prop.Name == "theia:pqc:quantum-status" {
			status := QuantumVulnerabilityStatus(prop.Value)
			if status == QuantumSafe || status == HybridTransitional {
				return true
			}
		}
	}
	return false
}

// getQuantumStatus extracts the quantum status from component properties
func getQuantumStatus(component *cdx.Component) QuantumVulnerabilityStatus {
	if component.Properties == nil {
		return QuantumUnknown
	}
	for _, prop := range *component.Properties {
		if prop.Name == "theia:pqc:quantum-status" {
			return QuantumVulnerabilityStatus(prop.Value)
		}
	}
	return QuantumUnknown
}

// getExistingReplacements gets any already-identified replacements
func getExistingReplacements(component *cdx.Component) []string {
	if component.Properties == nil {
		return nil
	}
	for _, prop := range *component.Properties {
		if prop.Name == "theia:pqc:recommended-replacement" {
			return strings.Split(prop.Value, ",")
		}
	}
	return nil
}

// generateReplacementRecommendations creates PQC replacement recommendations
func (plugin *Plugin) generateReplacementRecommendations(component *cdx.Component) []string {
	algName := strings.ToUpper(extractAlgorithmName(component))
	primitive := getPrimitive(component)

	// Map algorithms to recommended PQC replacements
	switch {
	case strings.Contains(algName, "RSA"):
		if primitive == "signature" || strings.Contains(algName, "SIGN") {
			return []string{"ML-DSA-65", "ML-DSA-87", "SLH-DSA-SHA2-128f"}
		}
		return []string{"ML-KEM-768", "ML-KEM-1024"}

	case strings.Contains(algName, "ECDSA") || strings.Contains(algName, "ED25519") || strings.Contains(algName, "ED448"):
		return []string{"ML-DSA-65", "ML-DSA-87", "SLH-DSA-SHA2-128f"}

	case strings.Contains(algName, "ECDH") || strings.Contains(algName, "X25519") || strings.Contains(algName, "X448"):
		return []string{"ML-KEM-768", "X25519Kyber768"}

	case strings.Contains(algName, "DH"):
		return []string{"ML-KEM-768", "ML-KEM-1024"}

	case strings.Contains(algName, "DSA"):
		return []string{"ML-DSA-65", "ML-DSA-87"}

	case strings.Contains(algName, "AES-128"):
		return []string{"AES-256"} // Key size upgrade for Grover resistance

	default:
		// Generic recommendations based on primitive
		if primitive == "signature" {
			return []string{"ML-DSA-65"}
		} else if primitive == "key-agreement" || primitive == "kem" || primitive == "pke" {
			return []string{"ML-KEM-768"}
		}
	}

	return []string{}
}

// getPrimitive extracts the cryptographic primitive from component
func getPrimitive(component *cdx.Component) string {
	if component.CryptoProperties != nil && component.CryptoProperties.AlgorithmProperties != nil {
		// Convert CycloneDX primitive to string
		return string(component.CryptoProperties.AlgorithmProperties.Primitive)
	}
	return ""
}

// determineVulnerableMigrationPath determines the best migration approach for vulnerable algorithms
func determineVulnerableMigrationPath(component *cdx.Component) string {
	// Check if this is a CA or root certificate (harder to migrate)
	if isCAOrRoot(component) {
		return "hybrid-transition" // Recommend hybrid for critical infrastructure
	}

	// Check for TLS/network usage (can use hybrid for compatibility)
	if isNetworkFacing(component) {
		return "hybrid-transition"
	}

	// For internal/application crypto, direct migration may be possible
	return "direct"
}

// isCAOrRoot checks if component is a CA or root certificate
func isCAOrRoot(component *cdx.Component) bool {
	if component.Properties == nil {
		return false
	}
	for _, prop := range *component.Properties {
		if strings.Contains(prop.Name, "key-usage") && strings.Contains(prop.Value, "keyCertSign") {
			return true
		}
	}
	// Check name for CA indicators
	name := strings.ToLower(component.Name)
	return strings.Contains(name, "root") || strings.Contains(name, "ca") || strings.Contains(name, "authority")
}

// isNetworkFacing checks if component is used for network/TLS
func isNetworkFacing(component *cdx.Component) bool {
	if component.Evidence != nil && component.Evidence.Occurrences != nil {
		for _, occ := range *component.Evidence.Occurrences {
			path := strings.ToLower(occ.Location)
			if strings.Contains(path, "ssl") || strings.Contains(path, "tls") ||
				strings.Contains(path, "nginx") || strings.Contains(path, "apache") {
				return true
			}
		}
	}
	if component.Properties != nil {
		for _, prop := range *component.Properties {
			if strings.Contains(prop.Value, "serverAuth") || strings.Contains(prop.Value, "TLS") {
				return true
			}
		}
	}
	return false
}

// identifyMigrationBlockers identifies factors that complicate migration
func identifyMigrationBlockers(component *cdx.Component) []string {
	var blockers []string

	// CA certificates are harder to migrate
	if isCAOrRoot(component) {
		blockers = append(blockers, "ca-certificate")
	}

	// Long-validity certificates
	if component.CryptoProperties != nil && component.CryptoProperties.CertificateProperties != nil {
		// Already validated in risk scoring, but flag for migration
	}

	// Check for HSM indicators (hardware constraints)
	if component.Evidence != nil && component.Evidence.Occurrences != nil {
		for _, occ := range *component.Evidence.Occurrences {
			path := strings.ToLower(occ.Location)
			if strings.Contains(path, "hsm") || strings.Contains(path, "pkcs11") {
				blockers = append(blockers, "hsm-dependency")
			}
		}
	}

	// Interoperability concerns for network-facing
	if isNetworkFacing(component) {
		blockers = append(blockers, "interoperability-requirements")
	}

	return blockers
}

// enrichWithGuidance adds migration guidance properties to a component
func (plugin *Plugin) enrichWithGuidance(component *cdx.Component, guidance *MigrationGuidance) {
	if component.Properties == nil {
		component.Properties = &[]cdx.Property{}
	}

	props := []cdx.Property{}

	// Add recommendations if not already present
	if len(guidance.RecommendedReplacements) > 0 {
		existing := false
		for _, prop := range *component.Properties {
			if prop.Name == "theia:pqc:recommended-replacement" {
				existing = true
				break
			}
		}
		if !existing {
			props = append(props, cdx.Property{
				Name:  "theia:pqc:recommended-replacement",
				Value: strings.Join(guidance.RecommendedReplacements, ","),
			})
		}
	}

	// Add migration path if not already present
	existing := false
	for _, prop := range *component.Properties {
		if prop.Name == "theia:pqc:migration-path" {
			existing = true
			break
		}
	}
	if !existing && guidance.MigrationPath != "" {
		props = append(props, cdx.Property{
			Name:  "theia:pqc:migration-path",
			Value: guidance.MigrationPath,
		})
	}

	// Add urgency
	if guidance.Urgency != "" {
		props = append(props, cdx.Property{
			Name:  "theia:pqc:migration-urgency",
			Value: guidance.Urgency,
		})
	}

	// Add notes if present
	if guidance.Notes != "" {
		props = append(props, cdx.Property{
			Name:  "theia:pqc:migration-notes",
			Value: guidance.Notes,
		})
	}

	if len(props) > 0 {
		*component.Properties = append(*component.Properties, props...)
	}
}
