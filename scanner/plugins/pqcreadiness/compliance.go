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
	"strings"
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

// ComplianceResult contains the compliance status across multiple frameworks
type ComplianceResult struct {
	Frameworks          []FrameworkCompliance
	EarliestDeadline    *time.Time
	MostUrgentFramework string
	OverallStatus       string // "compliant", "non-compliant", "transition-needed"
}

// FrameworkCompliance represents compliance status for a single framework
type FrameworkCompliance struct {
	Framework     string     // "CNSA 2.0", "NIST SP 800-131A", "Custom"
	Status        string     // "compliant", "non-compliant", "transition-needed", "deprecated"
	Deadline      *time.Time // Applicable deadline
	DaysRemaining int        // Days until deadline (-1 if no deadline)
	Category      string     // Category within the framework
	Requirements  string     // Description of requirements
	Violations    []string   // Specific violations found
}

// checkComplianceTimelines checks compliance against multiple frameworks
func (plugin *Plugin) checkComplianceTimelines(component *cdx.Component) *ComplianceResult {
	result := &ComplianceResult{
		Frameworks:    []FrameworkCompliance{},
		OverallStatus: "compliant",
	}

	// Check CNSA 2.0 compliance
	if plugin.config.Compliance.CNSA20.Enabled {
		cnsa := plugin.checkCNSA20Compliance(component)
		result.Frameworks = append(result.Frameworks, cnsa)
		result.updateOverallStatus(cnsa)
	}

	// Check NIST SP 800-131A compliance
	if plugin.config.Compliance.NIST.Enabled {
		nist := plugin.checkNIST131ACompliance(component)
		result.Frameworks = append(result.Frameworks, nist)
		result.updateOverallStatus(nist)
	}

	// Check custom organizational deadlines
	if plugin.config.Compliance.Custom.Enabled {
		for _, custom := range plugin.config.Compliance.Custom.Deadlines {
			customResult := plugin.checkCustomCompliance(component, custom)
			if customResult != nil {
				result.Frameworks = append(result.Frameworks, *customResult)
				result.updateOverallStatus(*customResult)
			}
		}
	}

	// Find earliest deadline
	result.findEarliestDeadline()

	return result
}

// updateOverallStatus updates the overall compliance status
func (result *ComplianceResult) updateOverallStatus(framework FrameworkCompliance) {
	switch framework.Status {
	case "non-compliant":
		result.OverallStatus = "non-compliant"
	case "transition-needed":
		if result.OverallStatus == "compliant" {
			result.OverallStatus = "transition-needed"
		}
	case "deprecated":
		if result.OverallStatus == "compliant" {
			result.OverallStatus = "deprecated"
		}
	}
}

// findEarliestDeadline finds the most urgent deadline
func (result *ComplianceResult) findEarliestDeadline() {
	for _, fw := range result.Frameworks {
		if fw.Deadline != nil {
			if result.EarliestDeadline == nil || fw.Deadline.Before(*result.EarliestDeadline) {
				result.EarliestDeadline = fw.Deadline
				result.MostUrgentFramework = fw.Framework
			}
		}
	}
}

// checkCNSA20Compliance checks compliance with CNSA 2.0 requirements
func (plugin *Plugin) checkCNSA20Compliance(component *cdx.Component) FrameworkCompliance {
	result := FrameworkCompliance{
		Framework:     "CNSA 2.0",
		Status:        "compliant",
		DaysRemaining: -1,
		Violations:    []string{},
	}

	// Determine component category
	category := plugin.determineCNSA20Category(component)
	result.Category = category

	// Get applicable deadline
	var deadlineStr string
	switch category {
	case "software-signing":
		deadlineStr = plugin.config.Compliance.CNSA20.SoftwareSigningDeadline
		result.Requirements = "Software/firmware signing must use PQC by deadline"
	case "firmware":
		deadlineStr = plugin.config.Compliance.CNSA20.FirmwareDeadline
		result.Requirements = "Firmware must use PQC by deadline"
	case "networking":
		deadlineStr = plugin.config.Compliance.CNSA20.NetworkingDeadline
		result.Requirements = "Traditional networking equipment must use PQC by deadline"
	case "os-infrastructure":
		deadlineStr = plugin.config.Compliance.CNSA20.OSDeadline
		result.Requirements = "Operating systems and infrastructure must use PQC by deadline"
	default:
		deadlineStr = plugin.config.Compliance.CNSA20.NetworkingDeadline
		result.Requirements = "Default to networking timeline"
	}

	if deadline, err := ParseDeadline(deadlineStr); err == nil {
		result.Deadline = deadline
		result.DaysRemaining = DaysUntil(deadline)
	}

	// Check if component uses quantum-vulnerable algorithms
	quantumStatus := getQuantumStatus(component)
	switch quantumStatus {
	case QuantumVulnerable:
		result.Status = "non-compliant"
		result.Violations = append(result.Violations, "Uses quantum-vulnerable algorithm")
	case QuantumPartiallySecure:
		result.Status = "transition-needed"
		result.Violations = append(result.Violations, "May need key size upgrade for Grover resistance")
	case HybridTransitional:
		result.Status = "transition-needed"
		result.Violations = append(result.Violations, "Using hybrid scheme; full PQC required by deadline")
	case QuantumSafe:
		result.Status = "compliant"
	}

	// Check specific CNSA 2.0 algorithm requirements
	algName := strings.ToUpper(extractAlgorithmName(component))

	// RSA is not approved in CNSA 2.0
	if strings.Contains(algName, "RSA") {
		result.Status = "non-compliant"
		result.Violations = append(result.Violations, "RSA not approved in CNSA 2.0")
	}

	// ECDSA/ECDH with P-384 allowed during transition
	if strings.Contains(algName, "ECDSA") || strings.Contains(algName, "ECDH") {
		curve := extractCurve(component)
		if curve != "P-384" {
			result.Violations = append(result.Violations, "CNSA 2.0 requires P-384 for ECC during transition")
			result.Status = "non-compliant"
		} else {
			result.Status = "transition-needed"
			result.Violations = append(result.Violations, "P-384 allowed only during transition period")
		}
	}

	// Check hash requirements
	if strings.Contains(algName, "SHA-1") || strings.Contains(algName, "SHA1") {
		result.Status = "non-compliant"
		result.Violations = append(result.Violations, "SHA-1 not approved in CNSA 2.0")
	}
	if strings.Contains(algName, "SHA-256") || strings.Contains(algName, "SHA256") {
		if !strings.Contains(algName, "SHA-384") && !strings.Contains(algName, "SHA-512") {
			result.Violations = append(result.Violations, "CNSA 2.0 requires SHA-384 or SHA-512")
		}
	}

	return result
}

// determineCNSA20Category determines which CNSA 2.0 category applies
func (plugin *Plugin) determineCNSA20Category(component *cdx.Component) string {
	if component.Evidence != nil && component.Evidence.Occurrences != nil {
		for _, occ := range *component.Evidence.Occurrences {
			path := strings.ToLower(occ.Location)

			if strings.Contains(path, "signing") || strings.Contains(path, "codesign") ||
				strings.Contains(path, "apksign") || strings.Contains(path, "authenticode") {
				return "software-signing"
			}
			if strings.Contains(path, "firmware") || strings.Contains(path, "uefi") ||
				strings.Contains(path, "bios") {
				return "firmware"
			}
			if strings.Contains(path, "nginx") || strings.Contains(path, "apache") ||
				strings.Contains(path, "ssl") || strings.Contains(path, "tls") {
				return "networking"
			}
		}
	}

	// Default based on component type
	if component.CryptoProperties != nil {
		if component.CryptoProperties.AssetType == cdx.CryptoAssetTypeProtocol {
			return "networking"
		}
	}

	return "networking" // Default
}

// checkNIST131ACompliance checks compliance with NIST SP 800-131A Rev 2
func (plugin *Plugin) checkNIST131ACompliance(component *cdx.Component) FrameworkCompliance {
	result := FrameworkCompliance{
		Framework:     "NIST SP 800-131A",
		Status:        "compliant",
		DaysRemaining: -1,
		Violations:    []string{},
		Requirements:  "Transitioning the Use of Cryptographic Algorithms and Key Lengths",
	}

	algName := strings.ToUpper(extractAlgorithmName(component))
	keySize := extractKeySize(component)

	// SHA-1 for digital signatures is disallowed
	if strings.Contains(algName, "SHA-1") || strings.Contains(algName, "SHA1") {
		if strings.Contains(algName, "SIGN") || strings.Contains(algName, "RSA") ||
			strings.Contains(algName, "DSA") || strings.Contains(algName, "ECDSA") {
			result.Status = "non-compliant"
			result.Violations = append(result.Violations, "SHA-1 disallowed for digital signatures")
		}
	}

	// RSA key sizes
	if strings.Contains(algName, "RSA") {
		if keySize > 0 && keySize < 2048 {
			result.Status = "non-compliant"
			result.Violations = append(result.Violations, fmt.Sprintf("RSA key size %d < 2048 bits disallowed", keySize))
		}
	}

	// DSA key sizes
	if strings.Contains(algName, "DSA") && !strings.Contains(algName, "ECDSA") {
		if keySize > 0 && keySize < 2048 {
			result.Status = "non-compliant"
			result.Violations = append(result.Violations, fmt.Sprintf("DSA key size %d < 2048 bits disallowed", keySize))
		}
	}

	// 3DES is deprecated
	if strings.Contains(algName, "3DES") || strings.Contains(algName, "TRIPLE") ||
		strings.Contains(algName, "DES-EDE") {
		result.Status = "deprecated"
		result.Violations = append(result.Violations, "3DES deprecated as of 2023")
	}

	// MD5 is disallowed
	if strings.Contains(algName, "MD5") {
		result.Status = "non-compliant"
		result.Violations = append(result.Violations, "MD5 disallowed for cryptographic purposes")
	}

	// Check classical security bits
	if component.Properties != nil {
		for _, prop := range *component.Properties {
			if prop.Name == "theia:pqc:classical-security-bits" {
				if bits, err := strconv.Atoi(prop.Value); err == nil && bits < 112 {
					result.Status = "non-compliant"
					result.Violations = append(result.Violations, fmt.Sprintf("Security strength %d bits < 112 bits minimum", bits))
				}
			}
		}
	}

	return result
}

// checkCustomCompliance checks compliance with custom organizational deadlines
func (plugin *Plugin) checkCustomCompliance(component *cdx.Component, custom CustomDeadline) *FrameworkCompliance {
	algName := strings.ToUpper(extractAlgorithmName(component))

	// Check if this custom deadline applies to this algorithm
	applies := false
	for _, alg := range custom.AppliesTo {
		if strings.Contains(algName, strings.ToUpper(alg)) {
			applies = true
			break
		}
	}

	if !applies {
		return nil
	}

	result := &FrameworkCompliance{
		Framework:     "Custom: " + custom.Name,
		Status:        "compliant",
		DaysRemaining: -1,
		Violations:    []string{},
		Requirements:  custom.Name,
	}

	if deadline, err := ParseDeadline(custom.Deadline); err == nil {
		result.Deadline = deadline
		result.DaysRemaining = DaysUntil(deadline)
	}

	// Check quantum status
	quantumStatus := getQuantumStatus(component)
	if quantumStatus == QuantumVulnerable {
		result.Status = "non-compliant"
		result.Violations = append(result.Violations, "Quantum-vulnerable algorithm must be migrated by deadline")
	} else if quantumStatus == HybridTransitional {
		result.Status = "transition-needed"
	}

	return result
}

// enrichWithCompliance adds compliance properties to a component
func (plugin *Plugin) enrichWithCompliance(component *cdx.Component, compliance *ComplianceResult) {
	if component.Properties == nil {
		component.Properties = &[]cdx.Property{}
	}

	props := []cdx.Property{}

	// Overall status
	props = append(props, cdx.Property{
		Name:  "theia:pqc:compliance:overall-status",
		Value: compliance.OverallStatus,
	})

	// Earliest deadline
	if compliance.EarliestDeadline != nil {
		props = append(props, cdx.Property{
			Name:  "theia:pqc:compliance:earliest-deadline",
			Value: compliance.EarliestDeadline.Format("2006-01-02"),
		})
		props = append(props, cdx.Property{
			Name:  "theia:pqc:compliance:days-until-deadline",
			Value: fmt.Sprintf("%d", DaysUntil(compliance.EarliestDeadline)),
		})
		props = append(props, cdx.Property{
			Name:  "theia:pqc:compliance:most-urgent-framework",
			Value: compliance.MostUrgentFramework,
		})
	}

	// Per-framework details
	for _, fw := range compliance.Frameworks {
		prefix := "theia:pqc:compliance:" + strings.ToLower(strings.ReplaceAll(fw.Framework, " ", "-"))

		props = append(props, cdx.Property{
			Name:  prefix + ":status",
			Value: fw.Status,
		})

		if fw.Category != "" {
			props = append(props, cdx.Property{
				Name:  prefix + ":category",
				Value: fw.Category,
			})
		}

		if fw.Deadline != nil {
			props = append(props, cdx.Property{
				Name:  prefix + ":deadline",
				Value: fw.Deadline.Format("2006-01-02"),
			})
		}

		if len(fw.Violations) > 0 {
			props = append(props, cdx.Property{
				Name:  prefix + ":violations",
				Value: strings.Join(fw.Violations, "; "),
			})
		}
	}

	*component.Properties = append(*component.Properties, props...)
}
