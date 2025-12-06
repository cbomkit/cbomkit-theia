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
	"path/filepath"
	"strings"
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

// RiskCategory represents the severity of HNDL risk
type RiskCategory string

const (
	RiskCritical RiskCategory = "critical"
	RiskHigh     RiskCategory = "high"
	RiskMedium   RiskCategory = "medium"
	RiskLow      RiskCategory = "low"
)

// HNDLRiskScore represents the "Harvest Now, Decrypt Later" risk assessment
type HNDLRiskScore struct {
	OverallScore       float64      // 0.0 - 10.0
	Category           RiskCategory // critical, high, medium, low
	DataSensitivity    float64      // 0.0 - 1.0
	CryptoLifetime     float64      // Normalized lifetime score
	VulnerabilityLevel float64      // 0.0 - 1.0 (1.0 = completely broken)
	ExposureLevel      float64      // 0.0 - 1.0 (network-facing vs internal)
	Factors            []RiskFactor // Detailed breakdown
}

// RiskFactor represents a single risk factor contribution
type RiskFactor struct {
	Name        string
	Value       float64
	Weight      float64
	Description string
}

// MigrationPriority represents the urgency of migration to PQC
type MigrationPriority struct {
	Priority        RiskCategory
	Score           float64    // 0.0 - 100.0
	Deadline        *time.Time // Compliance deadline if applicable
	BlockingFactors []string   // What's preventing migration
	RecommendedPath string     // Suggested migration approach
}

// calculateHNDLRisk calculates the Harvest Now, Decrypt Later risk score
func (plugin *Plugin) calculateHNDLRisk(component *cdx.Component, bom *cdx.BOM) *HNDLRiskScore {
	risk := &HNDLRiskScore{
		Factors: []RiskFactor{},
	}

	// Calculate data sensitivity
	risk.DataSensitivity = plugin.calculateDataSensitivity(component)
	risk.Factors = append(risk.Factors, RiskFactor{
		Name:        "data_sensitivity",
		Value:       risk.DataSensitivity,
		Weight:      plugin.config.RiskWeights.DataSensitivity,
		Description: "Estimated sensitivity of data protected by this cryptography",
	})

	// Calculate crypto lifetime
	risk.CryptoLifetime = plugin.calculateCryptoLifetime(component)
	risk.Factors = append(risk.Factors, RiskFactor{
		Name:        "crypto_lifetime",
		Value:       risk.CryptoLifetime,
		Weight:      plugin.config.RiskWeights.CryptoLifetime,
		Description: "Duration the cryptographic protection needs to remain secure",
	})

	// Calculate vulnerability level
	risk.VulnerabilityLevel = plugin.calculateVulnerabilityLevel(component)
	risk.Factors = append(risk.Factors, RiskFactor{
		Name:        "vulnerability_level",
		Value:       risk.VulnerabilityLevel,
		Weight:      plugin.config.RiskWeights.VulnerabilityLevel,
		Description: "Degree to which algorithm is vulnerable to quantum attacks",
	})

	// Calculate exposure level
	risk.ExposureLevel = plugin.calculateExposureLevel(component)
	risk.Factors = append(risk.Factors, RiskFactor{
		Name:        "exposure_level",
		Value:       risk.ExposureLevel,
		Weight:      plugin.config.RiskWeights.ExposureLevel,
		Description: "Network exposure and attack surface",
	})

	// Calculate overall score (weighted sum normalized to 0-10)
	weightedSum := risk.DataSensitivity*plugin.config.RiskWeights.DataSensitivity +
		risk.CryptoLifetime*plugin.config.RiskWeights.CryptoLifetime +
		risk.VulnerabilityLevel*plugin.config.RiskWeights.VulnerabilityLevel +
		risk.ExposureLevel*plugin.config.RiskWeights.ExposureLevel

	totalWeight := plugin.config.RiskWeights.DataSensitivity +
		plugin.config.RiskWeights.CryptoLifetime +
		plugin.config.RiskWeights.VulnerabilityLevel +
		plugin.config.RiskWeights.ExposureLevel

	risk.OverallScore = (weightedSum / totalWeight) * 10.0

	// Determine category
	risk.Category = categorizeRisk(risk.OverallScore)

	return risk
}

// calculateDataSensitivity infers data sensitivity from component properties
func (plugin *Plugin) calculateDataSensitivity(component *cdx.Component) float64 {
	sensitivity := 0.5 // Default medium sensitivity

	// Check file path for sensitivity indicators
	if component.Evidence != nil && component.Evidence.Occurrences != nil {
		for _, occ := range *component.Evidence.Occurrences {
			path := strings.ToLower(occ.Location)

			// Check against configured sensitivity rules
			for _, rule := range plugin.config.SensitivityRules {
				if rule.Pattern != "" {
					matched, _ := filepath.Match(strings.ToLower(rule.Pattern), filepath.Base(path))
					if matched || strings.Contains(path, strings.Trim(rule.Pattern, "*")) {
						if rule.Sensitivity > sensitivity {
							sensitivity = rule.Sensitivity
						}
					}
				}
			}

			// Additional path-based heuristics
			if strings.Contains(path, "pki") || strings.Contains(path, "ca") {
				sensitivity = maxFloat(sensitivity, 0.85)
			}
			if strings.Contains(path, "signing") {
				sensitivity = maxFloat(sensitivity, 0.8)
			}
			if strings.Contains(path, "auth") {
				sensitivity = maxFloat(sensitivity, 0.75)
			}
		}
	}

	// Check for key usage indicators in properties
	if component.Properties != nil {
		for _, prop := range *component.Properties {
			if strings.Contains(prop.Name, "key-usage") || strings.Contains(prop.Name, "keyUsage") {
				for _, rule := range plugin.config.SensitivityRules {
					if rule.KeyUsageContains != "" && strings.Contains(prop.Value, rule.KeyUsageContains) {
						sensitivity = maxFloat(sensitivity, rule.Sensitivity)
					}
				}
			}
		}
	}

	// Certificate signing keys are high sensitivity
	if component.CryptoProperties != nil {
		if component.CryptoProperties.AssetType == cdx.CryptoAssetTypeCertificate {
			sensitivity = maxFloat(sensitivity, 0.7)
		}
	}

	return sensitivity
}

// calculateCryptoLifetime estimates how long the cryptography needs to protect data
func (plugin *Plugin) calculateCryptoLifetime(component *cdx.Component) float64 {
	// Default: assume 10 years of protection needed
	lifetimeYears := 10.0

	// Check certificate validity period
	if component.CryptoProperties != nil && component.CryptoProperties.CertificateProperties != nil {
		certProps := component.CryptoProperties.CertificateProperties
		if certProps.NotValidAfter != "" && certProps.NotValidBefore != "" {
			notAfter, err1 := time.Parse(time.RFC3339, certProps.NotValidAfter)
			notBefore, err2 := time.Parse(time.RFC3339, certProps.NotValidBefore)
			if err1 == nil && err2 == nil {
				validityPeriod := notAfter.Sub(notBefore)
				lifetimeYears = validityPeriod.Hours() / (24 * 365.25)
			}
		}
	}

	// Normalize to 0-1 scale (assuming 20 years is maximum concern)
	normalized := lifetimeYears / 20.0
	if normalized > 1.0 {
		normalized = 1.0
	}

	return normalized
}

// calculateVulnerabilityLevel determines how vulnerable the algorithm is
func (plugin *Plugin) calculateVulnerabilityLevel(component *cdx.Component) float64 {
	// Check quantum status from properties
	if component.Properties != nil {
		for _, prop := range *component.Properties {
			if prop.Name == "theia:pqc:quantum-status" {
				switch QuantumVulnerabilityStatus(prop.Value) {
				case QuantumVulnerable:
					return 1.0 // Completely broken by Shor's algorithm
				case QuantumPartiallySecure:
					return 0.5 // Reduced security (Grover's)
				case HybridTransitional:
					return 0.2 // Hybrid provides some protection
				case QuantumResistant, QuantumSafe:
					return 0.0 // Not vulnerable
				}
			}
		}
	}

	// Default to high vulnerability for unclassified crypto
	return 0.8
}

// calculateExposureLevel determines network exposure
func (plugin *Plugin) calculateExposureLevel(component *cdx.Component) float64 {
	exposure := 0.5 // Default medium exposure

	// Check file path for exposure indicators
	if component.Evidence != nil && component.Evidence.Occurrences != nil {
		for _, occ := range *component.Evidence.Occurrences {
			path := strings.ToLower(occ.Location)

			// Network-facing indicators
			for _, indicator := range plugin.config.ExposureRules.NetworkFacingIndicators {
				if strings.Contains(path, strings.ToLower(indicator)) {
					exposure = maxFloat(exposure, 0.9)
				}
			}

			// Internal indicators
			for _, indicator := range plugin.config.ExposureRules.InternalIndicators {
				if strings.Contains(path, strings.ToLower(indicator)) {
					exposure = minFloat(exposure, 0.3)
				}
			}
		}
	}

	// Check for server authentication (TLS) indicators
	if component.Properties != nil {
		for _, prop := range *component.Properties {
			if strings.Contains(prop.Value, "serverAuth") || strings.Contains(prop.Value, "TLS") {
				exposure = maxFloat(exposure, 0.85)
			}
			if strings.Contains(prop.Value, "clientAuth") {
				exposure = minFloat(exposure, 0.4)
			}
		}
	}

	return exposure
}

// calculateMigrationPriority determines migration urgency
func (plugin *Plugin) calculateMigrationPriority(component *cdx.Component, risk *HNDLRiskScore) *MigrationPriority {
	priority := &MigrationPriority{
		BlockingFactors: []string{},
	}

	// Base priority on risk score
	priority.Score = risk.OverallScore * 10.0 // Convert to 0-100

	// Adjust based on compliance deadlines
	if plugin.config.Compliance.CNSA20.Enabled {
		deadline := plugin.getApplicableCNSA20Deadline(component)
		if deadline != nil {
			priority.Deadline = deadline
			daysRemaining := DaysUntil(deadline)
			if daysRemaining < 365 {
				priority.Score = maxFloat(priority.Score, 90.0)
			} else if daysRemaining < 730 {
				priority.Score = maxFloat(priority.Score, 75.0)
			}
		}
	}

	// Determine priority category
	switch {
	case priority.Score >= 80:
		priority.Priority = RiskCritical
	case priority.Score >= 60:
		priority.Priority = RiskHigh
	case priority.Score >= 40:
		priority.Priority = RiskMedium
	default:
		priority.Priority = RiskLow
	}

	// Determine recommended migration path
	priority.RecommendedPath = plugin.determineRecommendedPath(component, risk)

	// Identify blocking factors
	priority.BlockingFactors = plugin.identifyBlockingFactors(component)

	return priority
}

func (plugin *Plugin) getApplicableCNSA20Deadline(component *cdx.Component) *time.Time {
	// Determine which CNSA 2.0 category applies
	cfg := plugin.config.Compliance.CNSA20

	// Check for signing usage
	if component.Evidence != nil && component.Evidence.Occurrences != nil {
		for _, occ := range *component.Evidence.Occurrences {
			path := strings.ToLower(occ.Location)
			if strings.Contains(path, "signing") || strings.Contains(path, "codesign") {
				if deadline, err := ParseDeadline(cfg.SoftwareSigningDeadline); err == nil {
					return deadline
				}
			}
		}
	}

	// Default to networking deadline for TLS-related crypto
	if deadline, err := ParseDeadline(cfg.NetworkingDeadline); err == nil {
		return deadline
	}

	return nil
}

func (plugin *Plugin) determineRecommendedPath(component *cdx.Component, risk *HNDLRiskScore) string {
	// Check quantum status
	if component.Properties != nil {
		for _, prop := range *component.Properties {
			if prop.Name == "theia:pqc:quantum-status" {
				switch QuantumVulnerabilityStatus(prop.Value) {
				case QuantumVulnerable:
					if risk.OverallScore >= 7.0 {
						return "hybrid-transition" // Immediate action needed
					}
					return "direct" // Can migrate directly
				case HybridTransitional:
					return "complete-transition" // Move from hybrid to pure PQC
				}
			}
		}
	}

	return "requires-analysis"
}

func (plugin *Plugin) identifyBlockingFactors(component *cdx.Component) []string {
	var factors []string

	// Check for legacy indicators
	if component.Properties != nil {
		for _, prop := range *component.Properties {
			if prop.Name == "theia:pqc:classical-security-bits" {
				if prop.Value == "80" || prop.Value == "64" {
					factors = append(factors, "legacy-key-size")
				}
			}
		}
	}

	// Check for CA certificates (harder to migrate)
	if component.CryptoProperties != nil && component.CryptoProperties.AssetType == cdx.CryptoAssetTypeCertificate {
		if component.Properties != nil {
			for _, prop := range *component.Properties {
				if strings.Contains(prop.Name, "key-usage") && strings.Contains(prop.Value, "keyCertSign") {
					factors = append(factors, "ca-certificate")
				}
			}
		}
	}

	return factors
}

// enrichWithRisk adds risk scoring properties to a component
func (plugin *Plugin) enrichWithRisk(component *cdx.Component, risk *HNDLRiskScore) {
	if component.Properties == nil {
		component.Properties = &[]cdx.Property{}
	}

	props := []cdx.Property{
		{
			Name:  "theia:pqc:hndl-risk-score",
			Value: fmt.Sprintf("%.1f", risk.OverallScore),
		},
		{
			Name:  "theia:pqc:hndl-risk-category",
			Value: string(risk.Category),
		},
		{
			Name:  "theia:pqc:risk-data-sensitivity",
			Value: fmt.Sprintf("%.2f", risk.DataSensitivity),
		},
		{
			Name:  "theia:pqc:risk-crypto-lifetime",
			Value: fmt.Sprintf("%.2f", risk.CryptoLifetime),
		},
		{
			Name:  "theia:pqc:risk-vulnerability-level",
			Value: fmt.Sprintf("%.2f", risk.VulnerabilityLevel),
		},
		{
			Name:  "theia:pqc:risk-exposure-level",
			Value: fmt.Sprintf("%.2f", risk.ExposureLevel),
		},
	}

	*component.Properties = append(*component.Properties, props...)
}

// enrichWithMigrationPriority adds migration priority properties to a component
func (plugin *Plugin) enrichWithMigrationPriority(component *cdx.Component, priority *MigrationPriority) {
	if component.Properties == nil {
		component.Properties = &[]cdx.Property{}
	}

	props := []cdx.Property{
		{
			Name:  "theia:pqc:migration-priority",
			Value: string(priority.Priority),
		},
		{
			Name:  "theia:pqc:migration-priority-score",
			Value: fmt.Sprintf("%.1f", priority.Score),
		},
		{
			Name:  "theia:pqc:migration-path",
			Value: priority.RecommendedPath,
		},
	}

	if len(priority.BlockingFactors) > 0 {
		props = append(props, cdx.Property{
			Name:  "theia:pqc:blocking-factors",
			Value: strings.Join(priority.BlockingFactors, ","),
		})
	}

	*component.Properties = append(*component.Properties, props...)
}

func categorizeRisk(score float64) RiskCategory {
	switch {
	case score >= 8.0:
		return RiskCritical
	case score >= 6.0:
		return RiskHigh
	case score >= 4.0:
		return RiskMedium
	default:
		return RiskLow
	}
}

func maxFloat(a, b float64) float64 {
	if a > b {
		return a
	}
	return b
}

func minFloat(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}
