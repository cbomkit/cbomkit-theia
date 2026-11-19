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
	"os"
	"path/filepath"
	"time"

	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v3"
)

// PQCConfig contains configuration for the PQC Readiness plugin
type PQCConfig struct {
	Features           FeatureFlags           `yaml:"features"`
	RiskWeights        RiskWeights            `yaml:"risk_weights"`
	SensitivityRules   []SensitivityRule      `yaml:"sensitivity_rules"`
	Compliance         ComplianceConfig       `yaml:"compliance"`
	CustomPQCAlgorithms []CustomPQCAlgorithm  `yaml:"custom_pqc_algorithms"`
	ExposureRules      ExposureRules          `yaml:"exposure_rules"`
}

// FeatureFlags controls which features are enabled
type FeatureFlags struct {
	VulnerabilityClassification bool `yaml:"vulnerability_classification"`
	PQCDetection                bool `yaml:"pqc_detection"`
	RiskScoring                 bool `yaml:"risk_scoring"`
	SecurityLevelCalculation    bool `yaml:"security_level_calculation"`
	MigrationGuidance           bool `yaml:"migration_guidance"`
	ComplianceTracking          bool `yaml:"compliance_tracking"`
}

// RiskWeights defines the weights for risk score calculation
type RiskWeights struct {
	DataSensitivity    float64 `yaml:"data_sensitivity"`
	CryptoLifetime     float64 `yaml:"crypto_lifetime"`
	VulnerabilityLevel float64 `yaml:"vulnerability_level"`
	ExposureLevel      float64 `yaml:"exposure_level"`
}

// SensitivityRule defines rules for inferring data sensitivity
type SensitivityRule struct {
	Pattern           string  `yaml:"pattern"`
	KeyUsageContains  string  `yaml:"key_usage_contains"`
	Sensitivity       float64 `yaml:"sensitivity"`
}

// ComplianceConfig contains compliance framework configurations
type ComplianceConfig struct {
	CNSA20  CNSA20Config  `yaml:"cnsa_2_0"`
	NIST    NISTConfig    `yaml:"nist"`
	Custom  CustomConfig  `yaml:"custom"`
}

// CNSA20Config contains CNSA 2.0 compliance deadlines
type CNSA20Config struct {
	Enabled                 bool   `yaml:"enabled"`
	SoftwareSigningDeadline string `yaml:"software_signing_deadline"`
	FirmwareDeadline        string `yaml:"firmware_deadline"`
	NetworkingDeadline      string `yaml:"networking_deadline"`
	OSDeadline              string `yaml:"os_deadline"`
}

// NISTConfig contains NIST SP 800-131A compliance settings
type NISTConfig struct {
	Enabled bool `yaml:"enabled"`
}

// CustomConfig contains custom organizational compliance settings
type CustomConfig struct {
	Enabled   bool             `yaml:"enabled"`
	Deadlines []CustomDeadline `yaml:"deadlines"`
}

// CustomDeadline represents a custom organizational deadline
type CustomDeadline struct {
	Name      string   `yaml:"name"`
	Deadline  string   `yaml:"deadline"`
	AppliesTo []string `yaml:"applies_to"`
}

// CustomPQCAlgorithm allows users to define custom PQC algorithms
type CustomPQCAlgorithm struct {
	Name      string   `yaml:"name"`
	Family    string   `yaml:"family"`
	OIDs      []string `yaml:"oids"`
	NISTLevel int      `yaml:"nist_level"`
	Primitive string   `yaml:"primitive"`
}

// ExposureRules defines rules for determining exposure level
type ExposureRules struct {
	NetworkFacingIndicators []string `yaml:"network_facing_indicators"`
	InternalIndicators      []string `yaml:"internal_indicators"`
}

// loadConfig loads the PQC configuration from the user's config directory
func loadConfig() (*PQCConfig, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}

	configPath := filepath.Join(homeDir, ".cbomkit-theia", "pqc_config.yaml")

	// Check if file exists
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		log.Debug("No PQC config file found, using defaults")
		return getDefaultConfig(), nil
	}

	// Read file
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, err
	}

	// Parse YAML
	var wrapper struct {
		PQCReadiness PQCConfig `yaml:"pqc_readiness"`
	}
	if err := yaml.Unmarshal(data, &wrapper); err != nil {
		return nil, err
	}

	// Merge with defaults
	config := getDefaultConfig()
	mergeConfig(config, &wrapper.PQCReadiness)

	log.Info("Loaded PQC configuration from file")
	return config, nil
}

// getDefaultConfig returns the default configuration
func getDefaultConfig() *PQCConfig {
	return &PQCConfig{
		Features: FeatureFlags{
			VulnerabilityClassification: true,
			PQCDetection:                true,
			RiskScoring:                 true,
			SecurityLevelCalculation:    true,
			MigrationGuidance:           true,
			ComplianceTracking:          true,
		},
		RiskWeights: RiskWeights{
			DataSensitivity:    0.30,
			CryptoLifetime:     0.25,
			VulnerabilityLevel: 0.30,
			ExposureLevel:      0.15,
		},
		SensitivityRules: []SensitivityRule{
			{Pattern: "*.gov.*", Sensitivity: 1.0},
			{Pattern: "*healthcare*", Sensitivity: 0.9},
			{Pattern: "*financial*", Sensitivity: 0.9},
			{Pattern: "*pii*", Sensitivity: 0.8},
			{KeyUsageContains: "keyCertSign", Sensitivity: 0.85},
			{KeyUsageContains: "digitalSignature", Sensitivity: 0.7},
		},
		Compliance: ComplianceConfig{
			CNSA20: CNSA20Config{
				Enabled:                 true,
				SoftwareSigningDeadline: "2025-12-31",
				FirmwareDeadline:        "2027-12-31",
				NetworkingDeadline:      "2030-12-31",
				OSDeadline:              "2033-12-31",
			},
			NIST: NISTConfig{
				Enabled: true,
			},
			Custom: CustomConfig{
				Enabled:   false,
				Deadlines: []CustomDeadline{},
			},
		},
		ExposureRules: ExposureRules{
			NetworkFacingIndicators: []string{
				"/etc/nginx",
				"/etc/apache2",
				"/etc/ssl",
				"serverAuth",
			},
			InternalIndicators: []string{
				"/internal",
				"clientAuth",
			},
		},
	}
}

// mergeConfig merges user config with defaults
func mergeConfig(base, user *PQCConfig) {
	// Only override if user has set values
	if user.Features.VulnerabilityClassification || user.Features.PQCDetection ||
		user.Features.RiskScoring || user.Features.SecurityLevelCalculation ||
		user.Features.MigrationGuidance || user.Features.ComplianceTracking {
		base.Features = user.Features
	}

	if user.RiskWeights.DataSensitivity > 0 {
		base.RiskWeights = user.RiskWeights
	}

	if len(user.SensitivityRules) > 0 {
		base.SensitivityRules = user.SensitivityRules
	}

	if user.Compliance.CNSA20.SoftwareSigningDeadline != "" {
		base.Compliance.CNSA20 = user.Compliance.CNSA20
	}

	if len(user.Compliance.Custom.Deadlines) > 0 {
		base.Compliance.Custom = user.Compliance.Custom
	}

	if len(user.CustomPQCAlgorithms) > 0 {
		base.CustomPQCAlgorithms = user.CustomPQCAlgorithms
	}

	if len(user.ExposureRules.NetworkFacingIndicators) > 0 {
		base.ExposureRules = user.ExposureRules
	}
}

// ParseDeadline parses a deadline string into a time.Time
func ParseDeadline(deadline string) (*time.Time, error) {
	t, err := time.Parse("2006-01-02", deadline)
	if err != nil {
		return nil, err
	}
	return &t, nil
}

// DaysUntil calculates the number of days until a deadline
func DaysUntil(deadline *time.Time) int {
	if deadline == nil {
		return -1
	}
	duration := time.Until(*deadline)
	return int(duration.Hours() / 24)
}
