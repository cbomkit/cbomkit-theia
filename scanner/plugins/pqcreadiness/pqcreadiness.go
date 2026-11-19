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
	"github.com/cbomkit/cbomkit-theia/provider/cyclonedx"
	"github.com/cbomkit/cbomkit-theia/provider/filesystem"
	"github.com/cbomkit/cbomkit-theia/scanner/plugins"
	cdx "github.com/CycloneDX/cyclonedx-go"
	log "github.com/sirupsen/logrus"
)

// Plugin implements the PQC Readiness Assessment
type Plugin struct {
	config      *PQCConfig
	algorithmDB *AlgorithmDatabase
	pqcOIDDB    *PQCOIDDatabase
}

// GetName returns the name of the plugin
func (*Plugin) GetName() string {
	return "PQC Readiness Assessment Plugin"
}

// GetExplanation returns a description of what the plugin does
func (*Plugin) GetExplanation() string {
	return "Assess post-quantum cryptography readiness by classifying quantum vulnerability of cryptographic assets, detecting PQC algorithms, calculating HNDL risk scores, and providing migration guidance with compliance tracking (CNSA 2.0, NIST SP 800-131A)"
}

// GetType returns the plugin type
func (*Plugin) GetType() plugins.PluginType {
	return plugins.PluginTypeVerify
}

// NewPQCReadinessPlugin creates a new instance of the PQC Readiness Assessment Plugin
func NewPQCReadinessPlugin() (plugins.Plugin, error) {
	// Load configuration
	config, err := loadConfig()
	if err != nil {
		log.WithError(err).Debug("Could not load PQC config, using defaults")
		config = getDefaultConfig()
	}

	// Load algorithm database
	algorithmDB, err := loadAlgorithmDatabase()
	if err != nil {
		return nil, err
	}

	// Load PQC OID database
	pqcOIDDB, err := loadPQCOIDDatabase()
	if err != nil {
		return nil, err
	}

	return &Plugin{
		config:      config,
		algorithmDB: algorithmDB,
		pqcOIDDB:    pqcOIDDB,
	}, nil
}

// UpdateBOM enriches the BOM with PQC readiness information
func (plugin *Plugin) UpdateBOM(fs filesystem.Filesystem, bom *cdx.BOM) error {
	if bom.Components == nil {
		bom.Components = new([]cdx.Component)
	}

	stats := &ProcessingStats{}

	// Phase 1: Scan filesystem for PQC configurations (creates new components)
	if plugin.config.Features.PQCDetection {
		pqcComponents, err := plugin.scanForPQCConfigurations(fs)
		if err != nil {
			log.WithError(err).Warn("PQC configuration scanning failed")
		}
		if len(pqcComponents) > 0 {
			cyclonedx.AddComponents(bom, pqcComponents)
			stats.PQCFound += len(pqcComponents)
			log.WithField("count", len(pqcComponents)).Info("Added PQC configuration components")
		}
	}

	// Phase 2: Enrich existing components
	for i := range *bom.Components {
		component := &(*bom.Components)[i]

		if !isCryptoComponent(component) {
			continue
		}
		stats.TotalCrypto++

		// 1. Classify quantum vulnerability
		if plugin.config.Features.VulnerabilityClassification {
			if vuln := plugin.classifyQuantumVulnerability(component); vuln != nil {
				plugin.enrichWithVulnerability(component, vuln)
				if vuln.QuantumStatus == QuantumVulnerable {
					stats.VulnerableCount++
				}
			}
		}

		// 2. Detect PQC algorithms (mark hybrid-transitional for hybrids)
		if plugin.config.Features.PQCDetection {
			if pqc := plugin.detectPQCAlgorithm(component); pqc != nil {
				plugin.enrichWithPQC(component, pqc)
				stats.PQCFound++
			}
		}

		// 3. Calculate security levels
		if plugin.config.Features.SecurityLevelCalculation {
			level := plugin.calculateSecurityLevel(component)
			plugin.setSecurityLevels(component, level)
		}

		// 4. Calculate risk scores (vulnerable components only)
		if plugin.config.Features.RiskScoring && isVulnerable(component) {
			risk := plugin.calculateHNDLRisk(component, bom)
			plugin.enrichWithRisk(component, risk)

			priority := plugin.calculateMigrationPriority(component, risk)
			plugin.enrichWithMigrationPriority(component, priority)
		}

		// 5. Add migration guidance
		if plugin.config.Features.MigrationGuidance {
			guidance := plugin.generateMigrationGuidance(component)
			plugin.enrichWithGuidance(component, guidance)
		}

		// 6. Check compliance timelines (CNSA 2.0, NIST, custom)
		if plugin.config.Features.ComplianceTracking {
			compliance := plugin.checkComplianceTimelines(component)
			plugin.enrichWithCompliance(component, compliance)
		}
	}

	log.WithFields(log.Fields{
		"total_crypto": stats.TotalCrypto,
		"vulnerable":   stats.VulnerableCount,
		"pqc_found":    stats.PQCFound,
	}).Info("PQC Readiness Assessment completed")

	return nil
}

// ProcessingStats tracks statistics during BOM processing
type ProcessingStats struct {
	TotalCrypto     int
	VulnerableCount int
	PQCFound        int
}

// isCryptoComponent checks if a component is a cryptographic asset
func isCryptoComponent(component *cdx.Component) bool {
	if component.Type != cdx.ComponentTypeCryptographicAsset {
		return false
	}
	if component.CryptoProperties == nil {
		return false
	}
	return true
}

// isVulnerable checks if a component has been marked as quantum-vulnerable
func isVulnerable(component *cdx.Component) bool {
	if component.Properties == nil {
		return false
	}
	for _, prop := range *component.Properties {
		if prop.Name == "theia:pqc:quantum-status" && prop.Value == string(QuantumVulnerable) {
			return true
		}
	}
	return false
}
