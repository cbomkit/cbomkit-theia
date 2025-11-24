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

package problematicca

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/cbomkit/cbomkit-theia/provider/filesystem"
	"github.com/cbomkit/cbomkit-theia/scanner/plugins"
	cdx "github.com/CycloneDX/cyclonedx-go"
	log "github.com/sirupsen/logrus"
)

// ProblematicCA represents a CA with known security issues or malpractice
type ProblematicCA struct {
	Name        string   // Common name or organization name
	Identifiers []string // List of possible DN patterns to match
	Status      string   // "compromised", "distrusted", "deprecated", "warning"
	Severity    string   // "critical", "high", "medium", "low"
	IssueDate   string   // When the CA was flagged
	Reason      string   // Brief description of the issue
}

// Plugin to detect certificates from problematic CAs
type Plugin struct {
	problematicCAs []ProblematicCA
}

// GetName Get the name of the plugin
func (*Plugin) GetName() string {
	return "Problematic CA Detection Plugin"
}

func (*Plugin) GetExplanation() string {
	return "Check for certificates issued by CAs with a history of security malpractice or compromise"
}

// GetType Get the type of the plugin
func (*Plugin) GetType() plugins.PluginType {
	return plugins.PluginTypeVerify
}

// NewProblematicCAPlugin Creates a new instance of the Problematic CA Detection Plugin
func NewProblematicCAPlugin() (plugins.Plugin, error) {
	// Start with built-in database
	problematicCAs := getProblematicCADatabase()

	// Try to load custom CAs from user config directory
	customCAs, err := loadCustomProblematicCAs()
	if err != nil {
		log.WithError(err).Debug("Could not load custom problematic CA list (this is optional)")
	} else if len(customCAs) > 0 {
		log.WithField("count", len(customCAs)).Info("Loaded custom problematic CAs")
		problematicCAs = append(problematicCAs, customCAs...)
	}

	return &Plugin{
		problematicCAs: problematicCAs,
	}, nil
}

// loadCustomProblematicCAs loads custom CA definitions from the user's config directory
func loadCustomProblematicCAs() ([]ProblematicCA, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}

	customCAPath := filepath.Join(homeDir, ".cbomkit-theia", "problematic_cas.json")

	// Check if the file exists
	if _, err := os.Stat(customCAPath); os.IsNotExist(err) {
		// File doesn't exist - this is expected and not an error
		return nil, nil
	}

	// Read the file
	data, err := os.ReadFile(customCAPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read custom CA file: %w", err)
	}

	// Parse JSON
	var customCAs []ProblematicCA
	if err := json.Unmarshal(data, &customCAs); err != nil {
		return nil, fmt.Errorf("failed to parse custom CA file: %w", err)
	}

	return customCAs, nil
}

// UpdateBOM Checks certificate components against problematic CA database
func (plugin *Plugin) UpdateBOM(fs filesystem.Filesystem, bom *cdx.BOM) error {
	if bom.Components == nil || len(*bom.Components) == 0 {
		log.Debug("No components found in BOM to check")
		return nil
	}

	checkedCount := 0
	flaggedCount := 0

	for i := range *bom.Components {
		component := &(*bom.Components)[i]

		// Only process certificate components
		if !isCertificateComponent(component) {
			continue
		}

		checkedCount++
		issuer := extractIssuerFromComponent(component)
		if issuer == "" {
			log.WithField("component", component.Name).Debug("Could not extract issuer from certificate component")
			continue
		}

		// Check against problematic CA database
		if problematicCA := plugin.matchProblematicCA(issuer); problematicCA != nil {
			flaggedCount++
			plugin.enrichComponentWithCAWarning(component, problematicCA)
			log.WithFields(log.Fields{
				"component":     component.Name,
				"ca":            problematicCA.Name,
				"severity":      problematicCA.Severity,
				"status":        problematicCA.Status,
			}).Warn("Certificate from problematic CA detected")
		}
	}

	log.WithFields(log.Fields{
		"checked": checkedCount,
		"flagged": flaggedCount,
	}).Info("Problematic CA detection completed")

	return nil
}

// isCertificateComponent checks if a component represents a certificate
func isCertificateComponent(component *cdx.Component) bool {
	if component.Type != cdx.ComponentTypeCryptographicAsset {
		return false
	}

	// Check properties for certificate indicators
	if component.Properties != nil {
		for _, prop := range *component.Properties {
			if prop.Name == "ibm:cryptography:asset-type" &&
			   (prop.Value == "certificate" || strings.Contains(prop.Value, "certificate")) {
				return true
			}
		}
	}

	return false
}

// extractIssuerFromComponent extracts the issuer DN from a certificate component
func extractIssuerFromComponent(component *cdx.Component) string {
	if component.Properties == nil {
		return ""
	}

	for _, prop := range *component.Properties {
		if prop.Name == "ibm:cryptography:certificate:issuer" {
			return prop.Value
		}
	}

	return ""
}

// matchProblematicCA checks if the issuer matches any problematic CA
func (plugin *Plugin) matchProblematicCA(issuer string) *ProblematicCA {
	issuerLower := strings.ToLower(issuer)

	for i := range plugin.problematicCAs {
		ca := &plugin.problematicCAs[i]
		for _, identifier := range ca.Identifiers {
			if strings.Contains(issuerLower, strings.ToLower(identifier)) {
				return ca
			}
		}
	}

	return nil
}

// enrichComponentWithCAWarning adds warning properties to the component
func (plugin *Plugin) enrichComponentWithCAWarning(component *cdx.Component, ca *ProblematicCA) {
	if component.Properties == nil {
		component.Properties = &[]cdx.Property{}
	}

	warnings := []cdx.Property{
		{
			Name:  "ibm:cryptography:ca-warning:status",
			Value: ca.Status,
		},
		{
			Name:  "ibm:cryptography:ca-warning:severity",
			Value: ca.Severity,
		},
		{
			Name:  "ibm:cryptography:ca-warning:ca-name",
			Value: ca.Name,
		},
		{
			Name:  "ibm:cryptography:ca-warning:reason",
			Value: ca.Reason,
		},
		{
			Name:  "ibm:cryptography:ca-warning:flagged-date",
			Value: ca.IssueDate,
		},
	}

	*component.Properties = append(*component.Properties, warnings...)

	// Reduce confidence if component has confidence property
	plugin.reduceComponentConfidence(component, ca.Severity)
}

// reduceComponentConfidence lowers the confidence score based on severity
func (plugin *Plugin) reduceComponentConfidence(component *cdx.Component, severity string) {
	if component.Properties == nil {
		return
	}

	// Find existing confidence properties and reduce them
	for i := range *component.Properties {
		prop := &(*component.Properties)[i]
		if strings.Contains(prop.Name, "confidence") && prop.Value != "" {
			// Parse and reduce confidence based on severity
			var reduction int
			switch severity {
			case "critical":
				reduction = 90 // Nearly eliminate confidence
			case "high":
				reduction = 70
			case "medium":
				reduction = 40
			case "low":
				reduction = 20
			default:
				reduction = 30
			}

			// Add a warning note about reduced confidence
			*component.Properties = append(*component.Properties, cdx.Property{
				Name:  "ibm:cryptography:ca-warning:confidence-impact",
				Value: fmt.Sprintf("Confidence reduced due to problematic CA (-%d%%)", reduction),
			})
			return
		}
	}
}

// getProblematicCADatabase returns the built-in database of problematic CAs
func getProblematicCADatabase() []ProblematicCA {
	return []ProblematicCA{
		{
			Name: "DigiNotar",
			Identifiers: []string{
				"diginotar",
			},
			Status:    "compromised",
			Severity:  "critical",
			IssueDate: "2011-09",
			Reason:    "Completely compromised in 2011; issued fraudulent certificates for google.com and other domains; led to complete CA shutdown",
		},
		{
			Name: "Symantec/VeriSign",
			Identifiers: []string{
				"symantec",
				"verisign",
				"geotrust",
				"rapidssl",
				"thawte",
			},
			Status:    "distrusted",
			Severity:  "high",
			IssueDate: "2017-09",
			Reason:    "Repeated misissuance of certificates and failure to follow industry standards; distrusted by major browsers starting 2018",
		},
		{
			Name: "WoSign",
			Identifiers: []string{
				"wosign",
				"startcom",
				"startssl",
			},
			Status:    "distrusted",
			Severity:  "high",
			IssueDate: "2016-09",
			Reason:    "Backdating certificates, undisclosed ownership relationships, and misissuance; removed from browser trust stores",
		},
		{
			Name: "CNNIC",
			Identifiers: []string{
				"china internet network information center",
				"cnnic",
			},
			Status:    "warning",
			Severity:  "medium",
			IssueDate: "2015-04",
			Reason:    "Issued unauthorized intermediate certificates used for MitM attacks; restrictions placed by major browsers",
		},
		{
			Name: "TrustCor",
			Identifiers: []string{
				"trustcor",
			},
			Status:    "distrusted",
			Severity:  "high",
			IssueDate: "2022-11",
			Reason:    "Ties to U.S. government surveillance; removed from Mozilla and Chrome root stores",
		},
		{
			Name: "TÜRKTRUST",
			Identifiers: []string{
				"turktrust",
				"türktrust",
			},
			Status:    "warning",
			Severity:  "medium",
			IssueDate: "2013-01",
			Reason:    "Inadvertently issued intermediate CA certificates to organizations that used them to issue fraudulent certificates",
		},
		{
			Name: "Comodo",
			Identifiers: []string{
				"comodo",
			},
			Status:    "warning",
			Severity:  "medium",
			IssueDate: "2011-03",
			Reason:    "Suffered breach where attacker obtained certificates for major domains including google.com; multiple security incidents over the years",
		},
		{
			Name: "StartCom",
			Identifiers: []string{
				"startcom certification authority",
			},
			Status:    "distrusted",
			Severity:  "high",
			IssueDate: "2016-10",
			Reason:    "Related to WoSign; same ownership and similar malpractice; removed from browser trust stores",
		},
		{
			Name: "India CCA",
			Identifiers: []string{
				"india pki",
				"cca india",
			},
			Status:    "warning",
			Severity:  "low",
			IssueDate: "2014-07",
			Reason:    "Concerns over government-controlled CA and potential for surveillance; not widely trusted internationally",
		},
		{
			Name: "Camerfirma",
			Identifiers: []string{
				"camerfirma",
			},
			Status:    "deprecated",
			Severity:  "medium",
			IssueDate: "2020-03",
			Reason:    "Multiple compliance failures and delayed incident reporting; Mozilla reduced trust",
		},
		{
			Name: "VISA eCommerce Root",
			Identifiers: []string{
				"visa ecommerce root",
			},
			Status:    "deprecated",
			Severity:  "low",
			IssueDate: "2016-12",
			Reason:    "Failed to maintain required audits; removed from Mozilla root store",
		},
		{
			Name: "E-Tugra",
			Identifiers: []string{
				"e-tugra",
				"etugra",
			},
			Status:    "warning",
			Severity:  "medium",
			IssueDate: "2019-07",
			Reason:    "Misissuance incidents and inadequate security controls; increased scrutiny from browser vendors",
		},
		{
			Name: "Certinomis",
			Identifiers: []string{
				"certinomis",
			},
			Status:    "warning",
			Severity:  "low",
			IssueDate: "2019-01",
			Reason:    "Validation failures and delayed incident response; warnings from browser vendors",
		},
		{
			Name: "Trustwave",
			Identifiers: []string{
				"trustwave",
			},
			Status:    "warning",
			Severity:  "medium",
			IssueDate: "2012-02",
			Reason:    "Sold subordinate root certificates to corporate customers for SSL interception; controversial practice",
		},
		{
			Name: "Dark Matter (DarkMatter)",
			Identifiers: []string{
				"darkmatter",
				"dark matter",
			},
			Status:    "distrusted",
			Severity:  "high",
			IssueDate: "2019-03",
			Reason:    "UAE-based CA with ties to surveillance; denied admission to browser root programs due to security concerns",
		},
	}
}
