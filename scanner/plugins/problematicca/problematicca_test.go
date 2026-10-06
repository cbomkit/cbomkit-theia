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
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/stretchr/testify/assert"
)

func TestMatchProblematicCA(t *testing.T) {
	plugin := &Plugin{
		problematicCAs: getProblematicCADatabase(),
	}

	tests := []struct {
		name     string
		issuer   string
		expected bool
		caName   string
	}{
		{
			name:     "DigiNotar CA should be detected",
			issuer:   "CN=DigiNotar Root CA, O=DigiNotar, C=NL",
			expected: true,
			caName:   "DigiNotar",
		},
		{
			name:     "Symantec CA should be detected",
			issuer:   "CN=VeriSign Class 3 Public Primary CA, OU=VeriSign Trust Network",
			expected: true,
			caName:   "Symantec/VeriSign",
		},
		{
			name:     "WoSign CA should be detected",
			issuer:   "CN=CA WoSign ECC Root, O=WoSign CA Limited",
			expected: true,
			caName:   "WoSign",
		},
		{
			name:     "StartCom CA should be detected (related to WoSign)",
			issuer:   "CN=StartCom Certification Authority, OU=Secure Digital Certificate Signing",
			expected: true,
			caName:   "WoSign",
		},
		{
			name:     "CNNIC CA should be detected",
			issuer:   "CN=China Internet Network Information Center EV Certificates Root, O=China Internet Network Information Center",
			expected: true,
			caName:   "CNNIC",
		},
		{
			name:     "TrustCor CA should be detected",
			issuer:   "CN=TrustCor RootCert CA-1, OU=TrustCor Certificate Authority",
			expected: true,
			caName:   "TrustCor",
		},
		{
			name:     "Legitimate CA should not be detected",
			issuer:   "CN=DigiCert Global Root CA, OU=www.digicert.com, O=DigiCert Inc, C=US",
			expected: false,
			caName:   "",
		},
		{
			name:     "Let's Encrypt should not be detected",
			issuer:   "CN=Let's Encrypt Authority X3, O=Let's Encrypt, C=US",
			expected: false,
			caName:   "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := plugin.matchProblematicCA(tt.issuer)
			if tt.expected {
				assert.NotNil(t, result, "Expected to find problematic CA but got nil")
				if result != nil {
					assert.Equal(t, tt.caName, result.Name, "CA name mismatch")
				}
			} else {
				assert.Nil(t, result, "Expected nil but found problematic CA: %v", result)
			}
		})
	}
}

func TestIsCertificateComponent(t *testing.T) {
	tests := []struct {
		name      string
		component cdx.Component
		expected  bool
	}{
		{
			name: "Valid certificate component",
			component: cdx.Component{
				Type: cdx.ComponentTypeCryptographicAsset,
				Properties: &[]cdx.Property{
					{
						Name:  "ibm:cryptography:asset-type",
						Value: "certificate",
					},
				},
			},
			expected: true,
		},
		{
			name: "Non-certificate cryptographic asset",
			component: cdx.Component{
				Type: cdx.ComponentTypeCryptographicAsset,
				Properties: &[]cdx.Property{
					{
						Name:  "ibm:cryptography:asset-type",
						Value: "key",
					},
				},
			},
			expected: false,
		},
		{
			name: "Non-cryptographic component",
			component: cdx.Component{
				Type: cdx.ComponentTypeLibrary,
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isCertificateComponent(&tt.component)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestExtractIssuerFromComponent(t *testing.T) {
	tests := []struct {
		name      string
		component cdx.Component
		expected  string
	}{
		{
			name: "Component with issuer property",
			component: cdx.Component{
				Properties: &[]cdx.Property{
					{
						Name:  "ibm:cryptography:certificate:issuer",
						Value: "CN=Test CA, O=Test Org, C=US",
					},
				},
			},
			expected: "CN=Test CA, O=Test Org, C=US",
		},
		{
			name: "Component without issuer property",
			component: cdx.Component{
				Properties: &[]cdx.Property{
					{
						Name:  "ibm:cryptography:asset-type",
						Value: "certificate",
					},
				},
			},
			expected: "",
		},
		{
			name:      "Component with no properties",
			component: cdx.Component{},
			expected:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractIssuerFromComponent(&tt.component)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestEnrichComponentWithCAWarning(t *testing.T) {
	plugin := &Plugin{}

	component := cdx.Component{
		Type:       cdx.ComponentTypeCryptographicAsset,
		Properties: &[]cdx.Property{},
	}

	ca := &ProblematicCA{
		Name:      "Test CA",
		Status:    "distrusted",
		Severity:  "high",
		IssueDate: "2024-01",
		Reason:    "Test reason",
	}

	plugin.enrichComponentWithCAWarning(&component, ca)

	assert.NotNil(t, component.Properties)
	assert.Greater(t, len(*component.Properties), 0)

	// Check that warning properties were added
	props := *component.Properties
	foundStatus := false
	foundSeverity := false
	foundCAName := false
	foundReason := false
	foundDate := false

	for _, prop := range props {
		switch prop.Name {
		case "ibm:cryptography:ca-warning:status":
			foundStatus = true
			assert.Equal(t, "distrusted", prop.Value)
		case "ibm:cryptography:ca-warning:severity":
			foundSeverity = true
			assert.Equal(t, "high", prop.Value)
		case "ibm:cryptography:ca-warning:ca-name":
			foundCAName = true
			assert.Equal(t, "Test CA", prop.Value)
		case "ibm:cryptography:ca-warning:reason":
			foundReason = true
			assert.Equal(t, "Test reason", prop.Value)
		case "ibm:cryptography:ca-warning:flagged-date":
			foundDate = true
			assert.Equal(t, "2024-01", prop.Value)
		}
	}

	assert.True(t, foundStatus, "Status property not found")
	assert.True(t, foundSeverity, "Severity property not found")
	assert.True(t, foundCAName, "CA name property not found")
	assert.True(t, foundReason, "Reason property not found")
	assert.True(t, foundDate, "Flagged date property not found")
}

func TestGetProblematicCADatabase(t *testing.T) {
	db := getProblematicCADatabase()

	assert.NotEmpty(t, db, "Database should not be empty")

	// Check that well-known problematic CAs are in the database
	caNames := make(map[string]bool)
	for _, ca := range db {
		caNames[ca.Name] = true

		// Validate each CA entry has required fields
		assert.NotEmpty(t, ca.Name, "CA name should not be empty")
		assert.NotEmpty(t, ca.Identifiers, "CA identifiers should not be empty")
		assert.NotEmpty(t, ca.Status, "CA status should not be empty")
		assert.NotEmpty(t, ca.Severity, "CA severity should not be empty")
		assert.NotEmpty(t, ca.Reason, "CA reason should not be empty")

		// Validate status values
		validStatuses := map[string]bool{
			"compromised": true,
			"distrusted":  true,
			"deprecated":  true,
			"warning":     true,
		}
		assert.True(t, validStatuses[ca.Status], "Invalid status: %s", ca.Status)

		// Validate severity values
		validSeverities := map[string]bool{
			"critical": true,
			"high":     true,
			"medium":   true,
			"low":      true,
		}
		assert.True(t, validSeverities[ca.Severity], "Invalid severity: %s", ca.Severity)
	}

	// Check for specific well-known problematic CAs
	assert.True(t, caNames["DigiNotar"], "DigiNotar should be in database")
	assert.True(t, caNames["Symantec/VeriSign"], "Symantec/VeriSign should be in database")
	assert.True(t, caNames["WoSign"], "WoSign should be in database")
	assert.True(t, caNames["TrustCor"], "TrustCor should be in database")
}

func TestNewProblematicCAPlugin(t *testing.T) {
	plugin, err := NewProblematicCAPlugin()

	assert.NoError(t, err, "Plugin creation should not error")
	assert.NotNil(t, plugin, "Plugin should not be nil")

	// Verify plugin implements the interface
	assert.Equal(t, "Problematic CA Detection Plugin", plugin.GetName())
	assert.NotEmpty(t, plugin.GetExplanation())
}
