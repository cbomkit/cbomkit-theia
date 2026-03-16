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
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewPQCReadinessPlugin(t *testing.T) {
	plugin, err := NewPQCReadinessPlugin()
	require.NoError(t, err)
	require.NotNil(t, plugin)

	assert.Equal(t, "PQC Readiness Assessment Plugin", plugin.GetName())
	assert.NotEmpty(t, plugin.GetExplanation())
	assert.Equal(t, PluginTypeVerify, int(plugin.GetType()))
}

func TestClassifyQuantumVulnerability_RSA(t *testing.T) {
	plugin := createTestPlugin(t)

	tests := []struct {
		name           string
		componentName  string
		keySize        int
		expectedStatus QuantumVulnerabilityStatus
		expectedThreat QuantumThreat
	}{
		{
			name:           "RSA-2048 is quantum vulnerable",
			componentName:  "RSA-2048",
			keySize:        2048,
			expectedStatus: QuantumVulnerable,
			expectedThreat: ThreatShor,
		},
		{
			name:           "RSA-4096 is quantum vulnerable",
			componentName:  "RSA-4096",
			keySize:        4096,
			expectedStatus: QuantumVulnerable,
			expectedThreat: ThreatShor,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			component := createCryptoComponent(tt.componentName, "")
			result := plugin.classifyQuantumVulnerability(component)

			require.NotNil(t, result)
			assert.Equal(t, tt.expectedStatus, result.QuantumStatus)
			assert.Equal(t, tt.expectedThreat, result.PrimaryThreat)
		})
	}
}

func TestClassifyQuantumVulnerability_ECDSA(t *testing.T) {
	plugin := createTestPlugin(t)

	tests := []struct {
		name           string
		componentName  string
		curve          string
		expectedStatus QuantumVulnerabilityStatus
	}{
		{
			name:           "ECDSA P-256 is quantum vulnerable",
			componentName:  "ECDSA-P256",
			curve:          "P-256",
			expectedStatus: QuantumVulnerable,
		},
		{
			name:           "ECDSA P-384 is quantum vulnerable",
			componentName:  "ECDSA-P384",
			curve:          "P-384",
			expectedStatus: QuantumVulnerable,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			component := createCryptoComponentWithCurve(tt.componentName, tt.curve)
			result := plugin.classifyQuantumVulnerability(component)

			require.NotNil(t, result)
			assert.Equal(t, tt.expectedStatus, result.QuantumStatus)
		})
	}
}

func TestClassifyQuantumVulnerability_AES(t *testing.T) {
	plugin := createTestPlugin(t)

	tests := []struct {
		name              string
		componentName     string
		keySize           int
		expectedStatus    QuantumVulnerabilityStatus
		expectedQuantumBits int
	}{
		{
			name:              "AES-128 is partially secure",
			componentName:     "AES-128",
			keySize:           128,
			expectedStatus:    QuantumPartiallySecure,
			expectedQuantumBits: 64,
		},
		{
			name:              "AES-256 provides 128-bit quantum security",
			componentName:     "AES-256",
			keySize:           256,
			expectedStatus:    QuantumPartiallySecure, // Grover's algorithm halves effective security
			expectedQuantumBits: 128,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			component := createCryptoComponent(tt.componentName, "")
			result := plugin.classifyQuantumVulnerability(component)

			require.NotNil(t, result)
			assert.Equal(t, tt.expectedStatus, result.QuantumStatus)
			assert.Equal(t, tt.expectedQuantumBits, result.QuantumSecurityBits)
		})
	}
}

func TestClassifyQuantumVulnerability_SHA(t *testing.T) {
	plugin := createTestPlugin(t)

	tests := []struct {
		name           string
		componentName  string
		expectedStatus QuantumVulnerabilityStatus
	}{
		{
			name:           "SHA-256 is resistant",
			componentName:  "SHA-256",
			expectedStatus: QuantumResistant,
		},
		{
			name:           "SHA-384 is resistant",
			componentName:  "SHA-384",
			expectedStatus: QuantumResistant,
		},
		{
			name:           "SHA3-256 is resistant",
			componentName:  "SHA3-256",
			expectedStatus: QuantumResistant,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			component := createCryptoComponent(tt.componentName, "")
			result := plugin.classifyQuantumVulnerability(component)

			require.NotNil(t, result)
			assert.Equal(t, tt.expectedStatus, result.QuantumStatus)
		})
	}
}

func TestDetectPQCAlgorithm_ByOID(t *testing.T) {
	plugin := createTestPlugin(t)

	tests := []struct {
		name           string
		oid            string
		expectedFamily string
		expectedLevel  int
	}{
		{
			name:           "ML-KEM-768 detection by OID",
			oid:            "1.3.6.1.4.1.22554.5.6.2",
			expectedFamily: "ML-KEM",
			expectedLevel:  3,
		},
		{
			name:           "ML-DSA-65 detection by OID",
			oid:            "1.3.6.1.4.1.22554.5.5.2",
			expectedFamily: "ML-DSA",
			expectedLevel:  3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			component := createCryptoComponentWithOID("TestAlgorithm", tt.oid)
			result := plugin.detectPQCAlgorithm(component)

			require.NotNil(t, result)
			assert.Equal(t, tt.expectedFamily, result.Algorithm.Family)
			assert.Equal(t, tt.expectedLevel, result.Algorithm.NISTLevel)
			assert.Equal(t, "oid", result.DetectionMethod)
		})
	}
}

func TestDetectPQCAlgorithm_ByName(t *testing.T) {
	plugin := createTestPlugin(t)

	tests := []struct {
		name           string
		componentName  string
		expectedFamily string
		expectedHybrid bool
	}{
		{
			name:           "ML-KEM-768 detection by name",
			componentName:  "ML-KEM-768",
			expectedFamily: "lattice-kem", // Family from pqc_oids.json database
			expectedHybrid: false,
		},
		{
			name:           "X25519Kyber768 hybrid detection",
			componentName:  "X25519Kyber768",
			expectedFamily: "hybrid",
			expectedHybrid: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			component := createCryptoComponent(tt.componentName, "")
			result := plugin.detectPQCAlgorithm(component)

			require.NotNil(t, result)
			assert.Equal(t, tt.expectedFamily, result.Algorithm.Family)
			assert.Equal(t, tt.expectedHybrid, result.IsHybridDeployment)
		})
	}
}

func TestCalculateSecurityLevel(t *testing.T) {
	plugin := createTestPlugin(t)

	tests := []struct {
		name              string
		componentName     string
		expectedClassical int
		expectedQuantum   int
		expectedNISTLevel int
	}{
		{
			name:              "RSA-2048 security levels",
			componentName:     "RSA-2048",
			expectedClassical: 112,
			expectedQuantum:   0,
			expectedNISTLevel: 0,
		},
		{
			name:              "AES-256 security levels",
			componentName:     "AES-256",
			expectedClassical: 256,
			expectedQuantum:   128,
			expectedNISTLevel: 3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			component := createCryptoComponent(tt.componentName, "")

			// First classify vulnerability to populate properties
			plugin.classifyQuantumVulnerability(component)

			level := plugin.calculateSecurityLevel(component)

			require.NotNil(t, level)
			assert.Equal(t, tt.expectedClassical, level.ClassicalBits)
			assert.Equal(t, tt.expectedQuantum, level.QuantumBits)
			assert.Equal(t, tt.expectedNISTLevel, level.NISTLevel)
		})
	}
}

func TestRiskScoring(t *testing.T) {
	plugin := createTestPlugin(t)

	// Create a vulnerable component
	component := createCryptoComponent("RSA-2048", "")
	component.Evidence = &cdx.Evidence{
		Occurrences: &[]cdx.EvidenceOccurrence{
			{Location: "/etc/ssl/certs/server.pem"},
		},
	}

	// Add quantum status property
	component.Properties = &[]cdx.Property{
		{Name: "theia:pqc:quantum-status", Value: string(QuantumVulnerable)},
	}

	bom := &cdx.BOM{
		Components: &[]cdx.Component{*component},
	}

	risk := plugin.calculateHNDLRisk(component, bom)

	require.NotNil(t, risk)
	assert.Greater(t, risk.OverallScore, 0.0)
	assert.LessOrEqual(t, risk.OverallScore, 10.0)
	assert.NotEmpty(t, risk.Category)
	assert.Equal(t, 1.0, risk.VulnerabilityLevel) // Quantum vulnerable = 1.0
}

func TestMigrationGuidance(t *testing.T) {
	plugin := createTestPlugin(t)

	tests := []struct {
		name                   string
		componentName          string
		quantumStatus          QuantumVulnerabilityStatus
		expectReplacements     bool
	}{
		{
			name:               "RSA needs replacement",
			componentName:      "RSA-2048",
			quantumStatus:      QuantumVulnerable,
			expectReplacements: true,
		},
		{
			name:               "ML-KEM-768 no replacement needed",
			componentName:      "ML-KEM-768",
			quantumStatus:      QuantumSafe,
			expectReplacements: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			component := createCryptoComponent(tt.componentName, "")
			component.Properties = &[]cdx.Property{
				{Name: "theia:pqc:quantum-status", Value: string(tt.quantumStatus)},
			}

			guidance := plugin.generateMigrationGuidance(component)

			require.NotNil(t, guidance)
			if tt.expectReplacements {
				assert.NotEmpty(t, guidance.RecommendedReplacements)
			}
		})
	}
}

func TestComplianceTracking(t *testing.T) {
	plugin := createTestPlugin(t)

	// Create a component with quantum-vulnerable algorithm
	component := createCryptoComponent("RSA-2048", "")
	component.Properties = &[]cdx.Property{
		{Name: "theia:pqc:quantum-status", Value: string(QuantumVulnerable)},
	}
	component.Evidence = &cdx.Evidence{
		Occurrences: &[]cdx.EvidenceOccurrence{
			{Location: "/etc/ssl/server.key"},
		},
	}

	compliance := plugin.checkComplianceTimelines(component)

	require.NotNil(t, compliance)
	assert.NotEmpty(t, compliance.Frameworks)

	// Check CNSA 2.0 compliance
	var cnsa *FrameworkCompliance
	for i := range compliance.Frameworks {
		if compliance.Frameworks[i].Framework == "CNSA 2.0" {
			cnsa = &compliance.Frameworks[i]
			break
		}
	}

	require.NotNil(t, cnsa)
	assert.Equal(t, "non-compliant", cnsa.Status)
	assert.NotEmpty(t, cnsa.Violations)
}

func TestNIST131ACompliance(t *testing.T) {
	plugin := createTestPlugin(t)

	tests := []struct {
		name           string
		componentName  string
		expectedStatus string
	}{
		{
			name:           "SHA-1 signature is non-compliant",
			componentName:  "SHA1WithRSA",
			expectedStatus: "non-compliant",
		},
		{
			name:           "MD5 is non-compliant",
			componentName:  "MD5",
			expectedStatus: "non-compliant",
		},
		{
			name:           "3DES is deprecated",
			componentName:  "3DES",
			expectedStatus: "deprecated",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			component := createCryptoComponent(tt.componentName, "")
			nist := plugin.checkNIST131ACompliance(component)

			assert.Equal(t, tt.expectedStatus, nist.Status)
		})
	}
}

func TestAlgorithmDatabaseLoading(t *testing.T) {
	db, err := loadAlgorithmDatabase()
	require.NoError(t, err)
	require.NotNil(t, db)

	// Check that key algorithms are present
	_, hasRSA := db.ClassicalAlgorithms["RSA"]
	assert.True(t, hasRSA, "RSA should be in database")

	_, hasAES := db.ClassicalAlgorithms["AES"]
	assert.True(t, hasAES, "AES should be in database")
}

func TestPQCOIDDatabaseLoading(t *testing.T) {
	db, err := loadPQCOIDDatabase()
	require.NoError(t, err)
	require.NotNil(t, db)

	// Check that ML-KEM is present
	_, hasMLKEM := db.PQCAlgorithms["ML-KEM"]
	assert.True(t, hasMLKEM, "ML-KEM should be in database")

	// Check OID lookup works
	info := db.LookupByOID("1.3.6.1.4.1.22554.5.6.2")
	require.NotNil(t, info)
	assert.Equal(t, "ML-KEM", info.Family)
}

// Helper functions

func createTestPlugin(t *testing.T) *Plugin {
	p, err := NewPQCReadinessPlugin()
	require.NoError(t, err)
	return p.(*Plugin)
}

func createCryptoComponent(name, oid string) *cdx.Component {
	component := &cdx.Component{
		Type:   cdx.ComponentTypeCryptographicAsset,
		Name:   name,
		BOMRef: "test-ref",
		CryptoProperties: &cdx.CryptoProperties{
			AssetType: cdx.CryptoAssetTypeAlgorithm,
		},
	}
	if oid != "" {
		component.CryptoProperties.OID = oid
	}
	return component
}

func createCryptoComponentWithOID(name, oid string) *cdx.Component {
	return createCryptoComponent(name, oid)
}

func createCryptoComponentWithCurve(name, curve string) *cdx.Component {
	component := createCryptoComponent(name, "")
	component.CryptoProperties.AlgorithmProperties = &cdx.CryptoAlgorithmProperties{
		Curve: curve,
	}
	return component
}

// PluginTypeVerify is the integer value for PluginTypeVerify
const PluginTypeVerify = 2
