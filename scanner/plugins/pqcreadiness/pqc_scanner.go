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
	"bufio"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/cbomkit/cbomkit-theia/provider/filesystem"
	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"
)

// PQCConfigFinding represents a PQC configuration found in a file
type PQCConfigFinding struct {
	Path             string
	ConfigType       string // "openssl", "nginx", "apache", "generic"
	PQCAlgorithms    []string
	IsHybrid         bool
	HybridComponents []string
	RawSettings      map[string]string
}

// scanForPQCConfigurations scans the filesystem for PQC-related configurations
func (plugin *Plugin) scanForPQCConfigurations(fs filesystem.Filesystem) ([]cdx.Component, error) {
	var findings []PQCConfigFinding

	err := fs.WalkDir(func(path string) error {
		// Check for OpenSSL configuration files
		if isOpenSSLConfigFile(path) {
			if finding := plugin.scanOpenSSLConfigForPQC(fs, path); finding != nil {
				findings = append(findings, *finding)
			}
		}

		// Check for PEM files that might contain PQC keys
		if isPEMFile(path) {
			if finding := plugin.scanPEMFileForPQC(fs, path); finding != nil {
				findings = append(findings, *finding)
			}
		}

		// Check for nginx/apache TLS configurations
		if isWebServerConfig(path) {
			if finding := plugin.scanWebServerConfigForPQC(fs, path); finding != nil {
				findings = append(findings, *finding)
			}
		}

		return nil
	})

	if err != nil {
		return nil, err
	}

	// Convert findings to components
	var components []cdx.Component
	for _, finding := range findings {
		component := plugin.createPQCConfigComponent(&finding)
		components = append(components, component)
	}

	return components, nil
}

// isOpenSSLConfigFile checks if a path is an OpenSSL configuration file
func isOpenSSLConfigFile(path string) bool {
	base := strings.ToLower(filepath.Base(path))
	return strings.Contains(base, "openssl") && (strings.HasSuffix(base, ".cnf") || strings.HasSuffix(base, ".conf"))
}

// isPEMFile checks if a path is a PEM file
func isPEMFile(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	return ext == ".pem" || ext == ".key" || ext == ".pub"
}

// isWebServerConfig checks if a path is a web server configuration
func isWebServerConfig(path string) bool {
	lowerPath := strings.ToLower(path)
	return strings.Contains(lowerPath, "nginx") || strings.Contains(lowerPath, "apache") ||
		strings.Contains(lowerPath, "httpd") || strings.Contains(lowerPath, "ssl")
}

// scanOpenSSLConfigForPQC scans an OpenSSL config file for PQC settings
func (plugin *Plugin) scanOpenSSLConfigForPQC(fs filesystem.Filesystem, path string) *PQCConfigFinding {
	rc, err := fs.Open(path)
	if err != nil {
		log.WithField("path", path).Debug("Could not open OpenSSL config file")
		return nil
	}
	defer rc.Close()

	finding := &PQCConfigFinding{
		Path:          path,
		ConfigType:    "openssl",
		PQCAlgorithms: []string{},
		RawSettings:   make(map[string]string),
	}

	// PQC-related OpenSSL configuration patterns
	pqcPatterns := []*regexp.Regexp{
		regexp.MustCompile(`(?i)Groups\s*=\s*(.+)`),
		regexp.MustCompile(`(?i)SignatureAlgorithms\s*=\s*(.+)`),
		regexp.MustCompile(`(?i)Curves\s*=\s*(.+)`),
		regexp.MustCompile(`(?i)CipherSuites\s*=\s*(.+)`),
	}

	// PQC algorithm name patterns
	pqcAlgorithmPatterns := []string{
		"kyber", "mlkem", "ml-kem",
		"dilithium", "mldsa", "ml-dsa",
		"sphincs", "slhdsa", "slh-dsa",
		"falcon", "fndsa", "fn-dsa",
		"x25519kyber", "p256kyber", "p384kyber",
	}

	scanner := bufio.NewScanner(rc)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip comments and empty lines
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}

		for _, pattern := range pqcPatterns {
			if matches := pattern.FindStringSubmatch(line); len(matches) > 1 {
				value := strings.TrimSpace(matches[1])
				lowerValue := strings.ToLower(value)

				// Check if the value contains PQC algorithms
				for _, pqcPattern := range pqcAlgorithmPatterns {
					if strings.Contains(lowerValue, pqcPattern) {
						// Extract individual algorithms
						algorithms := strings.Split(value, ":")
						for _, alg := range algorithms {
							alg = strings.TrimSpace(alg)
							if alg != "" {
								for _, p := range pqcAlgorithmPatterns {
									if strings.Contains(strings.ToLower(alg), p) {
										finding.PQCAlgorithms = append(finding.PQCAlgorithms, alg)
										// Check for hybrid
										if strings.Contains(strings.ToLower(alg), "x25519") ||
											strings.Contains(strings.ToLower(alg), "p256") ||
											strings.Contains(strings.ToLower(alg), "p384") {
											finding.IsHybrid = true
										}
									}
								}
							}
						}

						// Store raw setting
						settingName := strings.Split(line, "=")[0]
						finding.RawSettings[strings.TrimSpace(settingName)] = value
					}
				}
			}
		}
	}

	// Only return finding if PQC algorithms were found
	if len(finding.PQCAlgorithms) > 0 {
		log.WithFields(log.Fields{
			"path":       path,
			"algorithms": finding.PQCAlgorithms,
			"isHybrid":   finding.IsHybrid,
		}).Info("PQC configuration detected in OpenSSL config")
		return finding
	}

	return nil
}

// scanPEMFileForPQC scans a PEM file for PQC key types
func (plugin *Plugin) scanPEMFileForPQC(fs filesystem.Filesystem, path string) *PQCConfigFinding {
	rc, err := fs.Open(path)
	if err != nil {
		return nil
	}
	defer rc.Close()

	// PQC key header patterns
	pqcKeyPatterns := []*regexp.Regexp{
		regexp.MustCompile(`(?i)-----BEGIN\s+(ML-KEM|KYBER|MLKEM)\s+`),
		regexp.MustCompile(`(?i)-----BEGIN\s+(ML-DSA|DILITHIUM|MLDSA)\s+`),
		regexp.MustCompile(`(?i)-----BEGIN\s+(SLH-DSA|SPHINCS|SLHDSA)\s+`),
		regexp.MustCompile(`(?i)-----BEGIN\s+(FN-DSA|FALCON|FNDSA)\s+`),
	}

	scanner := bufio.NewScanner(rc)
	for scanner.Scan() {
		line := scanner.Text()
		for _, pattern := range pqcKeyPatterns {
			if matches := pattern.FindStringSubmatch(line); len(matches) > 1 {
				return &PQCConfigFinding{
					Path:          path,
					ConfigType:    "pem-key",
					PQCAlgorithms: []string{matches[1]},
					IsHybrid:      false,
				}
			}
		}
	}

	return nil
}

// scanWebServerConfigForPQC scans web server configs for PQC TLS settings
func (plugin *Plugin) scanWebServerConfigForPQC(fs filesystem.Filesystem, path string) *PQCConfigFinding {
	rc, err := fs.Open(path)
	if err != nil {
		return nil
	}
	defer rc.Close()

	finding := &PQCConfigFinding{
		Path:          path,
		ConfigType:    "webserver",
		PQCAlgorithms: []string{},
		RawSettings:   make(map[string]string),
	}

	// Patterns for TLS cipher/group configuration in web servers
	tlsPatterns := []*regexp.Regexp{
		regexp.MustCompile(`(?i)ssl_ecdh_curve\s+(.+);`),           // nginx
		regexp.MustCompile(`(?i)ssl_conf_command\s+Groups\s+(.+)`), // nginx with OpenSSL 3.0+
		regexp.MustCompile(`(?i)SSLOpenSSLConfCmd\s+Groups\s+(.+)`), // Apache
	}

	pqcAlgorithmPatterns := []string{
		"kyber", "mlkem", "ml-kem",
		"x25519kyber", "p256kyber", "p384kyber",
	}

	scanner := bufio.NewScanner(rc)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		for _, pattern := range tlsPatterns {
			if matches := pattern.FindStringSubmatch(line); len(matches) > 1 {
				value := strings.TrimSpace(matches[1])
				lowerValue := strings.ToLower(value)

				for _, pqcPattern := range pqcAlgorithmPatterns {
					if strings.Contains(lowerValue, pqcPattern) {
						groups := strings.Split(value, ":")
						for _, group := range groups {
							group = strings.TrimSpace(group)
							if group != "" {
								for _, p := range pqcAlgorithmPatterns {
									if strings.Contains(strings.ToLower(group), p) {
										finding.PQCAlgorithms = append(finding.PQCAlgorithms, group)
										if strings.Contains(strings.ToLower(group), "x25519") ||
											strings.Contains(strings.ToLower(group), "p256") ||
											strings.Contains(strings.ToLower(group), "p384") {
											finding.IsHybrid = true
										}
									}
								}
							}
						}
					}
				}
			}
		}
	}

	if len(finding.PQCAlgorithms) > 0 {
		log.WithFields(log.Fields{
			"path":       path,
			"algorithms": finding.PQCAlgorithms,
		}).Info("PQC configuration detected in web server config")
		return finding
	}

	return nil
}

// createPQCConfigComponent creates a CycloneDX component from a PQC config finding
func (plugin *Plugin) createPQCConfigComponent(finding *PQCConfigFinding) cdx.Component {
	// Determine the quantum status
	var quantumStatus QuantumVulnerabilityStatus
	if finding.IsHybrid {
		quantumStatus = HybridTransitional
	} else {
		quantumStatus = QuantumSafe
	}

	// Build component name
	name := "PQC-Config:" + filepath.Base(finding.Path)

	// Build properties
	props := []cdx.Property{
		{
			Name:  "theia:pqc:is-pqc-algorithm",
			Value: "true",
		},
		{
			Name:  "theia:pqc:quantum-status",
			Value: string(quantumStatus),
		},
		{
			Name:  "theia:pqc:config-type",
			Value: finding.ConfigType,
		},
		{
			Name:  "theia:pqc:pqc-algorithms",
			Value: strings.Join(finding.PQCAlgorithms, ","),
		},
		{
			Name:  "theia:pqc:is-hybrid",
			Value: boolToString(finding.IsHybrid),
		},
		{
			Name:  "theia:pqc:detection-method",
			Value: "config-scan",
		},
		{
			Name:  "theia:pqc:quantum-threat",
			Value: string(ThreatNone),
		},
	}

	// Add raw settings as properties
	for key, value := range finding.RawSettings {
		props = append(props, cdx.Property{
			Name:  "theia:pqc:config:" + strings.ToLower(key),
			Value: value,
		})
	}

	return cdx.Component{
		Type:        cdx.ComponentTypeCryptographicAsset,
		Name:        name,
		BOMRef:      uuid.New().String(),
		Description: "PQC configuration detected in " + finding.ConfigType + " file",
		CryptoProperties: &cdx.CryptoProperties{
			AssetType: cdx.CryptoAssetTypeAlgorithm,
		},
		Properties: &props,
		Evidence: &cdx.Evidence{
			Occurrences: &[]cdx.EvidenceOccurrence{
				{Location: finding.Path},
			},
		},
	}
}

func boolToString(b bool) string {
	if b {
		return "true"
	}
	return "false"
}
