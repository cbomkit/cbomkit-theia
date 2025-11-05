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

package javasecurity

import (
	"fmt"
	"path/filepath"
	"strconv"
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/IBM/cbomkit-theia/provider/filesystem"
	scannererrors "github.com/IBM/cbomkit-theia/scanner/errors"
	"github.com/IBM/cbomkit-theia/scanner/plugins"

	cdx "github.com/CycloneDX/cyclonedx-go"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/magiconair/properties"
)

// Plugin Represents the java security plugin in a specific scanning context
// Implements the config/ConfigPlugin interface
type Plugin struct{}

// NewJavaSecurityPlugin Creates underlying data structure for evaluation
func NewJavaSecurityPlugin() (plugins.Plugin, error) {
	return &Plugin{}, nil
}

// GetName Get the algorithm of the plugin for debugging purposes
func (*Plugin) GetName() string {
	return "java.security Plugin"
}

func (*Plugin) GetExplanation() string {
	return "Verify the excitability of cryptographic assets from Java code\nAdds a confidence level (0-100) to the CBOM components to show how likely it is that this component is actually executable"
}

// GetType Get the type of the plugin
func (*Plugin) GetType() plugins.PluginType {
	return plugins.PluginTypeVerify
}

// UpdateBOM High-level function to update a list of components
// (e.g., remove components and add new ones) based on the underlying filesystem
func (plugin *Plugin) UpdateBOM(fs filesystem.Filesystem, bom *cdx.BOM) error {
	log.Warn("Current version does not take dynamic changes of java javaSecurity properties (e.g. via System.setProperty) into account.")
	javaSecurityFiles, err := plugin.findJavaSecurityFiles(fs)
	if err != nil {
		return err
	}

	if len(javaSecurityFiles) == 0 {
		log.Warn("No java.security file found")
		return nil
	}

	log.WithField("number", len(javaSecurityFiles)).Info("java.security files found")

	var javaSecurityFile *JavaSecurity
	if dockerConfig, ok := fs.GetConfig(); ok {
		javaSecurityFile = plugin.selectJavaSecurityFile(javaSecurityFiles, &dockerConfig)
	} else {
		javaSecurityFile = plugin.selectJavaSecurityFile(javaSecurityFiles, nil)
	}

	err = javaSecurityFile.analyse(fs)
	if err != nil {
		log.WithError(err).Error("Could not analyse java.security file")
		return err
	}

	for _, component := range *bom.Components {
		err := javaSecurityFile.updateComponent(&component, bom.Components)
		if err != nil {
			log.WithError(err).Warnf("Error while updating component %v", component.Name)
			continue
		}
	}
	log.Info("java.security analysis done!")
	return nil
}

func (plugin *Plugin) findJavaSecurityFiles(fs filesystem.Filesystem) ([]JavaSecurity, error) {
	var javaSecurityFiles []JavaSecurity
	if err := fs.WalkDir(
		func(path string) (err error) {
			if plugin.isConfigFile(path) {
				readCloser, err := fs.Open(path)
				if err != nil {
					return scannererrors.GetParsingFailedAlthoughCheckedError(err, plugin.GetName())
				}
				content, err := filesystem.ReadAllAndClose(readCloser)
				if err != nil {
					return scannererrors.GetParsingFailedAlthoughCheckedError(err, plugin.GetName())
				}
				config, err := properties.LoadString(string(content))
				if err != nil {
					return scannererrors.GetParsingFailedAlthoughCheckedError(err, plugin.GetName())
				}
				if config == nil {
					return fmt.Errorf("java.security: there are no java.security properties")
				}

				log.WithField("path", path).Debug("java.security file found")
				javaSecurityFiles = append(javaSecurityFiles, New(*config, path))
			}
			return nil
		}); err != nil {
		log.WithError(err).Error("Error while trying to find java.security files")
		return nil, err
	}
	return javaSecurityFiles, nil
}

func (plugin *Plugin) selectJavaSecurityFile(javaSecurityFiles []JavaSecurity, dockerConfig *v1.Config) *JavaSecurity {
	if dockerConfig == nil {
		return plugin.chooseFirstConfiguration(javaSecurityFiles)
	}

	jdkPath, ok := getJDKPath(*dockerConfig)
	if !ok {
		return plugin.chooseFirstConfiguration(javaSecurityFiles)
	}
	for _, file := range javaSecurityFiles {
		if strings.HasPrefix(file.path, jdkPath) {
			log.WithField("path", file.path).Info("Select java.security file")
			return &file
		}
	}
	return plugin.chooseFirstConfiguration(javaSecurityFiles)
}

// Choose the first one
func (*Plugin) chooseFirstConfiguration(javaSecurityFiles []JavaSecurity) *JavaSecurity {
	for _, file := range javaSecurityFiles {
		log.WithField("path", file.path).Info("Select java.security file")
		return &file
	}
	return nil
}

// Checks whether the current file at a path is a java.security config file
func (*Plugin) isConfigFile(path string) bool {
	// Check if this file is the java.security file and if that is the case extract the path of the active crypto.policy files
	dir, _ := filepath.Split(path)
	dir = filepath.Clean(dir)
	// Check the correct directory
	if !(strings.HasSuffix(dir, filepath.Join("jre", "lib", "security")) ||
		strings.HasSuffix(dir, filepath.Join("conf", "security"))) {
		return false
	}
	// Check a file extension
	ext := filepath.Ext(path)
	if ext != ".security" {
		return false
	}
	// If all checks passed, return true
	return true
}

func getJDKPath(dockerConfig v1.Config) (value string, ok bool) {
	jdkPath, ok := getJDKPathFromEnvironmentVariables(dockerConfig.Env)
	if ok {
		return jdkPath, true
	}

	jdkPath, ok = getJDKPathFromRunCommand(dockerConfig)
	if ok {
		return jdkPath, true
	}

	return "", false
}

func getJDKPathFromEnvironmentVariables(envVariables []string) (value string, ok bool) {
	for _, env := range envVariables {
		keyAndValue := strings.Split(env, "=")
		key := keyAndValue[0]
		value := keyAndValue[1]

		switch key {
		case "JAVA_HOME", "JDK_HOME":
			return value, true
		case "JRE_HOME":
			return filepath.Dir(value), true
		default:
			continue
		}
	}
	return "", false
}

func getJDKPathFromRunCommand(dockerConfig v1.Config) (value string, ok bool) {
	const lineSeparator = "/"
	for _, s := range append(dockerConfig.Cmd, dockerConfig.Entrypoint...) {
		if strings.Contains(s, "java") {
			// Try to extract only the binary path
			fields := strings.Fields(s)
			if len(fields) > 0 {
				path := fields[0]
				pathList := strings.Split(path, lineSeparator)
				for i, pathElement := range pathList {
					if strings.Contains(pathElement, "jdk") {
						return lineSeparator + filepath.Join(pathList[:i+1]...), true
					}
				}
			}
		}
	}
	return "", false
}

// JavaSecurity represents the java.security file(s) found on the system
type JavaSecurity struct {
	properties            properties.Properties
	path                  string
	tlsDisabledAlgorithms []AlgorithmRestriction
}

func New(p properties.Properties, path string) JavaSecurity {
	return JavaSecurity{properties: p, path: path, tlsDisabledAlgorithms: make([]AlgorithmRestriction, 0)}
}

func (javaSecurity *JavaSecurity) analyse(fs filesystem.Filesystem) error {
	// environment
	additionalSecurityProperties, overridden, err := javaSecurity.checkForEnvironmentConfigurations(fs)
	if err != nil {
		return err
	}
	if overridden && additionalSecurityProperties != nil {
		javaSecurity.properties.Merge(additionalSecurityProperties)
	}
	// tls and algorithm restriction
	restrictions, err := javaSecurity.extractTLSRules()
	if err != nil {
		return err
	}
	javaSecurity.tlsDisabledAlgorithms = restrictions

	return nil
}

// Assesses if the component is from a source affected by this type of config (e.g., a java file),
// requires "Evidence" and "Occurrences" to be present in the BOM
func (*JavaSecurity) isComponentAffectedByConfig(component *cdx.Component) (bool, error) {
	if component.Evidence == nil || component.Evidence.Occurrences == nil { // If there is no evidence telling us that whether this component comes from a java file,
		// we cannot assess it
		return false, scannererrors.GetInsufficientInformationError("Unable to process due to missing evidence/occurrences in BOM", component.Name)
	}

	for _, occurrence := range *component.Evidence.Occurrences {
		if filepath.Ext(occurrence.Location) == ".java" {
			return true, nil
		}
	}
	return false, nil
}

// Update a single component; returns nil if component is not allowed
func (javaSecurity *JavaSecurity) updateComponent(component *cdx.Component, components *[]cdx.Component) error {
	ok, err := javaSecurity.isComponentAffectedByConfig(component)
	if !ok {
		return err
	}

	log.WithFields(log.Fields{
		"component": component.Name,
		"bom-ref":   component.BOMRef,
	}).Info("component is affected by java.security file")

	allowed, restrictionResult, err := isAllowed(component, components, javaSecurity)
	if err != nil {
		return err
	}
	// component has restrictions
	if allowed {
		return nil
	}

	if restrictionResult == nil {
		return fmt.Errorf("no restriction result provided, but component %s is marked as restricted", component.Name)
	}

	var props []cdx.Property
	for _, restriction := range *restrictionResult {
		props = append(props, cdx.Property{
			Name:  fmt.Sprintf("ibm:cryptography:restriction:rule"),
			Value: fmt.Sprintf("%+v", restriction.restriction),
		})
		props = append(props, cdx.Property{
			Name:  fmt.Sprintf("ibm:cryptography:restriction:reason"),
			Value: fmt.Sprintf("%+v", restriction.reason),
		})
		props = append(props, cdx.Property{
			Name:  fmt.Sprintf("ibm:cryptography:restriction:confidence"),
			Value: fmt.Sprintf("%+v", restriction.confidence),
		})
	}

	if component.Properties == nil {
		component.Properties = &[]cdx.Property{}
	}
	*component.Properties = append(*component.Properties, props...)
	return nil
}

// Recursively get all comma-separated values of the property key. Recursion is necessary since values can include
// "include" directives which refer to other properties and include them in this property.
func (javaSecurity *JavaSecurity) extractValuesForKey(key string) (values []string, err error) {
	fullString, ok := javaSecurity.properties.Get(key)
	if ok {
		values = strings.Split(fullString, ",")
		for i, value := range values {
			values[i] = strings.TrimSpace(value)
		}
	}
	return values, nil
}

// Parses the TLS Rules from the java.security file
// Returns a joined list of errors which occurred during parsing of algorithms
func (javaSecurity *JavaSecurity) extractTLSRules() ([]AlgorithmRestriction, error) {
	log.WithField("path", javaSecurity.path).Debug("Extracting TLS rules from java.security file")

	algorithms, err := javaSecurity.extractValuesForKey("jdk.tls.disabledAlgorithms")
	if err != nil {
		return nil, err
	}

	if len(algorithms) == 0 {
		return nil, err
	}

	var algorithmRestriction []AlgorithmRestriction
	for _, algorithm := range algorithms {
		keySize := 0
		operator := keySizeOperatorNone
		name := algorithm

		if strings.Contains(algorithm, "jdkCA") ||
			strings.Contains(algorithm, "denyAfter") ||
			strings.Contains(algorithm, "usage") {
			log.WithField("algorithm", algorithm).Warn("Found constraint in java.security file that is not supported in this version")
			continue
		}

		log.WithFields(log.Fields{
			"algorithm": algorithm,
			"property":  "jdk.tls.disabledAlgorithms",
		}).Debug("Found constraint in java.security file")

		if strings.Contains(algorithm, "keySize") {
			split := strings.Split(algorithm, "keySize")
			if len(split) > 2 {
				log.WithField("algorithm", algorithm).Warn("key size check failed; too many elements")
				continue
			}
			name = strings.TrimSpace(split[0])
			split[1] = strings.TrimSpace(split[1])
			keyRestrictions := strings.Split(split[1], " ")

			switch keyRestrictions[0] {
			case "<=":
				operator = keySizeOperatorLowerEqual
			case "<":
				operator = keySizeOperatorLower
			case "==":
				operator = keySizeOperatorEqual
			case "!=":
				operator = keySizeOperatorNotEqual
			case ">=":
				operator = keySizeOperatorGreaterEqual
			case ">":
				operator = keySizeOperatorGreater
			case "":
				operator = keySizeOperatorNone
			default:
				log.WithFields(log.Fields{
					"algorithm":       algorithm,
					"keySizeOperator": keyRestrictions[0],
				}).Warn("Could not analyse the keySizeOperator")
				continue
			}

			keySize, err = strconv.Atoi(keyRestrictions[1])
			if err != nil {
				log.WithField("algorithm", algorithm).Warn("Could not extract key size")
				continue
			}
		}

		algorithmRestriction = append(algorithmRestriction, AlgorithmRestriction{
			algorithm:       name,
			keySize:         keySize,
			keySizeOperator: operator,
		})
	}
	return algorithmRestriction, nil
}

// Tries to get a config from the fs and checks the Config for potentially relevant information
func (javaSecurity *JavaSecurity) checkForEnvironmentConfigurations(fs filesystem.Filesystem) (*properties.Properties, bool, error) {
	log.WithField("filesystem", fs.GetIdentifier()).Debug("Checking filesystem configuration for additional java.security properties")

	configuration, ok := fs.GetConfig()
	if !ok {
		log.WithField("filesystem", fs.GetIdentifier()).Debug("Filesystem did not provide a configuration")
		return nil, false, nil
	}
	additionalSecurityProperties, overridden, err := javaSecurity.checkForAdditionalSecurityFilesInDockerConfig(configuration, fs)
	return additionalSecurityProperties, overridden, err
}

// Searches the image config for potentially relevant CMD parameters and potentially adds new properties
func (javaSecurity *JavaSecurity) checkForAdditionalSecurityFilesInDockerConfig(config v1.Config, fs filesystem.Filesystem) (*properties.Properties, bool, error) {
	// We have to check if adding additional security files via CMD is even allowed via the java.security file (security.overridePropertiesFile property)
	overridePropertiesFile := javaSecurity.properties.GetBool("security.overridePropertiesFile", true)
	if !overridePropertiesFile {
		log.WithField("filesystem", fs.GetIdentifier()).Debug("java.security file properties don't allow additional security files. Stopping searching directly")
		return nil, false, nil
	}

	const securityCmdArgument = "-Djava.security.properties="
	// check for additional files added via CMD
	for _, command := range append(config.Cmd, config.Entrypoint...) {
		value, overridden, ok := extractFlagValue(command, securityCmdArgument)
		if !ok {
			continue
		}
		log.WithField("command", command).Debug("Found command that specifies new properties")
		readCloser, err := fs.Open(value)
		if err != nil {
			log.WithField("file", value).Warn("Failed to read file specified via a command flag in the image configuration (e.g. Dockerfile); the image or image config is probably malformed; continuing without")
			continue
		}
		content, err := filesystem.ReadAllAndClose(readCloser)
		if err != nil {
			log.WithField("file", value).Warn("Failed to read file specified via a command flag in the image configuration (e.g. Dockerfile); the image or image config is probably malformed; continuing without")
			continue
		}
		additionalSecurityProperties, err := properties.LoadString(string(content))
		return additionalSecurityProperties, overridden, err
	}
	return nil, false, nil
}

// Tries to extract the value of a flag in command;
// returns ok if found; returns overwrite if double equals signs were used (==)
func extractFlagValue(command string, flag string) (string, bool, bool) {
	split := strings.Split(command, flag)
	if len(split) != 2 {
		return "", false, false
	}
	split = strings.Fields(split[1])
	value := split[0]
	if strings.HasPrefix(value, "=") {
		value = value[1:]
		return value, true, true
	}
	return value, false, true
}
