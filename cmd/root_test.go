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

package cmd

import (
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/cbomkit/cbomkit-theia/scanner"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
)

// setupTest resets global state and prepares a temp config directory.
// Returns the config directory path.
func setupTest(t *testing.T) string {
	t.Helper()
	viper.Reset()
	// Reset the activatedPlugins package variable
	activatedPlugins = scanner.GetAllPluginNames()
	// Reset the cobra flag's Changed state
	flag := rootCmd.PersistentFlags().Lookup("plugins")
	flag.Changed = false
	return t.TempDir()
}

// writeConfigFile creates a config.yaml in the given directory with specified plugins.
func writeConfigFile(t *testing.T, dir string, plugins []string) {
	t.Helper()
	content := "plugins:\n"
	for _, p := range plugins {
		content += "  - " + p + "\n"
	}
	err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte(content), 0644)
	assert.NoError(t, err)
}

// runInitConfigWithDir runs the plugin validation logic from initConfig using the given config directory.
func runInitConfigWithDir(t *testing.T, configDir string) {
	t.Helper()
	allPlugins := scanner.GetAllPluginNames()

	viper.SetConfigName(configName)
	viper.SetConfigType(configType)
	viper.AddConfigPath(configDir)
	viper.SetDefault("plugins", allPlugins)

	err := viper.BindPFlag("plugins", rootCmd.PersistentFlags().Lookup("plugins"))
	assert.NoError(t, err)

	if err := viper.ReadInConfig(); err != nil {
		t.Fatalf("failed to read config: %v", err)
	}

	// Replicate the plugin validation logic from initConfig
	if !rootCmd.PersistentFlags().Lookup("plugins").Changed {
		configPlugins := viper.GetStringSlice("plugins")
		allPluginSet := make(map[string]bool, len(allPlugins))
		for _, p := range allPlugins {
			allPluginSet[p] = true
		}

		var validPlugins []string
		for _, p := range configPlugins {
			if allPluginSet[p] {
				validPlugins = append(validPlugins, p)
			}
		}

		if len(validPlugins) != len(configPlugins) {
			viper.Set("plugins", validPlugins)
			err := viper.WriteConfig()
			assert.NoError(t, err)
		}
	}
}

func TestPluginFlag_FiltersSinglePlugin(t *testing.T) {
	configDir := setupTest(t)
	writeConfigFile(t, configDir, scanner.GetAllPluginNames())

	// Simulate --plugins flag set to "certificates"
	activatedPlugins = []string{"certificates"}
	rootCmd.PersistentFlags().Lookup("plugins").Changed = true

	runInitConfigWithDir(t, configDir)

	got := viper.GetStringSlice("plugins")
	assert.Equal(t, []string{"certificates"}, got)
}

func TestPluginFlag_FiltersMultiplePlugins(t *testing.T) {
	configDir := setupTest(t)
	writeConfigFile(t, configDir, scanner.GetAllPluginNames())

	// Simulate --plugins flag set to "certificates,secrets"
	activatedPlugins = []string{"certificates", "secrets"}
	rootCmd.PersistentFlags().Lookup("plugins").Changed = true

	runInitConfigWithDir(t, configDir)

	got := viper.GetStringSlice("plugins")
	sort.Strings(got)
	assert.Equal(t, []string{"certificates", "secrets"}, got)
}

func TestPluginFlag_OverridesConfigFileSubset(t *testing.T) {
	configDir := setupTest(t)

	// Config has only certificates and secrets
	writeConfigFile(t, configDir, []string{"certificates", "secrets"})

	// User explicitly passes --plugins=opensslconf
	activatedPlugins = []string{"opensslconf"}
	rootCmd.PersistentFlags().Lookup("plugins").Changed = true

	runInitConfigWithDir(t, configDir)

	// Flag value should take priority over config
	got := viper.GetStringSlice("plugins")
	assert.Equal(t, []string{"opensslconf"}, got)

	// Config file should NOT be modified
	configContent, err := os.ReadFile(filepath.Join(configDir, "config.yaml"))
	assert.NoError(t, err)
	assert.Contains(t, string(configContent), "certificates")
	assert.Contains(t, string(configContent), "secrets")
	assert.NotContains(t, string(configContent), "opensslconf")
}

func TestConfigFile_SubsetOfPluginsRespected(t *testing.T) {
	configDir := setupTest(t)

	// Config has only "certificates" and "secrets"
	writeConfigFile(t, configDir, []string{"certificates", "secrets"})

	// Flag NOT changed (user didn't pass --plugins)
	runInitConfigWithDir(t, configDir)

	// Should return only the config file's subset
	got := viper.GetStringSlice("plugins")
	sort.Strings(got)
	assert.Equal(t, []string{"certificates", "secrets"}, got)

	// Config file should NOT have been modified (no invalid entries)
	configContent, err := os.ReadFile(filepath.Join(configDir, "config.yaml"))
	assert.NoError(t, err)
	assert.Contains(t, string(configContent), "certificates")
	assert.Contains(t, string(configContent), "secrets")
	assert.NotContains(t, string(configContent), "javasecurity")
}

func TestConfigFile_InvalidPluginsRemoved(t *testing.T) {
	configDir := setupTest(t)

	// Config has a mix of valid and invalid plugin names
	writeConfigFile(t, configDir, []string{"certificates", "nonexistent_plugin", "secrets"})

	runInitConfigWithDir(t, configDir)

	// Viper should only have valid plugins
	got := viper.GetStringSlice("plugins")
	sort.Strings(got)
	assert.Equal(t, []string{"certificates", "secrets"}, got)

	// Config file should have been updated to remove invalid entry
	configContent, err := os.ReadFile(filepath.Join(configDir, "config.yaml"))
	assert.NoError(t, err)
	assert.Contains(t, string(configContent), "certificates")
	assert.Contains(t, string(configContent), "secrets")
	assert.NotContains(t, string(configContent), "nonexistent_plugin")
}

func TestConfigFile_SinglePluginRespected(t *testing.T) {
	configDir := setupTest(t)

	// Config has only one plugin
	writeConfigFile(t, configDir, []string{"secrets"})

	runInitConfigWithDir(t, configDir)

	got := viper.GetStringSlice("plugins")
	assert.Equal(t, []string{"secrets"}, got)
}

func TestConfigFile_AllPlugins_NoModification(t *testing.T) {
	configDir := setupTest(t)

	allPlugins := scanner.GetAllPluginNames()
	writeConfigFile(t, configDir, allPlugins)

	runInitConfigWithDir(t, configDir)

	got := viper.GetStringSlice("plugins")
	sort.Strings(got)
	expected := make([]string, len(allPlugins))
	copy(expected, allPlugins)
	sort.Strings(expected)
	assert.Equal(t, expected, got)
}
