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
	"testing"

	"github.com/cbomkit/cbomkit-theia/provider/filesystem"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// resolveWithWiring runs flag parsing, flag bindings and initConfig,
// returns ignore patterns the same way dir and image commands load them.
func resolveWithWiring(t *testing.T, configYAML string, args ...string) []string {
	t.Helper()
	dir := setupTest(t)
	t.Setenv("HOME", dir)
	t.Setenv("USERPROFILE", dir) // os.UserHomeDir on Windows
	require.NoError(t, bindPersistentFlags())

	if configYAML != "" {
		cfgPath := filepath.Join(dir, "config.yaml")
		require.NoError(t, os.WriteFile(cfgPath, []byte(configYAML), 0644))
		args = append([]string{"--config", cfgPath}, args...)
	}
	require.NoError(t, rootCmd.ParseFlags(args))
	initConfig()
	return filesystem.LoadIgnorePatterns("", viper.GetStringSlice("ignore"), ignorePatterns)
}

// TestIgnore_ConfigAndFlagAreMerged is the regression test for --ignore
// replacing the config file's patterns. Reference: #242, introduced in #150
func TestIgnore_ConfigAndFlagAreMerged(t *testing.T) {
	got := resolveWithWiring(t, "ignore:\n  - cfg/\n", "--ignore", "cli/")
	assert.Equal(t, []string{"cfg/", "cli/"}, got)
}

// TestIgnore_FlagNotWrittenToNewConfig checks that the default config file
// created on the first run does not persist --ignore values.
func TestIgnore_FlagNotWrittenToNewConfig(t *testing.T) {
	got := resolveWithWiring(t, "", "--ignore", "cli/")
	assert.Equal(t, []string{"cli/"}, got)

	home, err := os.UserHomeDir()
	require.NoError(t, err)
	content, err := os.ReadFile(filepath.Join(home, ".cbomkit-theia", "config.yaml"))
	require.NoError(t, err)
	assert.NotContains(t, string(content), "cli/")
	assert.Contains(t, string(content), "ignore: []")
}
