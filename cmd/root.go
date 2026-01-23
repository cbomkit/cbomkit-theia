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
	"fmt"
	"os"

	"github.com/cbomkit/cbomkit-theia/scanner"
	log "github.com/sirupsen/logrus"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var cfgFile string
var bomFilePath string
var activatedPlugins []string

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "cbomkit-theia",
	Short: "CBOMkit-theia analyzes cryptographic assets in a container image or directory",
	Long: `
 ██████╗██████╗  ██████╗ ███╗   ███╗██╗  ██╗██╗████████╗████████╗██╗  ██╗███████╗██╗ █████╗ 
██╔════╝██╔══██╗██╔═══██╗████╗ ████║██║ ██╔╝██║╚══██╔══╝╚══██╔══╝██║  ██║██╔════╝██║██╔══██╗
██║     ██████╔╝██║   ██║██╔████╔██║█████╔╝ ██║   ██║█████╗██║   ███████║█████╗  ██║███████║
██║     ██╔══██╗██║   ██║██║╚██╔╝██║██╔═██╗ ██║   ██║╚════╝██║   ██╔══██║██╔══╝  ██║██╔══██║
╚██████╗██████╔╝╚██████╔╝██║ ╚═╝ ██║██║  ██╗██║   ██║      ██║   ██║  ██║███████╗██║██║  ██║
 ╚═════╝╚═════╝  ╚═════╝ ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝   ╚═╝      ╚═╝   ╚═╝  ╚═╝╚══════╝╚═╝╚═╝  ╚═╝ by IBM Research

CBOMkit-theia analyzes cryptographic assets in a container image or directory.
It is part of CBOMkit (https://github.com/cbomkit/cbomkit) donated to PQCA by IBM Research.

--> Disclaimer: CBOMkit-theia does *not* perform source code scanning <--
--> Use https://github.com/cbomkit/sonar-cryptography for source code scanning <--

Features
- Find certificates in your image/directory
- Find keys in your image/directory
- Find secrets in your image/directory
- Verify the excitability of cryptographic assets in a CBOM (requires --bom to be set)
- Output: Enriched CBOM to stdout/console

Supported image/filesystem sources:
- local directory 
- local application with dockerfile (ready to be build)
- local docker image from docker daemon
- local docker image as TAR archive
- local OCI image as directory
- local OCI image as TAR archive
- OCI image from OCI registry
- docker image from dockerhub registry
- image from singularity

Supported BOM formats (input & output):
- CycloneDXv1.6

Examples:
cbomkit-theia dir my/cool/directory
cbomkit-theia image nginx` +
		"\n\n" + getPluginExplanations(),
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	// add image command
	rootCmd.AddCommand(imageCommand)
	rootCmd.AddCommand(dirCommand)
	// read in config file and ENV variables if set
	cobra.OnInitialize(initConfig)
	// add config flag
	rootCmd.
		PersistentFlags().
		StringVar(&cfgFile, "config", "", "config file (default is $HOME/.cbomkit-theia.yaml)")

	// add bom flag
	rootCmd.
		PersistentFlags().
		StringVarP(&bomFilePath, "bom", "b", "", "BOM file to be verified and enriched")
	err := rootCmd.MarkPersistentFlagFilename("bom", ".json")
	if err != nil {
		log.Error(err)
		return
	}

	// add plugins
	rootCmd.
		PersistentFlags().
		StringSliceVarP(&activatedPlugins, "plugins", "p", scanner.GetAllPluginNames(), "list of plugins to use")
	err = viper.BindPFlag("plugins", rootCmd.PersistentFlags().Lookup("plugins"))
	if err != nil {
		log.Error(err)
		return
	}
}

const configName = "config"
const configType = "yaml"

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	home, err := os.UserHomeDir()
	configPath := home + "/.cbomkit-theia"

	viper.SetConfigName(configName)
	viper.SetConfigType(configType)
	viper.AddConfigPath(configPath)

	if cfgFile != "" {
		// Use a config file from the flag.
		viper.SetConfigFile(cfgFile)
	}

	// Always ensure all plugins are set as default values
	allPlugins := scanner.GetAllPluginNames()
	viper.SetDefault("docker_host", "unix:///var/run/docker.sock")
	viper.SetDefault("plugins", allPlugins)

	// Find and read the config file
	if err := viper.ReadInConfig(); err != nil { // Handle errors reading the config file
		createConfFolder(configPath)

		path := configPath + "/" + configName + "." + configType
		if _, err := os.Create(path); err != nil { // perm 0666
			log.WithField("path", path).WithError(err).Error("could not create config file")
			return
		}

		err = viper.WriteConfig()
		if err != nil {
			log.Error("Error in creating default configuration: ", err)
			return
		}
	} else {
		// Config file exists - ensure plugins list matches available plugins
		configPlugins := viper.GetStringSlice("plugins")
		allPluginSet := make(map[string]bool, len(allPlugins))
		for _, p := range allPlugins {
			allPluginSet[p] = true
		}

		// Keep only valid plugins and check if any valid plugin is missing
		var validPlugins []string
		for _, p := range configPlugins {
			if allPluginSet[p] {
				validPlugins = append(validPlugins, p)
			}
		}
		needsUpdate := len(validPlugins) != len(configPlugins) || len(validPlugins) != len(allPlugins)

		if needsUpdate {
			viper.Set("plugins", allPlugins)
			err = viper.WriteConfig()
			if err != nil {
				log.Error("Error updating plugins in configuration: ", err)
			}
		}
	}
	// docker configuration
	err = viper.BindPFlag("docker_host", imageCommand.PersistentFlags().Lookup("docker_host"))
	if err != nil {
		log.Error("Error in configuring cbomkit-theia: ", err)
		return
	}
	// read in environment variables that match
	viper.AutomaticEnv()
}

func getPluginExplanations() string {
	out := "Plugin Explanations:\n"
	for name, constructor := range scanner.GetAllPluginConstructors() {
		p, err := constructor()
		if err != nil {
			panic(err)
		}
		out += fmt.Sprintf("> \"%v\": %v\n%v\n\n", name, p.GetName(), p.GetExplanation())
	}
	return out
}

func createConfFolder(location string) {
	if _, err := os.Stat(location); os.IsNotExist(err) {
		err := os.Mkdir(location, 0755)
		if err != nil {
			err = fmt.Errorf("could not create application folder '%s', %s", location, err)
			fmt.Println(err)
			return
		}
	}
}
