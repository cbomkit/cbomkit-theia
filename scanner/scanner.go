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

package scanner

import (
	"fmt"
	"io"
	"os"
	"slices"

	"github.com/cbomkit/cbomkit-theia/provider/cyclonedx"
	"github.com/cbomkit/cbomkit-theia/provider/filesystem"
	pluginpackage "github.com/cbomkit/cbomkit-theia/scanner/plugins"
	"github.com/cbomkit/cbomkit-theia/scanner/plugins/certificates"
	"github.com/cbomkit/cbomkit-theia/scanner/plugins/javasecurity"
	"github.com/cbomkit/cbomkit-theia/scanner/plugins/opensslconf"
	"github.com/cbomkit/cbomkit-theia/scanner/plugins/problematicca"
	"github.com/cbomkit/cbomkit-theia/scanner/plugins/secrets"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"go.uber.org/dig"
)

var Version = "edge"

type ParameterStruct struct {
	dig.In
	Fs          filesystem.Filesystem
	Target      io.Writer
	BomFilePath string                 `name:"bomFilePath"`
	Plugins     []pluginpackage.Plugin `group:"plugins"`
}

func GetAllPluginNames() []string {
	out := make([]string, 0, len(GetAllPluginConstructors()))
	for name := range GetAllPluginConstructors() {
		out = append(out, name)
	}
	return out
}

func GetAllPluginConstructors() map[string]pluginpackage.PluginConstructor {
	return map[string]pluginpackage.PluginConstructor{
		"certificates":   certificates.NewCertificatePlugin,
		"javasecurity":   javasecurity.NewJavaSecurityPlugin,
		"secrets":        secrets.NewSecretsPlugin,
		"opensslconf":    opensslconf.NewOpenSSLConfPlugin,
		"problematicca":  problematicca.NewProblematicCAPlugin,
	}
}

func getPluginConstructorsFromNames(names []string) ([]pluginpackage.PluginConstructor, error) {
	pluginConstructors := make([]pluginpackage.PluginConstructor, 0, len(names))
	for _, name := range names {
		constructor, ok := GetAllPluginConstructors()[name]
		if !ok {
			return pluginConstructors, fmt.Errorf("%v is not a valid plugin name", name)
		} else {
			pluginConstructors = append(pluginConstructors, constructor)
		}
	}
	return pluginConstructors, nil
}

// RunScan High-level function to do most heavy lifting for scanning a filesystem with a BOM.
func RunScan(params ParameterStruct) error {
	return runScan(params.BomFilePath, params.Fs, params.Target)
}

func runScan(bomFilePath string, fs filesystem.Filesystem, target io.Writer) error {
	var bom *cdx.BOM
	if bomFilePath != "" {
		log.WithField("path", bomFilePath).Debug("bom provided")

		bomReader, err := os.Open(bomFilePath)
		if err != nil {
			return err
		}
		bom, err = cyclonedx.ParseBOM(bomReader)
		if err != nil {
			return err
		}
	} else {
		bom = cyclonedx.NewBOMWithMetadata()
	}

	pluginConstructors, err := getPluginConstructorsFromNames(viper.GetStringSlice("plugins"))
	if err != nil {
		return err
	}

	var plugins []pluginpackage.Plugin
	for _, pluginConstructor := range pluginConstructors {
		plugin, err := pluginConstructor()
		if err != nil {
			return err
		}
		// exclude java security plugin when no bom is provided
		if bomFilePath == "" && plugin.GetName() == "java.security Plugin" {
			log.Info("Since no BOM is provided as input the java security check is automatically disabled.")
			continue
		}
		plugins = append(plugins, plugin)
	}

	scan := newScanner(plugins)

	newBom, err := scan.scan(bom, fs)
	if err != nil {
		return err
	}
	scan.addMetadata(newBom)
	return cyclonedx.WriteBOM(newBom, target)
}

// scanner is used internally to represent a single scanner with several plugins (e.g. java.security plugin) scanning a single filesystem (e.g. a docker image layer)
type scanner struct {
	configPlugins []pluginpackage.Plugin
}

// Scan a single BOM using all plugins
func (scanner *scanner) scan(bom *cdx.BOM, fs filesystem.Filesystem) (*cdx.BOM, error) {
	var err error
	if bom.Components == nil {
		log.Warn("No BOM provided or provided BOM does not have any components, this scan will only add components")
		bom.Components = new([]cdx.Component)
	}

	// Sort the plugins based on the plugin type
	slices.SortFunc(scanner.configPlugins, func(a pluginpackage.Plugin, b pluginpackage.Plugin) int {
		return int(a.GetType()) - int(b.GetType())
	})

	for _, plugin := range scanner.configPlugins {
		log.Info("=> Running ", plugin.GetName())
		err = plugin.UpdateBOM(fs, bom)
		if err != nil {
			return bom, fmt.Errorf("plugin (%v) failed to updated components of bom; %w", plugin.GetName(), err)
		}
	}
	return bom, nil
}

// Create a new scanner object for the specific filesystem
func newScanner(plugins []pluginpackage.Plugin) scanner {
	log.WithField("plugins", pluginpackage.PluginSliceToString(plugins)).Debug("initializing a new scanner")
	return scanner{
		configPlugins: plugins,
	}
}

// Add Metadata to the BOM
func (scanner *scanner) addMetadata(bom *cdx.BOM) {
	if bom.Metadata == nil {
		bom.Metadata = new(cdx.Metadata)
	}
	if bom.Metadata.Tools == nil {
		bom.Metadata.Tools = new(cdx.ToolsChoice)
	}
	if bom.Metadata.Tools.Services == nil {
		services := make([]cdx.Service, 0, 1)
		bom.Metadata.Tools.Services = &services
	}

	pluginServices := make([]cdx.Service, len(scanner.configPlugins))
	for i, plugin := range scanner.configPlugins {
		pluginServices[i] = cdx.Service{
			Name: plugin.GetName(),
		}
	}

	*bom.Metadata.Tools.Services = append(*bom.Metadata.Tools.Services, cdx.Service{
		Provider: &cdx.OrganizationalEntity{
			Name: "PQCA",
		},
		Name:     "cbomkit-theia",
		Version:  Version,
		Services: &pluginServices,
	})
}
