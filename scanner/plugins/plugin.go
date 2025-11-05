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

package plugins

import (
	"strings"

	"github.com/IBM/cbomkit-theia/provider/filesystem"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

type PluginType int

/*
	A list of possible plugin types

Important: order these in the way you want to run the plugins;
e.g., here the plugins are running in this order: PluginTypeAppend -> PluginTypeVerify -> PluginTypeOther
*/
const (
	PluginTypeAppend PluginType = iota + 1
	PluginTypeVerify
	PluginTypeOther
)

// Plugin Interface to be implemented by all plugins
type Plugin interface {
	GetName() string                                        // return a name for the plugin
	GetExplanation() string                                 // explain the functionality of this plugin
	GetType() PluginType                                    // return the plugin type
	UpdateBOM(fs filesystem.Filesystem, bom *cdx.BOM) error // Update BOM using found files
}

// PluginConstructor should be exposed by all plugin packages
type PluginConstructor func() (Plugin, error)

func PluginSliceToString(plugins []Plugin) string {
	builder := strings.Builder{}
	for i, plugin := range plugins {
		builder.WriteString(plugin.GetName())
		if i < len(plugins)-1 {
			builder.WriteString("; ")
		}
	}
	return builder.String()
}
