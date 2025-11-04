// Copyright 2025 IBM
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

package opensslconf

import (
	"bufio"
	"fmt"
	"io"
	"path/filepath"
	"sort"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/IBM/cbomkit-theia/provider/filesystem"
	"github.com/IBM/cbomkit-theia/scanner/plugins"
	log "github.com/sirupsen/logrus"
)

// Plugin implements plugins.Plugin
// It scans for OpenSSL configuration files (openssl.cnf) and adds relevant settings to the BOM.
type Plugin struct{}

func NewOpenSSLConfPlugin() (plugins.Plugin, error) { return &Plugin{}, nil }

func (*Plugin) GetName() string { return "OpenSSL Config Plugin" }

func (*Plugin) GetExplanation() string {
	return "Scans for OpenSSL configuration files (openssl.cnf) and adds selected TLS settings (Min/MaxProtocol, CipherString, Options, CAfile/CApath, default_md) to the CBOM as component properties."
}

func (*Plugin) GetType() plugins.PluginType { return plugins.PluginTypeAppend }

// UpdateBOM walks the filesystem, finds openssl.cnf files and adds a file component per config
func (p *Plugin) UpdateBOM(fs filesystem.Filesystem, bom *cdx.BOM) error {
	found := make([]configFinding, 0)
	if err := fs.WalkDir(func(path string) error {
		if isOpenSSLConf(path) {
			exists, err := fs.Exists(path)
			if err != nil {
				return err
			} else if !exists {
				return nil
			}
			rc, err := fs.Open(path)
			if err != nil {
				return nil // skip unreadable files
			}
			defer rc.Close()
			settings, err := parseOpenSSLConf(rc)
			if err != nil {
				log.WithError(err).WithField("path", path).Warn("Failed to parse openssl.cnf")
				return nil
			}
			found = append(found, configFinding{path: path, settings: settings})
		}
		return nil
	}); err != nil {
		return err
	}

	if len(found) == 0 {
		log.Info("No OpenSSL configuration files found.")
		return nil
	}

	// Add as components
	components := make([]cdx.Component, 0, len(found))
	for _, f := range found {
		props := extractRelevantProperties(f.settings)
		comp := cdx.Component{
			Type:        cdx.ComponentTypeFile,
			Name:        filepath.Base(f.path),
			Description: "OpenSSL configuration",
			BOMRef:      fmt.Sprintf("opensslconf:%s", f.path),
			Properties:  &props,
			Evidence: &cdx.Evidence{Occurrences: &[]cdx.EvidenceOccurrence{{Location: f.path}}},
		}
		components = append(components, comp)
	}

	// Keep deterministic order in BOM
	sort.Slice(components, func(i, j int) bool { return components[i].BOMRef < components[j].BOMRef })

	*bom.Components = append(*bom.Components, components...)
	return nil
}

type configFinding struct {
	path     string
	settings map[string]map[string]string // section -> key -> val
}

func isOpenSSLConf(path string) bool {
	name := strings.ToLower(filepath.Base(path))
	if name == "openssl.cnf" {
		return true
	}
	// common alternative names
	return strings.HasSuffix(name, "openssl.cnf.dist") || strings.HasSuffix(name, ".openssl.cnf")
}

// parseOpenSSLConf parses a minimal subset of the OpenSSL config format.
// - Supports [sections]
// - Key/Value as "key = value" or "key=value"
// - Comments with '#' or ';'
// - Line continuation when the next line starts with whitespace
func parseOpenSSLConf(rc io.Reader) (map[string]map[string]string, error) {
	// Note: use bufio.Scanner and handle continuations
	scanner := bufio.NewScanner(rc)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	section := "default"
	cfg := map[string]map[string]string{section: {}}
	var pending string
	flushPending := func() {
		if strings.TrimSpace(pending) == "" {
			pending = ""
			return
		}
		line := strings.TrimSpace(pending)
		pending = ""
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.TrimSpace(line[1 : len(line)-1])
			if _, ok := cfg[section]; !ok {
				cfg[section] = map[string]string{}
			}
			return
		}
		// key=value
		if i := strings.IndexAny(line, ":="); i != -1 { // allow ':' or '=' as separator (some distros use ':')
			key := strings.TrimSpace(line[:i])
			val := strings.TrimSpace(strings.TrimLeft(line[i+1:], "= :"))
			if key != "" {
				cfg[section][key] = val
			}
		}
	}
	for scanner.Scan() {
		row := scanner.Text()
		trim := strings.TrimSpace(row)
		if trim == "" || strings.HasPrefix(trim, "#") || strings.HasPrefix(trim, ";") {
			// flush previous pending complete statement
			flushPending()
			continue
		}
		if strings.HasPrefix(row, " ") || strings.HasPrefix(row, "\t") {
			// continuation lines: only append if we are in a key/value pending line
			trimmed := strings.TrimSpace(row)
			p := strings.TrimSpace(pending)
			if p == "" || (strings.HasPrefix(p, "[") && strings.HasSuffix(p, "]")) {
				// no pending key/value or pending is a section header → start a new pending statement
				pending = trimmed
			} else {
				pending += " " + trimmed
			}
			continue
		}
		// flush previous before starting a new one
		flushPending()
		pending = trim
	}
	// flush tail
	flushPending()
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return cfg, nil
}

func extractRelevantProperties(cfg map[string]map[string]string) []cdx.Property {
	properties := make([]cdx.Property, 0)
	// collect across sections, prefer system_default_sect and default
	keys := []string{"MinProtocol", "MaxProtocol", "CipherString", "Options", "CAfile", "CApath", "default_md"}
	preferredSections := []string{"system_default_sect", "default", "openssl_init", "req", "ca_default"}
	for _, k := range keys {
		if v, ok := getFirstKey(cfg, preferredSections, k); ok && v != "" {
			properties = append(properties, cdx.Property{Name: "theia:openssl:" + k, Value: v})
		}
	}
	return properties
}

func getFirstKey(cfg map[string]map[string]string, sections []string, key string) (string, bool) {
	for _, s := range sections {
		if sec, ok := cfg[s]; ok {
			if v, ok2 := sec[key]; ok2 {
				return v, true
			}
		}
	}
	// fallback: search any section deterministically
	secNames := make([]string, 0, len(cfg))
	for s := range cfg {
		secNames = append(secNames, s)
	}
	sort.Strings(secNames)
	for _, s := range secNames {
		if v, ok := cfg[s][key]; ok {
			return v, true
		}
	}
	return "", false
}
