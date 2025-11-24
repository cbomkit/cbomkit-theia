// Copyright 2025 PQCA
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
	"io"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
	provcdx "github.com/cbomkit/cbomkit-theia/provider/cyclonedx"
	"github.com/cbomkit/cbomkit-theia/provider/filesystem"
	"github.com/cbomkit/cbomkit-theia/scanner/plugins"
	"github.com/cbomkit/cbomkit-theia/scanner/tls"
	"github.com/google/uuid"
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
			log.WithFields(log.Fields{"file": path}).Info("OpenSSL config detected")
		}
		return nil
	}); err != nil {
		return err
	}

	if len(found) == 0 {
		log.Info("No OpenSSL configuration files found.")
		return nil
	}

	components := make([]cdx.Component, 0)

	for _, f := range found {
		// 1) Add openssl.cnf file component with properties
		props := extractRelevantProperties(f.settings)

		// If CipherString uses DEFAULT[@SECLEVEL=X], attempt to expand it into a concrete list
		if opensslNames, expanded := expandDefaultCipherString(f.settings); expanded && len(opensslNames) > 0 {
			// replace the property value with expanded colon-separated list for transparency
			joined := strings.Join(opensslNames, ":")
			for i := range props {
				if props[i].Name == "theia:openssl:CipherString" {
					props[i].Value = joined
					break
				}
			}
		}

		fileComp := cdx.Component{
			Type:        cdx.ComponentTypeFile,
			Name:        filepath.Base(f.path),
			Description: "OpenSSL configuration",
			BOMRef:      uuid.New().String(),
			Properties:  &props,
			Evidence:    &cdx.Evidence{Occurrences: &[]cdx.EvidenceOccurrence{{Location: f.path}}},
		}
		components = append(components, fileComp)

		// 2) Build protocol + cipher suite components (if possible)
		versions := detectTLSVersions(f.settings)
		suites := detectCipherSuiteNames(f.settings)
		// If default cipher string was detected, map expanded OpenSSL cipher names -> TLS_* and add to suites
		if opensslNames, expanded := expandDefaultCipherString(f.settings); expanded && len(opensslNames) > 0 {
			mapped := tls.MapOpenSSLNamesToTLS(opensslNames)
			if len(mapped) > 0 {
				// merge and deduplicate
				set := make(map[string]struct{}, len(suites)+len(mapped))
				for _, s := range suites {
					set[s] = struct{}{}
				}
				for _, s := range mapped {
					set[s] = struct{}{}
				}
				merged := make([]string, 0, len(set))
				for s := range set {
					merged = append(merged, s)
				}
				sort.Strings(merged)
				suites = merged
			}
		}

		if len(versions) == 0 || len(suites) == 0 {
			continue
		}
		for _, v := range versions {
			algoComps, protoComp, depMap := tls.BuildTLSProtocolComponents(v, suites, f.path)
			if len(algoComps) == 0 && (protoComp == nil) {
				continue
			}
			// Add algorithms first, then protocol
			components = append(components, algoComps...)
			if protoComp != nil {
				components = append(components, *protoComp)
			}
			// Add dependencies if any
			if len(depMap) > 0 {
				provcdx.AddDependencies(bom, depMap)
			}
		}
	}

	// Keep deterministic order in BOM
	sort.Slice(components, func(i, j int) bool { return components[i].BOMRef < components[j].BOMRef })

	if bom.Components == nil {
		comps := make([]cdx.Component, 0, len(components))
		bom.Components = &comps
	}
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

// --- TLS mapping to cryptographic-asset components ---

var tlsVersionRe = regexp.MustCompile(`(?i)^TLSv?(\d(?:\.\d)?)$`)

func detectTLSVersions(cfg map[string]map[string]string) []string {
	versions := make([]string, 0, 2)
	preferredSections := []string{"system_default_sect", "default", "openssl_init"}
	keys := []string{"MinProtocol", "MaxProtocol"}
	seen := map[string]struct{}{}
	for _, k := range keys {
		if v, ok := getFirstKey(cfg, preferredSections, k); ok {
			if m := tlsVersionRe.FindStringSubmatch(strings.TrimSpace(v)); len(m) == 2 {
				ver := m[1]
				if _, ex := seen[ver]; !ex {
					versions = append(versions, ver)
					seen[ver] = struct{}{}
				}
			}
		}
	}
	// deterministic order: ascending by version string
	sort.Strings(versions)
	return versions
}

var cipherNameRe = regexp.MustCompile(`\bTLS_[A-Z0-9_]+\b`)

func detectCipherSuiteNames(cfg map[string]map[string]string) []string {
	names := make([]string, 0)
	seen := map[string]struct{}{}
	// scan all values for tokens like TLS_FOO_BAR
	secNames := make([]string, 0, len(cfg))
	for s := range cfg {
		secNames = append(secNames, s)
	}
	sort.Strings(secNames)
	for _, s := range secNames {
		for _, v := range cfg[s] {
			for _, m := range cipherNameRe.FindAllString(v, -1) {
				if _, ok := seen[m]; !ok {
					seen[m] = struct{}{}
					names = append(names, m)
				}
			}
		}
	}
	sort.Strings(names)
	return names
}

// expandDefaultCipherString detects if the config sets CipherString to DEFAULT[@SECLEVEL=n]
// and tries to expand it to a concrete list of OpenSSL cipher names using the local openssl binary.
// It returns the list of OpenSSL cipher names and true if expansion was attempted, otherwise false.
func expandDefaultCipherString(cfg map[string]map[string]string) ([]string, bool) {
	preferredSections := []string{"system_default_sect", "default", "openssl_init"}
	if v, ok := getFirstKey(cfg, preferredSections, "CipherString"); ok {
		val := strings.TrimSpace(v)
		if defaultCipherStringRe.MatchString(val) {
			// try openssl ciphers DEFAULT
			out, err := exec.Command("openssl", "ciphers", "DEFAULT").Output()
			if err == nil {
				text := strings.TrimSpace(string(out))
				if text != "" {
					// split by colon and whitespace
					fields := strings.FieldsFunc(text, func(r rune) bool { return r == ':' || r == '\n' || r == '\r' || r == '\t' || r == ' ' })
					list := make([]string, 0, len(fields))
					for _, f := range fields {
						ff := strings.TrimSpace(f)
						if ff != "" {
							list = append(list, ff)
						}
					}
					if len(list) > 0 {
						sort.Strings(list)
						return list, true
					}
				}
			}
			// return empty list
			return []string{}, true
		}
	}
	return nil, false
}

var defaultCipherStringRe = regexp.MustCompile(`(?i)^DEFAULT(?:@SECLEVEL=\d+)?$`)

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
