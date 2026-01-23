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

package x509

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"sync"
)

//go:embed data/oid-registry.json
var registryData []byte

// AlgorithmEntry represents a single algorithm in the OID registry.
type AlgorithmEntry struct {
	OID                    string            `json:"oid"`
	Name                   string            `json:"name"`
	Type                   string            `json:"type"`     // "composite", "standalone", "hybrid"
	Primitive              string            `json:"primitive"` // "signature", "hash", "pke", "kem"
	CryptoFunctions        []string          `json:"cryptoFunctions"`
	Padding                string            `json:"padding,omitempty"`
	ParameterSetIdentifier string            `json:"parameterSetIdentifier,omitempty"`
	NistStandard           string            `json:"nistStandard,omitempty"`
	Curve                  string            `json:"curve,omitempty"`
	PSSHashOID             string            `json:"pssHashOID,omitempty"`
	Components             map[string]string `json:"components,omitempty"`
}

// OIDRegistry holds all algorithm entries and provides lookup capabilities.
type OIDRegistry struct {
	Algorithms map[string]AlgorithmEntry `json:"algorithms"`
	oidIndex   map[string][]string       // OID -> list of algorithm keys (for ambiguous OIDs like PSS)
}

var (
	globalRegistry *OIDRegistry
	registryOnce   sync.Once
	registryErr    error
)

// GetRegistry returns the global OID registry, loading it on first access.
func GetRegistry() (*OIDRegistry, error) {
	registryOnce.Do(func() {
		globalRegistry, registryErr = loadRegistry(registryData)
	})
	return globalRegistry, registryErr
}

func loadRegistry(data []byte) (*OIDRegistry, error) {
	var reg OIDRegistry
	if err := json.Unmarshal(data, &reg); err != nil {
		return nil, fmt.Errorf("failed to parse OID registry: %w", err)
	}

	// Build OID index for reverse lookups
	reg.oidIndex = make(map[string][]string)
	for key, entry := range reg.Algorithms {
		reg.oidIndex[entry.OID] = append(reg.oidIndex[entry.OID], key)
	}

	return &reg, nil
}

// LookupByKey returns the algorithm entry for the given key (algorithm name).
func (r *OIDRegistry) LookupByKey(key string) (AlgorithmEntry, bool) {
	entry, found := r.Algorithms[key]
	return entry, found
}

// LookupByOID returns algorithm entries matching the given OID.
// For unambiguous OIDs, returns a single entry.
// For ambiguous OIDs (e.g., RSA-PSS), returns multiple entries that must be disambiguated.
func (r *OIDRegistry) LookupByOID(oid string) ([]AlgorithmEntry, bool) {
	keys, found := r.oidIndex[oid]
	if !found {
		return nil, false
	}
	entries := make([]AlgorithmEntry, 0, len(keys))
	for _, key := range keys {
		entries = append(entries, r.Algorithms[key])
	}
	return entries, true
}

// LookupByOIDUnambiguous returns a single algorithm entry for an OID that maps to exactly one algorithm.
// For ambiguous OIDs (like RSA-PSS shared across hash variants), it returns the first non-PKE match.
// Use LookupByOID for cases where disambiguation is needed.
func (r *OIDRegistry) LookupByOIDUnambiguous(oid string) (AlgorithmEntry, bool) {
	entries, found := r.LookupByOID(oid)
	if !found || len(entries) == 0 {
		return AlgorithmEntry{}, false
	}
	if len(entries) == 1 {
		return entries[0], true
	}
	// For ambiguous OIDs, return the first signature entry (skip PKE variants)
	for _, entry := range entries {
		if entry.Primitive == "signature" && entry.Type != "standalone" {
			return entry, true
		}
	}
	return entries[0], true
}

// LookupPSSByHashOID resolves an RSA-PSS algorithm entry by the hash algorithm OID in its parameters.
func (r *OIDRegistry) LookupPSSByHashOID(hashOID string) (AlgorithmEntry, bool) {
	pssOID := "1.2.840.113549.1.1.10"
	keys, found := r.oidIndex[pssOID]
	if !found {
		return AlgorithmEntry{}, false
	}
	for _, key := range keys {
		entry := r.Algorithms[key]
		if entry.PSSHashOID == hashOID {
			return entry, true
		}
	}
	return AlgorithmEntry{}, false
}
