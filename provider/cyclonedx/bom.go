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

package cyclonedx

import (
	"bytes"
	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/google/uuid"
	"io"
	"log/slog"
	"slices"
	"time"
)

func NewBOMWithMetadata() *cdx.BOM {
	bom := cdx.NewBOM()
	bom.Metadata = &cdx.Metadata{
		Timestamp: time.Now().Format(time.RFC3339),
	}
	bom.SerialNumber = "urn:uuid:" + uuid.New().String()
	return bom
}

// WriteBOM Write bom to the file
func WriteBOM(bom *cdx.BOM, writer io.Writer) error {
	// Encode the BOM
	err := cdx.NewBOMEncoder(writer, cdx.BOMFileFormatJSON).
		SetPretty(true).
		Encode(bom)
	if err != nil {
		return err
	}
	return nil
}

// AddComponents Add components to the given bom
func AddComponents(bom *cdx.BOM, components []cdx.Component) {
	if len(components) > 0 {
		if bom.Components == nil {
			comps := make([]cdx.Component, 0, len(components))
			bom.Components = &comps
		}
		*bom.Components = append(*bom.Components, components...)
	}
}

// AddDependencies Add dependencies to the given bom
func AddDependencies(bom *cdx.BOM, dependencyMap map[cdx.BOMReference][]string) {
	if len(dependencyMap) > 0 {
		if bom.Dependencies == nil {
			deps := make([]cdx.Dependency, 0, len(dependencyMap))
			bom.Dependencies = &deps
		}
		*bom.Dependencies = mergeDependencyStructSlice(*bom.Dependencies, dependencyMapToStructSlice(dependencyMap))
	}
}

// ParseBOM Parse a CycloneDX BOM from a path using the schema under schemaPath
func ParseBOM(bomReader io.Reader) (*cdx.BOM, error) {
	bomBytes, err := io.ReadAll(bomReader)
	if err != nil {
		return new(cdx.BOM), err
	}
	// Decode BOM from JSON
	slog.Debug("Decoding BOM from JSON to GO object")
	bom := new(cdx.BOM)
	decoder := cdx.NewBOMDecoder(bytes.NewReader(bomBytes), cdx.BOMFileFormatJSON)
	err = decoder.Decode(bom)
	if err != nil {
		return new(cdx.BOM), err
	}
	return bom, nil
}

func dependencyMapToStructSlice(dependencyMap map[cdx.BOMReference][]string) []cdx.Dependency {
	dependencies := make([]cdx.Dependency, 0)
	for ref, dependsOn := range dependencyMap {
		dependencies = append(dependencies, cdx.Dependency{
			Ref:          string(ref),
			Dependencies: &dependsOn,
		})
	}
	return dependencies
}

func mergeDependencyStructSlice(a []cdx.Dependency, b []cdx.Dependency) []cdx.Dependency {
	for _, bStruct := range b {
		i := indexBomRefInDependencySlice(a, cdx.BOMReference(bStruct.Ref))
		if i != -1 {
			// Merge
			for _, s := range *bStruct.Dependencies {
				if !slices.Contains(*a[i].Dependencies, s) {
					*a[i].Dependencies = append(*a[i].Dependencies, s)
				}
			}
		} else {
			a = append(a, bStruct)
		}
	}
	return a
}

// Return index in slice if bomRef is found in slice or -1 if not present
func indexBomRefInDependencySlice(slice []cdx.Dependency, bomRef cdx.BOMReference) int {
	for i, dep := range slice {
		if dep.Ref == string(bomRef) {
			return i
		}
	}
	return -1
}
