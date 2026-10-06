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

package confidenceLevel

import (
	"fmt"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

// ConfidenceLevel A confidence level represents a level of confidence
// Example:
// A ConfidenceLevel could be used to represent the confidence that an algorithm is executable in a certain environment.
type ConfidenceLevel struct {
	value float64
}

// Constant value that can be used for the modification of a ConfidenceLevel
var (
	Max = New(1.0)
	Min = New(0.0)
)

// New Get a new ConfidenceLevel; default value is confidenceLevelDefault
func New(value float64) ConfidenceLevel {
	return ConfidenceLevel{
		value: value,
	}
}

// GetValue Get the value of the ConfidenceLevel
func (confidenceLevel ConfidenceLevel) GetValue() float64 {
	return confidenceLevel.value
}

// GetProperty Generate a CycloneDX component property from this confidence
func (confidenceLevel ConfidenceLevel) GetProperty() cdx.Property {
	return cdx.Property{
		Name:  "confidenceLevel",
		Value: fmt.Sprint(confidenceLevel.value),
	}
}
