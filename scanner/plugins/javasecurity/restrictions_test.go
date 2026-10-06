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

package javasecurity

import (
	"github.com/CycloneDX/cyclonedx-go"
	"testing"
)

func TestEvaluation(t *testing.T) {
	t.Run("Extracting TLS Rules from security file", func(t *testing.T) {
		component := cyclonedx.Component{
			Name: "RSA",
			CryptoProperties: &cyclonedx.CryptoProperties{
				AssetType: cyclonedx.CryptoAssetTypeAlgorithm,
				AlgorithmProperties: &cyclonedx.CryptoAlgorithmProperties{
					ParameterSetIdentifier: "2048",
				},
			},
		}
		algorithmRestriction := AlgorithmRestriction{"RSA", keySizeOperatorGreater, 2048}
		confidenceLevel, err := algorithmRestriction.allowed(&component)
		if err != nil {
			t.Fatal(err)
		}
		println(confidenceLevel)
	})
}
