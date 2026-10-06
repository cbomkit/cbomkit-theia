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
	"os"
	"testing"
)

var testfileFolder = "./testfiles"

var tests = []struct {
	in  string
	err bool
}{
	{testfileFolder + "/algorithm.json", false},
	{testfileFolder + "/algorithmBroken.json", true},
	{testfileFolder + "/protocol.json", false},
}

// Test if the BOMs are parsed as expected
func TestParseBOM(t *testing.T) {
	for _, test := range tests {
		t.Run(test.in, func(t *testing.T) {
			inReader, _ := os.Open(test.in)
			_, err := ParseBOM(inReader)
			if (err != nil) != test.err {
				t.Fatalf("Failed to parse %v", test.in)
			}
		})
	}
}
