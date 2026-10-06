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

package utils

import (
	"encoding/binary"
	"github.com/mitchellh/hashstructure/v2"
)

func Struct8Byte(a any) [8]byte {
	hash, err := hashstructure.Hash(a, hashstructure.FormatV2, &hashstructure.HashOptions{
		ZeroNil:      true,
		SlicesAsSets: true,
	})
	if err != nil {
		panic(err)
	}
	var b8 [8]byte
	b := make([]byte, 8)
	binary.LittleEndian.PutUint64(b, hash)
	copy(b8[:], b)
	return b8
}
