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

package pem

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"slices"

	"github.com/IBM/cbomkit-theia/scanner/key"

	"golang.org/x/crypto/ssh"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

// Filter that describes which PEMBlockTypes to allow
type Filter struct {
	FilterType TypeFilterType
	List       []BlockType
}

// TypeFilterType Used to specify whether a filter is an allow- or blocklist
type TypeFilterType bool

const (
	TypeAllowlist TypeFilterType = true  // Allowlist
	TypeBlocklist TypeFilterType = false // Blocklist
)

// BlockType A not complete list of PEMBlockTypes that can be detected currently
type BlockType string

const (
	BlockTypeCertificate         BlockType = "CERTIFICATE"
	BlockTypePrivateKey          BlockType = "PRIVATE KEY"
	BlockTypeEncryptedPrivateKey BlockType = "ENCRYPTED PRIVATE KEY"
	BlockTypePublicKey           BlockType = "PUBLIC KEY"
	BlockTypeECPrivateKey        BlockType = "EC PRIVATE KEY"
	BlockTypeRSAPrivateKey       BlockType = "RSA PRIVATE KEY"
	BlockTypeRSAPublicKey        BlockType = "RSA PUBLIC KEY"
	BlockTypeOPENSSHPrivateKey   BlockType = "OPENSSH PRIVATE KEY"
)

// ParsePEMToBlocksWithTypeFilter Just like ParsePEMToBlocksWithTypes but uses a filter for filtering
func ParsePEMToBlocksWithTypeFilter(raw []byte, filter Filter) map[*pem.Block]BlockType {
	blocksWithType := parsePEMToBlocksWithTypes(raw)
	filteredBlocksWithType := make(map[*pem.Block]BlockType)

	for block, t := range blocksWithType {
		if slices.Contains(filter.List, t) == bool(filter.FilterType) {
			filteredBlocksWithType[block] = t
		}
	}
	return filteredBlocksWithType
}

// GenerateCdxComponents Generate cyclone-go components from a block containing a key
func GenerateCdxComponents(block *pem.Block) ([]cdx.Component, error) {
	switch BlockType(block.Type) {
	case BlockTypePrivateKey:
		rawKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return []cdx.Component{}, err
		}
		return key.GenerateCdxComponents([]any{rawKey})
	case BlockTypeECPrivateKey:
		rawKey, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return []cdx.Component{}, err
		}
		return key.GenerateCdxComponents([]any{rawKey, &rawKey.PublicKey})
	case BlockTypeRSAPrivateKey:
		rawKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return []cdx.Component{}, err
		}
		return key.GenerateCdxComponents([]any{rawKey, &rawKey.PublicKey})
	case BlockTypePublicKey:
		rawKey, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return []cdx.Component{}, err
		}
		return key.GenerateCdxComponents([]any{rawKey})
	case BlockTypeRSAPublicKey:
		rawKey, err := x509.ParsePKCS1PublicKey(block.Bytes)
		if err != nil {
			return []cdx.Component{}, err
		}
		return key.GenerateCdxComponents([]any{rawKey})
	case BlockTypeOPENSSHPrivateKey:
		rawKey, err := ssh.ParseRawPrivateKey(pem.EncodeToMemory(block))
		if err != nil {
			return []cdx.Component{}, err
		}
		return key.GenerateCdxComponents([]any{rawKey})
	default:
		return []cdx.Component{}, fmt.Errorf("could not generate component from PEM. Block type is unknown or not a key")
	}
}

// Parse the []byte of a PEM file to a map containing the *pem.Block and a PEMBlockType for each block
func parsePEMToBlocksWithTypes(raw []byte) map[*pem.Block]BlockType {
	blocks := parsePEMToBlocks(raw)

	blocksWithType := make(map[*pem.Block]BlockType, len(blocks))

	for _, block := range blocks {
		blocksWithType[block] = BlockType(block.Type)
	}
	return blocksWithType
}

func parsePEMToBlocks(raw []byte) []*pem.Block {
	rest := raw
	var blocks []*pem.Block
	for len(rest) != 0 {
		var newBlock *pem.Block
		newBlock, rest = pem.Decode(rest)
		if newBlock != nil {
			blocks = append(blocks, newBlock)
		} else {
			break
		}
	}
	return blocks
}
