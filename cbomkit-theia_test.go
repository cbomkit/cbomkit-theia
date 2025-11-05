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

package main

import (
	"bytes"
	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/IBM/cbomkit-theia/provider/cyclonedx"
	"github.com/stretchr/testify/assert"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/IBM/cbomkit-theia/provider/filesystem"
	"github.com/IBM/cbomkit-theia/scanner"
	"go.uber.org/dig"
)

var testFileFolder = "./testdata"
var dirExtension = "/dir"

func TestEmpty(t *testing.T) {
	bom, err := runScanAndReceiveCBOM("/empty")
	assert.NoError(t, err)
	assert.NotEmpty(t, *bom)

	assert.Empty(t, bom.Components)
}

func TestUnknownKeySize(t *testing.T) {
	bom, err := runScanAndReceiveCBOM("/unknown_key_size")
	assert.NoError(t, err)
	assert.NotEmpty(t, *bom)

	// TODO: assert CBOM content

	err = cdx.NewBOMEncoder(os.Stdout, cdx.BOMFileFormatJSON).SetPretty(true).Encode(bom)
	if err != nil {
		t.Fail()
	}
}

func TestSingleCertificate(t *testing.T) {
	bom, err := runScanAndReceiveCBOM("/certificate")
	assert.NoError(t, err)
	assert.NotEmpty(t, *bom)

	// TODO: assert CBOM content

	err = cdx.NewBOMEncoder(os.Stdout, cdx.BOMFileFormatJSON).SetPretty(true).Encode(bom)
	if err != nil {
		t.Fail()
	}
}

func TestPrivateKey(t *testing.T) {
	bom, err := runScanAndReceiveCBOM("/private_key")
	assert.NoError(t, err)
	assert.NotEmpty(t, *bom)

	// TODO: assert CBOM content

	err = cdx.NewBOMEncoder(os.Stdout, cdx.BOMFileFormatJSON).SetPretty(true).Encode(bom)
	if err != nil {
		t.Fail()
	}
}

func TestSecrets(t *testing.T) {
	bom, err := runScanAndReceiveCBOM("/secrets")
	assert.NoError(t, err)
	assert.NotEmpty(t, *bom)

	// TODO: assert CBOM content

	err = cdx.NewBOMEncoder(os.Stdout, cdx.BOMFileFormatJSON).SetPretty(true).Encode(bom)
	if err != nil {
		t.Fail()
	}
}

func runScanAndReceiveCBOM(testPath string) (*cdx.BOM, error) {
	target := new(bytes.Buffer)
	container, err := createScannerConfig(target, testPath)
	if err != nil {
		return nil, err
	}
	err = container.Invoke(scanner.RunScan)
	if err != nil {
		return nil, err
	}

	bom, err := cyclonedx.ParseBOM(target)
	if err != nil {
		return nil, err
	}
	return bom, nil
}

func createScannerConfig(target io.Writer, testPath string) (*dig.Container, error) {
	container := dig.New()

	if err := container.Provide(func() string {
		bomFilePath := testFileFolder + testPath + "/bom.json"
		if _, err := os.Stat(bomFilePath); err != nil {
			return ""
		}
		return testFileFolder + testPath + "/bom.json"
	}, dig.Name("bomFilePath")); err != nil {
		return nil, err
	}

	if err := container.Provide(func() io.Writer {
		return target
	}); err != nil {
		return nil, err
	}

	for _, pluginConstructor := range scanner.GetAllPluginConstructors() {
		if err := container.Provide(pluginConstructor, dig.Group("plugins")); err != nil {
			return nil, err
		}
	}

	if err := container.Provide(func() filesystem.Filesystem {
		return filesystem.NewPlainFilesystem(filepath.Join(testFileFolder, testPath, dirExtension))
	}); err != nil {
		return nil, err
	}

	return container, nil
}
