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

package docker

import (
	"errors"
	"fmt"
	"github.com/cbomkit/cbomkit-theia/provider/filesystem"
	scannererrors "github.com/cbomkit/cbomkit-theia/scanner/errors"
	"io"
	"strings"

	"github.com/anchore/stereoscope/pkg/file"
	"github.com/anchore/stereoscope/pkg/filetree/filenode"
	"github.com/anchore/stereoscope/pkg/image"
	v1 "github.com/google/go-containerregistry/pkg/v1"
)

// Layer Struct to represent a single layer in an ActiveImage
type Layer struct { // implements Filesystem
	*image.Layer
	index int
	image *ActiveImage
}

// WalkDir Walk all files in the squashed layer using fn
func (layer Layer) WalkDir(fn filesystem.FilePathAnalysisFunc) error {
	return layer.SquashedTree.Walk(
		func(path file.Path, f filenode.FileNode) error {
			if f.FileType == file.TypeDirectory {
				return nil
			}

			err := fn(string(path))

			if errors.Is(err, scannererrors.ErrParsingFailedAlthoughChecked) {
				return nil
			} else {
				return err
			}
		}, nil)
}

// Open Read a file from this layer
func (layer Layer) Open(path string) (io.ReadCloser, error) {
	readCloser, err := layer.OpenPathFromSquash(file.Path(path))
	if err != nil {
		return nil, err
	}
	return readCloser, err
}

// Exists Check if a file at path exists in this layer
func (layer Layer) Exists(path string) (bool, error) {
	_, err := layer.OpenPathFromSquash(file.Path(path))
	if err != nil {
		if strings.HasPrefix(err.Error(), "could not find file path in Tree") {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// GetConfig Get the image config
func (layer Layer) GetConfig() (config v1.Config, ok bool) {
	return layer.image.GetConfig()
}

// GetIdentifier Get a unique string for this layer in the image; can be used for logging, etc.
func (layer Layer) GetIdentifier() string {
	return fmt.Sprintf("Docker Image Layer (id:%v, layer:%v)", layer.image.id, layer.index)
}
