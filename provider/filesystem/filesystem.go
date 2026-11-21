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

package filesystem

import (
	goerrors "errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"

	log "github.com/sirupsen/logrus"

	scannererrors "github.com/cbomkit/cbomkit-theia/scanner/errors"

	v1 "github.com/google/go-containerregistry/pkg/v1"
)

// FilePathAnalysisFunc A simple interface for a function to walk directories
type FilePathAnalysisFunc func(path string) error

// Filesystem interface is mainly used to interact with all types of possible data source
// (e.g., directories, docker images etc.); for images this represents a squashed layer
type Filesystem interface {
	WalkDir(fn FilePathAnalysisFunc) (err error)            // Walk the full filesystem using the FilePathAnalysisFunc fn
	Open(path string) (readCloser io.ReadCloser, err error) // Read a specific file with a path from the root of the filesystem
	Exists(path string) (exists bool, err error)            // Check if a specific file exists with a path from the root of the filesystem
	GetConfig() (config v1.Config, ok bool)                 // Get a config of this filesystem in container image format (if it exists)
	GetIdentifier() string                                  // Identifier for this specific filesystem; can be used for logging
}

// DirSkippingWalker is an optional interface for filesystems to prune
// directories during a walk without reading them.
type DirSkippingWalker interface {
	WalkDirSkipping(fn FilePathAnalysisFunc, skipDir func(relativePath string) bool) error
}

// PlainFilesystem Simple plain filesystem that is constructed from the directory
type PlainFilesystem struct { // implements Filesystem
	rootPath string
}

// NewPlainFilesystem Get a new PlainFilesystem from rootPath
func NewPlainFilesystem(rootPath string) PlainFilesystem {
	return PlainFilesystem{
		rootPath: rootPath,
	}
}

// WalkDir Walk the whole PlainFilesystem using fn
func (plainFilesystem PlainFilesystem) WalkDir(fn FilePathAnalysisFunc) error {
	return plainFilesystem.WalkDirSkipping(fn, nil)
}

// WalkDirSkipping Walk the PlainFilesystem using fn, without reading directories for which skipDir returns true.
// A nil skipDir will walk everything.
func (plainFilesystem PlainFilesystem) WalkDirSkipping(fn FilePathAnalysisFunc, skipDir func(relativePath string) bool) error {
	return filepath.WalkDir(plainFilesystem.rootPath, func(path string, d fs.DirEntry, err error) error {
		// WalkDir calls us for a directory before reading it, so returning SkipDir here means it won't be read at all
		if skipDir != nil && d != nil && d.IsDir() {
			if rel, relErr := filepath.Rel(plainFilesystem.rootPath, path); relErr == nil && rel != "." && skipDir(filepath.ToSlash(rel)) {
				return filepath.SkipDir
			}
		}

		if err != nil {
			return err
		}

		if d.IsDir() {
			return nil
		}

		// Only regular files can be scanned; for example opening a FIFO would make open() never return
		info, err := os.Stat(path)
		if err != nil || !info.Mode().IsRegular() {
			return nil
		}

		relativePath, err := filepath.Rel(plainFilesystem.rootPath, path)

		if err != nil {
			return err
		}

		// Normalize to forward slashes for cross-platform consistency
		relativePath = filepath.ToSlash(relativePath)

		err = fn(relativePath)

		if goerrors.Is(err, scannererrors.ErrParsingFailedAlthoughChecked) {
			log.Warn(err.Error())
			return nil
		} else {
			return err
		}
	})
}

// Open Read a file from this filesystem; a path should be relative to PlainFilesystem.rootPath
func (plainFilesystem PlainFilesystem) Open(path string) (io.ReadCloser, error) {
	return os.Open(filepath.Join(plainFilesystem.rootPath, path))
}

// Exists Check if a file at path exists in the filesystem; a path should be relative to PlainFilesystem.rootPath
func (plainFilesystem PlainFilesystem) Exists(path string) (bool, error) {
	_, err := os.Lstat(filepath.Join(plainFilesystem.rootPath, path))
	if os.IsNotExist(err) {
		return false, nil
	} else if err != nil {
		return false, err
	}
	return true, nil
}

// GetConfig A plain directory does not have a filesystem, so we return an empty object and false
func (plainFilesystem PlainFilesystem) GetConfig() (config v1.Config, ok bool) {
	return v1.Config{}, false
}

// GetIdentifier Get a unique string for this PlainFilesystem; can be used for logging, etc.
func (plainFilesystem PlainFilesystem) GetIdentifier() string {
	return fmt.Sprintf("Plain Filesystem (%v)", plainFilesystem.rootPath)
}

func ReadAllAndClose(rc io.ReadCloser) ([]byte, error) {
	defer rc.Close()
	b, err := io.ReadAll(rc)
	return b, err
}
