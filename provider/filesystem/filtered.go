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
	"io"
	"path/filepath"
	"strings"

	"github.com/bmatcuk/doublestar/v4"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	log "github.com/sirupsen/logrus"
)

// FilteredFilesystem wraps a Filesystem and skips paths matching ignore patterns.
type FilteredFilesystem struct {
	inner    Filesystem
	patterns []string
}

// NewFilteredFilesystem creates a new FilteredFilesystem that wraps inner and
// skips files matching any of the provided patterns. Patterns use doublestar
// glob syntax (compatible with .gitignore-style patterns).
func NewFilteredFilesystem(inner Filesystem, patterns []string) Filesystem {
	if len(patterns) == 0 {
		return inner
	}
	return &FilteredFilesystem{
		inner:    inner,
		patterns: patterns,
	}
}

// WalkDir walks the wrapped filesystem, skipping files that match any ignore pattern.
func (f *FilteredFilesystem) WalkDir(fn FilePathAnalysisFunc) error {
	return f.inner.WalkDir(func(path string) error {
		if f.shouldIgnore(path) {
			log.Debugf("Ignoring file: %s", path)
			return nil
		}
		return fn(path)
	})
}

// Open delegates to the inner filesystem.
func (f *FilteredFilesystem) Open(path string) (io.ReadCloser, error) {
	return f.inner.Open(path)
}

// Exists delegates to the inner filesystem.
func (f *FilteredFilesystem) Exists(path string) (bool, error) {
	return f.inner.Exists(path)
}

// GetConfig delegates to the inner filesystem.
func (f *FilteredFilesystem) GetConfig() (v1.Config, bool) {
	return f.inner.GetConfig()
}

// GetIdentifier delegates to the inner filesystem.
func (f *FilteredFilesystem) GetIdentifier() string {
	return f.inner.GetIdentifier()
}

// shouldIgnore checks if a path matches any of the ignore patterns.
func (f *FilteredFilesystem) shouldIgnore(path string) bool {
	// Normalize path separators to forward slashes for consistent matching
	normalizedPath := filepath.ToSlash(path)

	for _, pattern := range f.patterns {
		pattern = strings.TrimSpace(pattern)
		if pattern == "" || strings.HasPrefix(pattern, "#") {
			continue
		}

		// If pattern ends with /, it matches directories (i.e., any path with that prefix)
		if strings.HasSuffix(pattern, "/") {
			prefix := strings.TrimSuffix(pattern, "/")
			if strings.HasPrefix(normalizedPath, prefix+"/") || normalizedPath == prefix {
				return true
			}
		}

		// Try matching the pattern against the full path
		if matched, _ := doublestar.Match(pattern, normalizedPath); matched {
			return true
		}

		// Also try matching against just the filename (for patterns like "*.tmp")
		if !strings.Contains(pattern, "/") {
			base := filepath.Base(normalizedPath)
			if matched, _ := doublestar.Match(pattern, base); matched {
				return true
			}
		}
	}
	return false
}
