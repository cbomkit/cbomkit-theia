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
	filteredFn := func(path string) error {
		if f.shouldIgnore(path) {
			log.Debugf("Ignoring file: %s", path)
			return nil
		}
		return fn(path)
	}
	// Use WalkDirSkipping if supported, otherwise use WalkDir
	if walker, ok := f.inner.(DirSkippingWalker); ok {
		return walker.WalkDirSkipping(filteredFn, f.shouldSkipDir)
	}
	return f.inner.WalkDir(filteredFn)
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

// shouldSkipDir checks if a directory should be skipped during a walk.
func (f *FilteredFilesystem) shouldSkipDir(path string) bool {
	normalizedPath := normalizePath(path)
	// Never skip root.
	if normalizedPath == "" {
		return false
	}
	for _, rawPattern := range f.patterns {
		pattern := strings.TrimSpace(rawPattern)
		if pattern == "" || strings.HasPrefix(pattern, "#") {
			continue
		}
		normalizedPattern := normalizePath(pattern)
		if matchesDirPattern(normalizedPattern, normalizedPath) {
			log.Debugf("Skipping directory: %s (matches ignore pattern %q)", path, pattern)
			return true
		}
	}
	return false
}

// normalizePath strips any leading "/" and "./" so that relative (dir) and
// absolute (image) paths and ignore patterns are treated consistently.
func normalizePath(path string) string {
	// Loop, since a path may have multiple leading "/" or "./".
	for {
		switch {
		case strings.HasPrefix(path, "/"):
			path = path[1:]
		case strings.HasPrefix(path, "./"):
			path = path[2:]
		default:
			return path
		}
	}
}

// matchesDirPattern reports whether a normalized dir pattern ("**", "dir/" or "dir/**")
// matches the normalized path, i.e. the path is that directory or lies below it.
func matchesDirPattern(normalizedPattern, normalizedPath string) bool {
	switch {
	case normalizedPattern == "**":
		// "**", "/**" and "./**" match every directory (the root is never skipped by the caller)
		return true
	case strings.HasSuffix(normalizedPattern, "/**"):
		// already matches the directory and everything below it
	case strings.HasSuffix(normalizedPattern, "/"):
		normalizedPattern += "**"
	default:
		return false
	}
	matched, _ := doublestar.Match(normalizedPattern, normalizedPath)
	return matched
}

// shouldIgnore checks if a path matches any of the ignore patterns.
func (f *FilteredFilesystem) shouldIgnore(path string) bool {
	normalizedPath := normalizePath(path)

	for _, rawPattern := range f.patterns {
		rawPattern = strings.TrimSpace(rawPattern)
		if rawPattern == "" || strings.HasPrefix(rawPattern, "#") {
			continue
		}
		// A pattern containing "/" is anchored.
		// This has to be decided before the leading "/" is stripped, so
		// for example "/secret.key" does not match "sub/secret.key".
		anchored := strings.Contains(rawPattern, "/")
		pattern := normalizePath(rawPattern)
		if pattern == "" {
			continue
		}

		if matchesDirPattern(pattern, normalizedPath) {
			return true
		}

		// Try matching the pattern against the full path
		if matched, _ := doublestar.Match(pattern, normalizedPath); matched {
			return true
		}

		// Also try matching against just the filename (for patterns like "*.tmp")
		if !anchored {
			base := filepath.Base(normalizedPath)
			if matched, _ := doublestar.Match(pattern, base); matched {
				return true
			}
		}
	}
	return false
}
