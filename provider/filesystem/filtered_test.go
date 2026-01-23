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
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewFilteredFilesystem_NoPatterns(t *testing.T) {
	plain := NewPlainFilesystem(".")
	result := NewFilteredFilesystem(plain, nil)
	// Should return the inner filesystem directly when no patterns
	assert.Equal(t, plain, result)

	result = NewFilteredFilesystem(plain, []string{})
	assert.Equal(t, plain, result)
}

func TestFilteredFilesystem_ShouldIgnore(t *testing.T) {
	inner := NewPlainFilesystem(".")
	patterns := []string{
		"testdata/",
		"*.tmp",
		"vendor/",
		"secret.key",
		"docs/**/*.pdf",
		"# this is a comment",
		"",
	}
	fs := &FilteredFilesystem{inner: inner, patterns: patterns}

	tests := []struct {
		path     string
		expected bool
	}{
		// Directory-style patterns
		{"testdata/cert.pem", true},
		{"testdata/sub/file.txt", true},
		{"vendor/lib/file.go", true},
		// Extension patterns
		{"some/path/file.tmp", true},
		{"file.tmp", true},
		// Exact file match
		{"secret.key", true},
		{"sub/secret.key", true},
		// Doublestar patterns
		{"docs/intro/manual.pdf", true},
		{"docs/manual.pdf", true},
		// Should NOT be ignored
		{"src/main.go", false},
		{"certificates/cert.pem", false},
		{"file.txt", false},
		{"testdata_backup/file.txt", false},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			assert.Equal(t, tt.expected, fs.shouldIgnore(tt.path), "path: %s", tt.path)
		})
	}
}

func TestFilteredFilesystem_WalkDir(t *testing.T) {
	// Create a temporary directory structure for testing
	tmpDir := t.TempDir()

	// Create files
	files := []string{
		"src/main.go",
		"src/util.go",
		"testdata/cert.pem",
		"testdata/key.pem",
		"vendor/lib.go",
		"README.md",
		"temp.tmp",
	}

	for _, f := range files {
		path := filepath.Join(tmpDir, f)
		err := os.MkdirAll(filepath.Dir(path), 0755)
		assert.NoError(t, err)
		err = os.WriteFile(path, []byte("test"), 0644)
		assert.NoError(t, err)
	}

	plain := NewPlainFilesystem(tmpDir)
	patterns := []string{"testdata/", "vendor/", "*.tmp"}
	filtered := NewFilteredFilesystem(plain, patterns)

	var walked []string
	err := filtered.WalkDir(func(path string) error {
		walked = append(walked, path)
		return nil
	})

	assert.NoError(t, err)
	assert.Contains(t, walked, "src/main.go")
	assert.Contains(t, walked, "src/util.go")
	assert.Contains(t, walked, "README.md")
	assert.NotContains(t, walked, "testdata/cert.pem")
	assert.NotContains(t, walked, "testdata/key.pem")
	assert.NotContains(t, walked, "vendor/lib.go")
	assert.NotContains(t, walked, "temp.tmp")
}

func TestFilteredFilesystem_DelegatesMethods(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test.txt")
	err := os.WriteFile(testFile, []byte("hello"), 0644)
	assert.NoError(t, err)

	plain := NewPlainFilesystem(tmpDir)
	filtered := NewFilteredFilesystem(plain, []string{"*.tmp"})

	// Test Open
	rc, err := filtered.Open("test.txt")
	assert.NoError(t, err)
	rc.Close()

	// Test Exists
	exists, err := filtered.Exists("test.txt")
	assert.NoError(t, err)
	assert.True(t, exists)

	exists, err = filtered.Exists("nonexistent.txt")
	assert.NoError(t, err)
	assert.False(t, exists)

	// Test GetConfig
	_, ok := filtered.GetConfig()
	assert.False(t, ok)

	// Test GetIdentifier
	assert.Contains(t, filtered.GetIdentifier(), tmpDir)
}

func TestFilteredFilesystem_CommentsAndEmptyLines(t *testing.T) {
	inner := NewPlainFilesystem(".")
	patterns := []string{
		"# comment",
		"",
		"  # indented comment",
		"  ",
		"*.log",
	}
	fs := &FilteredFilesystem{inner: inner, patterns: patterns}

	// Comments and empty lines should not affect matching
	assert.False(t, fs.shouldIgnore("src/main.go"))
	assert.True(t, fs.shouldIgnore("output.log"))
}

func TestLoadIgnorePatterns(t *testing.T) {
	tmpDir := t.TempDir()

	// Create .cbomkitignore file
	ignoreContent := "# Test ignore file\ntestdata/\n*.tmp\n\nvendor/\n"
	err := os.WriteFile(filepath.Join(tmpDir, IgnoreFileName), []byte(ignoreContent), 0644)
	assert.NoError(t, err)

	configPatterns := []string{"build/"}
	cliPatterns := []string{"*.log"}

	patterns := LoadIgnorePatterns(tmpDir, configPatterns, cliPatterns)

	assert.Contains(t, patterns, "testdata/")
	assert.Contains(t, patterns, "*.tmp")
	assert.Contains(t, patterns, "vendor/")
	assert.Contains(t, patterns, "build/")
	assert.Contains(t, patterns, "*.log")
	// Comments and empty lines should be excluded
	assert.NotContains(t, patterns, "# Test ignore file")
	assert.NotContains(t, patterns, "")
}

func TestLoadIgnorePatterns_NoIgnoreFile(t *testing.T) {
	tmpDir := t.TempDir()

	configPatterns := []string{"build/"}
	cliPatterns := []string{"*.log"}

	patterns := LoadIgnorePatterns(tmpDir, configPatterns, cliPatterns)

	// Should still have config and CLI patterns
	assert.Contains(t, patterns, "build/")
	assert.Contains(t, patterns, "*.log")
	assert.Len(t, patterns, 2)
}

func TestLoadIgnorePatterns_EmptyRootPath(t *testing.T) {
	configPatterns := []string{"build/"}
	cliPatterns := []string{"*.log"}

	patterns := LoadIgnorePatterns("", configPatterns, cliPatterns)

	assert.Contains(t, patterns, "build/")
	assert.Contains(t, patterns, "*.log")
	assert.Len(t, patterns, 2)
}
