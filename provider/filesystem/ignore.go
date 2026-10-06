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
	"bufio"
	"os"
	"path/filepath"
	"strings"

	log "github.com/sirupsen/logrus"
)

const IgnoreFileName = ".cbomkitignore"

// LoadIgnorePatterns loads ignore patterns from all sources:
// 1. The .cbomkitignore file in rootPath (if rootPath is non-empty)
// 2. Config-based patterns (passed in)
// 3. CLI flag patterns (passed in)
// Patterns are merged; duplicates are not removed (they are harmless).
func LoadIgnorePatterns(rootPath string, configPatterns []string, cliPatterns []string) []string {
	var patterns []string

	// Load from .cbomkitignore file if rootPath is provided
	if rootPath != "" {
		filePatterns := loadIgnoreFile(filepath.Join(rootPath, IgnoreFileName))
		patterns = append(patterns, filePatterns...)
	}

	// Add config patterns
	patterns = append(patterns, configPatterns...)

	// Add CLI patterns
	patterns = append(patterns, cliPatterns...)

	return patterns
}

// loadIgnoreFile reads an ignore file and returns the patterns found.
// Returns nil if the file does not exist or cannot be read.
func loadIgnoreFile(path string) []string {
	file, err := os.Open(path)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Warnf("Could not read ignore file %s: %v", path, err)
		}
		return nil
	}
	defer file.Close()

	log.Infof("Loading ignore patterns from %s", path)

	var patterns []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		patterns = append(patterns, line)
	}

	if err := scanner.Err(); err != nil {
		log.Warnf("Error reading ignore file %s: %v", path, err)
	}

	return patterns
}
