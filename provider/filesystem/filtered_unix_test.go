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

//go:build unix

package filesystem

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

// An ignored directory must be skipped without being read
func TestFilteredFilesystem_WalkDirSkipsIgnoredDir(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"dir_ignored", "dir_not_ignored"} {
		if err := os.Mkdir(filepath.Join(dir, name), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, name, "file.txt"), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// Make the ignored directory unreadable
	ignored := filepath.Join(dir, "dir_ignored")
	if err := os.Chmod(ignored, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(ignored, 0o755) })

	var visited []string
	filtered := NewFilteredFilesystem(NewPlainFilesystem(dir), []string{"dir_ignored/"})
	err := filtered.WalkDir(func(p string) error {
		visited = append(visited, p)
		return nil
	})

	assert.NoError(t, err)
	assert.Equal(t, []string{"dir_not_ignored/file.txt"}, visited)
}
