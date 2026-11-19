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
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestWalkDirSkipsSpecialFiles(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(filepath.Join(dir, "fifo"), 0o644); err != nil {
		t.Skipf("mkfifo not supported: %v", err)
	}
	if err := os.Symlink("fifo", filepath.Join(dir, "link_to_fifo")); err != nil {
		t.Fatal(err)
	}

	fsys := NewPlainFilesystem(dir)
	var visited []string
	done := make(chan error, 1)
	go func() {
		// Open every visited file like the plugins do; opening a FIFO blocks forever
		done <- fsys.WalkDir(func(p string) error {
			visited = append(visited, p)
			rc, err := fsys.Open(p)
			if err != nil {
				return err
			}
			return rc.Close()
		})
	}()

	select {
	case err := <-done:
		assert.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("WalkDir hung on a special file")
	}
	assert.Equal(t, []string{"a.txt"}, visited)
}
