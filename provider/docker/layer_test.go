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
	"archive/tar"
	"bytes"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cbomkit/cbomkit-theia/provider/filesystem"
)

var testFiles = []string{
	"secret.key",
	"sub/secret.key",
	"vendor/lib.go",
	"docs/sub/file.txt",
	"a/vendor/lib.go",
	"pages/[id]/page.ts",
}

// newTestImage writes testFiles to a single layer image archive and loads it
func newTestImage(t *testing.T) Layer {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, f := range testFiles {
		require.NoError(t, tw.WriteHeader(&tar.Header{Name: f, Typeflag: tar.TypeReg, Mode: 0o644}))
	}
	require.NoError(t, tw.Close())

	layer, err := tarball.LayerFromOpener(func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(buf.Bytes())), nil
	})
	require.NoError(t, err)
	img, err := mutate.AppendLayers(empty.Image, layer)
	require.NoError(t, err)

	archive := filepath.Join(t.TempDir(), "image.tar")
	require.NoError(t, tarball.WriteToFile(archive, name.MustParseReference("test:latest"), img))
	image, err := GetImage("docker-archive:" + archive)
	require.NoError(t, err)
	t.Cleanup(image.TearDown)
	return GetSquashedFilesystem(image).(Layer)
}

// skipRecorder wraps a DirSkippingWalker and records the directories it was told to skip.
// The unix test proves correct pruning with an unreadable dir, which fails the walk if it is entered.
// An image layer is walked in memory, so entering a dir never fails. Recording skipped dirs is
// the only way to verify correct pruning.
type skipRecorder struct {
	filesystem.Filesystem
	skipped []string
}

func (r *skipRecorder) WalkDirSkipping(fn filesystem.FilePathAnalysisFunc, skipDir func(path string) bool) error {
	return r.Filesystem.(filesystem.DirSkippingWalker).WalkDirSkipping(fn, func(p string) bool {
		skip := skipDir(p)
		if skip {
			r.skipped = append(r.skipped, strings.TrimPrefix(p, "/"))
		}
		return skip
	})
}

// Ignore patterns must give the same result on an image and a local dir with the same files
func TestLayer_WalkDirMatchesPlainFilesystem(t *testing.T) {
	root := t.TempDir()
	for _, f := range testFiles {
		p := filepath.Join(root, f)
		require.NoError(t, os.MkdirAll(filepath.Dir(p), 0o755))
		require.NoError(t, os.WriteFile(p, nil, 0o644))
	}
	filesystems := map[string]filesystem.Filesystem{
		"dir":   filesystem.NewPlainFilesystem(root),
		"image": newTestImage(t),
	}

	tests := map[string]struct {
		ignored []string
		skipped []string
	}{
		"vendor/":       {ignored: []string{"vendor/lib.go"}, skipped: []string{"vendor"}},
		"/vendor/":      {ignored: []string{"vendor/lib.go"}, skipped: []string{"vendor"}},
		"./vendor/**":   {ignored: []string{"vendor/lib.go"}, skipped: []string{"vendor"}},
		"secret.key":    {ignored: []string{"secret.key", "sub/secret.key"}},
		"/secret.key":   {ignored: []string{"secret.key"}},
		"docs/*":        {}, // direct children only, docs/sub/ is still walked
		"**/vendor/":    {ignored: []string{"vendor/lib.go", "a/vendor/lib.go"}, skipped: []string{"vendor", "a/vendor"}},
		"pages/[id]/":   {}, // "[id]" is a character class, it matches only i/ and d/
		`pages/\[id\]/`: {ignored: []string{"pages/[id]/page.ts"}, skipped: []string{"pages/[id]"}},
		// every top-level dir is pruned, so nested dirs like docs/sub are never reached
		"**":  {ignored: testFiles, skipped: []string{"sub", "vendor", "docs", "a", "pages"}},
		"/**": {ignored: testFiles, skipped: []string{"sub", "vendor", "docs", "a", "pages"}},
	}
	for pattern, tt := range tests {
		var expected []string
		for _, f := range testFiles {
			if !slices.Contains(tt.ignored, f) {
				expected = append(expected, f)
			}
		}
		for name, fs := range filesystems {
			t.Run(name+"/"+pattern, func(t *testing.T) {
				recorder := &skipRecorder{Filesystem: fs}
				var walked []string
				err := filesystem.NewFilteredFilesystem(recorder, []string{pattern}).WalkDir(func(p string) error {
					walked = append(walked, strings.TrimPrefix(p, "/"))
					return nil
				})
				require.NoError(t, err)
				assert.ElementsMatch(t, expected, walked)
				assert.ElementsMatch(t, tt.skipped, recorder.skipped)
			})
		}
	}
}

// A skipped dir must not be descended into
func TestLayer_WalkDirSkipping(t *testing.T) {
	var asked, walked []string
	err := newTestImage(t).WalkDirSkipping(func(p string) error {
		walked = append(walked, p)
		return nil
	}, func(p string) bool {
		asked = append(asked, p)
		return p == "/vendor"
	})
	require.NoError(t, err)

	assert.Contains(t, asked, "/vendor")
	assert.NotContains(t, walked, "/vendor/lib.go")
	assert.Len(t, walked, len(testFiles)-1)
}
