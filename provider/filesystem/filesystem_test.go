package filesystem

import (
	"path/filepath"
	"testing"
	"time"
)

func TestWalkDirSkipsSpecialFiles(t *testing.T) {
	dir := filepath.Join("..", "..", "testdata", "special_files")

	var visited []string
	done := make(chan error, 1)
	go func() {
		done <- NewPlainFilesystem(dir).WalkDir(func(p string) error {
			visited = append(visited, p)
			return nil
		})
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("WalkDir hung")
	}
	if len(visited) != 1 || visited[0] != "a.txt" {
		t.Fatalf("unexpected visited files: %v", visited)
	}
}
