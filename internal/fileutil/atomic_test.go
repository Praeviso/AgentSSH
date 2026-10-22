package fileutil

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestCreateFileExclusivePublishesOnceAndCompletely(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "a.json")
	if err := CreateFileExclusive(path, []byte("first\n"), 0o600, ".publish-*.tmp"); err != nil {
		t.Fatal(err)
	}
	err := CreateFileExclusive(path, []byte("second\n"), 0o600, ".publish-*.tmp")
	if !errors.Is(err, os.ErrExist) {
		t.Fatalf("second publish = %v, want os.ErrExist", err)
	}
	data, err := os.ReadFile(path)
	if err != nil || string(data) != "first\n" {
		t.Fatalf("content = %q %v, want the first publisher's", data, err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %v %v", info.Mode(), err)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Fatalf("temporary files left behind: %v", entries)
	}
}

// A reader racing the publisher sees no file or the whole file, never a
// prefix of it.
func TestCreateFileExclusiveIsNeverSeenPartial(t *testing.T) {
	dir := t.TempDir()
	content := bytes.Repeat([]byte("x"), 256<<10)
	for i := range 50 {
		path := filepath.Join(dir, "r"+string(rune('a'+i%26))+string(rune('a'+i/26))+".json")
		var wg sync.WaitGroup
		wg.Add(1)
		stop := make(chan struct{})
		go func() {
			defer wg.Done()
			for {
				data, err := os.ReadFile(path)
				if err == nil && len(data) != len(content) {
					t.Errorf("read %d of %d bytes", len(data), len(content))
					return
				}
				select {
				case <-stop:
					return
				default:
				}
			}
		}()
		if err := CreateFileExclusive(path, content, 0o600, ".publish-*.tmp"); err != nil {
			t.Fatal(err)
		}
		close(stop)
		wg.Wait()
	}
}
