package secrets

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestStoreRoundTripWrongMasterTamperAndMode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secrets.enc")
	store, err := Open(path, "master")
	if err != nil {
		t.Fatalf("open missing: %v", err)
	}
	store.Set("web-2", "pw2")
	store.Set("web-1", "pw1")
	if err := store.Save("master"); err != nil {
		t.Fatalf("save: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("mode = %v, want 0600", got)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read raw: %v", err)
	}
	for _, leak := range []string{"pw1", "pw2", "web-1"} {
		if strings.Contains(string(raw), leak) {
			t.Fatalf("ciphertext leaked %q: %q", leak, raw)
		}
	}

	opened, err := Open(path, "master")
	if err != nil {
		t.Fatalf("open saved: %v", err)
	}
	if got, ok := opened.Password("web-1"); !ok || got != "pw1" {
		t.Fatalf("password web-1 = %q %t", got, ok)
	}
	if names := opened.Names(); len(names) != 2 || names[0] != "web-1" || names[1] != "web-2" {
		t.Fatalf("names = %#v", names)
	}
	opened.Delete("web-1")
	if _, ok := opened.Password("web-1"); ok {
		t.Fatal("deleted password still present")
	}

	if _, err := Open(path, "wrong"); !errors.Is(err, ErrWrongMaster) {
		t.Fatalf("wrong master err = %v, want ErrWrongMaster", err)
	}
	tampered := append([]byte{}, raw...)
	tampered[len(tampered)-1] ^= 0xff
	if err := os.WriteFile(path, tampered, 0o600); err != nil {
		t.Fatalf("write tampered: %v", err)
	}
	if _, err := Open(path, "master"); !errors.Is(err, ErrWrongMaster) {
		t.Fatalf("tampered err = %v, want ErrWrongMaster", err)
	}
}

func TestSaveIsAtomicOnRenameError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "as-directory")
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatalf("mkdir conflict: %v", err)
	}
	store := &Store{path: path, passwords: map[string]string{"web-1": "pw1"}}
	if err := store.Save("master"); err == nil {
		t.Fatal("save to directory err = nil")
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), "secrets-") {
			t.Fatalf("temporary file was not cleaned up: %s", entry.Name())
		}
	}
}

func TestSaveRejectsGroupOrWorldWritableDir(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o777); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })

	store, err := Open(filepath.Join(dir, "secrets.enc"), "master")
	if err != nil {
		t.Fatalf("open empty store: %v", err)
	}
	store.Set("web-1", "pw")
	if err := store.Save("master"); err == nil {
		t.Fatal("Save must fail closed when the secrets directory is group/world writable")
	}
}
