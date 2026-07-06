package main

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestLoadStdinSpecRejectsNonRegularFile(t *testing.T) {
	dir := t.TempDir()
	fifo := filepath.Join(dir, "pipe")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Skipf("cannot create FIFO on this platform: %v", err)
	}
	// loadStdinSpec must reject the FIFO by mode, not block reading it.
	_, err := loadStdinSpec(fifo)
	if err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("err = %v, want non-regular-file rejection", err)
	}
}

func TestLoadStdinSpecRejectsOversizeDuringRead(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "big.bin")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(maxStdinBytes + 1); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
	_, err = loadStdinSpec(path)
	if err == nil || !strings.Contains(err.Error(), "limit") {
		t.Fatalf("err = %v, want size-limit rejection", err)
	}
}

func TestLoadStdinSpecReadsRegularFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "conf")
	if err := os.WriteFile(path, []byte("hello"), 0o600); err != nil {
		t.Fatal(err)
	}
	spec, err := loadStdinSpec(path)
	if err != nil {
		t.Fatalf("loadStdinSpec: %v", err)
	}
	if string(spec.data) != "hello" || spec.bytes != 5 || spec.sha256 == "" {
		t.Fatalf("spec = %+v", spec)
	}
}
