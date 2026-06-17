package config

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadMissingHome(t *testing.T) {
	t.Setenv(EnvHome, filepath.Join(t.TempDir(), "does-not-exist"))
	_, err := Load()
	var me MissingHomeError
	if !errors.As(err, &me) {
		t.Fatalf("want MissingHomeError, got %v", err)
	}
}

func TestLoadHomeNotADirectory(t *testing.T) {
	file := filepath.Join(t.TempDir(), "afile")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(EnvHome, file)
	_, err := Load()
	var se SetupError
	if !errors.As(err, &se) {
		t.Fatalf("want SetupError, got %v", err)
	}
}

func TestLoadMalformedYAML(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "inventory.yaml"), []byte("::: bad: ["), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(EnvHome, dir)
	_, err := Load()
	var pe ParseError
	if !errors.As(err, &pe) {
		t.Fatalf("want ParseError, got %v", err)
	}
}

func TestLoadValid(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "inventory.yaml"), []byte("version: 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := func() (*Config, error) {
		t.Setenv(EnvHome, dir)
		return Load()
	}()
	if err != nil {
		t.Fatalf("Load valid: %v", err)
	}
	if cfg.Paths.AuditFile != filepath.Join(dir, "audit.log") {
		t.Fatalf("audit path = %q", cfg.Paths.AuditFile)
	}
}
