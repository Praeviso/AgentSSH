package config

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/Praeviso/AgentSSH/internal/policy"
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

func TestEnsureHomeCreatesAndSeeds(t *testing.T) {
	home := filepath.Join(t.TempDir(), "agentssh")
	created, err := EnsureHome(home)
	if err != nil {
		t.Fatalf("EnsureHome: %v", err)
	}
	if !created {
		t.Fatal("created = false, want true for a new home")
	}
	info, err := os.Stat(home)
	if err != nil || !info.IsDir() {
		t.Fatalf("home not a directory: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o700 {
		t.Fatalf("home perm = %o, want 700", perm)
	}

	// Seeded files must parse and carry the safe defaults.
	t.Setenv(EnvHome, home)
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load seeded home: %v", err)
	}
	if cfg.Inventory.Transport != "native" {
		t.Fatalf("seeded transport = %q, want native", cfg.Inventory.Transport)
	}
	if cfg.Policy.Defaults.Policy != policy.ActionAllow {
		t.Fatalf("default policy = %q, want allow", cfg.Policy.Defaults.Policy)
	}
	if len(cfg.Policy.Rules) == 0 || cfg.Policy.Rules[0].Action != policy.ActionDeny {
		t.Fatalf("seeded policy missing catastrophic deny rule: %+v", cfg.Policy.Rules)
	}
}

func TestEnsureHomeIdempotentDoesNotOverwrite(t *testing.T) {
	home := t.TempDir() // already exists
	custom := []byte("version: 1\ntransport: ssh\n")
	if err := os.WriteFile(filepath.Join(home, "inventory.yaml"), custom, 0o600); err != nil {
		t.Fatal(err)
	}
	created, err := EnsureHome(home)
	if err != nil {
		t.Fatalf("EnsureHome: %v", err)
	}
	if created {
		t.Fatal("created = true, want false for an existing home")
	}
	got, err := os.ReadFile(filepath.Join(home, "inventory.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(custom) {
		t.Fatalf("existing inventory.yaml overwritten: %q", got)
	}
	// policy.yaml was missing, so EnsureHome should have seeded it.
	if _, err := os.Stat(filepath.Join(home, "policy.yaml")); err != nil {
		t.Fatalf("policy.yaml not seeded: %v", err)
	}
}

func TestEnsureHomePathNotDirectory(t *testing.T) {
	file := filepath.Join(t.TempDir(), "afile")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := EnsureHome(file)
	var se SetupError
	if !errors.As(err, &se) {
		t.Fatalf("want SetupError, got %v", err)
	}
}
