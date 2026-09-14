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
	if cfg.Paths.StateDir != dir {
		t.Fatalf("state dir = %q", cfg.Paths.StateDir)
	}
	if cfg.Paths.ApprovalsDir != filepath.Join(dir, "approvals") ||
		cfg.Paths.SessionsDir != filepath.Join(dir, "approvals", "sessions") ||
		cfg.Paths.PendingDir != filepath.Join(dir, "approvals", "pending") ||
		cfg.Paths.ResponsesDir != filepath.Join(dir, "approvals", "responses") ||
		cfg.Paths.PayloadsDir != filepath.Join(dir, "payloads") {
		t.Fatalf("approval paths = %#v", cfg.Paths)
	}
}

func TestLoadUsesSeparateStateDirWhenConfigured(t *testing.T) {
	home := t.TempDir()
	state := filepath.Join(t.TempDir(), "agentssh-state")
	if err := os.WriteFile(filepath.Join(home, "inventory.yaml"), []byte("version: 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(EnvHome, home)
	t.Setenv(EnvStateDir, state)
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load valid with state dir: %v", err)
	}
	if cfg.Paths.Home != home || cfg.Paths.StateDir != state {
		t.Fatalf("paths home/state = %q/%q", cfg.Paths.Home, cfg.Paths.StateDir)
	}
	if cfg.Paths.InventoryFile != filepath.Join(home, "inventory.yaml") ||
		cfg.Paths.PolicyFile != filepath.Join(home, "policy.yaml") ||
		cfg.Paths.SecretsFile != filepath.Join(home, "secrets.enc") {
		t.Fatalf("configuration paths moved into state dir: %#v", cfg.Paths)
	}
	if cfg.Paths.AuditFile != filepath.Join(state, "audit.log") ||
		cfg.Paths.ApprovalsDir != filepath.Join(state, "approvals") ||
		cfg.Paths.SessionsDir != filepath.Join(state, "approvals", "sessions") ||
		cfg.Paths.PendingDir != filepath.Join(state, "approvals", "pending") ||
		cfg.Paths.ResponsesDir != filepath.Join(state, "approvals", "responses") ||
		cfg.Paths.PlansDir != filepath.Join(state, "approvals", "plans") ||
		cfg.Paths.PayloadsDir != filepath.Join(state, "payloads") {
		t.Fatalf("runtime paths did not move together: %#v", cfg.Paths)
	}
	if _, err := os.Stat(state); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("Load should not create state dir, stat err=%v", err)
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
	if cfg.Inventory.SSH.Multiplexing != "on" || cfg.Inventory.SSH.ControlPersist != "60s" || cfg.Inventory.SSH.KeepAliveInterval != "30s" {
		t.Fatalf("seeded ssh config = %#v", cfg.Inventory.SSH)
	}
	if len(cfg.Policy.Rules) != 0 || len(cfg.Policy.HostOverrides) != 0 {
		t.Fatalf("seeded policy should have zero active rules: %+v", cfg.Policy)
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
