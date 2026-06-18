package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/Praeviso/AgentSSH/internal/inventory"
	"github.com/Praeviso/AgentSSH/internal/policy"
	"gopkg.in/yaml.v3"
)

const (
	// EnvHome overrides the default ~/.agentssh configuration directory.
	EnvHome = "AGENTSSH_HOME"
	// DefaultDirName is the configuration directory under the user's home.
	DefaultDirName = ".agentssh"
)

// seedInventoryYAML is written on first run when inventory.yaml is absent.
const seedInventoryYAML = `# AgentSSH inventory — manage via 'agentssh tui' (Hosts tab) or 'agentssh inventory'.
# Hosts listed here are the only targets the agent can reach. No keys or
# passwords live in this file; credentials stay in ssh-agent, ~/.ssh, and the
# encrypted secrets store.
version: 1
transport: native           # built-in Go SSH client; set "ssh" to shell out to system ssh
host_key_policy: strict     # or "accept-new" for trust-on-first-use
hosts: {}
`

// seedPolicyYAML is written on first run when policy.yaml is absent. It ships a
// safe starting point: allow by default, deny a handful of catastrophic
// commands, and redact obvious secrets from output. 'deny' is a hard boundary
// the agent cannot override.
const seedPolicyYAML = `# AgentSSH policy — allow/deny rules + output filtering.
# 'deny' is a hard boundary the agent cannot override. See docs/architecture/overview.md.
version: 1
defaults:
  policy: allow
rules:
  - name: catastrophic
    match:
      cmd_regex: '\b(rm\s+-rf|mkfs|dd|shutdown|reboot|init\s+0|userdel)'
    action: deny
output:
  max_bytes: 16384
  redact:
    - '(?i)(password|passwd|secret|token)\s*[=:]\s*\S+'
`

// Paths contains all MVP file locations under the AgentSSH home directory.
type Paths struct {
	Home          string
	InventoryFile string
	PolicyFile    string
	AuditFile     string
	SessionFile   string
	SecretsFile   string
}

// Config is the parsed local configuration set.
type Config struct {
	Paths     Paths
	Inventory inventory.Inventory
	Policy    policy.Config
}

// MissingHomeError reports an absent configuration directory with setup guidance.
type MissingHomeError struct {
	Home string
}

func (e MissingHomeError) Error() string {
	return fmt.Sprintf("agentssh config directory not found: %s; run 'agentssh tui' to initialize it, or set %s to another directory", e.Home, EnvHome)
}

// ParseError reports a malformed inventory.yaml or policy.yaml. It is a setup
// problem (the operator hand-edits these files), so callers map it to a usage
// error rather than a runtime failure.
type ParseError struct {
	File string
	Err  error
}

func (e ParseError) Error() string {
	return fmt.Sprintf("failed to parse %s: %v", e.File, e.Err)
}

func (e ParseError) Unwrap() error { return e.Err }

// SetupError reports a config-home setup problem (the path exists but is not a
// directory, or it cannot be inspected). Like MissingHomeError it is a usage
// problem, not a runtime failure, so callers map it to exit 2.
type SetupError struct {
	Msg string
	Err error
}

func (e SetupError) Error() string {
	if e.Err != nil {
		return e.Msg + ": " + e.Err.Error()
	}
	return e.Msg
}

func (e SetupError) Unwrap() error { return e.Err }

// ResolveHome returns the active AgentSSH configuration directory.
func ResolveHome() (string, error) {
	if override := os.Getenv(EnvHome); override != "" {
		return filepath.Clean(override), nil
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolve user home for agentssh config: %w", err)
	}

	return filepath.Join(home, DefaultDirName), nil
}

// EnsureHome creates the configuration directory (0700) and seeds starter
// inventory.yaml and policy.yaml when they are absent, so the first run of an
// operator entry point (agentssh tui) works without manual setup. It is
// idempotent: an existing directory is reused and existing files are never
// overwritten. It returns true only when the home directory itself did not
// exist and was created.
func EnsureHome(home string) (bool, error) {
	created := false
	info, err := os.Stat(home)
	switch {
	case err == nil:
		if !info.IsDir() {
			return false, SetupError{Msg: fmt.Sprintf("agentssh config path is not a directory: %s", home)}
		}
	case errors.Is(err, os.ErrNotExist):
		if mkErr := os.MkdirAll(home, 0o700); mkErr != nil {
			return false, SetupError{Msg: fmt.Sprintf("create agentssh config directory %s", home), Err: mkErr}
		}
		created = true
	default:
		return false, SetupError{Msg: fmt.Sprintf("inspect agentssh config directory %s", home), Err: err}
	}

	paths := NewPaths(home)
	if err := seedFileIfMissing(paths.InventoryFile, seedInventoryYAML); err != nil {
		return created, err
	}
	if err := seedFileIfMissing(paths.PolicyFile, seedPolicyYAML); err != nil {
		return created, err
	}
	return created, nil
}

func seedFileIfMissing(path, content string) error {
	if _, err := os.Stat(path); err == nil {
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return SetupError{Msg: fmt.Sprintf("inspect %s", path), Err: err}
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		return SetupError{Msg: fmt.Sprintf("write %s", path), Err: err}
	}
	return nil
}

// NewPaths derives the MVP file layout from a configuration home directory.
func NewPaths(home string) Paths {
	return Paths{
		Home:          home,
		InventoryFile: filepath.Join(home, "inventory.yaml"),
		PolicyFile:    filepath.Join(home, "policy.yaml"),
		AuditFile:     filepath.Join(home, "audit.log"),
		SessionFile:   filepath.Join(home, "session"),
		SecretsFile:   filepath.Join(home, "secrets.enc"),
	}
}

// Load parses the local AgentSSH configuration directory.
//
// Missing inventory.yaml or policy.yaml files leave their structs zero-valued;
// a missing directory returns MissingHomeError with setup guidance.
func Load() (*Config, error) {
	home, err := ResolveHome()
	if err != nil {
		return nil, err
	}

	if err := requireHome(home); err != nil {
		return nil, err
	}

	cfg := &Config{Paths: NewPaths(home)}
	if err := decodeYAMLFile(cfg.Paths.InventoryFile, &cfg.Inventory); err != nil {
		return nil, err
	}
	if err := decodeYAMLFile(cfg.Paths.PolicyFile, &cfg.Policy); err != nil {
		return nil, err
	}

	return cfg, nil
}

func requireHome(home string) error {
	info, err := os.Stat(home)
	if err == nil {
		if !info.IsDir() {
			return SetupError{Msg: fmt.Sprintf("agentssh config path is not a directory: %s", home)}
		}
		return nil
	}
	if errors.Is(err, os.ErrNotExist) {
		return MissingHomeError{Home: home}
	}
	return SetupError{Msg: fmt.Sprintf("inspect agentssh config directory %s", home), Err: err}
}

func decodeYAMLFile(path string, target any) error {
	file, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer func() {
		_ = file.Close()
	}()

	if err := yaml.NewDecoder(file).Decode(target); err != nil {
		return ParseError{File: path, Err: err}
	}
	return nil
}
