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

// Paths contains all MVP file locations under the AgentSSH home directory.
type Paths struct {
	Home          string
	InventoryFile string
	PolicyFile    string
	AuditFile     string
	SessionFile   string
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
	return fmt.Sprintf("agentssh config directory not found: %s; create it with inventory.yaml and policy.yaml, or set %s to another directory", e.Home, EnvHome)
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

// NewPaths derives the MVP file layout from a configuration home directory.
func NewPaths(home string) Paths {
	return Paths{
		Home:          home,
		InventoryFile: filepath.Join(home, "inventory.yaml"),
		PolicyFile:    filepath.Join(home, "policy.yaml"),
		AuditFile:     filepath.Join(home, "audit.log"),
		SessionFile:   filepath.Join(home, "session"),
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
