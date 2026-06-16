package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/Kritoooo/agentssh/internal/inventory"
	"github.com/Kritoooo/agentssh/internal/policy"
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
		return nil, fmt.Errorf("parse inventory config: %w", err)
	}
	if err := decodeYAMLFile(cfg.Paths.PolicyFile, &cfg.Policy); err != nil {
		return nil, fmt.Errorf("parse policy config: %w", err)
	}

	return cfg, nil
}

func requireHome(home string) error {
	info, err := os.Stat(home)
	if err == nil {
		if !info.IsDir() {
			return fmt.Errorf("agentssh config path is not a directory: %s", home)
		}
		return nil
	}
	if errors.Is(err, os.ErrNotExist) {
		return MissingHomeError{Home: home}
	}
	return fmt.Errorf("inspect agentssh config directory %s: %w", home, err)
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
		return fmt.Errorf("%s: %w", path, err)
	}
	return nil
}
