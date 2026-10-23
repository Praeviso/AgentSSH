package config

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/Praeviso/AgentSSH/internal/inventory"
	"github.com/Praeviso/AgentSSH/internal/managedmode"
	"github.com/Praeviso/AgentSSH/internal/policy"
	"github.com/Praeviso/AgentSSH/internal/remote"
	"github.com/Praeviso/AgentSSH/internal/remoteclient"
	"gopkg.in/yaml.v3"
)

const (
	// EnvHome overrides the default ~/.agentssh configuration directory.
	EnvHome = "AGENTSSH_HOME"
	// EnvStateDir overrides the runtime state directory. Configuration,
	// inventory, policy, secrets, and operator verification remain under EnvHome;
	// audit, approvals, sessions, responses, plans, executions, and payloads
	// move together under this directory.
	EnvStateDir = "AGENTSSH_STATE_DIR"
	// EnvApproval can enable the optional async approval flow when set truthy;
	// false values do not disable policy-file approval.
	EnvApproval = "AGENTSSH_APPROVAL"
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
ssh:
  multiplexing: on          # set "off" to disable connection reuse
  control_persist: 60s      # shell transport ControlPersist lifetime
  keepalive_interval: 30s   # pooled/native heartbeat and shell ServerAliveInterval
hosts: {}
`

// seedPolicyYAML is written on first run when policy.yaml is absent. It ships a
// default-deny scaffold with no active rules; operators must add explicit allow
// rules before an agent can execute commands.
const seedPolicyYAML = `# AgentSSH policy — priority-ordered allow/deny rules + output filtering.
# No command runs until an allow rule matches. See docs/architecture/overview.md.
version: 1
# rules:
#   - name: allow-readonly
#     priority: 10
#     match:
#       cmd_regex: '^(echo|uptime|whoami)\b'
#     action: allow
#   - name: deny-dangerous
#     priority: 100
#     match:
#       cmd_regex: '\b(rm\s+-rf|mkfs|dd|shutdown|reboot|init\s+0|userdel)'
#     action: deny
# host_overrides:
#   host:web-1:
#     rules:
#       - priority: 20
#         match:
#           cmd_regex: '^systemctl status\b'
#         action: allow
# rule_groups:
#   readonly:
#     rules:
#       - priority: 10
#         match:
#           cmd_regex: '^(uptime|whoami)\b'
#         action: allow
# Use 'agentssh policy host rule add web-1 --from-group readonly' to copy a
# group's current rules onto a host. Later group edits do not change the host copy.
output:
  max_bytes: 16384
  redact:
    - '(?i)(password|passwd|secret|token)\s*[=:]\s*\S+'
`

// Paths contains all MVP file locations under the AgentSSH home directory.
type Paths struct {
	Home          string
	StateDir      string
	InventoryFile string
	PolicyFile    string
	AuditFile     string
	SecretsFile   string
	ApprovalsDir  string
	SessionsDir   string
	PendingDir    string
	ResponsesDir  string
	PlansDir      string
	PayloadsDir   string
}

// Config is the parsed configuration set.
type Config struct {
	Paths     Paths
	Inventory inventory.Inventory
	Policy    policy.Config
	// Remote is the control-plane session when the home is enrolled for remote
	// control; nil in local mode. In remote mode Inventory and Policy come from
	// the signed bundle and the local policy.yaml is only a deny overlay.
	Remote *remoteclient.Session
	// Gateway is the control-plane client when the home is enrolled in
	// gateway mode; nil otherwise. Inventory and Policy are then empty: the
	// gateway resolves, authorizes and runs every command.
	Gateway *remoteclient.Client
}

// RemoteError reports that remote-managed configuration is unavailable. It is
// fail-closed: nothing runs on stale or unverifiable configuration.
type RemoteError struct {
	Err error
}

func (e RemoteError) Error() string {
	return fmt.Sprintf("remote configuration unavailable: %v", e.Err)
}

func (e RemoteError) Unwrap() error { return e.Err }

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

// ResolveStateDir returns the active AgentSSH runtime state directory.
func ResolveStateDir(home string) string {
	if override := os.Getenv(EnvStateDir); override != "" {
		return filepath.Clean(override)
	}
	return home
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
	stateDir := ResolveStateDir(home)
	approvalsDir := filepath.Join(stateDir, "approvals")
	return Paths{
		Home:          home,
		StateDir:      stateDir,
		InventoryFile: filepath.Join(home, "inventory.yaml"),
		PolicyFile:    filepath.Join(home, "policy.yaml"),
		AuditFile:     filepath.Join(stateDir, "audit.log"),
		SecretsFile:   filepath.Join(home, "secrets.enc"),
		ApprovalsDir:  approvalsDir,
		SessionsDir:   filepath.Join(approvalsDir, "sessions"),
		PendingDir:    filepath.Join(approvalsDir, "pending"),
		ResponsesDir:  filepath.Join(approvalsDir, "responses"),
		PlansDir:      filepath.Join(approvalsDir, "plans"),
		PayloadsDir:   filepath.Join(stateDir, "payloads"),
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
	return LoadHome(home)
}

// LoadPaths resolves the configuration directory without reading inventory or
// policy. Commands that only touch local state (audit, sessions, approvals)
// use it so they keep working in remote mode while the control plane is down.
func LoadPaths() (*Config, error) {
	home, err := ResolveHome()
	if err != nil {
		return nil, err
	}
	if err := requireHome(home); err != nil {
		return nil, err
	}
	cfg := &Config{Paths: NewPaths(home)}
	if _, err := remoteclient.LoadMode(home); err != nil {
		// An unreadable enrollment must not lock the operator out of the
		// local audit and sessions; commands that need the control plane
		// fail on it in Load.
		return cfg, nil
	}
	return cfg, attachGateway(cfg)
}

// attachGateway sets cfg.Gateway when the home is enrolled in gateway mode.
func attachGateway(cfg *Config) error {
	mode, err := remoteclient.LoadMode(cfg.Paths.Home)
	if err != nil {
		return RemoteError{Err: err}
	}
	if mode != remote.ModeGateway {
		return nil
	}
	client, err := remoteclient.NewClient(cfg.Paths.Home)
	if err != nil {
		return RemoteError{Err: err}
	}
	cfg.Gateway = client
	return nil
}

// LoadHome is Load for an explicit configuration directory.
func LoadHome(home string) (*Config, error) {
	if err := requireHome(home); err != nil {
		return nil, err
	}

	cfg := &Config{Paths: NewPaths(home)}
	if err := attachGateway(cfg); err != nil {
		return nil, err
	}
	if cfg.Gateway != nil {
		return cfg, nil
	}
	if managedmode.Enrolled(home) {
		return loadRemote(cfg)
	}
	if err := decodeYAMLFile(cfg.Paths.InventoryFile, &cfg.Inventory); err != nil {
		return nil, err
	}
	if err := decodeYAMLFile(cfg.Paths.PolicyFile, &cfg.Policy); err != nil {
		return nil, err
	}

	return cfg, nil
}

func loadRemote(cfg *Config) (*Config, error) {
	session, err := remoteclient.Open(context.Background(), cfg.Paths.Home, remoteclient.OpenOptions{})
	if err != nil {
		return nil, RemoteError{Err: err}
	}
	var local policy.Config
	if err := decodeYAMLFile(cfg.Paths.PolicyFile, &local); err != nil {
		return nil, err
	}
	cfg.Remote = session
	cfg.Inventory = session.Inventory
	cfg.Policy = session.Policy
	cfg.Policy.Overlay = &local
	if _, err := policy.NewEngine(cfg.Policy, cfg.Inventory); err != nil {
		return nil, ParseError{File: cfg.Paths.PolicyFile, Err: err}
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
