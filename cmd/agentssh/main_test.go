package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Praeviso/AgentSSH/internal/audit"
	"github.com/Praeviso/AgentSSH/internal/config"
	"github.com/Praeviso/AgentSSH/internal/discovery"
	"github.com/Praeviso/AgentSSH/internal/executor"
	"github.com/Praeviso/AgentSSH/internal/inventory"
	"github.com/Praeviso/AgentSSH/internal/output"
	"github.com/Praeviso/AgentSSH/internal/policy"
	"github.com/Praeviso/AgentSSH/internal/secrets"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
	"gopkg.in/yaml.v3"
)

func TestExitCodeForResult(t *testing.T) {
	tests := []struct {
		name   string
		result executor.Result
		want   int
	}{
		{
			name:   "success",
			result: executor.Result{ExitCode: 0},
			want:   exitOK,
		},
		{
			name:   "remote non-zero",
			result: executor.Result{ExitCode: 3},
			want:   exitRemoteFailed,
		},
		{
			name:   "ssh error",
			result: executor.Result{ExitCode: -1, Err: errors.New("connect failed")},
			want:   exitSSHError,
		},
		{
			name: "ssh exit 255",
			result: executor.Result{
				ExitCode: 255,
				Argv:     []string{"ssh", "deploy@10.0.0.11", "uptime"},
			},
			want: exitSSHError,
		},
		{
			name: "native remote exit 255 is remote failure",
			result: executor.Result{
				ExitCode: 255,
				Argv:     []string{"native-ssh", "deploy@10.0.0.11:22", "exit255"},
			},
			want: exitRemoteFailed,
		},
		{
			name: "native transport error",
			result: executor.Result{
				ExitCode: -1,
				Err:      errors.New("host key rejected"),
				Argv:     []string{"native-ssh", "deploy@10.0.0.11:22", "uptime"},
			},
			want: exitSSHError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := exitCodeForResult(tt.result); got != tt.want {
				t.Fatalf("exitCodeForResult = %d, want %d", got, tt.want)
			}
			t.Logf("case=%q status=%q mapped_exit=%d", tt.name, statusForResult(tt.result), tt.want)
		})
	}
}

func TestStatusForResultSSHExit255(t *testing.T) {
	result := executor.Result{
		ExitCode: 255,
		Argv:     []string{"ssh", "deploy@10.0.0.11", "uptime"},
	}
	if got := statusForResult(result); got != "ssh_error" {
		t.Fatalf("statusForResult = %q, want ssh_error", got)
	}
}

func TestTransportSelection(t *testing.T) {
	cfg := &config.Config{}
	defaultExec := newExecutor(cfg)
	if _, ok := defaultExec.(executor.NativeExecutor); !ok {
		t.Fatalf("default transport = %T, want built-in NativeExecutor", defaultExec)
	}
	cfg.Inventory.Transport = executor.TransportShell
	shellExec := newExecutor(cfg)
	if _, ok := shellExec.(executor.SSHExecutor); !ok {
		t.Fatalf("inventory shell transport = %T, want shell-out SSHExecutor", shellExec)
	}
	t.Setenv("AGENTSSH_TRANSPORT", executor.TransportShell)
	cfg.Inventory.Transport = executor.TransportNative
	envExec := newExecutor(cfg)
	if _, ok := envExec.(executor.SSHExecutor); !ok {
		t.Fatalf("env shell transport = %T, want SSHExecutor override", envExec)
	}
	t.Logf("transport default=%T inventory_shell=%T env_shell_overrides=%T", defaultExec, shellExec, envExec)
}

func TestPrintSSHExit255MappingDemo(t *testing.T) {
	result := executor.Result{
		ExitCode: 255,
		Argv:     []string{"ssh", "deploy@10.0.0.11", "uptime"},
	}
	fmt.Printf("exit_code=%d status=%q mapped_exit=%d\n", result.ExitCode, statusForResult(result), exitCodeForResult(result))
}

func TestMergeExitCode(t *testing.T) {
	if got := mergeExitCode(exitOK, exitRemoteFailed); got != exitRemoteFailed {
		t.Fatalf("merge success+remote = %d, want %d", got, exitRemoteFailed)
	}
	if got := mergeExitCode(exitRemoteFailed, exitSSHError); got != exitSSHError {
		t.Fatalf("merge remote+ssh = %d, want %d", got, exitSSHError)
	}
}

func TestInventoryAddFlagPathCreatesInventoryAndList(t *testing.T) {
	home := t.TempDir()
	t.Setenv("AGENTSSH_HOME", home)

	stdout, stderr, err := runCommandForTest(t, "inventory", "add", "web-1", "--addr", "10.0.0.11", "--user", "deploy", "--tags", "web,prod")
	if err != nil {
		t.Fatalf("inventory add err = %v stdout=%s stderr=%s", err, stdout, stderr)
	}
	inv := readInventoryFile(t, home)
	host := inv.Hosts["web-1"]
	if inv.Version != 1 || host.Addr != "10.0.0.11" || host.User != "deploy" || host.Port != 22 {
		t.Fatalf("inventory = %#v", inv)
	}
	if len(host.Tags) != 2 || host.Tags[0] != "web" || host.Tags[1] != "prod" {
		t.Fatalf("tags = %#v", host.Tags)
	}
	raw := readFileString(t, filepath.Join(home, "inventory.yaml"))
	if strings.Contains(raw, "transport:") || strings.Contains(raw, "host_key_policy:") || strings.Contains(raw, "ssh_config_alias:") {
		t.Fatalf("inventory yaml contains empty optional fields:\n%s", raw)
	}

	stdout, stderr, err = runCommandForTest(t, "inventory", "ls")
	if err != nil {
		t.Fatalf("inventory ls err = %v stderr=%s", err, stderr)
	}
	for _, want := range []string{"web-1", "addr=10.0.0.11", "user=deploy", "port=22", "tags=web,prod"} {
		if !strings.Contains(stdout, want) {
			t.Fatalf("inventory ls missing %q:\n%s", want, stdout)
		}
	}

	stdout, stderr, err = runCommandForTest(t, "inventory", "ls", "--json")
	if err != nil {
		t.Fatalf("inventory ls --json err = %v stderr=%s", err, stderr)
	}
	var decoded inventory.Inventory
	if err := json.Unmarshal([]byte(stdout), &decoded); err != nil {
		t.Fatalf("decode inventory json: %v\n%s", err, stdout)
	}
	if decoded.Hosts["web-1"].Addr != "10.0.0.11" || decoded.Hosts["web-1"].User != "deploy" {
		t.Fatalf("inventory json = %#v", decoded)
	}
}

func TestInventoryAddIdentityFileFlagAndHostsDoNotLeakIt(t *testing.T) {
	home := t.TempDir()
	t.Setenv("AGENTSSH_HOME", home)

	stdout, stderr, err := runCommandForTest(t, "inventory", "add", "web-1", "--addr", "10.0.0.11", "--identity-file", "~/.ssh/web-1")
	if err != nil {
		t.Fatalf("inventory add err = %v stdout=%s stderr=%s", err, stdout, stderr)
	}
	inv := readInventoryFile(t, home)
	if inv.Hosts["web-1"].IdentityFile != "~/.ssh/web-1" {
		t.Fatalf("identity_file = %q", inv.Hosts["web-1"].IdentityFile)
	}

	stdout, stderr, err = runCommandForTest(t, "inventory", "ls")
	if err != nil {
		t.Fatalf("inventory ls err = %v stderr=%s", err, stderr)
	}
	if !strings.Contains(stdout, "identity_file=~/.ssh/web-1") {
		t.Fatalf("inventory ls missing identity_file:\n%s", stdout)
	}

	stdout, stderr, err = runCommandForTest(t, "hosts", "--json")
	if err != nil {
		t.Fatalf("hosts err = %v stderr=%s", err, stderr)
	}
	if strings.Contains(stdout, "identity_file") || strings.Contains(stdout, "web-1") && strings.Contains(stdout, ".ssh") {
		t.Fatalf("hosts leaked identity file:\n%s", stdout)
	}
}

func TestSecretSetListRemoveRoundTripDoesNotPrintValues(t *testing.T) {
	home := t.TempDir()
	t.Setenv("AGENTSSH_HOME", home)
	t.Setenv(envMasterPassword, "master")
	restorePrompt := readSecretNoEcho
	readSecretNoEcho = func(prompt string) (string, error) {
		if !strings.Contains(prompt, "web-1") {
			t.Fatalf("prompt = %q", prompt)
		}
		return "ssh-password-value", nil
	}
	defer func() {
		readSecretNoEcho = restorePrompt
	}()

	stdout, stderr, err := runCommandForTest(t, "secret", "set", "web-1")
	if err != nil {
		t.Fatalf("secret set err = %v stdout=%s stderr=%s", err, stdout, stderr)
	}
	if strings.Contains(stdout+stderr, "ssh-password-value") {
		t.Fatalf("secret set leaked password stdout=%q stderr=%q", stdout, stderr)
	}
	store, err := secrets.Open(filepath.Join(home, "secrets.enc"), "master")
	if err != nil {
		t.Fatalf("open secrets: %v", err)
	}
	if got, ok := store.Password("web-1"); !ok || got != "ssh-password-value" {
		t.Fatalf("stored password = %q %t", got, ok)
	}

	stdout, stderr, err = runCommandForTest(t, "secret", "ls")
	if err != nil {
		t.Fatalf("secret ls err = %v stderr=%s", err, stderr)
	}
	if !strings.Contains(stdout, "web-1") || strings.Contains(stdout, "ssh-password-value") {
		t.Fatalf("secret ls stdout = %q", stdout)
	}
	stdout, stderr, err = runCommandForTest(t, "secret", "ls", "--json")
	if err != nil {
		t.Fatalf("secret ls json err = %v stderr=%s", err, stderr)
	}
	if !strings.Contains(stdout, `"web-1"`) || strings.Contains(stdout, "ssh-password-value") {
		t.Fatalf("secret ls json stdout = %q", stdout)
	}

	stdout, stderr, err = runCommandForTest(t, "secret", "rm", "web-1")
	if err != nil {
		t.Fatalf("secret rm err = %v stdout=%s stderr=%s", err, stdout, stderr)
	}
	store, err = secrets.Open(filepath.Join(home, "secrets.enc"), "master")
	if err != nil {
		t.Fatalf("open after rm: %v", err)
	}
	if _, ok := store.Password("web-1"); ok {
		t.Fatal("password still present after rm")
	}
}

func TestInventoryAddPasswordStoresSecretNotInventory(t *testing.T) {
	home := t.TempDir()
	t.Setenv("AGENTSSH_HOME", home)
	t.Setenv(envMasterPassword, "master")
	restorePrompt := readSecretNoEcho
	readSecretNoEcho = func(string) (string, error) { return "ssh-password-value", nil }
	defer func() {
		readSecretNoEcho = restorePrompt
	}()

	stdout, stderr, err := runCommandForTest(t, "inventory", "add", "web-1", "--addr", "10.0.0.11", "--user", "deploy", "--password")
	if err != nil {
		t.Fatalf("inventory add --password err = %v stdout=%s stderr=%s", err, stdout, stderr)
	}
	rawInventory := readFileString(t, filepath.Join(home, "inventory.yaml"))
	if strings.Contains(rawInventory, "ssh-password-value") || strings.Contains(rawInventory, "password") {
		t.Fatalf("inventory leaked password data:\n%s", rawInventory)
	}
	store, err := secrets.Open(filepath.Join(home, "secrets.enc"), "master")
	if err != nil {
		t.Fatalf("open secrets: %v", err)
	}
	if got, ok := store.Password("web-1"); !ok || got != "ssh-password-value" {
		t.Fatalf("stored password = %q %t", got, ok)
	}
}

func TestInventoryAddRejectsDuplicateAndPreservesExisting(t *testing.T) {
	home := t.TempDir()
	writeInventory(t, home, `
version: 1
transport: native
hosts:
  old:
    addr: 10.0.0.10
    user: root
groups:
  prod:
    tags: [prod]
`)
	t.Setenv("AGENTSSH_HOME", home)

	_, stderr, err := runCommandForTest(t, "inventory", "add", "new", "--addr", "10.0.0.11")
	if err != nil {
		t.Fatalf("add new err = %v stderr=%s", err, stderr)
	}
	inv := readInventoryFile(t, home)
	if inv.Transport != "native" || inv.Hosts["old"].Addr != "10.0.0.10" || inv.Hosts["new"].Addr != "10.0.0.11" {
		t.Fatalf("inventory after add = %#v", inv)
	}

	_, _, err = runCommandForTest(t, "inventory", "add", "old", "--addr", "10.0.0.12")
	if err == nil || !isUsageError(err) {
		t.Fatalf("duplicate err = %T %[1]v, want usageError", err)
	}
}

func TestInventoryAddCreatesMissingHomeDirectory(t *testing.T) {
	root := t.TempDir()
	home := filepath.Join(root, "missing", "agentssh")
	t.Setenv("AGENTSSH_HOME", home)

	_, stderr, err := runCommandForTest(t, "inventory", "add", "web-1", "--addr", "10.0.0.11")
	if err != nil {
		t.Fatalf("inventory add err = %v stderr=%s", err, stderr)
	}
	if _, err := os.Stat(filepath.Join(home, "inventory.yaml")); err != nil {
		t.Fatalf("inventory file stat: %v", err)
	}
}

func TestInventoryAddNonInteractiveRequiresFields(t *testing.T) {
	home := t.TempDir()
	t.Setenv("AGENTSSH_HOME", home)
	_, _, err := runCommandForTest(t, "inventory", "add", "--addr", "10.0.0.11")
	if err == nil || !isUsageError(err) {
		t.Fatalf("missing name err = %T %[1]v, want usageError", err)
	}
	_, _, err = runCommandForTest(t, "inventory", "add", "web-1")
	if err == nil || !isUsageError(err) {
		t.Fatalf("missing addr err = %T %[1]v, want usageError", err)
	}
}

func TestInventoryUpdateFlagPathPreservesUnchangedFields(t *testing.T) {
	home := t.TempDir()
	writeInventory(t, home, `
version: 1
hosts:
  web-1:
    addr: 10.0.0.11
    user: deploy
    port: 22
    identity_file: ~/.ssh/web-1
    os: linux
    tags: [web, prod]
`)
	t.Setenv("AGENTSSH_HOME", home)

	stdout, stderr, err := runCommandForTest(t, "inventory", "update", "web-1", "--addr", "10.0.0.12", "--port", "2222", "--tags", "api,prod")
	if err != nil {
		t.Fatalf("inventory update err = %v stdout=%s stderr=%s", err, stdout, stderr)
	}
	if !strings.Contains(stdout, "updated host web-1") {
		t.Fatalf("update stdout = %q", stdout)
	}
	host := readInventoryFile(t, home).Hosts["web-1"]
	if host.Addr != "10.0.0.12" || host.User != "deploy" || host.Port != 2222 || host.IdentityFile != "~/.ssh/web-1" || host.OS != "linux" {
		t.Fatalf("updated host = %#v", host)
	}
	if got := strings.Join(host.Tags, ","); got != "api,prod" {
		t.Fatalf("tags = %q", got)
	}
}

func TestInventoryUpdateRejectsInvalidFinalHost(t *testing.T) {
	home := t.TempDir()
	writeInventory(t, home, `
version: 1
hosts:
  web-1:
    addr: 10.0.0.11
`)
	t.Setenv("AGENTSSH_HOME", home)

	_, _, err := runCommandForTest(t, "inventory", "update", "web-1")
	if err == nil || !isUsageError(err) {
		t.Fatalf("missing update fields err = %T %[1]v, want usageError", err)
	}
	_, _, err = runCommandForTest(t, "inventory", "update", "web-1", "--addr", "")
	if err == nil || !isUsageError(err) {
		t.Fatalf("invalid update err = %T %[1]v, want usageError", err)
	}
}

func TestInventoryRemoveDeletesHostAndWritesAudit(t *testing.T) {
	home := t.TempDir()
	writeInventory(t, home, `
version: 1
hosts:
  web-1:
    addr: 10.0.0.11
  db-1:
    addr: 10.0.0.12
`)
	t.Setenv("AGENTSSH_HOME", home)

	stdout, stderr, err := runCommandForTest(t, "inventory", "rm", "web-1")
	if err != nil {
		t.Fatalf("inventory rm err = %v stdout=%s stderr=%s", err, stdout, stderr)
	}
	if !strings.Contains(stdout, "removed host web-1") {
		t.Fatalf("rm stdout = %q", stdout)
	}
	inv := readInventoryFile(t, home)
	if _, ok := inv.Hosts["web-1"]; ok {
		t.Fatalf("web-1 still present: %#v", inv.Hosts)
	}
	if _, ok := inv.Hosts["db-1"]; !ok {
		t.Fatalf("db-1 missing after rm: %#v", inv.Hosts)
	}
	records := mustReadAudit(t, home)
	if len(records) != 1 || records[0].Event != audit.EventCompleted || records[0].Host != "web-1" || records[0].Cmd != "inventory rm web-1" {
		t.Fatalf("delete audit records = %#v", records)
	}
	if records[0].ExitCode == nil || *records[0].ExitCode != exitOK || records[0].Error != "" {
		t.Fatalf("delete audit record = %#v", records[0])
	}
	if result, err := audit.NewStore(filepath.Join(home, "audit.log")).Verify(); err != nil || !result.OK {
		t.Fatalf("verify delete audit = %#v err=%v", result, err)
	}
}

func TestInventoryRemoveClearsOnlyDeletedHostRules(t *testing.T) {
	home := t.TempDir()
	writeInventory(t, home, `
version: 1
hosts:
  web-1:
    addr: 10.0.0.11
    tags: [prod]
  web-2:
    addr: 10.0.0.12
    tags: [prod]
groups:
  prod:
    tags: [prod]
`)
	writePolicy(t, home, `
version: 1
host_overrides:
  host:web-1:
    rules:
      - match: { cmd_regex: '^whoami$' }
        action: allow
  host:web-2:
    rules:
      - match: { cmd_regex: '^uptime$' }
        action: allow
  prod:
    rules:
      - match: { cmd_regex: '^id$' }
        action: deny
rule_groups:
  readonly:
    rules:
      - match: { cmd_regex: '^ls$' }
        action: allow
`)
	t.Setenv("AGENTSSH_HOME", home)

	stdout, stderr, err := runCommandForTest(t, "inventory", "rm", "web-1")
	if err != nil {
		t.Fatalf("inventory rm err = %v stdout=%s stderr=%s", err, stdout, stderr)
	}
	cfg := readPolicyFile(t, home)
	if _, ok := cfg.HostOverrides["host:web-1"]; ok {
		t.Fatalf("deleted host rules still present: %#v", cfg.HostOverrides)
	}
	if _, ok := cfg.HostOverrides["host:web-2"]; !ok {
		t.Fatalf("other host rules removed: %#v", cfg.HostOverrides)
	}
	if _, ok := cfg.HostOverrides["prod"]; !ok {
		t.Fatalf("group override removed: %#v", cfg.HostOverrides)
	}
	if _, ok := cfg.RuleGroups["readonly"]; !ok {
		t.Fatalf("rule group removed: %#v", cfg.RuleGroups)
	}
}

func TestInventoryRemoveDoesNotWriteInventoryWhenPolicyClearFails(t *testing.T) {
	home := t.TempDir()
	writeInventory(t, home, `
version: 1
hosts:
  web-1:
    addr: 10.0.0.11
  db-1:
    addr: 10.0.0.12
`)
	writePolicy(t, home, `
version: 1
host_overrides:
  host:web-1:
    rules:
      - match: { cmd_regex: '^whoami$' }
        action: allow
rules:
  - name: broken
    match: { cmd_regex: '[' }
    action: deny
`)
	t.Setenv("AGENTSSH_HOME", home)

	_, _, err := runCommandForTest(t, "inventory", "rm", "web-1")
	if err == nil {
		t.Fatal("inventory rm err = nil, want invalid policy error")
	}
	inv := readInventoryFile(t, home)
	if _, ok := inv.Hosts["web-1"]; !ok {
		t.Fatalf("web-1 was removed despite policy failure: %#v", inv.Hosts)
	}
	rawPolicy := readFileString(t, filepath.Join(home, "policy.yaml"))
	if !strings.Contains(rawPolicy, "host:web-1") {
		t.Fatalf("host policy was removed despite policy failure:\n%s", rawPolicy)
	}
}

func TestInventoryRemoveMissingWritesFailedAudit(t *testing.T) {
	home := t.TempDir()
	writeInventory(t, home, `
version: 1
hosts:
  web-1:
    addr: 10.0.0.11
`)
	t.Setenv("AGENTSSH_HOME", home)

	_, _, err := runCommandForTest(t, "inventory", "rm", "missing")
	if err == nil || !isUsageError(err) {
		t.Fatalf("missing rm err = %T %[1]v, want usageError", err)
	}
	records := mustReadAudit(t, home)
	if len(records) != 1 || records[0].Event != audit.EventFailed || records[0].Host != "missing" || records[0].Cmd != "inventory rm missing" {
		t.Fatalf("failed delete audit records = %#v", records)
	}
	if records[0].ExitCode == nil || *records[0].ExitCode != exitUsage || !strings.Contains(records[0].Error, "inventory host not found") {
		t.Fatalf("failed delete audit record = %#v", records[0])
	}
	stdout, stderr, err := runCommandForTest(t, "audit", "ls", "--status", "failed")
	if err != nil {
		t.Fatalf("audit ls failed err = %v stderr=%s", err, stderr)
	}
	if !strings.Contains(stdout, `err="inventory host not found"`) || !strings.Contains(stdout, `cmd="inventory rm missing"`) {
		t.Fatalf("audit ls missing delete failure context:\n%s", stdout)
	}
}

func TestPolicyRuleCRUDCommands(t *testing.T) {
	home := t.TempDir()
	writePolicy(t, home, `
version: 1
rules:
  - name: old
    priority: 1
    match: { cmd_regex: '^ls' }
    action: allow
output:
  max_bytes: 1024
`)
	t.Setenv("AGENTSSH_HOME", home)

	stdout, stderr, err := runCommandForTest(t, "policy", "rule", "add", "danger", "--cmd-regex", "rm -rf", "--action", "deny", "--priority", "50")
	if err != nil {
		t.Fatalf("policy rule add err = %v stdout=%s stderr=%s", err, stdout, stderr)
	}
	if !strings.Contains(stdout, "added policy rule danger") {
		t.Fatalf("add stdout = %q", stdout)
	}
	stdout, stderr, err = runCommandForTest(t, "policy", "rule", "ls")
	if err != nil {
		t.Fatalf("policy rule ls err = %v stderr=%s", err, stderr)
	}
	for _, want := range []string{"name=old", "priority=1", "cmd_regex=\"^ls\"", "name=danger", "priority=50", "action=deny", "cmd_regex=\"rm -rf\""} {
		if !strings.Contains(stdout, want) {
			t.Fatalf("policy rule ls missing %q:\n%s", want, stdout)
		}
	}

	stdout, stderr, err = runCommandForTest(t, "policy", "rule", "update", "danger", "--name", "catastrophic", "--cmd-regex", "mkfs", "--action", "deny", "--priority", "99")
	if err != nil {
		t.Fatalf("policy rule update err = %v stdout=%s stderr=%s", err, stdout, stderr)
	}
	if !strings.Contains(stdout, "updated policy rule catastrophic") {
		t.Fatalf("update stdout = %q", stdout)
	}
	stdout, stderr, err = runCommandForTest(t, "policy", "rule", "rm", "old")
	if err != nil {
		t.Fatalf("policy rule rm err = %v stdout=%s stderr=%s", err, stdout, stderr)
	}
	if !strings.Contains(stdout, "removed policy rule old") {
		t.Fatalf("rm stdout = %q", stdout)
	}
	var cfg policy.Config
	raw := readFileString(t, filepath.Join(home, "policy.yaml"))
	if err := yaml.Unmarshal([]byte(raw), &cfg); err != nil {
		t.Fatalf("decode policy: %v\n%s", err, raw)
	}
	if len(cfg.Rules) != 1 || cfg.Rules[0].Name != "catastrophic" || cfg.Rules[0].Match.CmdRegex != "mkfs" || cfg.Rules[0].Priority != 99 {
		t.Fatalf("policy after crud = %#v", cfg.Rules)
	}
	if _, _, err = runCommandForTest(t, "policy", "rule", "add", "missing-action", "--cmd-regex", "^ls"); err == nil || !isUsageError(err) {
		t.Fatalf("missing action err = %T %[1]v, want usageError", err)
	}
	if _, _, err = runCommandForTest(t, "policy", "rule", "add", "broken", "--cmd-regex", "[", "--action", "deny"); err == nil || !isUsageError(err) {
		t.Fatalf("invalid regex err = %T %[1]v, want usageError", err)
	}
}

func TestPolicyHostCRUDCommands(t *testing.T) {
	home := t.TempDir()
	writeInventory(t, home, `
version: 1
hosts:
  web-1:
    addr: 10.0.0.11
  web-2:
    addr: 10.0.0.12
`)
	writePolicy(t, home, `
version: 1
rules:
  - name: allow-cat
    match: { cmd_regex: '^cat\b' }
    action: allow
output:
  max_bytes: 1024
`)
	t.Setenv("AGENTSSH_HOME", home)

	stdout, stderr, err := runCommandForTest(t, "policy", "host", "rule", "add", "web-1", "--cmd-regex", "^cat\\b", "--action", "deny", "--priority", "20")
	if err != nil {
		t.Fatalf("policy host rule add err = %v stdout=%s stderr=%s", err, stdout, stderr)
	}
	if !strings.Contains(stdout, "added policy host rule web-1[0]") {
		t.Fatalf("add stdout = %q", stdout)
	}
	stdout, stderr, err = runCommandForTest(t, "policy", "host", "ls")
	if err != nil {
		t.Fatalf("policy host ls err = %v stderr=%s", err, stderr)
	}
	for _, want := range []string{"host=web-1", "rules=1", "key=host:web-1", "priority=20", "action=deny", `cmd_regex="^cat\\b"`} {
		if !strings.Contains(stdout, want) {
			t.Fatalf("policy host ls missing %q:\n%s", want, stdout)
		}
	}

	stdout, stderr, err = runCommandForTest(t, "policy", "test", "--host", "web-1", "cat", "/etc/passwd")
	if err != nil {
		t.Fatalf("policy test web-1 err = %v stdout=%s stderr=%s", err, stdout, stderr)
	}
	if !strings.Contains(stdout, "deny") || !strings.Contains(stdout, "host:web-1/rules[0]") {
		t.Fatalf("policy test web-1 output = %q", stdout)
	}
	stdout, stderr, err = runCommandForTest(t, "policy", "test", "--host", "web-2", "cat", "/etc/passwd")
	if err != nil {
		t.Fatalf("policy test web-2 err = %v stdout=%s stderr=%s", err, stdout, stderr)
	}
	if !strings.Contains(stdout, "allow") || strings.Contains(stdout, "host:web-1") {
		t.Fatalf("policy test web-2 output = %q", stdout)
	}

	stdout, stderr, err = runCommandForTest(t, "policy", "host", "rule", "add", "web-1", "--cmd-regex", "^uptime$", "--action", "allow")
	if err != nil {
		t.Fatalf("policy host rule add err = %v stdout=%s stderr=%s", err, stdout, stderr)
	}
	if !strings.Contains(stdout, "added policy host rule web-1[1]") {
		t.Fatalf("rule add stdout = %q", stdout)
	}
	stdout, stderr, err = runCommandForTest(t, "policy", "host", "rule", "rm", "web-1", "0")
	if err != nil {
		t.Fatalf("policy host rule rm err = %v stdout=%s stderr=%s", err, stdout, stderr)
	}
	if !strings.Contains(stdout, "removed policy host rule web-1[0]") {
		t.Fatalf("rule rm stdout = %q", stdout)
	}

	var cfg policy.Config
	raw := readFileString(t, filepath.Join(home, "policy.yaml"))
	if err := yaml.Unmarshal([]byte(raw), &cfg); err != nil {
		t.Fatalf("decode policy: %v\n%s", err, raw)
	}
	override, ok := cfg.HostOverrides["host:web-1"]
	if !ok || len(override.Rules) != 1 || override.Rules[0].Action != policy.ActionAllow || override.Rules[0].Match.CmdRegex != "^uptime$" {
		t.Fatalf("host override after crud = %#v ok=%v", override, ok)
	}

	stdout, stderr, err = runCommandForTest(t, "policy", "host", "rm", "web-1")
	if err != nil {
		t.Fatalf("policy host rm err = %v stdout=%s stderr=%s", err, stdout, stderr)
	}
	if !strings.Contains(stdout, "removed policy host web-1") {
		t.Fatalf("rm stdout = %q", stdout)
	}
	raw = readFileString(t, filepath.Join(home, "policy.yaml"))
	if strings.Contains(raw, "host:web-1") {
		t.Fatalf("host rules still present:\n%s", raw)
	}
	if _, _, err = runCommandForTest(t, "policy", "host", "rule", "add", "missing", "--cmd-regex", "^ls", "--action", "allow"); err == nil || !isUsageError(err) {
		t.Fatalf("missing host err = %T %[1]v, want usageError", err)
	}
	if _, _, err = runCommandForTest(t, "policy", "host", "rule", "add", "web-1", "--cmd-regex", "[", "--action", "allow"); err == nil || !isUsageError(err) {
		t.Fatalf("invalid host regex err = %T %[1]v, want usageError", err)
	}
}

func TestPolicyGroupCommands(t *testing.T) {
	home := t.TempDir()
	writeInventory(t, home, `
version: 1
hosts:
  web-1:
    addr: 10.0.0.11
`)
	writePolicy(t, home, `
version: 1
output:
  max_bytes: 1024
`)
	t.Setenv("AGENTSSH_HOME", home)

	stdout, stderr, err := runCommandForTest(t, "policy", "group", "add", "readonly")
	if err != nil {
		t.Fatalf("policy group add err = %v stdout=%s stderr=%s", err, stdout, stderr)
	}
	if !strings.Contains(stdout, "added policy group readonly") {
		t.Fatalf("group add stdout = %q", stdout)
	}
	stdout, stderr, err = runCommandForTest(t, "policy", "group", "rule", "add", "readonly", "--cmd-regex", "^uptime$", "--action", "allow", "--priority", "5")
	if err != nil {
		t.Fatalf("policy group rule add err = %v stdout=%s stderr=%s", err, stdout, stderr)
	}
	if !strings.Contains(stdout, "added policy group rule readonly[0]") {
		t.Fatalf("group rule add stdout = %q", stdout)
	}
	stdout, stderr, err = runCommandForTest(t, "policy", "group", "ls")
	if err != nil {
		t.Fatalf("policy group ls err = %v stderr=%s", err, stderr)
	}
	for _, want := range []string{"readonly", "rules=1", "allow=1", "deny=0"} {
		if !strings.Contains(stdout, want) {
			t.Fatalf("policy group ls missing %q:\n%s", want, stdout)
		}
	}
	stdout, stderr, err = runCommandForTest(t, "policy", "group", "rule", "ls", "readonly")
	if err != nil {
		t.Fatalf("policy group rule ls err = %v stderr=%s", err, stderr)
	}
	for _, want := range []string{`0 priority=5`, `action=allow`, `cmd_regex="^uptime$"`} {
		if !strings.Contains(stdout, want) {
			t.Fatalf("policy group rule ls missing %q:\n%s", want, stdout)
		}
	}

	stdout, stderr, err = runCommandForTest(t, "policy", "host", "rule", "add", "web-1", "--from-group", "readonly")
	if err != nil {
		t.Fatalf("policy host rule add --from-group err = %v stdout=%s stderr=%s", err, stdout, stderr)
	}
	if !strings.Contains(stdout, "stamped policy group readonly onto host web-1 (1 rule(s))") {
		t.Fatalf("stamp stdout = %q", stdout)
	}
	var cfg policy.Config
	raw := readFileString(t, filepath.Join(home, "policy.yaml"))
	if err := yaml.Unmarshal([]byte(raw), &cfg); err != nil {
		t.Fatalf("decode policy: %v\n%s", err, raw)
	}
	rules := cfg.HostOverrides["host:web-1"].Rules
	if len(rules) != 1 || rules[0].Group != "readonly" || rules[0].Match.CmdRegex != "^uptime$" {
		t.Fatalf("stamped host rules = %#v", rules)
	}

	stdout, stderr, err = runCommandForTest(t, "policy", "host", "rule", "ls", "web-1")
	if err != nil {
		t.Fatalf("policy host rule ls err = %v stderr=%s", err, stderr)
	}
	if !strings.Contains(stdout, `group="readonly"`) {
		t.Fatalf("host rule ls missing provenance:\n%s", stdout)
	}
	stdout, stderr, err = runCommandForTest(t, "policy", "host", "group", "rm", "web-1", "readonly")
	if err != nil {
		t.Fatalf("policy host group rm err = %v stdout=%s stderr=%s", err, stdout, stderr)
	}
	if !strings.Contains(stdout, "removed policy host group web-1[readonly]") {
		t.Fatalf("host group rm stdout = %q", stdout)
	}
	raw = readFileString(t, filepath.Join(home, "policy.yaml"))
	if strings.Contains(raw, "group: readonly") {
		t.Fatalf("stamped group still present after host group rm:\n%s", raw)
	}

	stdout, stderr, err = runCommandForTest(t, "policy", "group", "rule", "rm", "readonly", "0")
	if err != nil {
		t.Fatalf("policy group rule rm err = %v stdout=%s stderr=%s", err, stdout, stderr)
	}
	if !strings.Contains(stdout, "removed policy group rule readonly[0]") {
		t.Fatalf("group rule rm stdout = %q", stdout)
	}
	stdout, stderr, err = runCommandForTest(t, "policy", "group", "rm", "readonly")
	if err != nil {
		t.Fatalf("policy group rm err = %v stdout=%s stderr=%s", err, stdout, stderr)
	}
	if !strings.Contains(stdout, "removed policy group readonly") {
		t.Fatalf("group rm stdout = %q", stdout)
	}

	if _, _, err = runCommandForTest(t, "policy", "group", "rule", "add", "missing", "--cmd-regex", "^ls", "--action", "allow"); err == nil || !isUsageError(err) {
		t.Fatalf("missing group err = %T %[1]v, want usageError", err)
	}
	if _, _, err = runCommandForTest(t, "policy", "host", "rule", "add", "web-1", "--from-group", "missing"); err == nil || !isUsageError(err) {
		t.Fatalf("stamp missing group err = %T %[1]v, want usageError", err)
	}
	if _, _, err = runCommandForTest(t, "policy", "host", "rule", "add", "web-1", "--from-group", "readonly", "--cmd-regex", "^ls", "--action", "allow"); err == nil || !isUsageError(err) {
		t.Fatalf("from-group mutual exclusion err = %T %[1]v, want usageError", err)
	}
}

func TestAuditRepairTruncatesBrokenTail(t *testing.T) {
	home := t.TempDir()
	writeTestInventory(t, home)
	writeTestPolicy(t, home)
	t.Setenv("AGENTSSH_HOME", home)

	store := audit.NewStore(filepath.Join(home, "audit.log"))
	for _, record := range []audit.Record{
		{ReqID: "r1", Event: audit.EventCompleted, Host: "web-1"},
		{ReqID: "r2", Event: audit.EventCompleted, Host: "web-1"},
		{ReqID: "r3", Event: audit.EventCompleted, Host: "web-1"},
	} {
		if _, err := store.Append(record); err != nil {
			t.Fatalf("append audit: %v", err)
		}
	}
	records := mustReadAudit(t, home)
	records[1].Host = "evil"
	writeAuditRecords(t, filepath.Join(home, "audit.log"), records)

	stdout, stderr, err := runCommandForTest(t, "audit", "repair", "--truncate-broken")
	if err != nil {
		t.Fatalf("audit repair err = %v stdout=%s stderr=%s", err, stdout, stderr)
	}
	for _, want := range []string{"audit repaired", "broken_seq=1", "reason=hash", "kept=1", "removed=2", "backup="} {
		if !strings.Contains(stdout, want) {
			t.Fatalf("repair stdout missing %q:\n%s", want, stdout)
		}
	}
	repaired := mustReadAudit(t, home)
	if len(repaired) != 1 || repaired[0].ReqID != "r1" {
		t.Fatalf("repaired records = %#v", repaired)
	}
	if result, err := store.Verify(); err != nil || !result.OK || result.Count != 1 {
		t.Fatalf("verify repaired = %#v err=%v", result, err)
	}
	if _, _, err = runCommandForTest(t, "audit", "repair"); err == nil || !isUsageError(err) {
		t.Fatalf("repair without flag err = %T %[1]v, want usageError", err)
	}
}

func TestInventoryAddDoesNotOverwriteMalformedInventory(t *testing.T) {
	home := t.TempDir()
	bad := "::: not: yaml: ["
	if err := os.WriteFile(filepath.Join(home, "inventory.yaml"), []byte(bad), 0o600); err != nil {
		t.Fatalf("write bad inventory: %v", err)
	}
	t.Setenv("AGENTSSH_HOME", home)

	_, _, err := runCommandForTest(t, "inventory", "add", "web-1", "--addr", "10.0.0.11")
	if err == nil {
		t.Fatal("add malformed inventory err = nil")
	}
	if got := readFileString(t, filepath.Join(home, "inventory.yaml")); got != bad {
		t.Fatalf("inventory was overwritten: %q", got)
	}
}

func TestHostsStillShowsPublicInventoryOnly(t *testing.T) {
	home := t.TempDir()
	writeTestInventory(t, home)
	t.Setenv("AGENTSSH_HOME", home)

	stdout, stderr, err := runCommandForTest(t, "hosts", "--json")
	if err != nil {
		t.Fatalf("hosts err = %v stderr=%s", err, stderr)
	}
	if strings.Contains(stdout, "10.0.0.11") || strings.Contains(stdout, "deploy") {
		t.Fatalf("hosts leaked connection details:\n%s", stdout)
	}
	if !strings.Contains(stdout, `"name": "web-1"`) || !strings.Contains(stdout, `"tags"`) {
		t.Fatalf("hosts output missing public fields:\n%s", stdout)
	}
}

func TestRunJSONShapeHostObjectGroupArray(t *testing.T) {
	hostOut, _, groupOut, _ := runJSONShapeDemo(t)

	var hostValue map[string]any
	if err := json.Unmarshal([]byte(hostOut), &hostValue); err != nil {
		t.Fatalf("host JSON is not object: %v\n%s", err, hostOut)
	}
	if hostValue["host"] != "web-1" {
		t.Fatalf("host JSON host = %#v", hostValue["host"])
	}

	var groupValue []map[string]any
	if err := json.Unmarshal([]byte(groupOut), &groupValue); err != nil {
		t.Fatalf("group JSON is not array: %v\n%s", err, groupOut)
	}
	if len(groupValue) != 1 || groupValue[0]["host"] != "web-1" {
		t.Fatalf("group JSON = %#v", groupValue)
	}
}

func TestPrintRunJSONShapeDemo(t *testing.T) {
	hostOut, hostErr, groupOut, groupErr := runJSONShapeDemo(t)
	if hostErr != "" || groupErr != "" {
		t.Fatalf("unexpected stderr: host=%q group=%q", hostErr, groupErr)
	}
	fmt.Printf("host_json=%s", hostOut)
	fmt.Printf("group_json=%s", groupOut)
}

func runJSONShapeDemo(t *testing.T) (string, string, string, string) {
	t.Helper()
	home := t.TempDir()
	writeTestInventory(t, home)
	writeTestPolicy(t, home)
	t.Setenv("AGENTSSH_HOME", home)
	t.Setenv("AGENTSSH_SESSION", "s_test")

	restoreExecutor := newExecutor
	newExecutor = func(_ *config.Config) executor.Executor {
		return fakeExecutor{}
	}
	defer func() {
		newExecutor = restoreExecutor
	}()

	hostOut, hostErr, err := runCommandForTest(t, "run", "web-1", "--json", "--", "echo", "hi")
	if err != nil {
		t.Fatalf("host run: %v", err)
	}
	groupOut, groupErr, err := runCommandForTest(t, "run", "solo", "--json", "--", "echo", "hi")
	if err != nil {
		t.Fatalf("group run: %v", err)
	}
	return hostOut, hostErr, groupOut, groupErr
}

func TestRunDenyWritesAuditAndDoesNotExecute(t *testing.T) {
	home := t.TempDir()
	writeTestInventory(t, home)
	writeTestPolicy(t, home)
	t.Setenv("AGENTSSH_HOME", home)
	t.Setenv("AGENTSSH_SESSION", "s_test")

	var calls int32
	restoreExecutor := newExecutor
	newExecutor = func(_ *config.Config) executor.Executor {
		return fakeExecutor{calls: &calls}
	}
	defer func() {
		newExecutor = restoreExecutor
	}()

	_, stderr, err := runCommandForTest(t, "run", "web-1", "--", "rm", "-rf", "/")
	if err == nil {
		t.Fatal("deny run error = nil")
	}
	var exitErr commandExitError
	if !errors.As(err, &exitErr) || exitErr.Code != exitPolicyDenied {
		t.Fatalf("deny err = %v", err)
	}
	if atomic.LoadInt32(&calls) != 0 {
		t.Fatalf("executor calls = %d, want 0", calls)
	}
	if !strings.Contains(stderr, "denied by policy") {
		t.Fatalf("stderr = %q", stderr)
	}
	records := mustReadAudit(t, home)
	if len(records) != 1 || records[0].Event != audit.EventDenied || records[0].ExitCode != nil {
		t.Fatalf("audit records = %#v", records)
	}
}

func TestRunAllowWritesStartedAndCompleted(t *testing.T) {
	home := t.TempDir()
	writeTestInventory(t, home)
	writeTestPolicy(t, home)
	t.Setenv("AGENTSSH_HOME", home)
	t.Setenv("AGENTSSH_SESSION", "s_test")

	var calls int32
	restoreExecutor := newExecutor
	newExecutor = func(_ *config.Config) executor.Executor {
		return fakeExecutor{calls: &calls}
	}
	defer func() {
		newExecutor = restoreExecutor
	}()

	stdout, stderr, err := runCommandForTest(t, "run", "web-1", "--", "echo", "hi")
	if err != nil {
		t.Fatalf("allow run err = %v stderr=%s", err, stderr)
	}
	if atomic.LoadInt32(&calls) != 1 {
		t.Fatalf("executor calls = %d, want 1", calls)
	}
	if !strings.Contains(stdout, "✓ web-1") {
		t.Fatalf("stdout = %q", stdout)
	}
	records := mustReadAudit(t, home)
	if len(records) != 2 || records[0].Event != audit.EventStarted || records[1].Event != audit.EventCompleted {
		t.Fatalf("audit records = %#v", records)
	}
	if records[1].OutputSHA256 == "" || records[1].ExitCode == nil || *records[1].ExitCode != 0 {
		t.Fatalf("completed record = %#v", records[1])
	}
}

// A run with neither --session nor AGENTSSH_SESSION is a usage error (exit 2): the
// caller must declare a session so each task maps to one auditable session.
func TestRunWithoutSessionIsUsageError(t *testing.T) {
	setupHome(t)
	t.Setenv("AGENTSSH_SESSION", "") // override setupHome's session
	withFakeExecutor(t, fakeExecutor{})
	_, _, err := runCommandForTest(t, "run", "web-1", "--", "echo", "hi")
	if got := exitCodeForError(err); got != exitUsage {
		t.Fatalf("exit = %d, want %d (usage); err=%v", got, exitUsage, err)
	}
	if err == nil || !strings.Contains(err.Error(), "session must be declared") {
		t.Fatalf("err = %v, want it to mention a missing session", err)
	}
}

// --session declared on the run satisfies the requirement without any env var.
func TestRunSessionFlagSatisfiesRequirement(t *testing.T) {
	setupHome(t)
	t.Setenv("AGENTSSH_SESSION", "")
	withFakeExecutor(t, fakeExecutor{})
	if code, _, stderr := runExit(t, "run", "web-1", "--session", "s_flag", "--", "echo", "hi"); code != exitOK {
		t.Fatalf("code = %d, want 0; stderr=%q", code, stderr)
	}
}

func TestRunGroupDerivesSessionPerHost(t *testing.T) {
	home := t.TempDir()
	writeTestInventory(t, home)
	writeTestPolicy(t, home)
	t.Setenv("AGENTSSH_HOME", home)
	t.Setenv("AGENTSSH_SESSION", "")
	withFakeExecutor(t, fakeExecutor{})

	stdout, stderr, err := runCommandForTest(t, "run", "web", "--session", "s_batch", "--json", "--", "echo", "hi")
	if err != nil {
		t.Fatalf("group run err = %v stdout=%s stderr=%s", err, stdout, stderr)
	}
	var responses []runResponse
	if err := json.Unmarshal([]byte(stdout), &responses); err != nil {
		t.Fatalf("decode group response: %v\n%s", err, stdout)
	}
	if len(responses) != 2 {
		t.Fatalf("responses = %#v", responses)
	}
	want := map[string]string{"web-1": "s_batch@web-1", "web-2": "s_batch@web-2"}
	for _, response := range responses {
		if response.SessionID != want[response.Host] {
			t.Fatalf("response session for %s = %q, want %q in %#v", response.Host, response.SessionID, want[response.Host], responses)
		}
	}
	records := mustReadAudit(t, home)
	seen := map[string]string{}
	for _, record := range records {
		seen[record.Host] = record.SessionID
	}
	for host, sessionID := range want {
		if seen[host] != sessionID {
			t.Fatalf("audit session for %s = %q, want %q; records=%#v", host, seen[host], sessionID, records)
		}
	}
}

func TestRunUpdatesInventoryOSAfterConnection(t *testing.T) {
	home := t.TempDir()
	writeInventory(t, home, `
version: 1
hosts:
  web-1:
    addr: 10.0.0.11
    user: deploy
    os: windows
`)
	writeTestPolicy(t, home)
	t.Setenv("AGENTSSH_HOME", home)
	t.Setenv("AGENTSSH_SESSION", "s_test")

	restoreExecutor := newExecutor
	newExecutor = func(_ *config.Config) executor.Executor {
		return osDetectingExecutor{osName: "linux"}
	}
	defer func() {
		newExecutor = restoreExecutor
	}()

	if _, _, err := runCommandForTest(t, "run", "web-1", "--", "echo", "hi"); err != nil {
		t.Fatalf("run err = %v", err)
	}
	if got := readInventoryFile(t, home).Hosts["web-1"].OS; got != "linux" {
		t.Fatalf("inventory OS = %q, want linux", got)
	}
}

func TestRunAppliesOutputFilterToReturnAndAudit(t *testing.T) {
	home := t.TempDir()
	writeTestInventory(t, home)
	writeTestPolicy(t, home)
	t.Setenv("AGENTSSH_HOME", home)
	t.Setenv("AGENTSSH_SESSION", "s_test")

	restoreExecutor := newExecutor
	newExecutor = func(_ *config.Config) executor.Executor {
		return fakeExecutor{stdout: "password=secret123 abcdefghijklmnopqrstuvwxyz\n"}
	}
	defer func() {
		newExecutor = restoreExecutor
	}()

	stdout, stderr, err := runCommandForTest(t, "run", "web-1", "--json", "--", "echo", "secret")
	if err != nil {
		t.Fatalf("run err = %v stderr=%s", err, stderr)
	}
	var response runResponse
	if err := json.Unmarshal([]byte(stdout), &response); err != nil {
		t.Fatalf("unmarshal response: %v\n%s", err, stdout)
	}
	if strings.Contains(response.Stdout, "secret123") || !strings.Contains(response.Stdout, "«REDACTED»") {
		t.Fatalf("stdout not redacted: %q", response.Stdout)
	}
	if !response.OutputTruncated || response.Redactions != 1 {
		t.Fatalf("response filter metadata = %#v", response)
	}

	records := mustReadAudit(t, home)
	completed := records[len(records)-1]
	if completed.Redactions != 1 || !completed.OutputTruncated {
		t.Fatalf("audit filter metadata = %#v", completed)
	}
	if completed.OutputSHA256 != audit.ComputeOutputSHA256(response.Stdout, response.Stderr) {
		t.Fatalf("audit hash = %s, want hash of filtered output", completed.OutputSHA256)
	}
}

func TestAuditLSIncludesCommandAndOutcomeContext(t *testing.T) {
	home := t.TempDir()
	writeTestInventory(t, home)
	writeTestPolicy(t, home)
	t.Setenv("AGENTSSH_HOME", home)
	t.Setenv("AGENTSSH_SESSION", "s_test")

	restoreExecutor := newExecutor
	newExecutor = func(_ *config.Config) executor.Executor {
		return fakeExecutor{stdout: "password=secret123 abcdefghijklmnopqrstuvwxyz\n"}
	}
	defer func() {
		newExecutor = restoreExecutor
	}()

	if _, _, err := runCommandForTest(t, "run", "web-1", "--json", "--", "echo", "secret"); err != nil {
		t.Fatalf("allow run: %v", err)
	}
	if _, _, err := runCommandForTest(t, "run", "web-1", "--", "rm", "-rf", "/"); err == nil {
		t.Fatal("deny run error = nil")
	}

	stdout, stderr, err := runCommandForTest(t, "audit", "ls")
	if err != nil {
		t.Fatalf("audit ls err = %v stderr=%s", err, stderr)
	}
	assertContainsAll(t, stdout,
		"started",
		"completed",
		"denied",
		"host=web-1",
		"session=s_test",
		"policy=allow/rules:allow-test-commands",
		"policy=deny/rules:catastrophic",
		"exit=0",
		"exit=6",
		"out=truncated,redacted:1",
		`cmd="echo secret"`,
		`cmd="rm -rf /"`,
	)
}

func TestRunStreamingFiltersOutputAndAuditMatchesBuffered(t *testing.T) {
	home := t.TempDir()
	writeTestInventory(t, home)
	writeTestPolicy(t, home)
	t.Setenv("AGENTSSH_HOME", home)
	t.Setenv("AGENTSSH_SESSION", "s_stream")

	rawStdout := "first line\npassword=secret123 split\nemoji 世界 tail\n"
	rawStderr := "stderr token\n"
	restoreExecutor := newExecutor
	newExecutor = func(_ *config.Config) executor.Executor {
		return fakeExecutor{stdout: rawStdout, stderr: rawStderr}
	}
	defer func() {
		newExecutor = restoreExecutor
	}()

	stdout, stderr, err := runCommandForTest(t, "run", "web-1", "--", "echo", "secret")
	if err != nil {
		t.Fatalf("run err = %v stderr=%s", err, stderr)
	}
	if strings.Contains(stdout, "secret123") || !strings.Contains(stdout, "«REDACTED»") {
		t.Fatalf("stream stdout not filtered: %q", stdout)
	}
	if !strings.Contains(stdout, "✓ web-1 · exit 0") {
		t.Fatalf("stream footer missing: %q", stdout)
	}

	filter := mustOutputFilter(t)
	buffered := filter.Apply(rawStdout, rawStderr)
	records := mustReadAudit(t, home)
	completed := records[len(records)-1]
	if completed.OutputSHA256 != audit.ComputeOutputSHA256(buffered.Stdout, buffered.Stderr) {
		t.Fatalf("stream hash = %s, want buffered hash", completed.OutputSHA256)
	}
	if completed.Redactions != buffered.Redactions || completed.OutputTruncated != buffered.OutputTruncated {
		t.Fatalf("stream audit metadata = redactions %d truncated %t, want %d %t", completed.Redactions, completed.OutputTruncated, buffered.Redactions, buffered.OutputTruncated)
	}
}

func TestRunJSONAndGroupStillUseBufferedPath(t *testing.T) {
	home := t.TempDir()
	writeTestInventory(t, home)
	writeTestPolicy(t, home)
	t.Setenv("AGENTSSH_HOME", home)
	t.Setenv("AGENTSSH_SESSION", "s_buffered")

	var calls int32
	restoreExecutor := newExecutor
	newExecutor = func(_ *config.Config) executor.Executor {
		return bufferedOnlyExecutor{calls: &calls, stdout: "password=secret123\n"}
	}
	defer func() {
		newExecutor = restoreExecutor
	}()

	stdout, stderr, err := runCommandForTest(t, "run", "web-1", "--json", "--", "echo", "secret")
	if err != nil {
		t.Fatalf("json run err = %v stderr=%s", err, stderr)
	}
	var response runResponse
	if err := json.Unmarshal([]byte(stdout), &response); err != nil {
		t.Fatalf("json response: %v\n%s", err, stdout)
	}
	if !strings.Contains(response.Stdout, "«REDACTED»") || strings.Contains(response.Stdout, "secret123") {
		t.Fatalf("json response stdout = %q", response.Stdout)
	}

	groupStdout, groupStderr, err := runCommandForTest(t, "run", "solo", "--", "echo", "secret")
	if err != nil {
		t.Fatalf("group run err = %v stderr=%s", err, groupStderr)
	}
	if !strings.Contains(groupStdout, "✓ web-1") || !strings.Contains(groupStdout, "«REDACTED»") {
		t.Fatalf("group buffered stdout = %q", groupStdout)
	}
	if atomic.LoadInt32(&calls) != 2 {
		t.Fatalf("buffered calls = %d, want 2", calls)
	}
}

func TestRunRejectsMultiLineRedactPatternAsUsage(t *testing.T) {
	home := t.TempDir()
	writeTestInventory(t, home)
	writePolicy(t, home, `
version: 1
rules:
  - name: allow-echo
    match: { cmd_regex: '^echo\b' }
    action: allow
output:
  redact:
    - '(?s)BEGIN.*END'
`)
	t.Setenv("AGENTSSH_HOME", home)

	_, stderr, err := runCommandForTest(t, "run", "web-1", "--", "echo", "hi")
	if err == nil {
		t.Fatal("run err = nil")
	}
	if !isUsageError(err) {
		t.Fatalf("err = %T %[1]v, want usageError; stderr=%s", err, stderr)
	}
}

func TestRunNativeStreamingEndToEnd(t *testing.T) {
	home := t.TempDir()
	clientSigner := writeSSHClientKey(t, home)
	server := newCLITestSSHServer(t, clientSigner.PublicKey())
	defer server.Close()

	writeKnownHostsLine(t, home, server.Addr(), server.HostSigner.PublicKey())
	writeInventory(t, home, fmt.Sprintf(`
version: 1
transport: native
hosts:
  web-1:
    addr: %s
    port: %d
    user: test
    tags: [web]
groups:
  web: { tags: [web] }
`, server.Host(), server.Port()))
	writeTestPolicy(t, home)
	t.Setenv("AGENTSSH_HOME", home)
	t.Setenv("AGENTSSH_SESSION", "s_native_stream")

	stdout, stderr, err := runCommandForTest(t, "run", "web-1", "--", "stream-secret")
	if err != nil {
		t.Fatalf("native stream run err = %v stderr=%s", err, stderr)
	}
	if strings.Contains(stdout, "secret123") || !strings.Contains(stdout, "«REDACTED»") {
		t.Fatalf("native stream stdout not redacted: %q", stdout)
	}
	if !strings.Contains(stdout, "line1\n") || !strings.Contains(stdout, "line3\n") || !strings.Contains(stdout, "✓ web-1 · exit 0") {
		t.Fatalf("native stream stdout missing content/footer: %q", stdout)
	}
	records := mustReadAudit(t, home)
	completed := records[len(records)-1]
	buffered := mustOutputFilter(t).Apply("line1\npassword=secret123\nline3\n", "")
	if completed.Redactions != buffered.Redactions || completed.OutputTruncated != buffered.OutputTruncated {
		t.Fatalf("completed audit = %#v", completed)
	}
	t.Logf("native run streaming stdout=%q stderr=%q redactions=%d truncated=%t", stdout, stderr, completed.Redactions, completed.OutputTruncated)
}

func TestRunNativeUsesEncryptedPasswordFromEnvOnly(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	server := newCLIPasswordSSHServer(t, nil, "ssh-password-value")
	defer server.Close()

	writeKnownHostsLine(t, home, server.Addr(), server.HostSigner.PublicKey())
	writeInventory(t, home, fmt.Sprintf(`
version: 1
transport: native
hosts:
  web-1:
    addr: %s
    port: %d
    user: test
`, server.Host(), server.Port()))
	writeTestPolicy(t, home)
	store, err := secrets.Open(filepath.Join(home, "secrets.enc"), "master")
	if err != nil {
		t.Fatalf("open missing secrets: %v", err)
	}
	store.Set("web-1", "ssh-password-value")
	if err := store.Save("master"); err != nil {
		t.Fatalf("save secrets: %v", err)
	}
	t.Setenv("AGENTSSH_HOME", home)
	t.Setenv("AGENTSSH_SESSION", "s_password")
	t.Setenv(envMasterPassword, "master")
	t.Setenv("SSH_AUTH_SOCK", "")

	stdout, stderr, err := runCommandForTest(t, "run", "web-1", "--", "ok")
	if err != nil {
		t.Fatalf("run password err = %v stdout=%s stderr=%s", err, stdout, stderr)
	}
	if !strings.Contains(stdout, "ok\n") || strings.Contains(stdout+stderr, "ssh-password-value") {
		t.Fatalf("run output stdout=%q stderr=%q", stdout, stderr)
	}
	if got := atomic.LoadInt32(&server.passwordAttempts); got != 1 {
		t.Fatalf("password attempts = %d, want 1", got)
	}
}

func TestInventoryTestNativeEndToEnd(t *testing.T) {
	home := t.TempDir()
	clientSigner := writeSSHClientKey(t, home)
	server := newCLITestSSHServer(t, clientSigner.PublicKey())
	defer server.Close()

	writeKnownHostsLine(t, home, server.Addr(), server.HostSigner.PublicKey())
	writeInventory(t, home, fmt.Sprintf(`
version: 1
transport: native
hosts:
  web-1:
    addr: %s
    port: %d
    user: test
`, server.Host(), server.Port()))
	writeTestPolicy(t, home)
	t.Setenv("AGENTSSH_HOME", home)

	stdout, stderr, err := runCommandForTest(t, "inventory", "test", "web-1")
	if err != nil {
		t.Fatalf("inventory test err = %v stderr=%s", err, stderr)
	}
	if !strings.Contains(stdout, "OK web-1") {
		t.Fatalf("stdout = %q", stdout)
	}
}

func TestInventoryDiscoverProbeAndImport(t *testing.T) {
	home := t.TempDir()
	clientSigner := writeSSHClientKey(t, home)
	server := newCLITestSSHServer(t, clientSigner.PublicKey())
	defer server.Close()

	writeKnownHostsLine(t, home, server.Addr(), server.HostSigner.PublicKey())
	sshDir := filepath.Join(home, ".ssh")
	if err := os.WriteFile(filepath.Join(sshDir, "config"), []byte(fmt.Sprintf(`
Host web-1
  HostName %s
  Port %d
  User test
`, server.Host(), server.Port())), 0o600); err != nil {
		t.Fatalf("write ssh config: %v", err)
	}
	writeInventory(t, home, "version: 1\n")
	writeTestPolicy(t, home)
	t.Setenv("AGENTSSH_HOME", home)

	stdout, stderr, err := runCommandForTest(t, "inventory", "discover", "--probe", "--import")
	if err != nil {
		t.Fatalf("discover err = %v stdout=%s stderr=%s", err, stdout, stderr)
	}
	if !strings.Contains(stdout, "web-1") || !strings.Contains(stdout, "connectable") || !strings.Contains(stdout, "imported=1") {
		t.Fatalf("discover stdout = %q", stdout)
	}
	inv := readInventoryFile(t, home)
	host := inv.Hosts["web-1"]
	// ssh_config-sourced candidates are imported by alias so the operator's real
	// route (ProxyJump, multiple/tokenized IdentityFile) is preserved instead of a
	// flattened addr/user/port snapshot.
	if host.SSHConfigAlias != "web-1" || host.Addr != "" || host.Port != 0 {
		t.Fatalf("imported host = %#v", host)
	}
	if host.OS != "linux" {
		t.Fatalf("imported host OS = %q, want linux", host.OS)
	}
}

func TestPrintM2RunAuditDemo(t *testing.T) {
	home := t.TempDir()
	writeTestInventory(t, home)
	writeTestPolicy(t, home)
	t.Setenv("AGENTSSH_HOME", home)
	t.Setenv("AGENTSSH_SESSION", "s_demo")

	var calls int32
	restoreExecutor := newExecutor
	newExecutor = func(_ *config.Config) executor.Executor {
		return fakeExecutor{calls: &calls}
	}
	defer func() {
		newExecutor = restoreExecutor
	}()

	_, denyStderr, denyErr := runCommandForTest(t, "run", "web-1", "--", "rm", "-rf", "/")
	var denyExit commandExitError
	if !errors.As(denyErr, &denyExit) {
		t.Fatalf("deny err = %v", denyErr)
	}
	fmt.Printf("deny_exit=%d\n", denyExit.Code)
	fmt.Printf("deny_stderr=%s", denyStderr)

	allowStdout, allowStderr, allowErr := runCommandForTest(t, "run", "web-1", "--", "echo", "hi")
	if allowErr != nil {
		t.Fatalf("allow err = %v stderr=%s", allowErr, allowStderr)
	}
	fmt.Printf("allow_stdout=%s", allowStdout)
	fmt.Printf("executor_calls=%d\n", atomic.LoadInt32(&calls))

	records := mustReadAudit(t, home)
	for _, record := range records {
		fmt.Printf("audit seq=%d req=%s event=%s host=%s policy=%s/%s exit=%s session=%s\n", record.Seq, record.ReqID, record.Event, record.Host, record.PolicyAction, record.PolicyRule, formatExit(record.ExitCode), record.SessionID)
	}

	verify, err := audit.NewStore(filepath.Join(home, "audit.log")).Verify()
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	fmt.Printf("verify_ok=%t count=%d\n", verify.OK, verify.Count)

	sessionStdout, sessionStderr, sessionErr := runCommandForTest(t, "session", "ls")
	if sessionErr != nil {
		t.Fatalf("session ls err = %v stderr=%s", sessionErr, sessionStderr)
	}
	fmt.Printf("session_ls=%s", sessionStdout)

	lines, err := os.ReadFile(filepath.Join(home, "audit.log"))
	if err != nil {
		t.Fatalf("read audit for tamper: %v", err)
	}
	tampered := strings.Replace(string(lines), "web-1", "evil-1", 1)
	if err := os.WriteFile(filepath.Join(home, "audit.log"), []byte(tampered), 0o600); err != nil {
		t.Fatalf("write tampered audit: %v", err)
	}
	verify, err = audit.NewStore(filepath.Join(home, "audit.log")).Verify()
	if err != nil {
		t.Fatalf("verify tampered: %v", err)
	}
	fmt.Printf("verify_after_tamper_ok=%t broken_seq=%d reason=%s\n", verify.OK, verify.BrokenSeq, verify.Reason)
}

func TestPrintM4OutputFilterDemo(t *testing.T) {
	home := t.TempDir()
	writeTestInventory(t, home)
	writeTestPolicy(t, home)
	t.Setenv("AGENTSSH_HOME", home)
	t.Setenv("AGENTSSH_SESSION", "s_m4")

	restoreExecutor := newExecutor
	newExecutor = func(_ *config.Config) executor.Executor {
		return fakeExecutor{stdout: "password=secret123 abcdefghijklmnopqrstuvwxyz\n"}
	}
	defer func() {
		newExecutor = restoreExecutor
	}()

	stdout, stderr, err := runCommandForTest(t, "run", "web-1", "--json", "--", "echo", "secret")
	if err != nil {
		t.Fatalf("run err = %v stderr=%s", err, stderr)
	}
	fmt.Printf("run_json=%s", stdout)
	var response runResponse
	if err := json.Unmarshal([]byte(stdout), &response); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}

	auditStdout, auditStderr, err := runCommandForTest(t, "audit", "show", response.ReqID)
	if err != nil {
		t.Fatalf("audit show err = %v stderr=%s", err, auditStderr)
	}
	fmt.Printf("audit_show=%s", auditStdout)
}

func runCommandForTest(t *testing.T, args ...string) (string, string, error) {
	t.Helper()
	root := newRootCommand()
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	root.SetOut(&stdout)
	root.SetErr(&stderr)
	root.SetArgs(args)
	err := root.Execute()
	return stdout.String(), stderr.String(), err
}

func writeTestInventory(t *testing.T, home string) {
	t.Helper()
	writeInventory(t, home, `
version: 1
hosts:
  web-1:
    addr: 10.0.0.11
    user: deploy
    tags: [web, solo]
  web-2:
    addr: 10.0.0.12
    user: deploy
    tags: [web]
groups:
  web: { tags: [web] }
  solo: { tags: [solo] }
`)
}

func writeInventory(t *testing.T, home string, value string) {
	t.Helper()
	data := []byte(value)
	if err := os.WriteFile(filepath.Join(home, "inventory.yaml"), data, 0o600); err != nil {
		t.Fatalf("write inventory: %v", err)
	}
}

func readInventoryFile(t *testing.T, home string) inventory.Inventory {
	t.Helper()
	var inv inventory.Inventory
	data, err := os.ReadFile(filepath.Join(home, "inventory.yaml"))
	if err != nil {
		t.Fatalf("read inventory: %v", err)
	}
	if err := yaml.Unmarshal(data, &inv); err != nil {
		t.Fatalf("unmarshal inventory: %v\n%s", err, data)
	}
	return inv
}

func readPolicyFile(t *testing.T, home string) policy.Config {
	t.Helper()
	var cfg policy.Config
	data, err := os.ReadFile(filepath.Join(home, "policy.yaml"))
	if err != nil {
		t.Fatalf("read policy: %v", err)
	}
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		t.Fatalf("unmarshal policy: %v\n%s", err, data)
	}
	return cfg
}

func readFileString(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read file %s: %v", path, err)
	}
	return string(data)
}

func writeTestPolicy(t *testing.T, home string) {
	t.Helper()
	writePolicy(t, home, `
version: 1
rules:
  - name: catastrophic
    priority: 100
    match: { cmd_regex: 'rm\s+-rf' }
    action: deny
  - name: allow-test-commands
    priority: 0
    match: { cmd_regex: '^(echo|false|systemctl status|sudo systemctl restart|uptime|stream-secret|ok)\b' }
    action: allow
output:
  max_bytes: 24
  redact:
    - 'password=\S+'
`)
}

func writePolicy(t *testing.T, home string, value string) {
	t.Helper()
	data := []byte(value)
	if err := os.WriteFile(filepath.Join(home, "policy.yaml"), data, 0o600); err != nil {
		t.Fatalf("write policy: %v", err)
	}
}

func mustOutputFilter(t *testing.T) output.Filter {
	t.Helper()
	filter, err := output.NewFilter(policy.Output{
		MaxBytes: 24,
		Redact:   []string{`password=\S+`},
	})
	if err != nil {
		t.Fatalf("NewFilter: %v", err)
	}
	return filter
}

func mustReadAudit(t *testing.T, home string) []audit.Record {
	t.Helper()
	records, err := audit.NewStore(filepath.Join(home, "audit.log")).ReadAll()
	if err != nil {
		t.Fatalf("read audit: %v", err)
	}
	return records
}

func writeAuditRecords(t *testing.T, path string, records []audit.Record) {
	t.Helper()
	var builder strings.Builder
	for _, record := range records {
		line, err := json.Marshal(record)
		if err != nil {
			t.Fatalf("marshal audit record: %v", err)
		}
		builder.Write(line)
		builder.WriteByte('\n')
	}
	if err := os.WriteFile(path, []byte(builder.String()), 0o600); err != nil {
		t.Fatalf("write audit records: %v", err)
	}
}

func formatExit(exitCode *int) string {
	if exitCode == nil {
		return "-"
	}
	return fmt.Sprintf("%d", *exitCode)
}

func assertContainsAll(t *testing.T, value string, needles ...string) {
	t.Helper()
	for _, needle := range needles {
		if !strings.Contains(value, needle) {
			t.Fatalf("expected %q to contain %q", value, needle)
		}
	}
}

type fakeExecutor struct {
	calls    *int32
	stdout   string
	stderr   string
	exitCode int   // simulated remote/ssh exit code (0 = success)
	err      error // simulated transport error
}

func (e fakeExecutor) Run(_ context.Context, request executor.Request) executor.Result {
	if e.calls != nil {
		atomic.AddInt32(e.calls, 1)
	}
	stdout := e.stdout
	if stdout == "" && e.exitCode == 0 && e.err == nil {
		stdout = "ok\n"
	}
	return executor.Result{
		Stdout:   stdout,
		Stderr:   e.stderr,
		ExitCode: e.exitCode,
		Err:      e.err,
		Argv:     []string{"ssh", request.Target.Name, request.Command},
	}
}

var _ executor.Executor = fakeExecutor{}

func (e fakeExecutor) RunStreaming(_ context.Context, request executor.Request, stdout io.Writer, stderr io.Writer) executor.Result {
	if e.calls != nil {
		atomic.AddInt32(e.calls, 1)
	}
	out := e.stdout
	if out == "" && e.exitCode == 0 && e.err == nil {
		out = "ok\n"
	}
	writeInChunks(stdout, []byte(out), 7)
	writeInChunks(stderr, []byte(e.stderr), 7)
	return executor.Result{
		ExitCode: e.exitCode,
		Duration: time.Millisecond,
		Err:      e.err,
		Argv:     []string{"ssh", request.Target.Name, request.Command},
	}
}

var _ executor.StreamingExecutor = fakeExecutor{}

type osDetectingExecutor struct {
	osName string
}

func (e osDetectingExecutor) Run(_ context.Context, request executor.Request) executor.Result {
	return executor.Result{
		Stdout:   "ok\n",
		ExitCode: 0,
		Argv:     []string{"native-ssh", request.Target.Name, request.Command},
		OS:       e.osName,
	}
}

var _ executor.Executor = osDetectingExecutor{}

func writeInChunks(w io.Writer, data []byte, size int) {
	for len(data) > 0 {
		n := size
		if n > len(data) {
			n = len(data)
		}
		_, _ = w.Write(data[:n])
		data = data[n:]
	}
}

type bufferedOnlyExecutor struct {
	calls    *int32
	stdout   string
	stderr   string
	exitCode int
	err      error
}

func (e bufferedOnlyExecutor) Run(_ context.Context, request executor.Request) executor.Result {
	if e.calls != nil {
		atomic.AddInt32(e.calls, 1)
	}
	stdout := e.stdout
	if stdout == "" && e.exitCode == 0 && e.err == nil {
		stdout = "ok\n"
	}
	return executor.Result{
		Stdout:   stdout,
		Stderr:   e.stderr,
		ExitCode: e.exitCode,
		Err:      e.err,
		Argv:     []string{"ssh", request.Target.Name, request.Command},
	}
}

var _ executor.Executor = bufferedOnlyExecutor{}

type cliTestSSHServer struct {
	Listener   net.Listener
	HostSigner ssh.Signer
	allowedKey ssh.PublicKey
	wg         sync.WaitGroup
}

type cliPasswordSSHServer struct {
	Listener         net.Listener
	HostSigner       ssh.Signer
	allowedKey       ssh.PublicKey
	password         string
	wg               sync.WaitGroup
	passwordAttempts int32
}

func newCLIPasswordSSHServer(t *testing.T, allowedKey ssh.PublicKey, password string) *cliPasswordSSHServer {
	t.Helper()
	hostKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate host key: %v", err)
	}
	hostSigner, err := ssh.NewSignerFromKey(hostKey)
	if err != nil {
		t.Fatalf("host signer: %v", err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	server := &cliPasswordSSHServer{Listener: ln, HostSigner: hostSigner, allowedKey: allowedKey, password: password}
	server.wg.Add(1)
	go server.accept()
	return server
}

func (s *cliPasswordSSHServer) Addr() string { return s.Listener.Addr().String() }

func (s *cliPasswordSSHServer) Host() string {
	host, _, _ := net.SplitHostPort(s.Addr())
	return host
}

func (s *cliPasswordSSHServer) Port() int {
	_, portValue, _ := net.SplitHostPort(s.Addr())
	var port int
	_, _ = fmt.Sscanf(portValue, "%d", &port)
	return port
}

func (s *cliPasswordSSHServer) Close() {
	_ = s.Listener.Close()
	s.wg.Wait()
}

func (s *cliPasswordSSHServer) accept() {
	defer s.wg.Done()
	for {
		conn, err := s.Listener.Accept()
		if err != nil {
			return
		}
		s.wg.Add(1)
		go s.handle(conn)
	}
}

func (s *cliPasswordSSHServer) handle(conn net.Conn) {
	defer s.wg.Done()
	cfg := &ssh.ServerConfig{
		PublicKeyCallback: func(_ ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			if s.allowedKey != nil && string(key.Marshal()) == string(s.allowedKey.Marshal()) {
				return nil, nil
			}
			return nil, fmt.Errorf("unexpected public key")
		},
		PasswordCallback: func(_ ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
			atomic.AddInt32(&s.passwordAttempts, 1)
			if string(password) == s.password {
				return nil, nil
			}
			return nil, fmt.Errorf("unexpected password")
		},
	}
	cfg.AddHostKey(s.HostSigner)
	sshConn, chans, reqs, err := ssh.NewServerConn(conn, cfg)
	if err != nil {
		_ = conn.Close()
		return
	}
	defer func() { _ = sshConn.Close() }()
	go ssh.DiscardRequests(reqs)
	for ch := range chans {
		if ch.ChannelType() != "session" {
			_ = ch.Reject(ssh.UnknownChannelType, "session only")
			continue
		}
		channel, requests, err := ch.Accept()
		if err != nil {
			continue
		}
		go handleCLITestSession(channel, requests)
	}
}

func newCLITestSSHServer(t *testing.T, allowedKey ssh.PublicKey) *cliTestSSHServer {
	t.Helper()
	hostKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate host key: %v", err)
	}
	hostSigner, err := ssh.NewSignerFromKey(hostKey)
	if err != nil {
		t.Fatalf("host signer: %v", err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	server := &cliTestSSHServer{Listener: ln, HostSigner: hostSigner, allowedKey: allowedKey}
	server.wg.Add(1)
	go server.accept()
	return server
}

func (s *cliTestSSHServer) Addr() string { return s.Listener.Addr().String() }

func (s *cliTestSSHServer) Host() string {
	host, _, _ := net.SplitHostPort(s.Addr())
	return host
}

func (s *cliTestSSHServer) Port() int {
	_, portValue, _ := net.SplitHostPort(s.Addr())
	var port int
	_, _ = fmt.Sscanf(portValue, "%d", &port)
	return port
}

func (s *cliTestSSHServer) Close() {
	_ = s.Listener.Close()
	s.wg.Wait()
}

func (s *cliTestSSHServer) accept() {
	defer s.wg.Done()
	for {
		conn, err := s.Listener.Accept()
		if err != nil {
			return
		}
		s.wg.Add(1)
		go s.handle(conn)
	}
}

func (s *cliTestSSHServer) handle(conn net.Conn) {
	defer s.wg.Done()
	cfg := &ssh.ServerConfig{
		PublicKeyCallback: func(_ ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			if string(key.Marshal()) == string(s.allowedKey.Marshal()) {
				return nil, nil
			}
			return nil, fmt.Errorf("unexpected public key")
		},
	}
	cfg.AddHostKey(s.HostSigner)
	sshConn, chans, reqs, err := ssh.NewServerConn(conn, cfg)
	if err != nil {
		_ = conn.Close()
		return
	}
	defer func() { _ = sshConn.Close() }()
	go ssh.DiscardRequests(reqs)
	for ch := range chans {
		if ch.ChannelType() != "session" {
			_ = ch.Reject(ssh.UnknownChannelType, "session only")
			continue
		}
		channel, requests, err := ch.Accept()
		if err != nil {
			continue
		}
		go handleCLITestSession(channel, requests)
	}
}

func handleCLITestSession(channel ssh.Channel, requests <-chan *ssh.Request) {
	defer func() { _ = channel.Close() }()
	for req := range requests {
		if req.Type != "exec" {
			_ = req.Reply(false, nil)
			continue
		}
		var payload struct{ Command string }
		_ = ssh.Unmarshal(req.Payload, &payload)
		_ = req.Reply(true, nil)
		if payload.Command == executor.OSProbeCommand {
			_, _ = channel.Write([]byte("Linux\n"))
		} else if strings.Contains(payload.Command, "stream-secret") {
			_, _ = channel.Write([]byte("line1\npassword="))
			_, _ = channel.Write([]byte("secret123\nline3\n"))
		} else {
			_, _ = channel.Write([]byte("ok\n"))
		}
		_, _ = channel.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{}))
		return
	}
}

func writeSSHClientKey(t *testing.T, home string) ssh.Signer {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate client key: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		t.Fatalf("client signer: %v", err)
	}
	dir := filepath.Join(home, ".ssh")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("mkdir .ssh: %v", err)
	}
	data := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	if err := os.WriteFile(filepath.Join(dir, "id_rsa"), data, 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	t.Setenv("HOME", home)
	t.Setenv("SSH_AUTH_SOCK", "")
	return signer
}

func writeKnownHostsLine(t *testing.T, home string, addr string, key ssh.PublicKey) {
	t.Helper()
	dir := filepath.Join(home, ".ssh")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("mkdir .ssh: %v", err)
	}
	line := knownhosts.Line([]string{addr}, key)
	if err := os.WriteFile(filepath.Join(dir, "known_hosts"), []byte(line+"\n"), 0o600); err != nil {
		t.Fatalf("write known_hosts: %v", err)
	}
}

func TestEndpointKeyNormalization(t *testing.T) {
	if got := discovery.EndpointKey("  10.0.0.11 ", 0); got != "10.0.0.11:22" {
		t.Fatalf("default port = %q", got)
	}
	if got := discovery.EndpointKey("HOST.Example", 2222); got != "host.example:2222" {
		t.Fatalf("normalize = %q", got)
	}
	if got := discovery.EndpointKey("", 22); got != "" {
		t.Fatalf("empty addr should yield empty key, got %q", got)
	}
}

func TestEndpointKeysSkipsAliasOnlyHosts(t *testing.T) {
	inv := inventory.Inventory{Hosts: map[string]inventory.Host{
		"web-1":      {Addr: "10.0.0.11"},
		"alias-only": {SSHConfigAlias: "gw"},
	}}
	keys := discovery.EndpointKeys(inv)
	if !keys["10.0.0.11:22"] {
		t.Fatalf("missing concrete endpoint: %#v", keys)
	}
	if len(keys) != 1 {
		t.Fatalf("alias-only host should not contribute an endpoint key: %#v", keys)
	}
}

func TestImportHostUsesAliasForSSHConfig(t *testing.T) {
	h := discovery.ImportHost(discovery.Candidate{Source: discovery.SourceSSHConfig, Name: "prod-web", Addr: "10.0.0.11", Port: 22, OS: "linux"})
	if h.SSHConfigAlias != "prod-web" || h.Addr != "" || h.OS != "linux" {
		t.Fatalf("ssh_config import should reference the alias: %#v", h)
	}
	h2 := discovery.ImportHost(discovery.Candidate{Source: discovery.SourceKnownHosts, Addr: "10.0.0.20", Port: 2222, IdentityFile: "~/.ssh/db", OS: "bsd"})
	if h2.Addr != "10.0.0.20" || h2.Port != 2222 || h2.IdentityFile != "~/.ssh/db" || h2.SSHConfigAlias != "" || h2.OS != "bsd" {
		t.Fatalf("known_hosts import should be a concrete host: %#v", h2)
	}
}

func TestPrintSSHErrorHintDoesNotLeakOperatorDetails(t *testing.T) {
	cmd := &cobra.Command{}
	var buf bytes.Buffer
	cmd.SetErr(&buf)
	// Native transport errors can embed operator-only details (key paths, addrs).
	result := executor.Result{Err: errors.New("read identity file /home/op/.ssh/web1: dial tcp 10.0.0.11:22: connection refused")}
	printSSHErrorHint(cmd, result)
	out := buf.String()
	for _, leak := range []string{"/home/op/.ssh/web1", "10.0.0.11"} {
		if strings.Contains(out, leak) {
			t.Fatalf("agent-facing ssh error leaked %q:\n%s", leak, out)
		}
	}
	if !strings.Contains(out, "exit 9") || !strings.Contains(out, "hint:") {
		t.Fatalf("expected exit marker + hint, got:\n%s", out)
	}
}

func TestInventoryAddPasswordNonInteractiveNoMasterDoesNotPersistHost(t *testing.T) {
	home := t.TempDir()
	t.Setenv("AGENTSSH_HOME", home)
	// No AGENTSSH_MASTER_PASSWORD and no TTY: the credential preflight must fail
	// BEFORE the host is written, so inventory and secrets stay consistent.
	_, _, err := runCommandForTest(t, "inventory", "add", "web-1", "--addr", "10.0.0.11", "--password")
	if err == nil {
		t.Fatal("expected `inventory add --password` to fail without a master password")
	}
	if _, statErr := os.Stat(filepath.Join(home, "inventory.yaml")); statErr == nil {
		raw := readFileString(t, filepath.Join(home, "inventory.yaml"))
		if strings.Contains(raw, "web-1") {
			t.Fatalf("host persisted despite failed --password preflight:\n%s", raw)
		}
	}
}

func TestInventoryTestUsesEncryptedPasswordEndToEnd(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	server := newCLIPasswordSSHServer(t, nil, "ssh-password-value")
	defer server.Close()

	writeKnownHostsLine(t, home, server.Addr(), server.HostSigner.PublicKey())
	writeInventory(t, home, fmt.Sprintf(`
version: 1
transport: native
hosts:
  web-1:
    addr: %s
    port: %d
    user: test
`, server.Host(), server.Port()))
	writeTestPolicy(t, home)
	store, err := secrets.Open(filepath.Join(home, "secrets.enc"), "master")
	if err != nil {
		t.Fatalf("open secrets: %v", err)
	}
	store.Set("web-1", "ssh-password-value")
	if err := store.Save("master"); err != nil {
		t.Fatalf("save secrets: %v", err)
	}
	t.Setenv("AGENTSSH_HOME", home)
	t.Setenv(envMasterPassword, "master")
	t.Setenv("SSH_AUTH_SOCK", "")

	stdout, stderr, err := runCommandForTest(t, "inventory", "test", "web-1")
	if err != nil {
		t.Fatalf("inventory test err = %v stdout=%s stderr=%s", err, stdout, stderr)
	}
	if !strings.Contains(stdout, "OK") || strings.Contains(stdout+stderr, "ssh-password-value") {
		t.Fatalf("inventory test stdout=%q stderr=%q", stdout, stderr)
	}
}
