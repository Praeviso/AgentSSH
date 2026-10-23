package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Praeviso/AgentSSH/internal/audit"
	"github.com/Praeviso/AgentSSH/internal/config"
	"github.com/Praeviso/AgentSSH/internal/controlplane"
	"github.com/Praeviso/AgentSSH/internal/executor"
	"github.com/Praeviso/AgentSSH/internal/gateway"
	"github.com/Praeviso/AgentSSH/internal/inventory"
	"github.com/Praeviso/AgentSSH/internal/remote"
	"github.com/Praeviso/AgentSSH/internal/remoteclient"
)

func init() {
	gateway.ScryptWorkFactor = 10
}

// parityInventory and parityPolicy are pushed to the gateway and written to
// the local home alike.
const parityInventory = `
hosts:
  web-1: {addr: 10.0.0.11, user: deploy, identity: web, tags: [web, solo]}
  web-2: {addr: 10.0.0.12, user: deploy, identity: web, tags: [web]}
groups:
  web: {tags: [web]}
  solo: {tags: [solo]}
`

const parityPolicy = `
version: 1
rules:
  - {name: catastrophic, priority: 100, match: {cmd_regex: 'rm\s+-rf'}, action: deny}
  - {name: allow-test-commands, match: {cmd_regex: '^(echo|false|uptime)\b'}, action: allow}
approval:
  enabled: true
output:
  max_bytes: 64
  redact:
    - 'password=\S+'
`

// gatewayDevice is a home enrolled in gateway mode with an in-process
// gateway, whose commands reach the target through exec.
type gatewayDevice struct {
	home     string
	base     string
	dir      string
	deviceID string
	store    *controlplane.Store
	// exec is what the target does, for the gateway and local runs alike.
	exec *atomic.Pointer[fakeExecutor]
}

func newGatewayDevice(t *testing.T) *gatewayDevice {
	t.Helper()
	dir := t.TempDir()
	if err := gateway.Init(dir, "master"); err != nil {
		t.Fatalf("init: %v", err)
	}
	store, err := gateway.OpenStore(filepath.Join(dir, gateway.FileDatabase))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	keys, err := controlplane.Unlock(dir, "master")
	if err != nil {
		t.Fatal(err)
	}
	d := &gatewayDevice{dir: dir, store: store, exec: new(atomic.Pointer[fakeExecutor])}
	d.exec.Store(&fakeExecutor{})
	server := gateway.NewServer(dir, store, keys)
	server.Executor = func(inventory.Inventory) executor.Executor { return *d.exec.Load() }
	ingress := httptest.NewUnstartedServer(nil)
	ingress.StartTLS()
	t.Cleanup(ingress.Close)
	base := ingress.URL + "/agentssh"
	d.base = base
	handler, err := server.Handler(base)
	if err != nil {
		t.Fatal(err)
	}
	ingress.Config.Handler = handler
	trustIngress(t, ingress)

	recipient, err := controlplane.LoadRecipient(dir)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := controlplane.NewIdentity("web", recipient, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := store.CreateIdentity(identity); err != nil {
		t.Fatal(err)
	}
	d.home = t.TempDir()
	state, err := remoteclient.Enroll(context.Background(), d.home, base, d.token(t, base), remote.ModeGateway, time.Now())
	if err != nil {
		t.Fatalf("enroll: %v", err)
	}
	d.deviceID = state.DeviceID
	if _, err := controlplane.PushConfig(store, d.deviceID, parityInventory, parityPolicy, time.Now()); err != nil {
		t.Fatalf("push: %v", err)
	}
	return d
}

func (d *gatewayDevice) token(t *testing.T, base string) string {
	t.Helper()
	pub, err := controlplane.LoadBundlePublicKey(d.dir)
	if err != nil {
		t.Fatal(err)
	}
	token, err := d.store.CreateEnrollToken("agent-vm", base, remote.PublicKeyFingerprint(pub), time.Minute, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return token.String()
}

// trustIngress makes the ingress's certificate trusted, like an ordinary
// system-trusted HTTPS ingress.
func trustIngress(t *testing.T, ingress *httptest.Server) {
	t.Helper()
	original := http.DefaultTransport
	transport := original.(*http.Transport).Clone()
	pool := x509.NewCertPool()
	pool.AddCert(ingress.Certificate())
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: pool}
	http.DefaultTransport = transport
	t.Cleanup(func() { http.DefaultTransport = original; transport.CloseIdleConnections() })
}

func (d *gatewayDevice) audit(t *testing.T) []audit.Record {
	t.Helper()
	records, err := audit.NewStore(filepath.Join(d.dir, gateway.FileAudit)).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	return records
}

// paritySetup returns a local home and a gateway home with the same
// inventory and policy, and the device behind the gateway home. Both drive
// the same fake target.
func paritySetup(t *testing.T) (string, *gatewayDevice) {
	t.Helper()
	device := newGatewayDevice(t)
	local := t.TempDir()
	writeInventory(t, local, parityInventory)
	writePolicy(t, local, parityPolicy)
	restore := newExecutor
	newExecutor = func(*config.Config) executor.Executor { return *device.exec.Load() }
	t.Cleanup(func() { newExecutor = restore })
	t.Setenv("AGENTSSH_SESSION", "s_test")
	t.Setenv(config.EnvApproval, "")
	return local, device
}

// cliOutcome is what the agent sees: the exit code, both streams, and the
// error execute() prints last on stderr.
type cliOutcome struct {
	code                int
	stdout, stderr, err string
}

func runIn(t *testing.T, home string, args ...string) cliOutcome {
	t.Helper()
	t.Setenv("AGENTSSH_HOME", home)
	stdout, stderr, err := runCommandForTest(t, args...)
	outcome := cliOutcome{code: exitCodeForError(err), stdout: stdout, stderr: stderr}
	if err != nil && !errors.As(err, &commandExitError{}) {
		outcome.err = err.Error()
	}
	return outcome
}

// modeHints are the remediation hints that name what the agent's operator
// can change, which differs by mode: a gateway device's policy and SSH are
// the gateway administrator's.
var modeHints = map[string]string{
	"  If the policy should change, ask an operator to edit ~/.agentssh/policy.yaml.":                 "  This policy is managed by a remote control plane; ask its administrator to change it.",
	"hint: cannot reach SSH; check addr, port, network route, and firewall rules.":                    "hint: the gateway could not connect to this host; its administrator can find the cause in the gateway's log.",
	"hint: SSH connection failed; check addr, port, network, host key trust, and available SSH keys.": "hint: the gateway could not connect to this host; its administrator can find the cause in the gateway's log.",
}

// asGateway is what a local outcome reads like on a gateway device.
func asGateway(outcome cliOutcome) cliOutcome {
	for local, gateway := range modeHints {
		outcome.stderr = strings.ReplaceAll(outcome.stderr, local, gateway)
	}
	return outcome
}

// mintedIDs are the IDs each mode mints on its own.
var mintedIDs = []*regexp.Regexp{
	regexp.MustCompile(`("req_id": )"[0-9a-f]{6}"`),
	regexp.MustCompile(`()\bap_[0-9a-f]+\b`),
}

func normalizeIDs(value string) string {
	for _, pattern := range mintedIDs {
		value = pattern.ReplaceAllString(value, `${1}<id>`)
	}
	return value
}

// The agent-facing contract does not depend on the mode: the same command
// prints the same stdout and stderr and exits the same under local and
// gateway, apart from the IDs each mints.
func TestGatewayModeMatchesLocalMode(t *testing.T) {
	local, device := paritySetup(t)
	stdinFile := filepath.Join(t.TempDir(), "payload")
	if err := os.WriteFile(stdinFile, []byte("config"), 0o600); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		exec fakeExecutor
		args []string
	}{
		{"allowed", fakeExecutor{stdout: "hello\n"}, []string{"run", "web-1", "--", "echo", "hello"}},
		{"allowed json", fakeExecutor{stdout: "hello\n"}, []string{"run", "web-1", "--json", "--", "echo", "hello"}},
		{"fields", fakeExecutor{stdout: "hello\n"}, []string{"run", "web-1", "--fields", "status,exit_code,stdout", "--", "echo", "hello"}},
		{"redacted and capped", fakeExecutor{stdout: "password=hunter2 " + strings.Repeat("x", 100) + "\n"}, []string{"run", "web-1", "--json", "--", "echo", "secret"}},
		{"remote failure", fakeExecutor{exitCode: 3, stderr: "boom\n"}, []string{"run", "web-1", "--", "false"}},
		{"remote failure json", fakeExecutor{exitCode: 3, stderr: "boom\n"}, []string{"run", "web-1", "--json", "--", "false"}},
		{"ssh error", fakeExecutor{exitCode: -1, err: errors.New("dial tcp 10.0.0.11:22: connection refused")}, []string{"run", "web-1", "--", "uptime"}},
		{"ssh error json", fakeExecutor{exitCode: -1, err: errors.New("dial tcp 10.0.0.11:22: connection refused")}, []string{"run", "web-1", "--json", "--", "uptime"}},
		{"group", fakeExecutor{stdout: "up\n"}, []string{"run", "web", "--", "uptime"}},
		{"group json", fakeExecutor{stdout: "up\n"}, []string{"run", "web", "--json", "--", "uptime"}},
		{"one-host group json", fakeExecutor{stdout: "up\n"}, []string{"run", "solo", "--json", "--", "uptime"}},
		{"denied", fakeExecutor{}, []string{"run", "web-1", "--", "rm", "-rf", "/srv"}},
		{"denied json", fakeExecutor{}, []string{"run", "web-1", "--json", "--", "rm", "-rf", "/srv"}},
		{"gray zone", fakeExecutor{}, []string{"run", "web-1", "--", "systemctl", "restart", "nginx"}},
		{"gray zone json", fakeExecutor{}, []string{"run", "web-1", "--json", "--", "systemctl", "restart", "nginx"}},
		{"gray zone group", fakeExecutor{}, []string{"run", "web", "--json", "--", "systemctl", "restart", "nginx"}},
		{"stdin", fakeExecutor{stdout: "applied\n"}, []string{"run", "web-1", "--stdin-file", stdinFile, "--json", "--", "echo", "apply"}},
		{"argv and cwd", fakeExecutor{stdout: "ok\n"}, []string{"run", "web-1", "--argv", "--cwd", "/srv/app", "--json", "--", "echo", "a b"}},
		{"unknown host", fakeExecutor{}, []string{"run", "db-9", "--", "uptime"}},
		{"hosts", fakeExecutor{}, []string{"hosts"}},
		{"hosts json", fakeExecutor{}, []string{"hosts", "--json"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			exec := tc.exec
			device.exec.Store(&exec)
			want := asGateway(runIn(t, local, tc.args...))
			got := runIn(t, device.home, tc.args...)
			if got.code != want.code || got.err != want.err || normalizeIDs(got.stdout) != normalizeIDs(want.stdout) || normalizeIDs(got.stderr) != normalizeIDs(want.stderr) {
				t.Fatalf("gateway differs from local\nlocal:   exit %d %s\nstdout:\n%s\nstderr:\n%s\ngateway: exit %d %s\nstdout:\n%s\nstderr:\n%s",
					want.code, want.err, want.stdout, want.stderr, got.code, got.err, got.stdout, got.stderr)
			}
		})
	}

	t.Run("no session", func(t *testing.T) {
		t.Setenv("AGENTSSH_SESSION", "")
		for _, target := range []string{"web-1", "db-9"} {
			want := runIn(t, local, "run", target, "--", "uptime")
			got := runIn(t, device.home, "run", target, "--", "uptime")
			if got != want || want.code != exitUsage {
				t.Fatalf("%s: local %+v\ngateway %+v", target, want, got)
			}
		}
	})

	t.Run("status", func(t *testing.T) {
		device.exec.Store(&fakeExecutor{stdout: "hello\n"})
		var outcomes []cliOutcome
		for _, home := range []string{local, device.home} {
			run := runIn(t, home, "run", "web-1", "--json", "--", "echo", "hello")
			var response runResponse
			if err := json.Unmarshal([]byte(run.stdout), &response); err != nil {
				t.Fatalf("decode run: %v\n%s", err, run.stdout)
			}
			outcomes = append(outcomes, runIn(t, home, "status", response.ReqID, "--json"))
		}
		if normalizeIDs(outcomes[0].stdout) != normalizeIDs(outcomes[1].stdout) || outcomes[0].code != outcomes[1].code {
			t.Fatalf("local %+v\ngateway %+v", outcomes[0], outcomes[1])
		}
		want := runIn(t, local, "status", "abcdef")
		got := runIn(t, device.home, "status", "abcdef")
		if got != want || want.code != exitUsage {
			t.Fatalf("unknown request: local %+v gateway %+v", want, got)
		}
	})
}

// The gateway decides: a gateway device's local policy, inventory and
// approvals change nothing, and the command is audited on the gateway.
func TestGatewayModeIgnoresLocalConfiguration(t *testing.T) {
	_, device := paritySetup(t)
	writeInventory(t, device.home, "hosts:\n  web-1: {addr: 192.0.2.1, user: root}\n")
	writePolicy(t, device.home, "version: 1\nrules:\n  - {name: allow-all, match: {cmd_regex: '.*'}, action: allow}\n")
	var calls int32
	device.exec.Store(&fakeExecutor{calls: &calls})

	if got := runIn(t, device.home, "run", "web-1", "--", "rm", "-rf", "/srv"); got.code != exitPolicyDenied {
		t.Fatalf("a local allow-all rule changed the gateway's deny: %+v", got)
	}
	if got := runIn(t, device.home, "run", "web-1", "--", "systemctl", "restart", "nginx"); got.code != exitApprovalRequired {
		t.Fatalf("a local allow-all rule bypassed the gateway's approval: %+v", got)
	}
	if got := runIn(t, device.home, "run", "web-2", "--", "uptime"); got.code != exitOK {
		t.Fatalf("a host missing from the local inventory is still the gateway's: %+v", got)
	}
	if atomic.LoadInt32(&calls) != 1 {
		t.Fatalf("target ran %d commands, want only the allowed one", calls)
	}
	if _, err := os.Stat(filepath.Join(device.home, "audit.jsonl")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the device wrote a local audit: %v", err)
	}
	var events []string
	for _, record := range device.audit(t) {
		if record.DeviceID != device.deviceID {
			t.Fatalf("audit record for another device: %+v", record)
		}
		events = append(events, string(record.Event))
	}
	if strings.Join(events, ",") != "denied,approval_requested,started,completed" {
		t.Fatalf("gateway audit events = %v", events)
	}
}

// Commands that read or change state a gateway device does not keep are
// refused, before any operator prompt, with where that state lives.
func TestGatewayModeRefusesLocalStateCommands(t *testing.T) {
	_, device := paritySetup(t)
	withOperatorTTY(t)
	restore := readSecretNoEcho
	readSecretNoEcho = func(prompt string) (string, error) {
		t.Fatalf("prompted %q before refusing", prompt)
		return "", nil
	}
	t.Cleanup(func() { readSecretNoEcho = restore })
	for _, args := range [][]string{
		{"inventory", "ls"},
		{"inventory", "add", "db-1", "--addr", "10.0.0.20", "--user", "root"},
		{"policy", "test", "--host", "web-1", "--", "uptime"},
		{"policy", "show"},
		{"approval", "ls"},
		{"approval", "grant", "ap_0", "--once"},
		{"audit", "ls"},
		{"session", "ls"},
		{"tui"},
	} {
		got := runIn(t, device.home, args...)
		if got.code != exitUsage || !strings.Contains(got.err, "not available in gateway mode: this device's inventory, policy, approvals and audit live on the gateway") {
			t.Fatalf("%v: %+v", args, got)
		}
	}
	for _, args := range [][]string{
		{"approval", "wait", "ap_0"},
		{"plan", "status", "pl_0"},
		{"run", "web-1", "--wait-approval", "5s", "--", "uptime"},
	} {
		got := runIn(t, device.home, args...)
		if got.code != exitUsage || !strings.Contains(got.err, "not available in gateway mode yet: this device's approvals are kept on the gateway") {
			t.Fatalf("%v: %+v", args, got)
		}
	}
	if got := runIn(t, device.home, "session", "new"); got.code != exitOK || !strings.HasPrefix(got.stdout, "s_") {
		t.Fatalf("session new: %+v", got)
	}
	if got := runIn(t, device.home, "diagnostics", "--json"); got.code != exitOK || !strings.Contains(got.stdout, `"mode": "gateway"`) {
		t.Fatalf("diagnostics: %+v", got)
	}
}

// plan run executes each step through the gateway, which reauthorizes it, and
// streams step output with the step's request ID like a local run.
func TestGatewayPlanRunsEachStepThroughTheGateway(t *testing.T) {
	_, device := paritySetup(t)
	device.exec.Store(&fakeExecutor{stdout: "step output\n"})
	dir := t.TempDir()
	payload := filepath.Join(dir, "app.conf")
	if err := os.WriteFile(payload, []byte("listen 80\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	plan := filepath.Join(dir, "plan.yaml")
	if err := os.WriteFile(plan, []byte("version: 1\ncommands:\n  - {id: check, cmd: uptime}\n  - {id: apply, cmd: echo apply, stdin_file: "+payload+"}\n  - {id: restart, cmd: systemctl restart app}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got := runIn(t, device.home, "plan", "run", "web-1", "--file", plan, "--events")
	if got.code != exitApprovalRequired {
		t.Fatalf("plan run: %+v", got)
	}
	var executionID string
	outputs := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(got.stdout), "\n") {
		var event executionEvent
		if err := json.Unmarshal([]byte(line), &event); err != nil {
			t.Fatalf("event %q: %v", line, err)
		}
		executionID = event.ExecutionID
		if event.Type == "step_output" {
			if event.RequestID == "" {
				t.Fatalf("streamed output without its request: %s", line)
			}
			outputs[event.StepID] = event.RequestID
		}
		if event.Type == "step_completed" && event.Status == "completed" && outputs[event.StepID] != event.RequestID {
			t.Fatalf("step %s streamed as request %q but completed as %q", event.StepID, outputs[event.StepID], event.RequestID)
		}
	}
	steps := map[string]audit.Record{}
	for _, record := range device.audit(t) {
		if record.ExecutionID != executionID {
			t.Fatalf("gateway audit record outside the execution: %+v", record)
		}
		steps[record.StepID] = record
	}
	if steps["check"].Event != audit.EventCompleted || steps["apply"].Event != audit.EventCompleted || steps["apply"].StdinBytes != int64(len("listen 80\n")) {
		t.Fatalf("steps on the gateway: %+v", steps)
	}
	if steps["restart"].Event != audit.EventApprovalRequested {
		t.Fatalf("the gray-zone step was not sent for approval: %+v", steps["restart"])
	}

	status := runIn(t, device.home, "plan", "execution", executionID)
	var execution planExecution
	if err := json.Unmarshal([]byte(status.stdout), &execution); err != nil {
		t.Fatalf("execution: %v\n%s", err, status.stdout)
	}
	if execution.Status != "pending" || execution.Steps[2].Status != "not_started" || execution.NextAction == nil || !strings.Contains(strings.Join(execution.NextAction.Argv, " "), "plan resume "+executionID) {
		t.Fatalf("execution after a pending step: %+v", execution)
	}
	// Resuming asks the gateway again; without a decision the step stays
	// pending and the completed steps do not run again.
	if got := runIn(t, device.home, "plan", "resume", executionID, "--json"); got.code != exitApprovalRequired {
		t.Fatalf("resume: %+v", got)
	}
	if n := len(device.audit(t)); n != 6 {
		t.Fatalf("gateway audit has %d records after resume, want 6 (two steps run once, two approval requests)", n)
	}
	if got := runIn(t, device.home, "plan", "run", "solo", "--file", plan); got.code != exitUsage || !strings.Contains(got.err, "plan run requires a single host") {
		t.Fatalf("plan run on a group: %+v", got)
	}
}

// remote enroll checks the control plane's mode before spending the token,
// and a gateway device reports its mode instead of a configuration bundle.
func TestRemoteEnrollChecksTheMode(t *testing.T) {
	device := newGatewayDevice(t)
	withOperatorTTY(t)
	home := t.TempDir()
	token := device.token(t, device.base)
	got := runIn(t, home, "remote", "enroll", device.base, "--token", token)
	if got.code != exitUsage || !strings.Contains(got.err, "the control plane runs in gateway mode, not managed mode; the token was not used") || !strings.Contains(got.err, "--mode gateway") {
		t.Fatalf("managed enrollment against a gateway: %+v", got)
	}
	got = runIn(t, home, "remote", "enroll", device.base, "--token", token, "--mode", "gateway")
	if got.code != exitOK || !strings.Contains(got.stdout, "with gateway "+device.base) {
		t.Fatalf("gateway enrollment: %+v", got)
	}
	got = runIn(t, home, "remote", "status")
	if got.code != exitOK || !strings.Contains(got.stdout, "mode     gateway\n") || !strings.Contains(got.stdout, "(active)") || !strings.Contains(got.stdout, "config   kept on the gateway") || strings.Contains(got.stdout, "local ") {
		t.Fatalf("remote status: %+v", got)
	}
	if got := runIn(t, home, "remote", "refresh"); got.code != exitUsage {
		t.Fatalf("remote refresh: %+v", got)
	}
	if got := runIn(t, home, "remote", "enroll", device.base, "--token", token, "--mode", "local"); got.code != exitUsage {
		t.Fatalf("unknown mode: %+v", got)
	}
}

// An execution saved before the device enrolled with a gateway may still wait
// on a local approval plan. On a gateway device that plan authorizes nothing,
// so resume sends the remaining steps to the gateway instead of waiting on it.
func TestGatewayResumeIgnoresALocalApprovalPlan(t *testing.T) {
	_, device := paritySetup(t)
	device.exec.Store(&fakeExecutor{stdout: "up\n"})
	cfg := &config.Config{Paths: config.NewPaths(device.home)}
	const id = "px_0123456789abcdef01234567"
	path, err := executionPath(cfg, id)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	run := planExecution{Version: 1, ID: id, Host: "web-1", SessionID: "s_test", Status: "pending", ApprovalPlanID: "pl_0123456789abcdef01234567",
		Steps: []planExecutionStep{{ID: "check", Cmd: "uptime", Status: "not_started"}}}
	if err := saveExecution(path, &run); err != nil {
		t.Fatal(err)
	}
	got := runIn(t, device.home, "plan", "resume", id, "--json")
	var resumed planExecution
	if err := json.Unmarshal([]byte(got.stdout), &resumed); err != nil {
		t.Fatalf("resume: %+v: %v", got, err)
	}
	if got.code != exitOK || resumed.Status != "completed" || resumed.ApprovalPlanID != "" || resumed.Steps[0].Status != "completed" {
		t.Fatalf("resume: %+v\n%+v", got, resumed)
	}
	records := device.audit(t)
	if len(records) != 2 || records[1].Event != audit.EventCompleted || records[1].ExecutionID != id {
		t.Fatalf("gateway audit: %+v", records)
	}
}
