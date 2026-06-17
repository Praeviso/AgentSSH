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

	"github.com/Kritoooo/agentssh/internal/audit"
	"github.com/Kritoooo/agentssh/internal/config"
	"github.com/Kritoooo/agentssh/internal/executor"
	"github.com/Kritoooo/agentssh/internal/output"
	"github.com/Kritoooo/agentssh/internal/policy"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
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
	if _, ok := defaultExec.(executor.SSHExecutor); !ok {
		t.Fatalf("default transport = %T, want shell-out SSHExecutor", defaultExec)
	}
	cfg.Inventory.Transport = executor.TransportNative
	inventoryExec := newExecutor(cfg)
	if _, ok := inventoryExec.(executor.NativeExecutor); !ok {
		t.Fatalf("inventory native transport = %T, want NativeExecutor", inventoryExec)
	}
	t.Setenv("AGENTSSH_TRANSPORT", executor.TransportNative)
	cfg.Inventory.Transport = executor.TransportShell
	envExec := newExecutor(cfg)
	if _, ok := envExec.(executor.NativeExecutor); !ok {
		t.Fatalf("env native transport = %T, want NativeExecutor", envExec)
	}
	t.Logf("transport default=%T inventory_native=%T env_native_overrides=%T", defaultExec, inventoryExec, envExec)
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
	t.Setenv("AGENTSSH_HOME", home)

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
defaults:
  policy: allow
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

func writeTestPolicy(t *testing.T, home string) {
	t.Helper()
	writePolicy(t, home, `
version: 1
defaults:
  policy: allow
rules:
  - name: catastrophic
    match: { cmd_regex: 'rm\s+-rf' }
    action: deny
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

func formatExit(exitCode *int) string {
	if exitCode == nil {
		return "-"
	}
	return fmt.Sprintf("%d", *exitCode)
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
		if strings.Contains(payload.Command, "stream-secret") {
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
