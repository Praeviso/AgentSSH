package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/Kritoooo/agentssh/internal/audit"
	"github.com/Kritoooo/agentssh/internal/executor"
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
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := exitCodeForResult(tt.result); got != tt.want {
				t.Fatalf("exitCodeForResult = %d, want %d", got, tt.want)
			}
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
	newExecutor = func() executor.Executor {
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
	newExecutor = func() executor.Executor {
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
	newExecutor = func() executor.Executor {
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
	newExecutor = func() executor.Executor {
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

func TestPrintM2RunAuditDemo(t *testing.T) {
	home := t.TempDir()
	writeTestInventory(t, home)
	writeTestPolicy(t, home)
	t.Setenv("AGENTSSH_HOME", home)
	t.Setenv("AGENTSSH_SESSION", "s_demo")

	var calls int32
	restoreExecutor := newExecutor
	newExecutor = func() executor.Executor {
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
	newExecutor = func() executor.Executor {
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
	data := []byte(`
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
	if err := os.WriteFile(filepath.Join(home, "inventory.yaml"), data, 0o600); err != nil {
		t.Fatalf("write inventory: %v", err)
	}
}

func writeTestPolicy(t *testing.T, home string) {
	t.Helper()
	data := []byte(`
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
	if err := os.WriteFile(filepath.Join(home, "policy.yaml"), data, 0o600); err != nil {
		t.Fatalf("write policy: %v", err)
	}
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
