package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"sync/atomic"
	"testing"
)

func TestRunJSONCmdEchoTruncatedWithSHA(t *testing.T) {
	home := t.TempDir()
	writeTestInventory(t, home)
	writePolicy(t, home, `
version: 1
rules:
  - name: allow-echo
    priority: 0
    match: { cmd_regex: '^echo\b' }
    action: allow
output:
  max_bytes: 1024
`)
	t.Setenv("AGENTSSH_HOME", home)
	t.Setenv("AGENTSSH_SESSION", "s_test")
	withFakeExecutor(t, fakeExecutor{})

	payload := strings.Repeat("x", 3*cmdEchoMaxBytes)
	fullCmd := "echo " + payload
	code, stdout, stderr := runExit(t, "run", "web-1", "--json", "--", "echo", payload)
	if code != exitOK {
		t.Fatalf("exit=%d stderr=%s", code, stderr)
	}
	var response runResponse
	if err := json.Unmarshal([]byte(stdout), &response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !response.CmdTruncated {
		t.Fatalf("cmd_truncated not set; cmd len=%d", len(response.Cmd))
	}
	if len(response.Cmd) > cmdEchoMaxBytes {
		t.Fatalf("cmd echo len=%d > cap %d", len(response.Cmd), cmdEchoMaxBytes)
	}
	sum := sha256.Sum256([]byte(fullCmd))
	if response.CmdSHA256 != hex.EncodeToString(sum[:]) {
		t.Fatalf("cmd_sha256=%q want hash of full command", response.CmdSHA256)
	}
	// The audit log keeps the full command; only the echo is truncated.
	records := mustReadAudit(t, home)
	var sawFull bool
	for _, record := range records {
		if record.Cmd == fullCmd {
			sawFull = true
		}
	}
	if !sawFull {
		t.Fatalf("audit log does not retain the full command")
	}
}

func TestRunJSONShortCmdNotTruncated(t *testing.T) {
	setupHome(t)
	withFakeExecutor(t, fakeExecutor{})
	code, stdout, stderr := runExit(t, "run", "web-1", "--json", "--", "echo", "hi")
	if code != exitOK {
		t.Fatalf("exit=%d stderr=%s", code, stderr)
	}
	var response runResponse
	if err := json.Unmarshal([]byte(stdout), &response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if response.Cmd != "echo hi" || response.CmdTruncated {
		t.Fatalf("short cmd echo mangled: %#v", response)
	}
	if response.CmdSHA256 == "" {
		t.Fatalf("cmd_sha256 missing")
	}
}

func TestRunFieldsProjection(t *testing.T) {
	setupHome(t)
	withFakeExecutor(t, fakeExecutor{})
	code, stdout, stderr := runExit(t, "run", "web-1", "--fields", "req_id,status,exit_code", "--", "echo", "hi")
	if code != exitOK {
		t.Fatalf("exit=%d stderr=%s", code, stderr)
	}
	var row map[string]any
	if err := json.Unmarshal([]byte(stdout), &row); err != nil {
		t.Fatalf("decode projected response: %v\n%s", err, stdout)
	}
	if len(row) != 3 {
		t.Fatalf("projection has %d keys, want 3: %#v", len(row), row)
	}
	for _, key := range []string{"req_id", "status", "exit_code"} {
		if _, ok := row[key]; !ok {
			t.Fatalf("projection missing %q: %#v", key, row)
		}
	}
	if row["status"] != "completed" {
		t.Fatalf("status=%v", row["status"])
	}
}

func TestRunFieldsRejectsUnknownName(t *testing.T) {
	setupHome(t)
	var calls int32
	withFakeExecutor(t, fakeExecutor{calls: &calls})
	_, _, err := runCommandForTest(t, "run", "web-1", "--fields", "bogus", "--", "echo", "hi")
	if exitCodeForError(err) != exitUsage {
		t.Fatalf("exit=%d want usage error", exitCodeForError(err))
	}
	if err == nil || !strings.Contains(err.Error(), "unknown --fields name") {
		t.Fatalf("err=%v", err)
	}
	if atomic.LoadInt32(&calls) != 0 {
		t.Fatalf("executor ran despite invalid --fields")
	}
}

// TestOnceGrantTwoPhaseE2E covers the "approved but wasted" fix: a once
// approval must survive a transport-level failure (the command never executed)
// and be consumed only when the command actually reaches the remote.
func TestOnceGrantTwoPhaseE2E(t *testing.T) {
	home := t.TempDir()
	writeTestInventory(t, home)
	writePolicy(t, home, `
version: 1
approval:
  enabled: true
  host_grant_mode: safe-prefix
output:
  max_bytes: 1024
`)
	t.Setenv("AGENTSSH_HOME", home)
	t.Setenv("AGENTSSH_SESSION", "s_test")

	withFakeExecutor(t, fakeExecutor{})
	code, stdout, _ := runExit(t, "run", "web-1", "--json", "--", "systemctl", "restart", "nginx")
	if code != exitApprovalRequired {
		t.Fatalf("initial run exit=%d want 7", code)
	}
	var pending runResponse
	if err := json.Unmarshal([]byte(stdout), &pending); err != nil {
		t.Fatalf("decode pending: %v", err)
	}

	withOperatorAuth(t, home)
	if _, _, err := runCommandForTest(t, "approval", "grant", pending.ApprovalID, "--once"); err != nil {
		t.Fatalf("approval grant --once: %v", err)
	}

	// Transport failure: the remote never ran the command, so the once
	// approval must be released for a clean re-run.
	withFakeExecutor(t, fakeExecutor{exitCode: 255})
	if code, _, _ := runExit(t, "run", "web-1", "--json", "--", "systemctl", "restart", "nginx"); code != exitSSHError {
		t.Fatalf("transport-failure run exit=%d want 9", code)
	}

	// Re-run succeeds on the same once approval (no new approval request).
	var calls int32
	withFakeExecutor(t, fakeExecutor{calls: &calls})
	if code, _, stderr := runExit(t, "run", "web-1", "--json", "--", "systemctl", "restart", "nginx"); code != exitOK {
		t.Fatalf("re-run exit=%d stderr=%s", code, stderr)
	}
	if atomic.LoadInt32(&calls) != 1 {
		t.Fatalf("executor calls=%d want 1", calls)
	}

	// The successful run consumed the grant: the next identical run needs a
	// fresh approval.
	if code, _, _ := runExit(t, "run", "web-1", "--json", "--", "systemctl", "restart", "nginx"); code != exitApprovalRequired {
		t.Fatalf("post-consumption run exit=%d want 7", code)
	}
	if atomic.LoadInt32(&calls) != 1 {
		t.Fatalf("executor ran after grant was consumed: calls=%d", calls)
	}
}
