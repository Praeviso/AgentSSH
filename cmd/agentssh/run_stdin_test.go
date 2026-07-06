package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Praeviso/AgentSSH/internal/audit"
	"github.com/Praeviso/AgentSSH/internal/config"
	"github.com/Praeviso/AgentSSH/internal/executor"
)

// stdinCaptureExecutor records the stdin payload each Run request carried.
type stdinCaptureExecutor struct {
	captured *[][]byte
}

func (e stdinCaptureExecutor) Run(_ context.Context, request executor.Request) executor.Result {
	if e.captured != nil {
		*e.captured = append(*e.captured, append([]byte(nil), request.Stdin...))
	}
	return executor.Result{Stdout: "ok\n", Argv: []string{"ssh", request.Target.Name, request.Command}}
}

func (e stdinCaptureExecutor) RunStreaming(_ context.Context, request executor.Request, stdout io.Writer, _ io.Writer) executor.Result {
	if e.captured != nil {
		*e.captured = append(*e.captured, append([]byte(nil), request.Stdin...))
	}
	_, _ = stdout.Write([]byte("ok\n"))
	return executor.Result{Argv: []string{"ssh", request.Target.Name, request.Command}}
}

func (e stdinCaptureExecutor) Close() error { return nil }

func writeStdinFile(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "payload.conf")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write stdin file: %v", err)
	}
	return path
}

func withCaptureExecutor(t *testing.T, captured *[][]byte) {
	t.Helper()
	restore := newExecutor
	newExecutor = func(_ *config.Config) executor.Executor { return stdinCaptureExecutor{captured: captured} }
	t.Cleanup(func() { newExecutor = restore })
}

func TestRunStdinFileAllowedRuleFeedsExecutorAndAudits(t *testing.T) {
	home := t.TempDir()
	writeTestInventory(t, home)
	writePolicy(t, home, `
version: 1
rules:
  - name: allow-cat
    priority: 0
    match: { cmd_regex: '^cat\b' }
    action: allow
output:
  max_bytes: 1024
`)
	t.Setenv("AGENTSSH_HOME", home)
	t.Setenv("AGENTSSH_SESSION", "s_test")

	content := "server {\n  listen 80;\n}\n"
	path := writeStdinFile(t, content)
	var captured [][]byte
	withCaptureExecutor(t, &captured)

	code, stdout, stderr := runExit(t, "run", "web-1", "--json", "--stdin-file", path, "--", "cat")
	if code != exitOK {
		t.Fatalf("exit=%d stderr=%s", code, stderr)
	}
	if len(captured) != 1 || string(captured[0]) != content {
		t.Fatalf("executor stdin=%q want %q", captured, content)
	}

	sum := sha256.Sum256([]byte(content))
	wantSHA := hex.EncodeToString(sum[:])
	var response runResponse
	if err := json.Unmarshal([]byte(stdout), &response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if response.StdinSHA256 != wantSHA || response.StdinBytes != int64(len(content)) {
		t.Fatalf("response stdin identity = %q/%d", response.StdinSHA256, response.StdinBytes)
	}

	records := mustReadAudit(t, home)
	var stamped int
	for _, record := range records {
		if record.StdinSHA256 == wantSHA && record.StdinBytes == int64(len(content)) {
			stamped++
		}
	}
	if stamped == 0 {
		t.Fatalf("no audit record carries the stdin hash: %#v", records)
	}
	verify, err := audit.NewStore(filepath.Join(home, "audit.log")).Verify()
	if err != nil || !verify.OK {
		t.Fatalf("audit chain broken after stdin records: %+v err=%v", verify, err)
	}
}

func TestRunStdinFileApprovalBindsContent(t *testing.T) {
	home := t.TempDir()
	writeTestInventory(t, home)
	writePolicy(t, home, `
version: 1
approval:
  enabled: true
  host_grant_mode: prefix
output:
  max_bytes: 1024
`)
	t.Setenv("AGENTSSH_HOME", home)
	t.Setenv("AGENTSSH_SESSION", "s_test")

	path := writeStdinFile(t, "v1 content")
	var captured [][]byte
	withCaptureExecutor(t, &captured)

	code, stdout, _ := runExit(t, "run", "web-1", "--json", "--stdin-file", path, "--", "tee", "/etc/app.conf")
	if code != exitApprovalRequired {
		t.Fatalf("initial run exit=%d want 7", code)
	}
	var pending runResponse
	if err := json.Unmarshal([]byte(stdout), &pending); err != nil {
		t.Fatalf("decode pending: %v", err)
	}
	// Even under the permissive prefix mode, a stdin request must stay exact
	// and must not offer host scope.
	for _, scope := range pending.ProposedScopes {
		if scope == "host" {
			t.Fatalf("stdin approval offered host scope: %v", pending.ProposedScopes)
		}
	}
	if pending.StdinSHA256 == "" || pending.StdinBytes == 0 {
		t.Fatalf("pending response missing stdin identity: %#v", pending)
	}

	withOperatorAuth(t, home)
	if _, _, err := runCommandForTest(t, "approval", "grant", pending.ApprovalID, "--session"); err != nil {
		t.Fatalf("approval grant: %v", err)
	}

	// Same command + same content executes.
	if code, _, stderr := runExit(t, "run", "web-1", "--json", "--stdin-file", path, "--", "tee", "/etc/app.conf"); code != exitOK {
		t.Fatalf("approved rerun exit=%d stderr=%s", code, stderr)
	}
	if len(captured) != 1 || string(captured[0]) != "v1 content" {
		t.Fatalf("executor stdin=%q", captured)
	}

	// Same command with different content must NOT ride the grant.
	otherPath := writeStdinFile(t, "v2 content — changed")
	if code, _, _ := runExit(t, "run", "web-1", "--json", "--stdin-file", otherPath, "--", "tee", "/etc/app.conf"); code != exitApprovalRequired {
		t.Fatalf("changed-content run exit=%d want 7", code)
	}
	// Same command with NO stdin must not ride the grant either.
	if code, _, _ := runExit(t, "run", "web-1", "--json", "--", "tee", "/etc/app.conf"); code != exitApprovalRequired {
		t.Fatalf("no-stdin run exit=%d want 7", code)
	}
	if len(captured) != 1 {
		t.Fatalf("executor ran for unapproved stdin variants: %d calls", len(captured))
	}

	// The grant approved with stdin must not be granted to a host rule either:
	// verify the stored request rejects host scope outright.
	if _, _, err := runCommandForTest(t, "approval", "grant", pending.ApprovalID, "--host"); err == nil {
		t.Fatalf("host grant of a stdin approval unexpectedly succeeded")
	}
}

func TestRunStdinFileTooLargeIsUsageError(t *testing.T) {
	setupHome(t)
	withFakeExecutor(t, fakeExecutor{})
	path := filepath.Join(t.TempDir(), "big.bin")
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Truncate(maxStdinBytes + 1); err != nil {
		t.Fatal(err)
	}
	_ = file.Close()
	_, _, cmdErr := runCommandForTest(t, "run", "web-1", "--stdin-file", path, "--", "echo", "hi")
	if exitCodeForError(cmdErr) != exitUsage {
		t.Fatalf("exit=%d want usage", exitCodeForError(cmdErr))
	}
	if cmdErr == nil || !strings.Contains(cmdErr.Error(), "limit") {
		t.Fatalf("err=%v", cmdErr)
	}
}
