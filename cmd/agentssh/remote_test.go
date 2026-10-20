package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Praeviso/AgentSSH/internal/managedmode"
)

// An enrolled home whose control plane cannot be reached (and has no cached
// bundle) must fail closed for agent-facing commands, while purely local state
// such as the audit log stays reviewable.
func TestRemoteModeFailsClosedButKeepsAuditReadable(t *testing.T) {
	home := setupHome(t)
	dir := managedmode.Dir(home)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	state := "server_url: https://127.0.0.1:1\ndevice_id: dev_test\nca_fingerprint: x\nbundle_public_key: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n"
	if err := os.WriteFile(filepath.Join(dir, managedmode.MarkerName), []byte(state), 0o600); err != nil {
		t.Fatal(err)
	}

	_, _, err := runCommandForTest(t, "hosts")
	if exitCodeForError(err) != exitUsage || err == nil || !strings.Contains(err.Error(), "remote configuration unavailable") {
		t.Fatalf("hosts err=%v, want exit 2 with a remote configuration error", err)
	}
	code, _, stderr := runExit(t, "run", "--session", "s_test", "web-1", "--", "uptime")
	if code != exitUsage {
		t.Fatalf("run exit=%d stderr=%q, want exit 2", code, stderr)
	}
	if code, _, stderr := runExit(t, "audit", "verify"); code != exitOK {
		t.Fatalf("audit verify exit=%d stderr=%q, want 0 while the control plane is down", code, stderr)
	}
	if code, _, stderr := runExit(t, "session", "ls"); code != exitOK {
		t.Fatalf("session ls exit=%d stderr=%q, want 0", code, stderr)
	}
}

func TestRemoteStatusRequiresEnrollment(t *testing.T) {
	setupHome(t)
	_, _, err := runCommandForTest(t, "remote", "status")
	if exitCodeForError(err) != exitUsage || err == nil || !strings.Contains(err.Error(), "not enrolled") {
		t.Fatalf("remote status err=%v, want exit 2 not enrolled", err)
	}
}

func TestRemoteEnrollRequiresTTY(t *testing.T) {
	setupHome(t)
	original := stdinIsTerminal
	stdinIsTerminal = func() bool { return false }
	t.Cleanup(func() { stdinIsTerminal = original })
	code, _, _ := runExit(t, "remote", "enroll", "https://127.0.0.1:1", "--token", "x")
	if code != exitUsage {
		t.Fatalf("remote enroll without a TTY exit=%d, want 2", code)
	}
}
