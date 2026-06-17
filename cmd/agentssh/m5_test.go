package main

import (
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/Kritoooo/agentssh/internal/audit"
	"github.com/Kritoooo/agentssh/internal/config"
	"github.com/Kritoooo/agentssh/internal/executor"
	"github.com/Kritoooo/agentssh/internal/inventory"
)

// setupHome creates a temp $AGENTSSH_HOME with a valid inventory + policy and a
// fixed session id, returning the home path.
func setupHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	writeTestInventory(t, home)
	writeTestPolicy(t, home)
	t.Setenv("AGENTSSH_HOME", home)
	t.Setenv("AGENTSSH_SESSION", "s_test")
	return home
}

func withFakeExecutor(t *testing.T, fe fakeExecutor) {
	t.Helper()
	restore := newExecutor
	newExecutor = func(_ *config.Config) executor.Executor { return fe }
	t.Cleanup(func() { newExecutor = restore })
}

// runExit runs the root command with args and returns the mapped process exit
// code (via the same exitCodeForError that execute() uses) plus stdout/stderr.
func runExit(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	stdout, stderr, err := runCommandForTest(t, args...)
	return exitCodeForError(err), stdout, stderr
}

// ---- exit-code mapping end-to-end (DESIGN §A.5) ----

func TestExitCodeMatrix(t *testing.T) {
	t.Run("success=0", func(t *testing.T) {
		setupHome(t)
		withFakeExecutor(t, fakeExecutor{})
		if code, _, errOut := runExit(t, "run", "web-1", "--", "echo", "hi"); code != exitOK {
			t.Fatalf("code=%d want 0 (stderr=%q)", code, errOut)
		}
	})
	t.Run("remote-nonzero=1", func(t *testing.T) {
		setupHome(t)
		withFakeExecutor(t, fakeExecutor{exitCode: 3})
		if code, _, _ := runExit(t, "run", "web-1", "--", "false"); code != exitRemoteFailed {
			t.Fatalf("code=%d want 1", code)
		}
	})
	t.Run("policy-deny=6", func(t *testing.T) {
		setupHome(t)
		var calls int32
		withFakeExecutor(t, fakeExecutor{calls: &calls})
		if code, _, _ := runExit(t, "run", "web-1", "--", "rm", "-rf", "/"); code != exitPolicyDenied {
			t.Fatalf("code=%d want 6", code)
		}
		if atomic.LoadInt32(&calls) != 0 {
			t.Fatalf("executor ran despite deny: calls=%d", calls)
		}
	})
	t.Run("ssh-error-255=9", func(t *testing.T) {
		setupHome(t)
		withFakeExecutor(t, fakeExecutor{exitCode: 255})
		if code, _, _ := runExit(t, "run", "web-1", "--", "uptime"); code != exitSSHError {
			t.Fatalf("code=%d want 9", code)
		}
	})
	t.Run("usage-missing-dashdash=2", func(t *testing.T) {
		setupHome(t)
		if code, _, _ := runExit(t, "run", "web-1"); code != exitUsage {
			t.Fatalf("code=%d want 2", code)
		}
	})
	t.Run("usage-unknown-command=2", func(t *testing.T) {
		if code, _, _ := runExit(t, "boguscmd"); code != exitUsage {
			t.Fatalf("code=%d want 2", code)
		}
	})
	t.Run("usage-unknown-flag=2", func(t *testing.T) {
		setupHome(t)
		if code, _, _ := runExit(t, "hosts", "--nope"); code != exitUsage {
			t.Fatalf("code=%d want 2", code)
		}
	})
	t.Run("usage-extra-args=2", func(t *testing.T) {
		setupHome(t)
		if code, _, _ := runExit(t, "hosts", "extra"); code != exitUsage {
			t.Fatalf("code=%d want 2", code)
		}
	})
	t.Run("usage-invalid-status=2", func(t *testing.T) {
		setupHome(t)
		if code, _, _ := runExit(t, "audit", "ls", "--status", "bogus"); code != exitUsage {
			t.Fatalf("code=%d want 2", code)
		}
	})
	t.Run("usage-missing-home=2", func(t *testing.T) {
		t.Setenv("AGENTSSH_HOME", filepath.Join(t.TempDir(), "does-not-exist"))
		if code, _, _ := runExit(t, "hosts"); code != exitUsage {
			t.Fatalf("code=%d want 2", code)
		}
	})
	t.Run("usage-malformed-config=2", func(t *testing.T) {
		home := t.TempDir()
		t.Setenv("AGENTSSH_HOME", home)
		if err := os.WriteFile(filepath.Join(home, "inventory.yaml"), []byte("::: not: yaml: ["), 0o600); err != nil {
			t.Fatal(err)
		}
		// The usageError message is carried on the returned error (execute()
		// prints it to stderr in production); assert on the error here.
		_, _, err := runCommandForTest(t, "hosts")
		if exitCodeForError(err) != exitUsage {
			t.Fatalf("code=%d want 2", exitCodeForError(err))
		}
		if err == nil || !strings.Contains(err.Error(), "failed to parse") {
			t.Fatalf("expected parse guidance in error, got %v", err)
		}
	})
}

// ---- PRD §10 acceptance criteria ----

// S1: the agent completes a multi-step flow with zero credentials. Real SSH auth
// is out of CI scope; asserted at the seam: agent-facing output is credential-free
// and the executor is driven without any credential ever reaching the agent.
func TestS1ZeroCredentialFlow(t *testing.T) {
	home := setupHome(t)
	var calls int32
	withFakeExecutor(t, fakeExecutor{calls: &calls})

	out, _, err := runCommandForTest(t, "hosts")
	if err != nil {
		t.Fatalf("hosts: %v", err)
	}
	if !strings.Contains(out, "web-1") {
		t.Fatalf("hosts should list web-1: %q", out)
	}
	// No address or username from ANY inventory host may cross to the agent.
	secrets := []string{"10.0.0.11", "10.0.0.12", "deploy"}
	for _, secret := range secrets {
		if strings.Contains(out, secret) {
			t.Fatalf("hosts leaked credential/addr %q: %q", secret, out)
		}
	}
	jout, _, err := runCommandForTest(t, "hosts", "--json")
	if err != nil {
		t.Fatalf("hosts --json: %v", err)
	}
	for _, secret := range secrets {
		if strings.Contains(jout, secret) {
			t.Fatalf("hosts --json leaked %q: %q", secret, jout)
		}
	}

	// U1: status then restart, in one session.
	if _, _, err := runCommandForTest(t, "run", "web-1", "--skill", "restart-service", "--", "systemctl", "status", "nginx"); err != nil {
		t.Fatalf("status step: %v", err)
	}
	if _, _, err := runCommandForTest(t, "run", "web-1", "--skill", "restart-service", "--", "sudo", "systemctl", "restart", "nginx"); err != nil {
		t.Fatalf("restart step: %v", err)
	}
	if atomic.LoadInt32(&calls) != 2 {
		t.Fatalf("executor calls=%d want 2", calls)
	}
	records := mustReadAudit(t, home)
	if len(records) == 0 {
		t.Fatal("no audit records for the flow")
	}
	for _, r := range records {
		if r.SessionID != "s_test" {
			t.Fatalf("record outside session: %#v", r)
		}
	}
}

// S2: a denied command never executes and cannot be overridden in the moment —
// no accepted flag flips a deny, and no smuggled flag bypasses it.
func TestS2DenyUnoverridable(t *testing.T) {
	// (a) every ACCEPTED flag (and combos) still denies and never executes.
	flagSets := [][]string{
		nil,
		{"--skill", "restart-service"},
		{"--session", "s_x"},
		{"--session-label", "urgent"},
		{"--json"},
		{"--skill", "restart-service", "--json"},
	}
	for _, fs := range flagSets {
		setupHome(t)
		var calls int32
		withFakeExecutor(t, fakeExecutor{calls: &calls})
		args := append(append([]string{"run", "web-1"}, fs...), "--", "rm", "-rf", "/")
		code, _, _ := runExit(t, args...)
		if code != exitPolicyDenied {
			t.Fatalf("flags %v: exit=%d want 6 (deny)", fs, code)
		}
		if atomic.LoadInt32(&calls) != 0 {
			t.Fatalf("flags %v: executor ran despite deny", fs)
		}
	}

	// (b) an invented bypass flag is rejected (usage error), still never runs.
	setupHome(t)
	var calls int32
	withFakeExecutor(t, fakeExecutor{calls: &calls})
	code, _, _ := runExit(t, "run", "web-1", "--force", "--", "rm", "-rf", "/")
	if code != exitUsage {
		t.Fatalf("smuggled --force exit=%d want 2", code)
	}
	if atomic.LoadInt32(&calls) != 0 {
		t.Fatalf("executor ran on rejected flag")
	}
}

// S3: the audit chain is verifiable via the CLI and tampering is detected.
func TestS3AuditVerifyViaCLI(t *testing.T) {
	home := setupHome(t)
	withFakeExecutor(t, fakeExecutor{})
	if _, _, err := runCommandForTest(t, "run", "web-1", "--", "echo", "hi"); err != nil {
		t.Fatalf("seed run: %v", err)
	}

	out, _, err := runCommandForTest(t, "audit", "verify")
	if err != nil {
		t.Fatalf("verify err=%v", err)
	}
	if !strings.Contains(out, "audit chain ok") {
		t.Fatalf("verify out=%q", out)
	}

	path := filepath.Join(home, "audit.log")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(strings.Replace(string(data), "web-1", "evil-1", 1)), 0o600); err != nil {
		t.Fatal(err)
	}

	out, _, err = runCommandForTest(t, "audit", "verify")
	if exitCodeForError(err) != exitRemoteFailed {
		t.Fatalf("tampered verify exit=%d want 1", exitCodeForError(err))
	}
	if !strings.Contains(out, "audit chain broken") || !strings.Contains(out, "reason=hash") {
		t.Fatalf("tampered verify out=%q", out)
	}
}

// S5: a malicious command surfaced via a skill (prompt-injection model) is denied,
// not executed, and leaves a tamper-evident, queryable audit record with provenance.
func TestS5InjectionDeniedWithProvenance(t *testing.T) {
	home := setupHome(t)
	var calls int32
	withFakeExecutor(t, fakeExecutor{calls: &calls})

	code, _, stderr := runExit(t, "run", "web-1", "--skill", "restart-service", "--", "rm", "-rf", "/")
	if code != exitPolicyDenied {
		t.Fatalf("exit=%d want 6", code)
	}
	if atomic.LoadInt32(&calls) != 0 {
		t.Fatalf("executor ran on injected command: calls=%d", calls)
	}
	if !strings.Contains(stderr, "denied by policy") {
		t.Fatalf("stderr=%q", stderr)
	}

	records := mustReadAudit(t, home)
	if len(records) != 1 {
		t.Fatalf("want 1 deny record, got %d", len(records))
	}
	rec := records[0]
	if rec.Event != audit.EventDenied || !strings.Contains(rec.Cmd, "rm -rf /") || rec.Skill != "restart-service" {
		t.Fatalf("deny provenance wrong: %#v", rec)
	}

	if out, _, err := runCommandForTest(t, "audit", "verify"); err != nil || !strings.Contains(out, "audit chain ok") {
		t.Fatalf("deny record not in intact chain: err=%v out=%q", err, out)
	}
	sout, _, err := runCommandForTest(t, "status", rec.ReqID)
	if err != nil {
		t.Fatalf("status err=%v", err)
	}
	if !strings.Contains(sout, "denied") {
		t.Fatalf("status should report denied: %q", sout)
	}
	// Provenance survives to the queryable status path: the deny rule is shown.
	if !strings.Contains(sout, "catastrophic") {
		t.Fatalf("status should carry the policy rule provenance: %q", sout)
	}
}

// S4: a run is exactly one ssh invocation — nothing is uploaded/installed on the
// remote. Asserted at the executor seam (real SSH is out of CI scope); the
// fakeExecutor's argv is synthetic, so this exercises the real BuildSSHArgv.
func TestS4NoRemoteInstall(t *testing.T) {
	target := inventory.Target{
		Name: "web-1",
		Host: inventory.Host{Addr: "10.0.0.11", User: "deploy", Port: 22},
	}
	command := "systemctl status nginx"
	argv := executor.BuildSSHArgv(target, command)
	if len(argv) != 3 || argv[0] != "ssh" || argv[2] != command {
		t.Fatalf("expected a single [ssh target cmd] invocation, got %#v", argv)
	}
	for _, a := range argv {
		switch a {
		case "scp", "rsync", "sftp", "curl", "wget", "install", "bootstrap":
			t.Fatalf("argv contains a transfer/install verb: %#v", argv)
		}
	}
}

// Non-TTY tui must refuse and fall back to plain output (DESIGN §B.5). Under
// `go test` os.Stdin/os.Stdout are not terminals, so the guard fires.
func TestTUINonInteractiveFallback(t *testing.T) {
	// Force non-interactivity deterministically: tui.run() checks the real
	// os.Stdin/os.Stdout fds, so point them at /dev/null to guarantee the guard
	// fires (otherwise this would launch BubbleTea and hang under a real TTY).
	devnull, err := os.OpenFile(os.DevNull, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	origIn, origOut := os.Stdin, os.Stdout
	os.Stdin, os.Stdout = devnull, devnull
	t.Cleanup(func() {
		os.Stdin, os.Stdout = origIn, origOut
		_ = devnull.Close()
	})

	setupHome(t)
	withFakeExecutor(t, fakeExecutor{})
	if _, _, err := runCommandForTest(t, "run", "web-1", "--", "echo", "hi"); err != nil {
		t.Fatalf("seed run: %v", err)
	}
	out, errOut, err := runCommandForTest(t, "tui")
	if err != nil {
		t.Fatalf("tui should fall back without error under non-tty, got %v", err)
	}
	if !strings.Contains(errOut, "requires an interactive terminal") {
		t.Fatalf("missing fallback hint: %q", errOut)
	}
	if !strings.Contains(out, "s_test") {
		t.Fatalf("fallback should print session summary: %q", out)
	}
}
