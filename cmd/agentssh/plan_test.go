package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/Praeviso/AgentSSH/internal/approval"
	"github.com/Praeviso/AgentSSH/internal/audit"
	"github.com/Praeviso/AgentSSH/internal/config"
)

func setupPlanHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	writeTestInventory(t, home)
	writePolicy(t, home, `
version: 1
approval:
  enabled: true
  host_grant_mode: safe-prefix
rules:
  - name: catastrophic
    priority: 100
    match: { cmd_regex: 'rm\s+-rf' }
    action: deny
  - name: allow-echo
    priority: 0
    match: { cmd_regex: '^echo\b' }
    action: allow
output:
  max_bytes: 1024
`)
	t.Setenv("AGENTSSH_HOME", home)
	t.Setenv("AGENTSSH_SESSION", "s_test")
	return home
}

func TestPlanSubmitGrantRunE2E(t *testing.T) {
	home := setupPlanHome(t)
	var calls int32
	withFakeExecutor(t, fakeExecutor{calls: &calls})

	code, stdout, stderr := runExit(t, "plan", "submit", "web-1", "--json", "--",
		"echo preflight",
		"systemctl restart nginx",
		"docker compose -f /opt/app/compose.yml up -d")
	if code != exitApprovalRequired {
		t.Fatalf("submit exit=%d want 7 stdout=%s stderr=%s", code, stdout, stderr)
	}
	var response planSubmitResponse
	if err := json.Unmarshal([]byte(stdout), &response); err != nil {
		t.Fatalf("decode submit response: %v\n%s", err, stdout)
	}
	if response.PlanID == "" || response.Allowed != 1 || response.Pending != 2 || response.Denied != 0 {
		t.Fatalf("submit response = %+v", response)
	}
	if atomic.LoadInt32(&calls) != 0 {
		t.Fatalf("plan submit executed commands: calls=%d", calls)
	}

	// Status while pending: exit 7.
	if code, _, _ := runExit(t, "plan", "status", response.PlanID); code != exitApprovalRequired {
		t.Fatalf("pending plan status exit=%d want 7", code)
	}

	// One operator decision approves the whole batch for the session.
	withOperatorAuth(t, home)
	grantOut, _, err := runCommandForTest(t, "plan", "grant", response.PlanID, "--session")
	if err != nil {
		t.Fatalf("plan grant: %v", err)
	}
	if !strings.Contains(grantOut, "approved scope=session 2 command(s)") {
		t.Fatalf("grant stdout=%q", grantOut)
	}
	if code, _, _ := runExit(t, "plan", "status", response.PlanID); code != exitOK {
		t.Fatalf("approved plan status exit=%d want 0", code)
	}
	if code, _, _ := runExit(t, "plan", "wait", response.PlanID, "--timeout", "1ms"); code != exitOK {
		t.Fatalf("approved plan wait exit=%d want 0", code)
	}

	// Both gray commands now run without further approvals.
	if code, _, stderr := runExit(t, "run", "web-1", "--json", "--", "systemctl", "restart", "nginx"); code != exitOK {
		t.Fatalf("run 1 exit=%d stderr=%s", code, stderr)
	}
	if code, _, stderr := runExit(t, "run", "web-1", "--json", "--", "docker", "compose", "-f", "/opt/app/compose.yml", "up", "-d"); code != exitOK {
		t.Fatalf("run 2 exit=%d stderr=%s", code, stderr)
	}
	if atomic.LoadInt32(&calls) != 2 {
		t.Fatalf("executor calls=%d want 2", calls)
	}

	// Audit ties the batch together via plan_id on the approval lifecycle.
	records := mustReadAudit(t, home)
	var requested, granted int
	for _, record := range records {
		if record.PlanID != response.PlanID {
			continue
		}
		switch record.Event {
		case audit.EventApprovalRequested:
			requested++
			if record.ApprovalChannel != approval.ChannelPlan {
				t.Fatalf("requested channel=%q", record.ApprovalChannel)
			}
		case audit.EventApprovalGranted:
			granted++
		}
	}
	if requested != 2 || granted != 2 {
		t.Fatalf("plan audit requested=%d granted=%d want 2/2", requested, granted)
	}
	verify, err := audit.NewStore(home + "/audit.log").Verify()
	if err != nil || !verify.OK {
		t.Fatalf("audit chain broken: %+v err=%v", verify, err)
	}
}

func TestPlanSubmitReportsHardDenyLines(t *testing.T) {
	setupPlanHome(t)
	withFakeExecutor(t, fakeExecutor{})
	code, stdout, _ := runExit(t, "plan", "submit", "web-1", "--json", "--",
		"rm -rf /var/tmp/cache",
		"systemctl restart nginx")
	if code != exitPolicyDenied {
		t.Fatalf("submit exit=%d want 6 (deny dominates)", code)
	}
	var response planSubmitResponse
	if err := json.Unmarshal([]byte(stdout), &response); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if response.Denied != 1 || response.Pending != 1 {
		t.Fatalf("response=%+v", response)
	}
	if response.Commands[0].Status != "denied" || !strings.Contains(response.Commands[0].PolicyRule, "catastrophic") {
		t.Fatalf("denied line=%+v", response.Commands[0])
	}
}

func TestPlanDenyDeniesAllPending(t *testing.T) {
	home := setupPlanHome(t)
	withFakeExecutor(t, fakeExecutor{})
	_, stdout, _ := runExit(t, "plan", "submit", "web-1", "--json", "--", "systemctl restart nginx", "systemctl restart redis")
	var response planSubmitResponse
	if err := json.Unmarshal([]byte(stdout), &response); err != nil {
		t.Fatalf("decode: %v", err)
	}
	withOperatorAuth(t, home)
	if _, _, err := runCommandForTest(t, "plan", "deny", response.PlanID); err != nil {
		t.Fatalf("plan deny: %v", err)
	}
	if code, _, _ := runExit(t, "plan", "status", response.PlanID); code != exitPolicyDenied {
		t.Fatalf("denied plan status exit=%d want 6", code)
	}
}

func TestPlanSubmitFromFile(t *testing.T) {
	setupPlanHome(t)
	withFakeExecutor(t, fakeExecutor{})
	planFile := t.TempDir() + "/cmds.txt"
	content := "# deployment steps\nsystemctl restart nginx\n\nsystemctl restart redis\n"
	if err := os.WriteFile(planFile, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	code, stdout, _ := runExit(t, "plan", "submit", "web-1", "--json", "--file", planFile)
	if code != exitApprovalRequired {
		t.Fatalf("submit exit=%d want 7", code)
	}
	var response planSubmitResponse
	if err := json.Unmarshal([]byte(stdout), &response); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(response.Commands) != 2 || response.Pending != 2 {
		t.Fatalf("response=%+v", response)
	}
}

func TestStructuredPlanSubmitGrantRunStdinE2E(t *testing.T) {
	home := setupPlanHome(t)
	content := "server {\n  listen 8080;\n}\n"
	stdinPath := writeStdinFile(t, content)
	planPath := filepath.Join(t.TempDir(), "deploy.yaml")
	plan := fmt.Sprintf("version: 1\ncommands:\n  - cmd: tee /etc/nginx/nginx.conf\n    stdin_file: %s\n", stdinPath)
	if err := os.WriteFile(planPath, []byte(plan), 0o600); err != nil {
		t.Fatalf("write structured plan: %v", err)
	}

	var captured [][]byte
	withCaptureExecutor(t, &captured)
	code, stdout, stderr := runExit(t, "plan", "submit", "web-1", "--json", "--file", planPath)
	if code != exitApprovalRequired {
		t.Fatalf("submit exit=%d want 7 stdout=%s stderr=%s", code, stdout, stderr)
	}
	var response planSubmitResponse
	if err := json.Unmarshal([]byte(stdout), &response); err != nil {
		t.Fatalf("decode submit response: %v\n%s", err, stdout)
	}
	if response.PlanID == "" || response.Pending != 1 || len(response.Commands) != 1 {
		t.Fatalf("submit response=%+v", response)
	}
	if response.Commands[0].Cmd != "tee /etc/nginx/nginx.conf" {
		t.Fatalf("structured command=%q", response.Commands[0].Cmd)
	}
	sum := sha256.Sum256([]byte(content))
	wantSHA := hex.EncodeToString(sum[:])
	if response.Commands[0].StdinSHA256 != wantSHA || response.Commands[0].StdinBytes != int64(len(content)) {
		t.Fatalf("submit stdin identity=%q/%d want %q/%d", response.Commands[0].StdinSHA256, response.Commands[0].StdinBytes, wantSHA, len(content))
	}
	request, err := approvalStore(config.NewPaths(home)).Get(response.Commands[0].ApprovalID)
	if err != nil {
		t.Fatalf("read pending request: %v", err)
	}
	if request.StdinSHA256 == "" || request.StdinBytes != int64(len(content)) {
		t.Fatalf("pending stdin identity=%q/%d", request.StdinSHA256, request.StdinBytes)
	}
	if request.Candidate.Kind != approval.MatcherExact || request.Candidate.Promotable {
		t.Fatalf("stdin candidate=%+v want exact/non-promotable", request.Candidate)
	}
	for _, scope := range request.ProposedScopes {
		if scope == approval.ScopeHost {
			t.Fatalf("stdin request offered host scope: %v", request.ProposedScopes)
		}
	}
	if len(captured) != 0 {
		t.Fatalf("plan submit executed command: %#v", captured)
	}
	var requested int
	for _, record := range mustReadAudit(t, home) {
		if record.PlanID != response.PlanID || record.Event != audit.EventApprovalRequested {
			continue
		}
		requested++
		if record.StdinSHA256 != request.StdinSHA256 || record.StdinBytes != int64(len(content)) {
			t.Fatalf("approval audit stdin identity=%q/%d", record.StdinSHA256, record.StdinBytes)
		}
		if strings.Contains(record.Cmd, content) {
			t.Fatalf("stdin content leaked into audit command: %q", record.Cmd)
		}
	}
	if requested != 1 {
		t.Fatalf("approval_requested records=%d want 1", requested)
	}

	withOperatorAuth(t, home)
	if _, _, err := runCommandForTest(t, "plan", "grant", response.PlanID, "--session"); err != nil {
		t.Fatalf("plan grant: %v", err)
	}

	code, _, stderr = runExit(t, "run", "web-1", "--json", "--stdin-file", stdinPath, "--", "tee", "/etc/nginx/nginx.conf")
	if code != exitOK {
		t.Fatalf("approved run exit=%d stderr=%s", code, stderr)
	}
	if len(captured) != 1 || string(captured[0]) != content {
		t.Fatalf("executor stdin=%q want %q", captured, content)
	}

	otherPath := writeStdinFile(t, "server {\n  listen 9090;\n}\n")
	if code, _, _ := runExit(t, "run", "web-1", "--json", "--stdin-file", otherPath, "--", "tee", "/etc/nginx/nginx.conf"); code != exitApprovalRequired {
		t.Fatalf("changed-content run exit=%d want 7", code)
	}
	if code, _, _ := runExit(t, "run", "web-1", "--json", "--", "tee", "/etc/nginx/nginx.conf"); code != exitApprovalRequired {
		t.Fatalf("no-stdin run exit=%d want 7", code)
	}
	if len(captured) != 1 {
		t.Fatalf("executor ran unapproved stdin variants: %d calls", len(captured))
	}
	verify, err := audit.NewStore(filepath.Join(home, "audit.log")).Verify()
	if err != nil || !verify.OK {
		t.Fatalf("audit chain broken after structured stdin flow: %+v err=%v", verify, err)
	}
	if code, stdout, stderr := runExit(t, "audit", "verify"); code != exitOK || !strings.Contains(stdout, "audit chain ok") {
		t.Fatalf("audit verify exit=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
}

func assertPlanArtifactsEmpty(t *testing.T, home string) {
	t.Helper()
	paths := config.NewPaths(home)
	if pending, err := approvalStore(paths).List(); err != nil {
		t.Fatalf("list pending approvals: %v", err)
	} else if len(pending) != 0 {
		t.Fatalf("pending approvals left behind: %+v", pending)
	}
	entries, err := os.ReadDir(paths.PlansDir)
	if err != nil {
		if !os.IsNotExist(err) {
			t.Fatalf("read plans directory: %v", err)
		}
		return
	}
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".json") {
			t.Fatalf("plan manifest left behind: %s", entry.Name())
		}
	}
}

// A structured plan is rejected as a whole: every case here must exit with a
// usage error and leave no pending approval and no manifest behind.
func TestStructuredPlanUsageErrorsLeaveNoArtifacts(t *testing.T) {
	cases := []struct {
		name    string
		plan    func(t *testing.T) string
		wantErr string
	}{
		{
			name:    "syntax error after the version line never falls back to line mode",
			plan:    func(*testing.T) string { return "version: 1\ncommands: [\n" },
			wantErr: "structured",
		},
		{
			name: "syntax error in a trailing document never falls back to line mode",
			plan: func(*testing.T) string { return "version: 1\ncommands: []\n---\ncommands: [\n" },
		},
		{
			name:    "unsupported version",
			plan:    func(*testing.T) string { return "version: 2\ncommands:\n  - cmd: systemctl restart nginx\n" },
			wantErr: "version",
		},
		{
			name:    "multi-line block scalar command",
			plan:    func(*testing.T) string { return "version: 1\ncommands:\n  - cmd: |\n      echo one\n      echo two\n" },
			wantErr: "single line",
		},
		{
			name:    "two documents with real content",
			plan:    func(*testing.T) string { return "version: 1\ncommands: []\n---\nversion: 1\ncommands: []\n" },
			wantErr: "exactly one YAML document",
		},
		{
			name: "stdin_file missing on disk",
			plan: func(t *testing.T) string {
				return stdinPlanFile(writeStdinFile(t, "valid payload"), filepath.Join(t.TempDir(), "does-not-exist"))
			},
			wantErr: "commands[1].stdin_file",
		},
		{
			name: "stdin_file over the size cap",
			plan: func(t *testing.T) string {
				return stdinPlanFile(writeStdinFile(t, "valid payload"), writeOversizedFile(t))
			},
			// The broken path is the second command, and plan submit has no
			// --stdin-file flag to blame.
			wantErr: "commands[1].stdin_file",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			home := setupPlanHome(t)
			withFakeExecutor(t, fakeExecutor{})
			path := filepath.Join(t.TempDir(), "plan.yaml")
			if err := os.WriteFile(path, []byte(tc.plan(t)), 0o600); err != nil {
				t.Fatal(err)
			}
			_, _, err := runCommandForTest(t, "plan", "submit", "web-1", "--file", path)
			if exitCodeForError(err) != exitUsage {
				t.Fatalf("exit=%d want usage; err=%v", exitCodeForError(err), err)
			}
			if tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)) {
				t.Fatalf("error=%v want %q diagnostic", err, tc.wantErr)
			}
			assertPlanArtifactsEmpty(t, home)
		})
	}
}

// stdinPlanFile builds a two-line structured plan; the second line is the one
// each caller breaks, so a failure proves the first line wrote nothing either.
func stdinPlanFile(first string, second string) string {
	return fmt.Sprintf("version: 1\ncommands:\n  - cmd: tee /etc/app.conf\n    stdin_file: %q\n  - cmd: tee /etc/other.conf\n    stdin_file: %q\n", first, second)
}

func writeOversizedFile(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "too-large.bin")
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	// Sparse: the size check rejects it before a single byte is read.
	if err := file.Truncate(maxStdinBytes + 1); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}

// Dispatch must survive the shapes a real operator writes: a leading document
// marker, keys in either order, a trailing '---'. Getting this wrong is silent
// -- the file falls back to line mode and every stdin_file binding is dropped.
func TestStructuredPlanDispatchAcceptsOperatorYAMLShapes(t *testing.T) {
	cases := []struct {
		name string
		plan string
	}{
		{"leading document marker", "---\nversion: 1\ncommands:\n  - cmd: systemctl restart nginx\n"},
		{"commands before version", "commands:\n  - cmd: systemctl restart nginx\nversion: 1\n"},
		{"trailing document marker", "version: 1\ncommands:\n  - cmd: systemctl restart nginx\n---\n"},
		{"leading comment", "# deploy\nversion: 1\ncommands:\n  - cmd: systemctl restart nginx\n"},
		{"block scalar command", "version: 1\ncommands:\n  - cmd: |\n      systemctl restart nginx\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			setupPlanHome(t)
			withFakeExecutor(t, fakeExecutor{})
			path := filepath.Join(t.TempDir(), "plan.yaml")
			if err := os.WriteFile(path, []byte(tc.plan), 0o600); err != nil {
				t.Fatal(err)
			}
			code, stdout, stderr := runExit(t, "plan", "submit", "web-1", "--json", "--file", path)
			if code != exitApprovalRequired {
				t.Fatalf("exit=%d want 7; stderr=%q", code, stderr)
			}
			var response planSubmitResponse
			if err := json.Unmarshal([]byte(stdout), &response); err != nil {
				t.Fatalf("decode submit response: %v", err)
			}
			// Line mode would have split the YAML into several bogus commands.
			if len(response.Commands) != 1 || response.Commands[0].Cmd != "systemctl restart nginx" {
				t.Fatalf("commands=%+v want one exact command", response.Commands)
			}
		})
	}
}

func TestStructuredPlanDuplicateCommandsHaveOneManifestMember(t *testing.T) {
	home := setupPlanHome(t)
	withFakeExecutor(t, fakeExecutor{})
	code, stdout, _ := runExit(t, "plan", "submit", "web-1", "--json", "--", "systemctl restart nginx", "systemctl restart nginx")
	if code != exitApprovalRequired {
		t.Fatalf("submit exit=%d want 7", code)
	}
	var response planSubmitResponse
	if err := json.Unmarshal([]byte(stdout), &response); err != nil {
		t.Fatalf("decode submit response: %v", err)
	}
	if response.PlanID == "" || len(response.Commands) != 2 || response.Commands[0].ApprovalID != response.Commands[1].ApprovalID {
		t.Fatalf("duplicate response=%+v", response)
	}
	manifest, err := approvalStore(config.NewPaths(home)).GetPlan(response.PlanID)
	if err != nil {
		t.Fatalf("read plan manifest: %v", err)
	}
	if len(manifest.MemberIDs) != 1 || manifest.MemberIDs[0] != response.Commands[0].ApprovalID {
		t.Fatalf("manifest members=%v want one %s", manifest.MemberIDs, response.Commands[0].ApprovalID)
	}
	status, err := approvalStore(config.NewPaths(home)).PlanStatus(response.PlanID)
	if err != nil {
		t.Fatalf("plan status: %v", err)
	}
	if status.Pending != 1 || len(status.Members) != 1 {
		t.Fatalf("status=%+v want one pending member", status)
	}
	// submit must not claim more approvals than plan status will ever show.
	if response.Pending != status.Pending {
		t.Fatalf("submit pending=%d status pending=%d; counts must agree", response.Pending, status.Pending)
	}
}

func TestPlanSubmitRequiresApprovalEnabled(t *testing.T) {
	setupHome(t) // approval disabled policy
	withFakeExecutor(t, fakeExecutor{})
	_, _, err := runCommandForTest(t, "plan", "submit", "web-1", "--", "systemctl restart nginx")
	if exitCodeForError(err) != exitUsage {
		t.Fatalf("exit=%d want usage", exitCodeForError(err))
	}
	if err == nil || !strings.Contains(err.Error(), "approval") {
		t.Fatalf("err=%v", err)
	}
}

func TestPlanGrantRequiresScope(t *testing.T) {
	home := setupPlanHome(t)
	withFakeExecutor(t, fakeExecutor{})
	_, stdout, _ := runExit(t, "plan", "submit", "web-1", "--json", "--", "systemctl restart nginx")
	var response planSubmitResponse
	if err := json.Unmarshal([]byte(stdout), &response); err != nil {
		t.Fatalf("decode: %v", err)
	}
	withOperatorAuth(t, home)
	_, _, err := runCommandForTest(t, "plan", "grant", response.PlanID)
	if exitCodeForError(err) != exitUsage || !strings.Contains(err.Error(), "--once or --session") {
		t.Fatalf("err=%v", err)
	}
}
