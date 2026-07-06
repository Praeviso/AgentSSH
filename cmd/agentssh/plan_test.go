package main

import (
	"encoding/json"
	"os"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/Praeviso/AgentSSH/internal/approval"
	"github.com/Praeviso/AgentSSH/internal/audit"
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
