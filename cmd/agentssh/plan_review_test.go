package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Praeviso/AgentSSH/internal/approval"
	"github.com/Praeviso/AgentSSH/internal/audit"
	"github.com/Praeviso/AgentSSH/internal/config"
	"github.com/Praeviso/AgentSSH/internal/payload"
)

func TestPlanSubmitInspectFullReviewDoesNotMutatePending(t *testing.T) {
	home := setupPlanHome(t)
	withFakeExecutor(t, fakeExecutor{})
	planPath := filepath.Join(t.TempDir(), "plan.yaml")
	if err := os.WriteFile(planPath, []byte(`
version: 1
metadata:
  title: deploy api
  impact: restart nginx
  recovery: rollback service
commands:
  - id: preflight
    name: Preflight
    cmd: echo ok
  - id: restart
    name: Restart nginx
    cmd: systemctl restart nginx
`), 0o600); err != nil {
		t.Fatal(err)
	}
	code, stdout, stderr := runExit(t, "plan", "submit", "web-1", "--json", "--file", planPath)
	if code != exitApprovalRequired {
		t.Fatalf("submit exit=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	var response planSubmitResponse
	if err := json.Unmarshal([]byte(stdout), &response); err != nil {
		t.Fatalf("decode submit: %v", err)
	}
	if response.PlanID == "" || response.ReviewSHA256 == "" || response.Allowed != 1 || response.Pending != 1 {
		t.Fatalf("response=%+v", response)
	}
	store := approvalStore(config.NewPaths(home))
	manifest, err := store.GetPlan(response.PlanID)
	if err != nil {
		t.Fatalf("get plan: %v", err)
	}
	if manifest.Review == nil || len(manifest.Review.Steps) != 2 {
		t.Fatalf("manifest review=%+v", manifest.Review)
	}
	if manifest.Review.Steps[0].Status != "allowed" || !manifest.Review.Steps[0].AlreadyAuthorized {
		t.Fatalf("allowed step=%+v", manifest.Review.Steps[0])
	}
	req, err := store.Get(response.Commands[1].ApprovalID)
	if err != nil {
		t.Fatalf("get request: %v", err)
	}
	data, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "review_sha256") {
		t.Fatalf("pending request was mutated with review digest: %s", data)
	}
	code, inspect, stderr := runExit(t, "plan", "inspect", response.PlanID)
	if code != exitOK {
		t.Fatalf("inspect exit=%d stderr=%s", code, stderr)
	}
	for _, want := range []string{"deploy api", "preflight", "allowed", "restart", response.ReviewSHA256} {
		if !strings.Contains(inspect, want) {
			t.Fatalf("inspect missing %q:\n%s", want, inspect)
		}
	}
}

func TestPlanSubmitPayloadRefRevalidatesAndBindsIdentity(t *testing.T) {
	home := setupPlanHome(t)
	withFakeExecutor(t, fakeExecutor{})
	paths := config.NewPaths(home)
	content := []byte("retained config")
	ref, err := planPayloadStore(paths).Put(content, payload.PutOptions{RetainFor: time.Hour})
	if err != nil {
		t.Fatalf("put payload: %v", err)
	}
	planPath := filepath.Join(t.TempDir(), "plan.yaml")
	if err := os.WriteFile(planPath, []byte("version: 1\ncommands:\n  - id: write\n    cmd: tee /etc/app.conf\n    payload_ref: "+ref.String()+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, stdout, stderr := runExit(t, "plan", "submit", "web-1", "--json", "--file", planPath)
	if code != exitApprovalRequired {
		t.Fatalf("submit exit=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	var response planSubmitResponse
	if err := json.Unmarshal([]byte(stdout), &response); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(content)
	wantSHA := hex.EncodeToString(sum[:])
	if response.Commands[0].StdinSHA256 != wantSHA || response.Commands[0].StdinBytes != int64(len(content)) {
		t.Fatalf("stdin identity=%s/%d want %s/%d", response.Commands[0].StdinSHA256, response.Commands[0].StdinBytes, wantSHA, len(content))
	}
	manifest, err := approvalStore(paths).GetPlan(response.PlanID)
	if err != nil {
		t.Fatal(err)
	}
	if manifest.Review == nil || !manifest.Review.Steps[0].PayloadRetained || manifest.Review.Steps[0].PayloadRef != ref.String() {
		t.Fatalf("review payload state=%+v", manifest.Review)
	}
}

func TestPlanSubmitRejectsMissingPayloadRefWithoutArtifacts(t *testing.T) {
	home := setupPlanHome(t)
	withFakeExecutor(t, fakeExecutor{})
	planPath := filepath.Join(t.TempDir(), "plan.yaml")
	missing := "sha256:" + strings.Repeat("a", 64) + ":1"
	if err := os.WriteFile(planPath, []byte("version: 1\ncommands:\n  - id: write\n    cmd: tee /etc/app.conf\n    payload_ref: "+missing+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, _, err := runCommandForTest(t, "plan", "submit", "web-1", "--file", planPath)
	if exitCodeForError(err) != exitUsage {
		t.Fatalf("err=%v", err)
	}
	assertPlanArtifactsEmpty(t, home)
}

func TestPlanSubmitSavePayloadPinsPendingAndGrantReleases(t *testing.T) {
	home := setupPlanHome(t)
	withFakeExecutor(t, fakeExecutor{})
	content := "pending payload"
	stdinPath := writeStdinFile(t, content)
	planPath := filepath.Join(t.TempDir(), "plan.yaml")
	if err := os.WriteFile(planPath, []byte("version: 1\ncommands:\n  - id: write\n    cmd: tee /etc/app.conf\n    stdin_file: "+stdinPath+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, stdout, stderr := runExit(t, "plan", "submit", "web-1", "--json", "--file", planPath, "--save-payloads", "--payload-ttl", "1h")
	if code != exitApprovalRequired {
		t.Fatalf("submit exit=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	var response planSubmitResponse
	if err := json.Unmarshal([]byte(stdout), &response); err != nil {
		t.Fatal(err)
	}
	items, err := planPayloadStore(config.NewPaths(home)).List()
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 || len(items[0].Pins) != 1 || items[0].Pins[0] != response.PlanID {
		t.Fatalf("payload pins=%+v want plan pin %s", items, response.PlanID)
	}
	withOperatorAuth(t, home)
	if _, _, err := runCommandForTest(t, "plan", "grant", response.PlanID, "--session"); err != nil {
		t.Fatalf("grant: %v", err)
	}
	items, err = planPayloadStore(config.NewPaths(home)).List()
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 || len(items[0].Pins) != 0 {
		t.Fatalf("grant did not release plan pin: %+v", items)
	}
}

func TestPlanSubmitSavePayloadNoPendingReleasesPin(t *testing.T) {
	home := setupPlanHome(t)
	withFakeExecutor(t, fakeExecutor{})
	stdinPath := writeStdinFile(t, "allowed payload")
	planPath := filepath.Join(t.TempDir(), "plan.yaml")
	if err := os.WriteFile(planPath, []byte("version: 1\ncommands:\n  - id: allowed\n    cmd: echo ok\n    stdin_file: "+stdinPath+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, stdout, stderr := runExit(t, "plan", "submit", "web-1", "--json", "--file", planPath, "--save-payloads", "--payload-ttl", "1h")
	if code != exitOK {
		t.Fatalf("submit exit=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	items, err := planPayloadStore(config.NewPaths(home)).List()
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 || len(items[0].Pins) != 0 {
		t.Fatalf("no-pending submit kept plan pins: %+v", items)
	}
}

func TestPlanSubmitSavePayloadPartialFailureReleasesEarlierPins(t *testing.T) {
	home := setupPlanHome(t)
	withFakeExecutor(t, fakeExecutor{})
	paths := config.NewPaths(home)
	firstPath := writeStdinFile(t, "first payload")
	secondPath := writeStdinFile(t, "second payload")
	secondSum := sha256.Sum256([]byte("second payload"))
	secondSHA := hex.EncodeToString(secondSum[:])
	if err := os.MkdirAll(filepath.Join(paths.PayloadsDir, "objects", secondSHA), 0o700); err != nil {
		t.Fatal(err)
	}
	planPath := filepath.Join(t.TempDir(), "plan.yaml")
	if err := os.WriteFile(planPath, []byte("version: 1\ncommands:\n  - id: first\n    cmd: tee /etc/one\n    stdin_file: "+firstPath+"\n  - id: second\n    cmd: tee /etc/two\n    stdin_file: "+secondPath+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, _, err := runCommandForTest(t, "plan", "submit", "web-1", "--file", planPath, "--save-payloads", "--payload-ttl", "1h")
	if err == nil {
		t.Fatalf("submit unexpectedly succeeded")
	}
	items, listErr := planPayloadStore(paths).List()
	if listErr != nil {
		t.Fatal(listErr)
	}
	for _, item := range items {
		if len(item.Pins) != 0 {
			t.Fatalf("partial failure leaked payload pins: %+v", items)
		}
	}
}

func TestPlanPayloadGCReleasesTerminalPlanPins(t *testing.T) {
	home := setupPlanHome(t)
	withFakeExecutor(t, fakeExecutor{})
	stdinPath := writeStdinFile(t, "expired pending payload")
	planPath := filepath.Join(t.TempDir(), "plan.yaml")
	if err := os.WriteFile(planPath, []byte("version: 1\ncommands:\n  - id: write\n    cmd: tee /etc/app.conf\n    stdin_file: "+stdinPath+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, stdout, stderr := runExit(t, "plan", "submit", "web-1", "--json", "--file", planPath, "--save-payloads", "--payload-ttl", "1ns")
	if code != exitApprovalRequired {
		t.Fatalf("submit exit=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	var response planSubmitResponse
	if err := json.Unmarshal([]byte(stdout), &response); err != nil {
		t.Fatal(err)
	}
	paths := config.NewPaths(home)
	if _, err := approval.ApplyPlanDecision(approval.ApplyOptions{
		Pending:  approvalStore(paths),
		Sessions: approval.SessionStore{Dir: paths.SessionsDir},
		Audit:    audit.NewStore(paths.AuditFile),
	}, response.PlanID, approval.VerdictApproved, approval.ScopeSession); err != nil {
		t.Fatalf("apply plan decision: %v", err)
	}
	items, err := planPayloadStore(paths).List()
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 || len(items[0].Pins) != 1 || items[0].Pins[0] != response.PlanID {
		t.Fatalf("test setup did not leave stale plan pin: %+v", items)
	}
	code, stdout, stderr = runExit(t, "plan", "payload", "gc", "--json")
	if code != exitOK {
		t.Fatalf("gc exit=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	items, err = planPayloadStore(paths).List()
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 0 {
		t.Fatalf("gc did not release terminal plan pin and remove expired payload: %+v", items)
	}
}
