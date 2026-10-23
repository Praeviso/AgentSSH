package main

import (
	"bytes"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/Praeviso/AgentSSH/internal/approval"
	"github.com/Praeviso/AgentSSH/internal/audit"
	"github.com/Praeviso/AgentSSH/internal/gateway"
	"github.com/Praeviso/AgentSSH/internal/remote"
)

func TestServeRequiresExplicitPublicHTTPSBase(t *testing.T) {
	cmd := newRootCommand()
	cmd.SetArgs([]string{"serve"})
	if err := cmd.Execute(); err == nil || !strings.Contains(err.Error(), "--public-url") {
		t.Fatalf("serve: %v", err)
	}
}

func TestDeviceTokenCreateNamesGatewayMode(t *testing.T) {
	old := gateway.ScryptWorkFactor
	gateway.ScryptWorkFactor = 10
	t.Cleanup(func() { gateway.ScryptWorkFactor = old })
	dir := t.TempDir()
	if err := gateway.Init(dir, "master"); err != nil {
		t.Fatal(err)
	}
	cmd := newRootCommand()
	var stdout, stderr bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	cmd.SetArgs([]string{"--data", dir, "device", "token", "create", "--name", "agent-vm", "--public-url", "https://gw.example/agentssh"})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	token, err := remote.ParseEnrollToken(stdout.String())
	if err != nil || token.ServerURL != "https://gw.example/agentssh" {
		t.Fatalf("token: %+v %v", token, err)
	}
	if !strings.Contains(stderr.String(), "--mode gateway") || strings.Contains(stderr.String(), token.Secret) {
		t.Fatalf("enroll hint: %q", stderr.String())
	}
}

// The signing and bundle handlers live only in internal/remoteserver; the
// gateway binary must not link that package at all.
func TestGatewayDoesNotLinkManagedSigning(t *testing.T) {
	gobin, err := exec.LookPath("go")
	if err != nil {
		t.Skip("go toolchain not on PATH")
	}
	out, err := exec.Command(gobin, "list", "-deps", "-f", "{{.ImportPath}}", ".").CombinedOutput()
	if err != nil {
		t.Fatalf("go list: %v\n%s", err, out)
	}
	deps := strings.Fields(string(out))
	if !slices.Contains(deps, "github.com/Praeviso/AgentSSH/internal/gateway") {
		t.Fatalf("go list returned an unexpected graph: %v", deps)
	}
	if slices.Contains(deps, "github.com/Praeviso/AgentSSH/internal/remoteserver") {
		t.Fatal("agentssh-gateway depends on internal/remoteserver")
	}
}

func TestAuditVerifyOnFreshGateway(t *testing.T) {
	old := gateway.ScryptWorkFactor
	gateway.ScryptWorkFactor = 10
	t.Cleanup(func() { gateway.ScryptWorkFactor = old })
	dir := t.TempDir()
	if err := gateway.Init(dir, "master"); err != nil {
		t.Fatal(err)
	}
	cmd := newRootCommand()
	var stdout bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetArgs([]string{"--data", dir, "audit", "verify"})
	if err := cmd.Execute(); err != nil || stdout.String() != "audit chain ok · records=0\n" {
		t.Fatalf("audit verify: %q %v", stdout.String(), err)
	}
}

func runGatewayCLI(t *testing.T, args ...string) (string, error) {
	t.Helper()
	cmd := newRootCommand()
	var stdout bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs(args)
	err := cmd.Execute()
	return stdout.String(), err
}

// The gateway's operator reviews and decides devices' requests and plans from
// the data directory; host scope is refused before anything is resolved.
func TestApprovalAndPlanCommands(t *testing.T) {
	old := gateway.ScryptWorkFactor
	gateway.ScryptWorkFactor = 10
	t.Cleanup(func() { gateway.ScryptWorkFactor = old })
	dir := t.TempDir()
	if err := gateway.Init(dir, "master"); err != nil {
		t.Fatal(err)
	}
	base := filepath.Join(dir, "devices", "dev_test", "approval")
	store := approval.PendingStore{PendingDir: filepath.Join(base, "pending"), ResponsesDir: filepath.Join(base, "responses"), PlansDir: filepath.Join(base, "plans")}
	create := func(cmd, planID string) approval.PendingRequest {
		t.Helper()
		matcher, err := approval.Exact(cmd)
		if err != nil {
			t.Fatal(err)
		}
		req, err := store.Create(approval.PendingRequest{ReqID: "r1", SessionID: "s_test", Host: "web-1", Cmd: cmd, Candidate: matcher, PlanID: planID})
		if err != nil {
			t.Fatal(err)
		}
		return req
	}
	single := create("systemctl restart app", "")
	planID, _ := approval.NewPlanID()
	member := create("systemctl reload app", planID)
	metadata := approval.PlanMetadata{Title: "deploy app", Description: "reload the app\nwith the new config", Impact: "brief reload", Recovery: "reload again"}
	if _, err := store.CreatePlan(approval.PlanManifest{ID: planID, SessionID: "s_test", Host: "web-1", Metadata: metadata, MemberIDs: []string{member.ID}}); err != nil {
		t.Fatal(err)
	}

	out, err := runGatewayCLI(t, "--data", dir, "approval", "ls")
	if err != nil || !strings.Contains(out, single.ID+" device=dev_test host=web-1") || !strings.Contains(out, "plan="+planID) {
		t.Fatalf("approval ls: %v\n%s", err, out)
	}
	if _, err := runGatewayCLI(t, "--data", dir, "approval", "grant", single.ID); err == nil {
		t.Fatal("grant without a scope")
	}
	if out, err := runGatewayCLI(t, "--data", dir, "approval", "grant", single.ID, "--once"); err != nil || !strings.Contains(out, "approved "+single.ID+" for dev_test scope=once") {
		t.Fatalf("approval grant: %v %s", err, out)
	}
	if out, err := runGatewayCLI(t, "--data", dir, "approval", "show", single.ID); err != nil || !strings.Contains(out, `"status": "approved"`) || !strings.Contains(out, `"device_id": "dev_test"`) {
		t.Fatalf("approval show: %v %s", err, out)
	}
	if out, err := runGatewayCLI(t, "--data", dir, "plan", "show", planID); err != nil || !strings.Contains(out, "plan "+planID+" · pending · device dev_test") || !strings.Contains(out, `"systemctl reload app"`) ||
		!strings.Contains(out, `description  "reload the app\nwith the new config"`) || !strings.Contains(out, `impact       "brief reload"`) || !strings.Contains(out, `recovery     "reload again"`) {
		t.Fatalf("plan show: %v %s", err, out)
	}
	if out, err := runGatewayCLI(t, "--data", dir, "plan", "deny", planID); err != nil || !strings.Contains(out, "denied 1 command(s)") {
		t.Fatalf("plan deny: %v %s", err, out)
	}
	if _, err := runGatewayCLI(t, "--data", dir, "approval", "deny", "ap_00000000000000000000000000"); err == nil {
		t.Fatal("deny of an unknown request")
	}
	records, err := audit.NewStore(filepath.Join(dir, gateway.FileAudit)).ReadAll()
	if err != nil || len(records) != 2 || records[0].DeviceID != "dev_test" || records[1].Event != audit.EventApprovalDenied {
		t.Fatalf("audit = %+v, %v", records, err)
	}
}

func TestOperatorCommands(t *testing.T) {
	old := gateway.ScryptWorkFactor
	gateway.ScryptWorkFactor = 10
	t.Cleanup(func() { gateway.ScryptWorkFactor = old })
	gateway.PasswordParams.Time, gateway.PasswordParams.MemoryKiB = 1, 64
	dir := t.TempDir()
	if err := gateway.Init(dir, "master"); err != nil {
		t.Fatal(err)
	}
	t.Setenv(envOperatorPassword, "short")
	if _, err := runGatewayCLI(t, "--data", dir, "operator", "add", "alice"); err == nil {
		t.Fatal("a short password was accepted")
	}
	t.Setenv(envOperatorPassword, "correct horse battery")
	if out, err := runGatewayCLI(t, "--data", dir, "operator", "add", "alice"); err != nil || !strings.Contains(out, "Added operator alice") {
		t.Fatalf("add: %v %s", err, out)
	}
	if _, err := runGatewayCLI(t, "--data", dir, "operator", "add", "alice"); err == nil {
		t.Fatal("a duplicate operator was added")
	}
	if out, err := runGatewayCLI(t, "--data", dir, "operator", "ls"); err != nil || !strings.Contains(out, "alice") || !strings.Contains(out, "not set up") {
		t.Fatalf("ls: %v %s", err, out)
	}
	if out, err := runGatewayCLI(t, "--data", dir, "operator", "revoke", "alice"); err != nil || !strings.Contains(out, "Revoked operator alice") {
		t.Fatalf("revoke: %v %s", err, out)
	}
	if out, _ := runGatewayCLI(t, "--data", dir, "operator", "ls"); !strings.Contains(out, "revoked") {
		t.Fatalf("ls after revoke: %s", out)
	}
	if _, err := runGatewayCLI(t, "--data", dir, "serve", "--public-url", "https://gw.example/a", "--listen", "127.0.0.1:1", "--web-listen", "127.0.0.1:1"); err == nil || !strings.Contains(err.Error(), "--web-listen must differ") {
		t.Fatalf("shared listener: %v", err)
	}
}
