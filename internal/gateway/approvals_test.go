package gateway_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Praeviso/AgentSSH/internal/approval"
	"github.com/Praeviso/AgentSSH/internal/audit"
	"github.com/Praeviso/AgentSSH/internal/controlplane"
	"github.com/Praeviso/AgentSSH/internal/gateway"
	"github.com/Praeviso/AgentSSH/internal/managedmode"
	"github.com/Praeviso/AgentSSH/internal/remote"
	"github.com/Praeviso/AgentSSH/internal/remoteclient"
)

// signedPost sends body to path signed with home's device key, as a modified
// client could.
func signedPost(t *testing.T, f *fixture, home, path string, body []byte) int {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(managedmode.Dir(home), "device.key"))
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(data)
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	state, err := remoteclient.LoadState(home)
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodPost, f.base+path, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	if err := remote.SignHTTPRequest(req, body, state.DeviceID, remote.DeviceSignatureTag, parsed.(ed25519.PrivateKey), time.Now()); err != nil {
		t.Fatal(err)
	}
	resp, err := http.DefaultTransport.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	return resp.StatusCode
}

// No device request decides an approval: a device holding its own key and
// speaking the protocol directly finds no route that resolves one, and its
// request stays pending.
func TestDevicesCannotDecideApprovals(t *testing.T) {
	f, host := execGateway(t)
	home := f.enrollHome(t, "tampered")
	client, err := remoteclient.NewClient(home)
	if err != nil {
		t.Fatal(err)
	}
	inv := fmt.Sprintf("host_key_policy: accept-new\nhosts:\n  web-1: {addr: 127.0.0.1, port: %d, user: deploy, identity: web}\n", host.port())
	if _, err := controlplane.PushConfig(f.store, client.State.DeviceID, inv, testPolicy, time.Now()); err != nil {
		t.Fatal(err)
	}
	result, err := client.Exec(context.Background(), execReq("uname"), io.Discard, io.Discard)
	if err != nil || result.ExitCode != 7 {
		t.Fatalf("gray-zone run = %+v, %v", result, err)
	}
	id := result.Responses[0].ApprovalID
	decision := []byte(`{"approval_id":"` + id + `","id":"` + id + `","verdict":"approved","scope":"session"}`)
	for _, path := range []string{"/approvals/grant", "/approvals/deny", "/approvals/decide", "/approvals/resolve", "/approval/grant", "/plans/grant", "/plans/decide", "/grant", "/approvals/status/grant"} {
		if status := signedPost(t, f, home, path, decision); status != http.StatusNotFound {
			t.Fatalf("POST %s with a device key answered %d", path, status)
		}
	}
	status, err := client.ApprovalStatus(context.Background(), id)
	if err != nil || status.Status.Status != "pending" {
		t.Fatalf("after the attempts: %+v, %v", status, err)
	}
	if rerun, err := client.Exec(context.Background(), execReq("uname"), io.Discard, io.Discard); err != nil || rerun.ExitCode != 7 {
		t.Fatalf("rerun = %+v, %v", rerun, err)
	}
}

// The gateway's operator decides, the decision is in the gateway's audit
// chain with the device, and a device can read only its own requests.
func TestOperatorDecisionsAreAuditedPerDevice(t *testing.T) {
	f, _ := execGateway(t)
	result, err := f.client.Exec(context.Background(), execReq("uname"), io.Discard, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	id := result.Responses[0].ApprovalID
	requests, err := gateway.ListApprovals(f.dir)
	if err != nil || len(requests) != 1 || requests[0].ID != id || requests[0].DeviceID != f.client.State.DeviceID {
		t.Fatalf("pending = %+v, %v", requests, err)
	}
	if _, _, err := gateway.DecideApproval(f.dir, f.store, "", id, approval.VerdictApproved, approval.ScopeHost); !errors.Is(err, gateway.ErrHostScope) {
		t.Fatalf("host scope: %v", err)
	}
	deviceID, _, err := gateway.DecideApproval(f.dir, f.store, "", id, approval.VerdictApproved, approval.ScopeOnce)
	if err != nil || deviceID != f.client.State.DeviceID {
		t.Fatalf("decide = %s, %v", deviceID, err)
	}
	if _, _, err := gateway.DecideApproval(f.dir, f.store, "", id, approval.VerdictDenied, ""); !errors.Is(err, approval.ErrAlreadyResolved) {
		t.Fatalf("second decision: %v", err)
	}
	records, err := audit.NewStore(filepath.Join(f.dir, gateway.FileAudit)).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	last := records[len(records)-1]
	if last.Event != audit.EventApprovalGranted || last.ApprovalID != id || last.DeviceID != deviceID || last.ApprovalChannel != approval.ChannelGateway || last.ApprovalScope != string(approval.ScopeOnce) {
		t.Fatalf("decision record = %+v", last)
	}
	other := f.enroll(t, "other-vm")
	var apiErr *remote.APIError
	if _, err := other.ApprovalStatus(context.Background(), id); !errors.As(err, &apiErr) || apiErr.Code != remote.CodeUsage {
		t.Fatalf("another device read the request: %v", err)
	}
	// The target does not know the command; what matters is that it ran.
	if rerun, err := f.client.Exec(context.Background(), execReq("uname"), io.Discard, io.Discard); err != nil || rerun.Responses[0].GrantScope != string(approval.ScopeOnce) || rerun.Responses[0].ExecutionState != "finished" {
		t.Fatalf("rerun after the grant = %+v, %v", rerun, err)
	}
}

// A plan's review is shown to the gateway's operator, so a device cannot put
// terminal control sequences in it; multi-line descriptions stay allowed.
func TestPlanReviewTextCannotCarryControlCharacters(t *testing.T) {
	f, _ := execGateway(t)
	submit := func(review approval.PlanReview) error {
		planID, _ := approval.NewPlanID()
		_, err := f.client.SubmitPlan(context.Background(), remote.PlanSubmitRequest{
			PlanID: planID, Host: "web-1", Session: "s_test", Review: review,
			Commands: []remote.PlanSubmitCommand{{ID: "restart", Cmd: "systemctl restart app"}},
		})
		return err
	}
	for name, review := range map[string]approval.PlanReview{
		"title":       {Metadata: approval.PlanMetadata{Title: "deploy\x1b[2J\x1b[Happroved"}},
		"step status": {Steps: []approval.PlanReviewStep{{ID: "other", Cmd: "true", Status: "allowed\r\x1b[1A"}}},
		"description": {Metadata: approval.PlanMetadata{Description: "line\x1b]0;x\a"}},
	} {
		var apiErr *remote.APIError
		if err := submit(review); !errors.As(err, &apiErr) || apiErr.Code != remote.CodeUsage {
			t.Fatalf("%s with control characters: %v", name, err)
		}
	}
	if err := submit(approval.PlanReview{Metadata: approval.PlanMetadata{Title: "deploy", Description: "first line\n\tsecond line"}}); err != nil {
		t.Fatalf("multi-line description: %v", err)
	}
}

// Devices mint plan IDs, so a device must not be able to claim another
// device's: a decision by that ID would then land on its own plan.
func TestAPlanIDBelongsToOneDevice(t *testing.T) {
	f, host := execGateway(t)
	planID, _ := approval.NewPlanID()
	plan := remote.PlanSubmitRequest{PlanID: planID, Host: "web-1", Session: "s_test",
		Commands: []remote.PlanSubmitCommand{{ID: "restart", Cmd: "systemctl restart app"}}}
	if result, err := f.client.SubmitPlan(context.Background(), plan); err != nil || result.Response.PlanID != planID {
		t.Fatalf("submit = %+v, %v", result, err)
	}
	thief := f.enroll(t, "thief")
	inv := fmt.Sprintf("host_key_policy: accept-new\nhosts:\n  web-1: {addr: 127.0.0.1, port: %d, user: deploy, identity: web}\n", host.port())
	if _, err := controlplane.PushConfig(f.store, thief.State.DeviceID, inv, testPolicy, time.Now()); err != nil {
		t.Fatal(err)
	}
	plan.Commands[0].Cmd = "systemctl stop app"
	var apiErr *remote.APIError
	if _, err := thief.SubmitPlan(context.Background(), plan); !errors.As(err, &apiErr) || apiErr.Status != http.StatusConflict {
		t.Fatalf("another device reused the plan ID: %v", err)
	}
	deviceID, results, err := gateway.DecidePlan(f.dir, f.store, "", planID, approval.VerdictApproved, approval.ScopeOnce)
	if err != nil || deviceID != f.client.State.DeviceID || len(results) != 1 || results[0].Request.Cmd != "systemctl restart app" {
		t.Fatalf("decision = %s %+v, %v", deviceID, results, err)
	}
}

// An ID more than one device holds (for example plans written before IDs were
// checked) is decided only when the operator names the device.
func TestAnAmbiguousIDNeedsTheDevice(t *testing.T) {
	f, _ := execGateway(t)
	planID, _ := approval.NewPlanID()
	for _, device := range []string{"dev_a", "dev_b"} {
		base := filepath.Join(f.dir, "devices", device, "approval")
		store := approval.PendingStore{PendingDir: filepath.Join(base, "pending"), ResponsesDir: filepath.Join(base, "responses"), PlansDir: filepath.Join(base, "plans")}
		matcher, _ := approval.Exact("systemctl restart " + device)
		req, err := store.Create(approval.PendingRequest{ReqID: "r1", SessionID: "s_test", Host: "web-1", Cmd: "systemctl restart " + device, Candidate: matcher, PlanID: planID})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := store.CreatePlan(approval.PlanManifest{ID: planID, SessionID: "s_test", Host: "web-1", MemberIDs: []string{req.ID}}); err != nil {
			t.Fatal(err)
		}
	}
	if _, _, err := gateway.DecidePlan(f.dir, f.store, "", planID, approval.VerdictApproved, approval.ScopeOnce); !errors.Is(err, gateway.ErrAmbiguousID) {
		t.Fatalf("ambiguous decision: %v", err)
	}
	deviceID, results, err := gateway.DecidePlan(f.dir, f.store, "dev_b", planID, approval.VerdictApproved, approval.ScopeOnce)
	if err != nil || deviceID != "dev_b" || len(results) != 1 || results[0].Request.Cmd != "systemctl restart dev_b" {
		t.Fatalf("decision for dev_b = %s %+v, %v", deviceID, results, err)
	}
	if _, status, err := gateway.PlanStatus(f.dir, "dev_a", planID); err != nil || status.Status != "pending" {
		t.Fatalf("dev_a's plan = %+v, %v", status, err)
	}
}

// What a device leaves awaiting a decision stays on the gateway's disk, so it
// is capped per device: a plan that does not fit is refused before it creates
// anything, a gray-zone run beyond the cap is busy, plans built again and
// again from the same request count too, and other devices are unaffected.
func TestPendingApprovalsAreCappedPerDevice(t *testing.T) {
	f, host := execGateway(t)
	f.server.MaxPendingApprovals = 2
	submit := func(client *remoteclient.Client, cmds ...string) error {
		planID, _ := approval.NewPlanID()
		req := remote.PlanSubmitRequest{PlanID: planID, Host: "web-1", Session: "s_test"}
		for i, cmd := range cmds {
			req.Commands = append(req.Commands, remote.PlanSubmitCommand{ID: fmt.Sprintf("s%d", i), Cmd: cmd})
		}
		_, err := client.SubmitPlan(context.Background(), req)
		return err
	}
	busy := func(err error) bool {
		var apiErr *remote.APIError
		return errors.As(err, &apiErr) && apiErr.Code == remote.CodeBusy
	}
	if err := submit(f.client, "systemctl restart a", "systemctl restart b", "systemctl restart c"); !busy(err) {
		t.Fatalf("oversized plan: %v", err)
	}
	if requests, _ := gateway.ListApprovals(f.dir); len(requests) != 0 {
		t.Fatalf("a refused plan left %d requests", len(requests))
	}
	if err := submit(f.client, "systemctl restart a"); err != nil {
		t.Fatal(err)
	}
	if err := submit(f.client, "systemctl restart a"); err != nil {
		t.Fatalf("a second plan of the same request: %v", err)
	}
	if err := submit(f.client, "systemctl restart a"); !busy(err) {
		t.Fatalf("a third plan beyond the cap: %v", err)
	}
	if _, err := f.client.Exec(context.Background(), execReq("uname"), io.Discard, io.Discard); err != nil {
		t.Fatalf("second request within the cap: %v", err)
	}
	if _, err := f.client.Exec(context.Background(), execReq("hostname"), io.Discard, io.Discard); !busy(err) {
		t.Fatalf("a gray-zone run beyond the cap: %v", err)
	}
	other := f.enroll(t, "other-vm")
	inv := fmt.Sprintf("host_key_policy: accept-new\nhosts:\n  web-1: {addr: 127.0.0.1, port: %d, user: deploy, identity: web}\n", host.port())
	if _, err := controlplane.PushConfig(f.store, other.State.DeviceID, inv, testPolicy, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := submit(other, "systemctl restart a"); err != nil {
		t.Fatalf("another device was capped too: %v", err)
	}
}

// A grant covers the stdin size its request stated. The hash pins the
// content, so a plan that misstates the size to the operator gets a grant
// its real payload cannot use.
func TestGrantsAreBoundToTheStatedStdinSize(t *testing.T) {
	f, host := execGateway(t)
	payload := []byte("0123456789")
	sum := sha256.Sum256(payload)
	stdinSHA := hex.EncodeToString(sum[:])
	for _, stated := range []int64{0, -1, remote.MaxExecStdinBytes + 1} {
		planID, _ := approval.NewPlanID()
		_, err := f.client.SubmitPlan(context.Background(), remote.PlanSubmitRequest{PlanID: planID, Host: "web-1", Session: "s_bad",
			Commands: []remote.PlanSubmitCommand{{ID: "load", Cmd: "cat -", StdinSHA256: stdinSHA, StdinBytes: stated}}})
		var apiErr *remote.APIError
		if !errors.As(err, &apiErr) || apiErr.Code != remote.CodeUsage {
			t.Fatalf("stated size %d for a non-empty payload's hash: %v", stated, err)
		}
	}
	for _, stated := range []int64{1, int64(len(payload))} {
		planID, _ := approval.NewPlanID()
		session := fmt.Sprintf("s_%d", stated)
		if _, err := f.client.SubmitPlan(context.Background(), remote.PlanSubmitRequest{PlanID: planID, Host: "web-1", Session: session,
			Commands: []remote.PlanSubmitCommand{{ID: "load", Cmd: "cat -", StdinSHA256: stdinSHA, StdinBytes: stated}}}); err != nil {
			t.Fatal(err)
		}
		if _, _, err := gateway.DecidePlan(f.dir, f.store, "", planID, approval.VerdictApproved, approval.ScopeOnce); err != nil {
			t.Fatal(err)
		}
		req := remote.ExecRequest{Host: "web-1", Cmd: "cat -", Session: session, Stdin: payload}
		result, err := f.client.Exec(context.Background(), req, io.Discard, io.Discard)
		if err != nil {
			t.Fatal(err)
		}
		response := result.Responses[0]
		if stated == 1 && (result.ExitCode != 6 || response.PolicyRule != approval.RuleStdinSizeMismatch) {
			t.Fatalf("a payload larger than approved: %+v", response)
		}
		if stated != 1 && response.GrantScope != string(approval.ScopeOnce) {
			t.Fatalf("the payload the operator approved: %+v", response)
		}
	}
	if runs := host.runs("cat -"); runs != 1 {
		t.Fatalf("target ran cat %d times, want only the honestly stated payload", runs)
	}
}
