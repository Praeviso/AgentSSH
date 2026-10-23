package gateway_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/x509"
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
	if _, _, err := gateway.DecideApproval(f.dir, f.store, id, approval.VerdictApproved, approval.ScopeHost); !errors.Is(err, gateway.ErrHostScope) {
		t.Fatalf("host scope: %v", err)
	}
	deviceID, _, err := gateway.DecideApproval(f.dir, f.store, id, approval.VerdictApproved, approval.ScopeOnce)
	if err != nil || deviceID != f.client.State.DeviceID {
		t.Fatalf("decide = %s, %v", deviceID, err)
	}
	if _, _, err := gateway.DecideApproval(f.dir, f.store, id, approval.VerdictDenied, ""); !errors.Is(err, approval.ErrAlreadyResolved) {
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
