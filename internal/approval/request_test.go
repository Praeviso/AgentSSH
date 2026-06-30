package approval

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestPendingResponseDigestAndOExcl(t *testing.T) {
	root := t.TempDir()
	store := PendingStore{PendingDir: filepath.Join(root, "pending"), ResponsesDir: filepath.Join(root, "responses")}
	matcher, err := Generalize("systemctl status nginx", HostGrantSafePrefix)
	if err != nil {
		t.Fatal(err)
	}
	req, err := store.Create(PendingRequest{
		ReqID:     "r1",
		SessionID: "s_test",
		Host:      "web-1",
		Cmd:       "systemctl status nginx",
		Candidate: matcher,
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if len(req.ID) < len("ap_")+24 {
		t.Fatalf("approval id too short: %q", req.ID)
	}
	if _, err := store.Create(req); err == nil {
		t.Fatal("duplicate O_EXCL create succeeded")
	}
	resolution, err := store.Resolve(req, VerdictApproved, ScopeSession)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if resolution.ReqDigest != RequestDigest(req, ScopeSession) {
		t.Fatalf("digest = %q want %q", resolution.ReqDigest, RequestDigest(req, ScopeSession))
	}
	status, err := store.Status(req.ID)
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if status.Status != "approved" || status.Scope != ScopeSession {
		t.Fatalf("status = %#v", status)
	}
}

func TestResolutionDigestMismatchIsPending(t *testing.T) {
	root := t.TempDir()
	store := PendingStore{PendingDir: filepath.Join(root, "pending"), ResponsesDir: filepath.Join(root, "responses")}
	matcher, err := Exact("id")
	if err != nil {
		t.Fatal(err)
	}
	req, err := store.Create(PendingRequest{ReqID: "r1", SessionID: "s", Host: "web-1", Cmd: "id", Candidate: matcher})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(store.ResponsesDir, 0o700); err != nil {
		t.Fatal(err)
	}
	bad := Resolution{Version: 1, ID: req.ID, ReqDigest: "bad", Verdict: VerdictApproved, Scope: ScopeSession, TS: time.Now().UTC().Format(time.RFC3339)}
	data, _ := json.Marshal(bad)
	if err := os.WriteFile(responsePath(store.ResponsesDir, req.ID), data, 0o600); err != nil {
		t.Fatal(err)
	}
	status, err := store.Status(req.ID)
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if status.Status != "pending" {
		t.Fatalf("status = %#v, want pending", status)
	}
}

func TestWaitExitSemanticsInputs(t *testing.T) {
	root := t.TempDir()
	store := PendingStore{PendingDir: filepath.Join(root, "pending"), ResponsesDir: filepath.Join(root, "responses")}
	if _, err := store.Status("bad"); err != ErrInvalidID {
		t.Fatalf("bad id err = %v, want ErrInvalidID", err)
	}
	matcher, _ := Exact("id")
	req, err := store.Create(PendingRequest{ReqID: "r1", SessionID: "s", Host: "web-1", Cmd: "id", Candidate: matcher})
	if err != nil {
		t.Fatal(err)
	}
	status, err := store.Wait(req.ID, 10*time.Millisecond)
	if err != nil {
		t.Fatalf("Wait: %v", err)
	}
	if status.Status != "pending" {
		t.Fatalf("wait status = %#v", status)
	}
}
