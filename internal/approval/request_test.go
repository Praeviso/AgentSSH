package approval

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
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
	collision := req
	collision.Cmd = "whoami"
	collision.Candidate, _ = Exact("whoami")
	if _, err := store.Create(collision); err == nil {
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

func TestPendingMatcherDigestCoversPromotable(t *testing.T) {
	root := t.TempDir()
	store := PendingStore{PendingDir: filepath.Join(root, "pending"), ResponsesDir: filepath.Join(root, "responses")}
	matcher, err := Exact("sudo id")
	if err != nil {
		t.Fatal(err)
	}
	matcher.Promotable = false
	req, err := store.Create(PendingRequest{ReqID: "r1", SessionID: "s", Host: "web-1", Cmd: "sudo id", Candidate: matcher})
	if err != nil {
		t.Fatal(err)
	}

	path := pendingPath(store.PendingDir, req.ID)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var tampered PendingRequest
	if err := json.Unmarshal(data, &tampered); err != nil {
		t.Fatal(err)
	}
	tampered.Candidate.Promotable = true
	tampered.Promotable = true
	data, err = json.MarshalIndent(tampered, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(data, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Get(req.ID); err == nil || !strings.Contains(err.Error(), "digest mismatch") {
		t.Fatalf("Get tampered promotable err = %v, want digest mismatch", err)
	}
}

func TestCorruptResolutionSurfacesError(t *testing.T) {
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
	if err := os.WriteFile(responsePath(store.ResponsesDir, req.ID), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Status(req.ID); !errors.Is(err, ErrCorruptResolution) {
		t.Fatalf("Status err = %v, want ErrCorruptResolution", err)
	}
	if _, err := ApplyDecision(ApplyOptions{Pending: store}, req.ID, VerdictDenied, ""); !errors.Is(err, ErrCorruptResolution) {
		t.Fatalf("ApplyDecision err = %v, want ErrCorruptResolution", err)
	}
}

func TestPendingCreateDedupesUnresolvedRequest(t *testing.T) {
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
	again, err := store.Create(PendingRequest{ReqID: "r2", SessionID: "s", Host: "web-1", Cmd: "id", Candidate: matcher})
	if err != nil {
		t.Fatal(err)
	}
	if again.ID != req.ID || again.ReqID != req.ReqID {
		t.Fatalf("dedupe returned %#v, want original %#v", again, req)
	}
	otherHost, err := store.Create(PendingRequest{ReqID: "r3", SessionID: "s", Host: "web-2", Cmd: "id", Candidate: matcher})
	if err != nil {
		t.Fatal(err)
	}
	if otherHost.ID == req.ID {
		t.Fatalf("dedupe crossed host boundary: %#v", otherHost)
	}
}

func TestPendingStoreReapsOldResolvedFiles(t *testing.T) {
	root := t.TempDir()
	now := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
	store := PendingStore{
		PendingDir:   filepath.Join(root, "pending"),
		ResponsesDir: filepath.Join(root, "responses"),
		Now:          func() time.Time { return now },
	}
	matcher, err := Exact("id")
	if err != nil {
		t.Fatal(err)
	}
	req, err := store.Create(PendingRequest{ReqID: "r1", SessionID: "s", Host: "web-1", Cmd: "id", Candidate: matcher})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Resolve(req, VerdictDenied, ""); err != nil {
		t.Fatal(err)
	}
	old := now.Add(-48 * time.Hour)
	for _, path := range []string{pendingPath(store.PendingDir, req.ID), responsePath(store.ResponsesDir, req.ID)} {
		if err := os.Chtimes(path, old, old); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := store.List(); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{pendingPath(store.PendingDir, req.ID), responsePath(store.ResponsesDir, req.ID)} {
		if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("%s still exists after reap: %v", path, err)
		}
	}
}

// The cap on requests and on plans awaiting a decision holds under
// concurrent requesters, and the same request asked at once is created once.
func TestPendingCapHoldsUnderConcurrency(t *testing.T) {
	dir := t.TempDir()
	store := PendingStore{PendingDir: filepath.Join(dir, "pending"), ResponsesDir: filepath.Join(dir, "responses"), PlansDir: filepath.Join(dir, "plans"), MaxPending: 5}
	create := func(cmd string) (PendingRequest, error) {
		matcher, err := Exact(cmd)
		if err != nil {
			t.Fatal(err)
		}
		return store.Create(PendingRequest{ReqID: "r", SessionID: "s", Host: "web-1", Cmd: cmd, Candidate: matcher})
	}
	var wg sync.WaitGroup
	var mu sync.Mutex
	ids := map[string]bool{}
	for i := range 40 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// Twenty distinct commands, each asked twice at once.
			req, err := create(fmt.Sprintf("systemctl restart app-%d", i%20))
			if err != nil && !errors.Is(err, ErrTooManyPending) {
				t.Error(err)
				return
			}
			if err == nil {
				mu.Lock()
				ids[req.ID] = true
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if n, err := store.Unresolved(); err != nil || n != 5 || len(ids) != 5 {
		t.Fatalf("unresolved %d (%v), distinct requests returned %d; want exactly the cap of 5", n, err, len(ids))
	}

	member := ""
	for id := range ids {
		member = id
	}
	var plans sync.WaitGroup
	for range 20 {
		plans.Add(1)
		go func() {
			defer plans.Done()
			if _, err := store.CreatePlan(PlanManifest{SessionID: "s", Host: "web-1", MemberIDs: []string{member}}); err != nil && !errors.Is(err, ErrTooManyPending) {
				t.Error(err)
			}
		}()
	}
	plans.Wait()
	if n, err := store.pendingPlans(); err != nil || n != 5 {
		t.Fatalf("pending plans %d (%v), want exactly the cap of 5", n, err)
	}
}
