package approval

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func planTestStore(t *testing.T) PendingStore {
	t.Helper()
	dir := t.TempDir()
	return PendingStore{
		PendingDir:   dir + "/pending",
		ResponsesDir: dir + "/responses",
		PlansDir:     dir + "/plans",
	}
}

func mintPlanMember(t *testing.T, store PendingStore, cmd string) PendingRequest {
	t.Helper()
	matcher, err := Exact(cmd)
	if err != nil {
		t.Fatal(err)
	}
	req, err := store.Create(PendingRequest{
		ReqID:     "r1",
		SessionID: "s_plan",
		Host:      "web-1",
		Cmd:       cmd,
		Candidate: matcher,
	})
	if err != nil {
		t.Fatalf("create member: %v", err)
	}
	return req
}

// An approved plan whose member records were later reaped must report
// "expired", never "denied": the operator did not reject anything, and the
// agent's fix is to re-submit, not to treat the commands as forbidden.
func TestPlanStatusApprovedThenReapedIsExpiredNotDenied(t *testing.T) {
	store := planTestStore(t)
	member := mintPlanMember(t, store, "systemctl restart nginx")
	manifest, err := store.CreatePlan(PlanManifest{
		SessionID: "s_plan",
		Host:      "web-1",
		MemberIDs: []string{member.ID},
	})
	if err != nil {
		t.Fatalf("create plan: %v", err)
	}
	if _, err := store.Resolve(member, VerdictApproved, ScopeSession); err != nil {
		t.Fatalf("resolve: %v", err)
	}
	status, err := store.PlanStatus(manifest.ID)
	if err != nil || status.Status != "approved" || status.Approved != 1 {
		t.Fatalf("approved status = %+v err=%v", status, err)
	}

	// Simulate the resolved-request reaper removing the member's files.
	if err := os.Remove(store.PendingDir + "/" + member.ID + ".json"); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(store.ResponsesDir + "/" + member.ID + ".json"); err != nil {
		t.Fatal(err)
	}
	status, err = store.PlanStatus(manifest.ID)
	if err != nil {
		t.Fatalf("expired status err: %v", err)
	}
	if status.Status != "expired" || status.Expired != 1 || status.Denied != 0 {
		t.Fatalf("reaped plan status = %+v, want expired/1/0", status)
	}
}

func TestWaitPlanReturnsOnceAllResolved(t *testing.T) {
	store := planTestStore(t)
	member := mintPlanMember(t, store, "docker compose up -d")
	manifest, err := store.CreatePlan(PlanManifest{
		SessionID: "s_plan",
		Host:      "web-1",
		MemberIDs: []string{member.ID},
	})
	if err != nil {
		t.Fatalf("create plan: %v", err)
	}
	if _, err := store.Resolve(member, VerdictDenied, ""); err != nil {
		t.Fatalf("resolve: %v", err)
	}
	status, err := store.WaitPlan(manifest.ID, time.Second)
	if err != nil || status.Status != "denied" || status.Pending != 0 {
		t.Fatalf("wait status = %+v err=%v", status, err)
	}
}

func TestPlanReviewDigestTamperingFailsClosed(t *testing.T) {
	store := planTestStore(t)
	member := mintPlanMember(t, store, "systemctl restart nginx")
	review := PlanReview{
		Version:   1,
		SessionID: "s_plan",
		Host:      "web-1",
		Metadata:  PlanMetadata{Title: "deploy"},
		Steps: []PlanReviewStep{{
			Seq:        1,
			ID:         "restart",
			Cmd:        "systemctl restart nginx",
			Status:     "approval_pending",
			ApprovalID: member.ID,
		}},
	}
	manifest, err := store.CreatePlan(PlanManifest{
		SessionID: "s_plan",
		Host:      "web-1",
		Metadata:  review.Metadata,
		Review:    &review,
		MemberIDs: []string{member.ID},
	})
	if err != nil {
		t.Fatalf("create plan: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(store.PlansDir, manifest.ID+".json"))
	if err != nil {
		t.Fatalf("read manifest: %v", err)
	}
	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatal(err)
	}
	raw["host"] = "web-2"
	data, _ = json.MarshalIndent(raw, "", "  ")
	if err := os.WriteFile(filepath.Join(store.PlansDir, manifest.ID+".json"), append(data, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.GetPlan(manifest.ID); err != ErrPlanDigest {
		t.Fatalf("GetPlan err=%v, want ErrPlanDigest", err)
	}
}

func TestPlanMetadataDoesNotChangeGrantSemantics(t *testing.T) {
	root := t.TempDir()
	store := PendingStore{PendingDir: filepath.Join(root, "pending"), ResponsesDir: filepath.Join(root, "responses"), PlansDir: filepath.Join(root, "plans")}
	member := mintPlanMember(t, store, "systemctl restart nginx")
	review := PlanReview{
		Version:   1,
		SessionID: member.SessionID,
		Host:      member.Host,
		Metadata:  PlanMetadata{Title: "operator prose", Impact: "restart service"},
		Steps: []PlanReviewStep{{
			Seq:        1,
			ID:         "step-001",
			Cmd:        member.Cmd,
			Status:     "approval_pending",
			ApprovalID: member.ID,
		}},
	}
	manifest, err := store.CreatePlan(PlanManifest{
		SessionID: member.SessionID,
		Host:      member.Host,
		Metadata:  review.Metadata,
		Review:    &review,
		MemberIDs: []string{member.ID},
	})
	if err != nil {
		t.Fatalf("create plan: %v", err)
	}
	sessions := SessionStore{Dir: filepath.Join(root, "sessions")}
	results, err := ApplyPlanDecision(ApplyOptions{Pending: store, Sessions: sessions, TaskTTL: time.Hour}, manifest.ID, VerdictApproved, ScopeSession)
	if err != nil {
		t.Fatalf("apply plan: %v", err)
	}
	if len(results) != 1 || results[0].Grant == nil || results[0].Grant.Regex == "" {
		t.Fatalf("results=%+v", results)
	}
	if results[0].Grant.Regex == review.Metadata.Title || results[0].Grant.Regex == review.Metadata.Impact {
		t.Fatalf("metadata affected matcher: %+v", results[0].Grant)
	}
}
