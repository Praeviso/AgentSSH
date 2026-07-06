package approval

import (
	"os"
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
