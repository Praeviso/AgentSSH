package tui

import (
	"strings"
	"testing"

	"github.com/Praeviso/AgentSSH/internal/approval"
)

func TestApprovalsPlansCollapseAndExpandWithStableSelection(t *testing.T) {
	m := loadedPlanApprovalsApp(t)
	if len(m.approvals.visibleIndices()) != 2 {
		t.Fatal("plan is not collapsed")
	}
	m = press(t, m, "j")
	if req, _ := m.approvals.selected(); req.StdinSHA256 == "" {
		t.Fatal("navigation did not skip hidden members")
	}
	m = press(t, m, "k")
	m = press(t, m, "e")
	if len(m.approvals.visibleIndices()) != 3 {
		t.Fatal("expand did not expose members")
	}
	m = press(t, m, "j")
	if req, _ := m.approvals.selected(); req.PlanSeq != 2 {
		t.Fatal("expanded navigation skipped member")
	}
	m = press(t, m, "e")
	if m.approvals.cursor != 0 || len(m.approvals.visibleIndices()) != 2 {
		t.Fatal("collapse left cursor hidden")
	}
}

func TestApprovalsTaskReviewShowsBoundsAndExactFallback(t *testing.T) {
	m := loadedPlanApprovalsApp(t)
	m = press(t, m, "t")
	view := m.View()
	for _, want := range []string{"Review task permissions", "service-maintenance", "nginx", "restart,", "reload", "exact", "docker compose up -d", "expires", "[task]"} {
		if !strings.Contains(view, want) {
			t.Errorf("missing %q:\n%s", want, view)
		}
	}
	if !m.approvals.choosing || !m.approvals.planMode {
		t.Fatal("task preview did not target the full plan")
	}
	m = press(t, m, "esc")
	if m.approvals.choosing || m.approvals.planMode {
		t.Fatal("escape did not cancel")
	}
}

func TestApprovalsCollapsedPlanDecisionApprovesEveryMember(t *testing.T) {
	m := loadedPlanApprovalsApp(t)
	m.approvals.paths.PlansDir = t.TempDir()
	store := m.approvals.pendingStore()
	var ids []string
	var pending []approval.PendingRequest
	for _, source := range planApprovalQueue(t)[:2] {
		source.ID = ""
		req, err := store.Create(source)
		if err != nil {
			t.Fatal(err)
		}
		pending = append(pending, req)
		ids = append(ids, req.ID)
	}
	if _, err := store.CreatePlan(approval.PlanManifest{ID: pending[0].PlanID, SessionID: pending[0].SessionID, Host: pending[0].Host, MemberIDs: ids}); err != nil {
		t.Fatal(err)
	}
	m.approvals.pending = pending
	next, _ := m.approvals.resolveWith(approval.VerdictApproved, approval.ScopeTask)
	section := next.(approvalsSection)
	if section.err != nil {
		t.Fatal(section.err)
	}
	for _, id := range ids {
		status, err := store.Status(id)
		if err != nil || status.Status != "approved" {
			t.Fatal(id, status, err)
		}
	}
}
