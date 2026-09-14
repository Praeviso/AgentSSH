package tui

import (
	"strings"
	"testing"

	"github.com/Praeviso/AgentSSH/internal/approval"
	"github.com/Praeviso/AgentSSH/internal/payload"
)

// planApprovalQueue mixes plan members, a stdin request, and a plain request so
// the render test covers every new consequence-line branch.
func planApprovalQueue(t *testing.T) []approval.PendingRequest {
	t.Helper()
	first := mkApprovalReq(t, "ap_7f3a1b2c3d4e5f6071829300", "web-1", "s_1a2b3c4d", "systemctl restart nginx")
	first.PlanID = "pl_92bf946360961c4b23c4c974"
	first.PlanSeq = 1
	first.PlanTotal = 2
	second := mkApprovalReq(t, "ap_5c12aabbccddeeff00112233", "web-1", "s_1a2b3c4d", "docker compose up -d")
	second.PlanID = "pl_92bf946360961c4b23c4c974"
	second.PlanSeq = 2
	second.PlanTotal = 2
	stdinReq := mkApprovalReq(t, "ap_9d04ffeeddccbbaa99887766", "web-1", "s_1a2b3c4d", "tee /etc/nginx/nginx.conf")
	stdinReq.StdinSHA256 = strings.Repeat("ab", 32)
	stdinReq.StdinBytes = 2048
	return []approval.PendingRequest{first, second, stdinReq}
}

func loadedPlanApprovalsApp(t *testing.T) appModel {
	t.Helper()
	t.Setenv("AGENTSSH_APPROVAL", "1")
	m := buildAppWith(t, "version: 1\nhosts: {}\n", "version: 1\n")
	m = sized(t, m, 92, 20)
	m = press(t, m, "3")
	next, _ := m.Update(approvalsLoadedMsg{pending: planApprovalQueue(t)})
	return next.(appModel)
}

func TestApprovalsPlanMemberShowsPlanHintAndChooser(t *testing.T) {
	m := loadedPlanApprovalsApp(t)
	store := m.approvals.pendingStore()
	pending := planApprovalQueue(t)
	payloadRef, err := (payload.Store{Dir: m.approvals.paths.PayloadsDir}).Put([]byte("preview text"), payload.PutOptions{})
	if err != nil {
		t.Fatalf("put payload: %v", err)
	}
	secondPayloadRef, err := (payload.Store{Dir: m.approvals.paths.PayloadsDir}).Put([]byte("second preview"), payload.PutOptions{})
	if err != nil {
		t.Fatalf("put second payload: %v", err)
	}
	review := approval.PlanReview{
		Version:   1,
		PlanID:    pending[0].PlanID,
		SessionID: pending[0].SessionID,
		Host:      pending[0].Host,
		Metadata:  approval.PlanMetadata{Title: "deploy \x1b[31mapi"},
		Steps: []approval.PlanReviewStep{
			{Seq: 1, ID: "restart", Name: "Restart  API", Cmd: pending[0].Cmd + " 'a  b'\x1b[31m", Status: "approval_pending", ApprovalID: pending[0].ID, PayloadRef: payloadRef.String(), PayloadRetained: true},
			{Seq: 2, ID: "compose", Cmd: pending[1].Cmd, Status: "approval_pending", ApprovalID: pending[1].ID, PayloadRef: secondPayloadRef.String(), PayloadRetained: true},
		},
	}
	if _, err := store.CreatePlan(approval.PlanManifest{ID: pending[0].PlanID, SessionID: pending[0].SessionID, Host: pending[0].Host, Metadata: review.Metadata, Review: &review, MemberIDs: []string{pending[0].ID, pending[1].ID}}); err != nil {
		t.Fatalf("create plan: %v", err)
	}
	view := m.View()
	t.Logf("\n%s", view)
	if !strings.Contains(view, "plan 1/2") {
		t.Errorf("plan position missing:\n%s", view)
	}
	if !strings.Contains(view, "[p] decide whole plan") {
		t.Errorf("plan key hint missing:\n%s", view)
	}

	// p opens the whole-plan chooser without a host option.
	m = press(t, m, "p")
	view = m.View()
	t.Logf("\n%s", view)
	if !strings.Contains(view, "decide plan pl_92bf9463") {
		t.Errorf("plan chooser label missing:\n%s", view)
	}
	if !strings.Contains(view, "deploy api") || !strings.Contains(view, "review sha256=") {
		t.Errorf("full review missing metadata/digest:\n%s", view)
	}
	if strings.Contains(view, "\x1b[31m") {
		t.Errorf("review rendered terminal escape:\n%s", view)
	}
	if !strings.Contains(view, "recorded facts") || !strings.Contains(view, "submitter descriptions") {
		t.Errorf("review did not separate facts from submitter descriptions:\n%s", view)
	}
	if !strings.Contains(view, "submitter step name (unverified)") {
		t.Errorf("step name not labeled as submitter description:\n%s", view)
	}
	if !strings.Contains(view, "a  b") || strings.Contains(view, "a b") && !strings.Contains(view, "a  b") {
		t.Errorf("command whitespace was not preserved in escaped display:\n%s", view)
	}
	if strings.Contains(view, "preview text") {
		t.Errorf("payload preview loaded without v:\n%s", view)
	}
	// The chooser itself offers once/session/task/deny — no host scope.
	if !strings.Contains(view, "[once]  session   task   deny") {
		t.Errorf("plan chooser options wrong (want once/session/task/deny):\n%s", view)
	}
	m = press(t, m, "v")
	view = m.View()
	if !strings.Contains(view, "preview text") {
		t.Errorf("payload preview missing after v:\n%s", view)
	}
	m = press(t, m, "n")
	view = m.View()
	if !strings.Contains(view, "second preview") {
		t.Errorf("payload preview did not advance to selected payload step:\n%s", view)
	}
}

func TestApprovalsStdinRowShowsHashAndKind(t *testing.T) {
	m := loadedPlanApprovalsApp(t)
	m = press(t, m, "G") // focus the stdin request (last row)
	view := m.View()
	t.Logf("\n%s", view)
	if !strings.Contains(view, "stdin 2048 B sha256=abababababab…") {
		t.Errorf("stdin identity line missing:\n%s", view)
	}
	if !strings.Contains(view, "no host-allow") {
		t.Errorf("stdin host-unavailable note missing:\n%s", view)
	}
	if !strings.Contains(view, "stdin") {
		t.Errorf("stdin kind label missing:\n%s", view)
	}
}

func TestApprovalsPlanKeyNoopOnNonPlanRow(t *testing.T) {
	m := loadedPlanApprovalsApp(t)
	m = press(t, m, "G") // stdin request has no plan
	m = press(t, m, "p")
	view := m.View()
	if strings.Contains(view, "decide plan") {
		t.Errorf("plan chooser opened on non-plan request:\n%s", view)
	}
}
