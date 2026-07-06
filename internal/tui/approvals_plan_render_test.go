package tui

import (
	"strings"
	"testing"

	"github.com/Praeviso/AgentSSH/internal/approval"
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
	// The chooser itself offers once/session/deny only — no host scope.
	if !strings.Contains(view, "[once]  session   deny") {
		t.Errorf("plan chooser options wrong (want once/session/deny only):\n%s", view)
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
