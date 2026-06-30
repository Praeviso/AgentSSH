package tui

import (
	"strings"
	"testing"

	"github.com/Praeviso/AgentSSH/internal/approval"
)

func mkApprovalReq(t *testing.T, id, host, session, cmd string) approval.PendingRequest {
	t.Helper()
	matcher, err := approval.Generalize(cmd, approval.HostGrantSafePrefix)
	if err != nil {
		t.Fatalf("generalize %q: %v", cmd, err)
	}
	return approval.PendingRequest{
		ID:         id,
		Host:       host,
		SessionID:  session,
		Cmd:        cmd,
		Candidate:  matcher,
		Promotable: matcher.Promotable,
	}
}

func sampleApprovalQueue(t *testing.T) []approval.PendingRequest {
	t.Helper()
	return []approval.PendingRequest{
		mkApprovalReq(t, "ap_7f3a1b2c3d4e5f6071829300", "web-1", "s_1a2b3c4d", "systemctl status nginx"),
		mkApprovalReq(t, "ap_5c12aabbccddeeff00112233", "web-1", "s_1a2b3c4d", "sudo systemctl restart nginx"),
		mkApprovalReq(t, "ap_9d04ffeeddccbbaa99887766", "db-1", "s_99ff0011", "cat /etc/passwd | grep root"),
	}
}

// loadedApprovalsApp returns a sized app on the Approvals tab with the sample
// queue injected (approval enabled via env).
func loadedApprovalsApp(t *testing.T) appModel {
	t.Helper()
	t.Setenv("AGENTSSH_APPROVAL", "1")
	m := buildAppWith(t, "version: 1\nhosts: {}\n", "version: 1\n")
	m = sized(t, m, 92, 20)
	m = press(t, m, "3") // switch to Approvals
	next, _ := m.Update(approvalsLoadedMsg{pending: sampleApprovalQueue(t)})
	return next.(appModel)
}

func TestApprovalsTabRendersConsequenceFirst(t *testing.T) {
	m := loadedApprovalsApp(t)
	view := m.View()
	t.Logf("\n%s", view)

	// Active tab + ambient pending badge in the status bar.
	if !strings.Contains(view, "3 Approvals") {
		t.Errorf("Approvals tab not shown:\n%s", view)
	}
	if !strings.Contains(view, "3 pending") {
		t.Errorf("pending badge missing:\n%s", view)
	}
	// One line per request: commands visible.
	for _, want := range []string{"systemctl status nginx", "sudo systemctl restart nginx", "cat /etc/passwd"} {
		if !strings.Contains(view, want) {
			t.Errorf("request %q missing from list:\n%s", want, view)
		}
	}
	// Focused row (first, a safe prefix) drives the consequence footer.
	if !strings.Contains(view, "host-allow frees systemctl status *") {
		t.Errorf("prefix consequence missing for focused row:\n%s", view)
	}
}

func TestApprovalsConsequenceFollowsCursor(t *testing.T) {
	m := loadedApprovalsApp(t)

	// Move to the sudo request: host scope must read as unavailable (privileged).
	m = press(t, m, "j")
	view := m.View()
	if !strings.Contains(view, "unavailable") || !strings.Contains(view, "privileged") {
		t.Errorf("sudo row should show host unavailable:\n%s", view)
	}

	// Move to the piped request: host-allow stays exact (no generalize).
	m = press(t, m, "j")
	view = m.View()
	if !strings.Contains(view, "this exact command only") {
		t.Errorf("piped row should show exact-only host consequence:\n%s", view)
	}
}

func TestApprovalsHostOnPrivilegedRefusesWithoutWrite(t *testing.T) {
	m := loadedApprovalsApp(t)
	m = press(t, m, "j") // focus the sudo (non-promotable) request
	m = press(t, m, "h") // attempt host scope
	view := m.View()
	if !strings.Contains(view, "host scope unavailable") {
		t.Errorf("host on privileged request should be refused in-place:\n%s", view)
	}
	// The queue is unchanged (nothing was written/resolved).
	if got := m.approvals.pendingCount(); got != 3 {
		t.Errorf("refused decision must not drop the request: pending=%d", got)
	}
}

func TestApprovalsDisabledShowsOffNote(t *testing.T) {
	m := buildAppWith(t, "version: 1\nhosts: {}\n", "version: 1\n")
	m = sized(t, m, 92, 20)
	m = press(t, m, "3")
	view := m.View()
	if !strings.Contains(view, "Approvals are off") {
		t.Errorf("disabled approvals should show the off note:\n%s", view)
	}
}
