package tui

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Praeviso/AgentSSH/internal/approval"
	"github.com/Praeviso/AgentSSH/internal/config"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
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

func TestApprovalsDisabledDoesNotPollBadgeOrDecide(t *testing.T) {
	req := sampleApprovalQueue(t)[:1]
	m := buildAppWith(t, "version: 1\nhosts: {}\n", "version: 1\n")
	m = sized(t, m, 92, 20)
	m.approvals.pending = req
	m = press(t, m, "3")
	if got := m.approvals.pendingCount(); got != 0 {
		t.Fatalf("disabled pendingCount = %d, want 0", got)
	}
	if strings.Contains(m.renderStatusBar(), "pending") {
		t.Fatalf("disabled status bar shows pending badge:\n%s", m.renderStatusBar())
	}
	next, cmd := m.approvals.Update(approvalsTickMsg{})
	if cmd != nil {
		t.Fatal("disabled tick should not poll or re-arm")
	}
	section := next.(approvalsSection)
	before := section.pendingCount()
	next, cmd = section.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("d")})
	if cmd != nil {
		t.Fatal("disabled verdict key should be a no-op command")
	}
	section = next.(approvalsSection)
	if got := section.pendingCount(); got != before {
		t.Fatalf("disabled verdict key changed pending count from %d to %d", before, got)
	}
}

func TestApprovalsDecisionLoadErrorAborts(t *testing.T) {
	dir := t.TempDir()
	paths := config.NewPaths(dir)
	if err := os.WriteFile(paths.InventoryFile, []byte("version: 1\nhosts:\n  web-1: {addr: 10.0.0.11}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(paths.PolicyFile, []byte("version: 1\nhost_overrides: [bad\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	req := mkApprovalReq(t, "ap_7f3a1b2c3d4e5f6071829300", "web-1", "s1", "ls /var")
	store := approval.PendingStore{PendingDir: paths.PendingDir, ResponsesDir: paths.ResponsesDir}
	if _, err := store.Create(req); err != nil {
		t.Fatal(err)
	}

	section := approvalsSection{
		paths:   paths,
		styles:  newAppStyles(lipgloss.NewRenderer(os.Stdout)),
		runtime: approval.RuntimeConfig{Enabled: true},
		pending: []approval.PendingRequest{req},
	}
	next, cmd := section.decide(approval.VerdictApproved, approval.ScopeHost)
	if cmd != nil {
		t.Fatal("load failure should not trigger reload command")
	}
	section = next.(approvalsSection)
	if section.err == nil {
		t.Fatal("decision error = nil, want policy load error")
	}
	if _, err := os.Stat(filepath.Join(paths.ResponsesDir, req.ID+".json")); !os.IsNotExist(err) {
		t.Fatalf("response file exists after load failure: %v", err)
	}
	raw, err := os.ReadFile(paths.PolicyFile)
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != "version: 1\nhost_overrides: [bad\n" {
		t.Fatalf("policy file was clobbered:\n%s", raw)
	}
}
