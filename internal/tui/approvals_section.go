package tui

import (
	"fmt"
	"strings"
	"time"

	"github.com/Praeviso/AgentSSH/internal/approval"
	"github.com/Praeviso/AgentSSH/internal/audit"
	"github.com/Praeviso/AgentSSH/internal/config"
	"github.com/Praeviso/AgentSSH/internal/inventory"
	"github.com/Praeviso/AgentSSH/internal/policy"
	"github.com/charmbracelet/bubbles/help"
	"github.com/charmbracelet/bubbles/key"
	tea "github.com/charmbracelet/bubbletea"
)

// approvalsSection is the operator's adjudication surface for gray-zone
// (default-deny) command requests. The agent's `run` returns exit 7 and writes
// a pending request; this tab lists those requests one line each and lets the
// operator decide each with o/s/h/d. "Consequence-first": the footer shows, for
// the focused request, exactly what an [h] host-allow would free.
type approvalsSection struct {
	paths   config.Paths
	styles  appStyles
	runtime approval.RuntimeConfig
	pending []approval.PendingRequest
	cursor  int
	err     error
	result  string
	w, h    int
}

const approvalsPollInterval = 1500 * time.Millisecond

// approvalsTickMsg drives periodic polling of the pending queue.
type approvalsTickMsg struct{}

// approvalsLoadedMsg carries a freshly listed pending queue.
type approvalsLoadedMsg struct {
	pending []approval.PendingRequest
	err     error
}

func newApprovalsSection(paths config.Paths, st appStyles, runtime approval.RuntimeConfig) approvalsSection {
	return approvalsSection{paths: paths, styles: st, runtime: runtime}
}

// capturing is always false: this tab has no text input or modal, so the shell
// keeps ownership of tab/esc/q.
func (s approvalsSection) capturing() bool { return false }

func (s approvalsSection) Init() tea.Cmd {
	return tea.Batch(s.loadCmd(), approvalsTickCmd())
}

func approvalsTickCmd() tea.Cmd {
	return tea.Tick(approvalsPollInterval, func(time.Time) tea.Msg { return approvalsTickMsg{} })
}

func (s approvalsSection) pendingStore() approval.PendingStore {
	return approval.PendingStore{PendingDir: s.paths.PendingDir, ResponsesDir: s.paths.ResponsesDir}
}

func (s approvalsSection) loadCmd() tea.Cmd {
	store := s.pendingStore()
	return func() tea.Msg {
		reqs, err := store.List()
		return approvalsLoadedMsg{pending: reqs, err: err}
	}
}

// pendingCount is read by the shell to badge the tab from any screen.
func (s approvalsSection) pendingCount() int { return len(s.pending) }

func (s approvalsSection) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		s.w, s.h = msg.Width, msg.Height
		return s, nil
	case approvalsTickMsg:
		// Keep polling regardless of the active tab so the queue and the tab badge
		// stay live; re-arm the tick.
		return s, tea.Batch(s.loadCmd(), approvalsTickCmd())
	case approvalsLoadedMsg:
		s.pending = msg.pending
		s.err = msg.err
		s.clampCursor()
		return s, nil
	case tea.KeyMsg:
		return s.updateKey(msg)
	}
	return s, nil
}

func (s approvalsSection) updateKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "j", "down":
		s.moveCursor(1)
	case "k", "up":
		s.moveCursor(-1)
	case "g", "home":
		s.cursor = 0
		s.clearStatus()
	case "G", "end":
		s.cursor = maxInt(len(s.pending)-1, 0)
		s.clearStatus()
	case "o":
		return s.decide(approval.VerdictApproved, approval.ScopeOnce)
	case "s":
		return s.decide(approval.VerdictApproved, approval.ScopeSession)
	case "h":
		return s.decide(approval.VerdictApproved, approval.ScopeHost)
	case "d":
		return s.decide(approval.VerdictDenied, "")
	case "r":
		s.clearStatus()
		return s, s.loadCmd()
	}
	return s, nil
}

func (s *approvalsSection) moveCursor(delta int) {
	s.clearStatus()
	n := len(s.pending)
	if n == 0 {
		s.cursor = 0
		return
	}
	s.cursor += delta
	if s.cursor < 0 {
		s.cursor = 0
	}
	if s.cursor >= n {
		s.cursor = n - 1
	}
}

func (s *approvalsSection) clampCursor() {
	if s.cursor >= len(s.pending) {
		s.cursor = maxInt(len(s.pending)-1, 0)
	}
	if s.cursor < 0 {
		s.cursor = 0
	}
}

func (s *approvalsSection) clearStatus() {
	s.err = nil
	s.result = ""
}

func (s approvalsSection) selected() (approval.PendingRequest, bool) {
	if s.cursor < 0 || s.cursor >= len(s.pending) {
		return approval.PendingRequest{}, false
	}
	return s.pending[s.cursor], true
}

// decide applies an operator verdict to the focused request, mirroring the CLI
// `approval grant/deny` wiring exactly (it reloads inventory+policy from disk so
// a host grant never clobbers a concurrent edit). The TUI is the operator
// console by definition, so it needs no extra master/TTY gate.
func (s approvalsSection) decide(verdict approval.Verdict, scope approval.Scope) (tea.Model, tea.Cmd) {
	req, ok := s.selected()
	if !ok {
		return s, nil
	}
	if verdict == approval.VerdictApproved && scope == approval.ScopeHost && !req.Candidate.Promotable {
		s.err = nil
		s.result = "host scope unavailable — privileged command; use once or session"
		return s, nil
	}
	inv, _ := inventory.Load(s.paths.InventoryFile)
	pol, _ := policy.Load(s.paths.PolicyFile)
	_, err := approval.ApplyDecision(approval.ApplyOptions{
		Pending:    s.pendingStore(),
		Sessions:   approval.SessionStore{Dir: s.paths.SessionsDir},
		Audit:      audit.NewStore(s.paths.AuditFile),
		Bundle:     policy.Bundle{Policy: pol, Inventory: inv},
		PolicyPath: s.paths.PolicyFile,
		SessionTTL: s.runtime.SessionTTL,
		Channel:    approval.ChannelTUI,
		SavePolicy: func(next policy.Config) error {
			return policy.Save(s.paths.PolicyFile, next)
		},
	}, req.ID, verdict, scope)
	if err != nil {
		s.err = err
		s.result = ""
		return s, s.loadCmd()
	}
	// Optimistically drop the decided request; the reload confirms.
	s.pending = append(append([]approval.PendingRequest(nil), s.pending[:s.cursor]...), s.pending[s.cursor+1:]...)
	s.clampCursor()
	s.err = nil
	s.result = ""
	return s, tea.Batch(s.loadCmd(), toastCmd(decisionToast(req, verdict, scope)))
}

func decisionToast(req approval.PendingRequest, verdict approval.Verdict, scope approval.Scope) string {
	short := shortApprovalID(req.ID)
	if verdict == approval.VerdictDenied {
		return fmt.Sprintf("denied %s", short)
	}
	return fmt.Sprintf("approved %s · %s", short, scope)
}

func (s approvalsSection) helpKeyMap() help.KeyMap {
	if !s.runtime.Enabled || len(s.pending) == 0 {
		return helpMap{short: []key.Binding{hk("r", "refresh")}}
	}
	return helpMap{
		short: []key.Binding{hk("o", "once"), hk("s", "session"), hk("h", "host"), hk("d", "deny")},
		full: [][]key.Binding{
			{hk("j/k", "move"), hk("g/G", "home/end"), hk("r", "refresh")},
			{hk("o", "once"), hk("s", "session"), hk("h", "host"), hk("d", "deny")},
		},
	}
}

func (s approvalsSection) View() string {
	inner := s.w
	if inner < 8 {
		inner = 8
	}
	if !s.runtime.Enabled {
		return s.styles.dim.Render(truncate("Approvals are off. Enable with approval.enabled: true in policy.yaml or AGENTSSH_APPROVAL=1.", inner)) +
			"\n" + s.styles.dim.Render(truncate("Until enabled, gray-zone commands are denied (exit 6) — unchanged.", inner))
	}
	if len(s.pending) == 0 {
		body := s.styles.dim.Render("No pending approvals. Waiting for requests…")
		if s.err != nil {
			body += "\n" + truncate(s.styles.err.Render(s.err.Error()), inner)
		}
		return body
	}

	var b strings.Builder
	visible := s.visibleRows()
	start, end := scrollWindow(s.cursor, len(s.pending), visible)
	for i := start; i < end; i++ {
		b.WriteString(s.renderRow(s.pending[i], i == s.cursor, inner))
		b.WriteString("\n")
	}
	if end < len(s.pending) || start > 0 {
		b.WriteString(s.styles.dim.Render(fmt.Sprintf("%d-%d of %d", start+1, end, len(s.pending))))
		b.WriteString("\n")
	}
	b.WriteString(s.styles.dim.Render(strings.Repeat("─", inner)))
	b.WriteString("\n")
	if req, ok := s.selected(); ok {
		b.WriteString(truncate(s.consequenceLine(req), inner))
	}
	if s.err != nil {
		b.WriteString("\n" + truncate(s.styles.err.Render(s.err.Error()), inner))
	} else if s.result != "" {
		b.WriteString("\n" + truncate(s.styles.confirm.Render(s.result), inner))
	}
	return s.styles.background.MaxWidth(s.w).Render(b.String())
}

// renderRow draws one pending request on a single line: cursor · id · host ·
// command · a short kind marker (priv / exact). The focused row is brighter.
func (s approvalsSection) renderRow(req approval.PendingRequest, selected bool, inner int) string {
	marker := "  "
	if selected {
		marker = s.styles.cursor.Render("▌ ")
	}
	id := s.styles.dim.Render(shortApprovalID(req.ID))
	host := padCell(req.Host, 12)
	kind := s.rowMarker(req)

	// Reserve columns for id (12), host (12), marker prefix (2), kind (~6) and gaps.
	cmdWidth := inner - 2 - 12 - 1 - 12 - 1 - 7
	if cmdWidth < 8 {
		cmdWidth = 8
	}
	cmd := truncate(req.Cmd, cmdWidth)
	if selected {
		cmd = s.styles.header.Render(cmd)
	}
	line := marker + id + " " + s.styles.dim.Render(host) + " " + cmd
	if kind != "" {
		line += "  " + kind
	}
	return truncate(line, inner)
}

func (s approvalsSection) rowMarker(req approval.PendingRequest) string {
	switch {
	case !req.Candidate.Promotable:
		return s.styles.confirm.Render("priv")
	case req.Candidate.Kind == approval.MatcherPrefix:
		return ""
	default:
		return s.styles.dim.Render("exact")
	}
}

// consequenceLine is the "consequence-first" payload: for the focused request it
// states plainly what an [h] host-allow would free, or why host is unavailable.
func (s approvalsSection) consequenceLine(req approval.PendingRequest) string {
	id := s.styles.cursor.Render(shortApprovalID(req.ID))
	sep := s.styles.dim.Render(" · ")
	c := req.Candidate
	switch {
	case !c.Promotable:
		return id + sep + s.styles.deny.Render("[h]") + s.styles.dim.Render(" unavailable — privileged command; use once or session")
	case c.Kind == approval.MatcherPrefix:
		glob := strings.Join(c.Prefix, " ") + " *"
		return id + sep + s.styles.ok.Render("[h]") + s.styles.dim.Render(" host-allow frees ") +
			s.styles.header.Render(glob) + s.styles.dim.Render(" — won't ask again")
	default:
		return id + sep + s.styles.ok.Render("[h]") + s.styles.dim.Render(" host-allow → this exact command only (won't generalize)")
	}
}

func (s approvalsSection) visibleRows() int {
	// Body height minus the separator, the consequence line, and a possible
	// status/overflow line.
	v := s.h - 3
	if v < 1 {
		v = 1
	}
	return v
}

func shortApprovalID(id string) string {
	if len(id) <= 11 {
		return id
	}
	return id[:11] + "…"
}

func padCell(value string, width int) string {
	if len(value) >= width {
		return truncate(value, width)
	}
	return value + strings.Repeat(" ", width-len(value))
}
