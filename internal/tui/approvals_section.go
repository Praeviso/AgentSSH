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
	// choosing is the Enter-driven verdict menu: while open the footer swaps to a
	// selectable once/session/host/deny chooser and this tab owns the keyboard.
	choosing  bool
	choiceIdx int
	choiceID  string // request the open chooser targets, so a poll can't misapply it
	err       error
	result    string
	w, h      int
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

// capturing is true only while the Enter-driven verdict chooser is open, so the
// shell hands this tab the keyboard (esc cancels, enter applies) instead of
// treating those keys as tab/quit navigation.
func (s approvalsSection) capturing() bool { return s.choosing }

func (s approvalsSection) Init() tea.Cmd {
	if !s.runtime.Enabled {
		return nil
	}
	return tea.Batch(s.loadCmd(), approvalsTickCmd())
}

func approvalsTickCmd(enabled ...bool) tea.Cmd {
	if len(enabled) > 0 && !enabled[0] {
		return nil
	}
	return tea.Tick(approvalsPollInterval, func(time.Time) tea.Msg { return approvalsTickMsg{} })
}

func (s approvalsSection) pendingStore() approval.PendingStore {
	return approval.PendingStore{PendingDir: s.paths.PendingDir, ResponsesDir: s.paths.ResponsesDir}
}

func (s approvalsSection) loadCmd() tea.Cmd {
	if !s.runtime.Enabled {
		return nil
	}
	store := s.pendingStore()
	return func() tea.Msg {
		reqs, err := store.List()
		return approvalsLoadedMsg{pending: reqs, err: err}
	}
}

// pendingCount is read by the shell to badge the tab from any screen.
func (s approvalsSection) pendingCount() int {
	if !s.runtime.Enabled {
		return 0
	}
	return len(s.pending)
}

func (s approvalsSection) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		s.w, s.h = msg.Width, msg.Height
		return s, nil
	case approvalsTickMsg:
		if !s.runtime.Enabled {
			return s, nil
		}
		// Keep polling regardless of the active tab so the queue and the tab badge
		// stay live; re-arm the tick.
		return s, tea.Batch(s.loadCmd(), approvalsTickCmd(s.runtime.Enabled))
	case approvalsLoadedMsg:
		s.pending = msg.pending
		s.err = msg.err
		s.clampCursor()
		s.resyncChooser()
		return s, nil
	case tea.KeyMsg:
		return s.updateKey(msg)
	}
	return s, nil
}

func (s approvalsSection) updateKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	if s.choosing {
		return s.updateChoosing(msg)
	}
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
	case "enter":
		return s.openChooser()
	case "o":
		return s.resolveWith(approval.VerdictApproved, approval.ScopeOnce)
	case "s":
		return s.resolveWith(approval.VerdictApproved, approval.ScopeSession)
	case "h":
		return s.resolveWith(approval.VerdictApproved, approval.ScopeHost)
	case "d":
		return s.resolveWith(approval.VerdictDenied, "")
	case "r":
		s.clearStatus()
		return s, s.loadCmd()
	}
	return s, nil
}

// updateChoosing drives the Enter verdict menu: arrows/tab move the highlight,
// enter/space applies it, esc cancels, and the o/s/h/d shortcuts still apply a
// verdict directly. All other keys are swallowed so the modal keeps focus.
func (s approvalsSection) updateChoosing(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	choices := s.choices()
	switch msg.String() {
	case "left", "shift+tab":
		s.choiceIdx = maxInt(s.choiceIdx-1, 0)
	case "right", "tab":
		s.choiceIdx = minInt(s.choiceIdx+1, len(choices)-1)
	case "enter", " ":
		if s.choiceIdx >= 0 && s.choiceIdx < len(choices) {
			c := choices[s.choiceIdx]
			return s.resolveWith(c.verdict, c.scope)
		}
	case "esc":
		s.choosing = false
		s.choiceID = ""
		s.clearStatus()
	case "o":
		return s.resolveWith(approval.VerdictApproved, approval.ScopeOnce)
	case "s":
		return s.resolveWith(approval.VerdictApproved, approval.ScopeSession)
	case "h":
		return s.resolveWith(approval.VerdictApproved, approval.ScopeHost)
	case "d":
		return s.resolveWith(approval.VerdictDenied, "")
	}
	return s, nil
}

// openChooser starts the verdict menu on the focused request. It is a no-op when
// approval is disabled or the queue is empty.
func (s approvalsSection) openChooser() (tea.Model, tea.Cmd) {
	if !s.runtime.Enabled {
		return s, nil
	}
	req, ok := s.selected()
	if !ok {
		return s, nil
	}
	s.clearStatus()
	s.choosing = true
	s.choiceIdx = 0
	s.choiceID = req.ID
	return s, nil
}

// resolveWith closes the chooser (if open) and applies a verdict to the focused
// request, shared by the direct o/s/h/d shortcuts and the menu.
func (s approvalsSection) resolveWith(verdict approval.Verdict, scope approval.Scope) (tea.Model, tea.Cmd) {
	if !s.runtime.Enabled {
		return s, nil
	}
	s.choosing = false
	s.choiceID = ""
	return s.decide(verdict, scope)
}

// resyncChooser keeps the open menu pinned to the request it targeted across a
// background poll: it re-points the cursor to that request, or closes the menu
// if the request was resolved elsewhere and is gone.
func (s *approvalsSection) resyncChooser() {
	if !s.choosing {
		return
	}
	idx := s.indexOfReq(s.choiceID)
	if idx < 0 {
		s.choosing = false
		s.choiceID = ""
		return
	}
	s.cursor = idx
	if choices := s.choices(); s.choiceIdx >= len(choices) {
		s.choiceIdx = maxInt(len(choices)-1, 0)
	}
}

func (s approvalsSection) indexOfReq(id string) int {
	for i, req := range s.pending {
		if req.ID == id {
			return i
		}
	}
	return -1
}

// approvalChoice is one entry in the verdict menu.
type approvalChoice struct {
	label   string
	verdict approval.Verdict
	scope   approval.Scope
}

// choices are the verdict options for the focused request. Host is offered only
// when the request is promotable, so the menu never presents an action that
// would be refused.
func (s approvalsSection) choices() []approvalChoice {
	out := []approvalChoice{
		{"once", approval.VerdictApproved, approval.ScopeOnce},
		{"session", approval.VerdictApproved, approval.ScopeSession},
	}
	if req, ok := s.selected(); ok && req.Candidate.Promotable {
		out = append(out, approvalChoice{"host", approval.VerdictApproved, approval.ScopeHost})
	}
	return append(out, approvalChoice{"deny", approval.VerdictDenied, ""})
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
	inv, err := inventory.Load(s.paths.InventoryFile)
	if err != nil {
		s.err = err
		s.result = ""
		return s, nil
	}
	pol, err := policy.Load(s.paths.PolicyFile)
	if err != nil {
		s.err = err
		s.result = ""
		return s, nil
	}
	_, err = approval.ApplyDecision(approval.ApplyOptions{
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
	if s.choosing {
		return helpMap{
			short: []key.Binding{hk("←/→", "move"), hk("enter", "apply"), hk("esc", "cancel")},
		}
	}
	return helpMap{
		short: []key.Binding{hk("enter", "decide"), hk("j/k", "move"), hk("r", "refresh")},
		full: [][]key.Binding{
			{hk("j/k", "move"), hk("g/G", "home/end"), hk("enter", "decide"), hk("r", "refresh")},
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
	rows := make([][]string, 0, end-start)
	for i := start; i < end; i++ {
		rows = append(rows, approvalRow(s.pending[i]))
	}
	// Reuse the shared responsive table (fill=true) so the columns span the
	// frame instead of clumping at fixed widths: COMMAND takes the slack, HOST
	// shows in full, KIND is a tidy right column.
	b.WriteString(renderTable(s.styles, approvalColumns, rows, s.cursor-start, inner, true))
	b.WriteString("\n")
	if end < len(s.pending) || start > 0 {
		b.WriteString(s.styles.dim.Render(fmt.Sprintf("%d-%d of %d", start+1, end, len(s.pending))))
		b.WriteString("\n")
	}
	b.WriteString(s.styles.dim.Render(strings.Repeat("─", inner)))
	b.WriteString("\n")
	if req, ok := s.selected(); ok {
		b.WriteString(truncate(s.consequenceLine(req), inner))
	}
	switch {
	case s.choosing:
		b.WriteString("\n" + truncate(s.chooserLine(), inner))
	case s.err != nil:
		b.WriteString("\n" + truncate(s.styles.err.Render(s.err.Error()), inner))
	case s.result != "":
		b.WriteString("\n" + truncate(s.styles.confirm.Render(s.result), inner))
	}
	return s.styles.background.MaxWidth(s.w).Render(b.String())
}

// approvalColumns is the aligned, responsive layout for the pending queue. KIND
// telegraphs what an [h] host-allow does (prefix generalizes, exact stays
// this-command-only, priv can't promote); COMMAND carries the most weight so it
// absorbs the slack on a wide frame.
var approvalColumns = []tableColumn{
	{header: "ID", min: 12, max: 14},
	{header: "HOST", min: 6, max: 20, weight: 1},
	{header: "COMMAND", min: 12, weight: 4},
	{header: "KIND", min: 4, max: 6, right: true},
}

func approvalRow(req approval.PendingRequest) []string {
	return []string{
		shortApprovalID(req.ID),
		req.Host,
		req.Cmd,
		kindLabel(req),
	}
}

// kindLabel classifies a request by what host-allow would free — the same split
// the consequence line spells out for the focused row.
func kindLabel(req approval.PendingRequest) string {
	switch {
	case !req.Candidate.Promotable:
		return "priv"
	case req.Candidate.Kind == approval.MatcherPrefix:
		return "prefix"
	default:
		return "exact"
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

// chooserLine renders the Enter-driven verdict menu that replaces the footer
// hints while open: once / session / host / deny with the focused option
// bracketed and highlighted, mirroring the Info pane's auth-mode chooser.
func (s approvalsSection) chooserLine() string {
	choices := s.choices()
	cells := make([]string, len(choices))
	for i, c := range choices {
		if i == s.choiceIdx {
			cells[i] = s.styles.cursor.Render("[" + c.label + "]")
		} else {
			cells[i] = s.styles.dim.Render(" " + c.label + " ")
		}
	}
	return s.styles.dim.Render("decide: ") + strings.Join(cells, " ")
}

func (s approvalsSection) visibleRows() int {
	// Body height minus the table header, the separator, the consequence line,
	// and a possible status/overflow line.
	v := s.h - 4
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
