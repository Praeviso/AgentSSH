package tui

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/Praeviso/AgentSSH/internal/audit"
	"github.com/Praeviso/AgentSSH/internal/session"
	"github.com/Praeviso/AgentSSH/internal/theme"
	"github.com/charmbracelet/bubbles/help"
	"github.com/charmbracelet/bubbles/key"
	"github.com/charmbracelet/bubbles/textinput"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// sessionGroup is one collapsible session block in the viewer. records are held
// in seq-descending order (most recent first) for display.
type sessionGroup struct {
	id           string
	label        string
	agent        string
	start        string
	end          string
	commandCount int
	records      []audit.Record
	denied       int
	failed       int
	expanded     bool
}

type rowKind int

const (
	rowHeader rowKind = iota
	rowRecord
)

// row is a flattened projection of the (possibly expanded) session groups.
type row struct {
	kind rowKind
	gi   int // group index
	ri   int // record index within the group
}

type focus int

const (
	focusList focus = iota
	focusDetail
	focusFilter
)

type keyMap struct {
	Up      key.Binding
	Down    key.Binding
	Toggle  key.Binding
	Detail  key.Binding
	Session key.Binding
	Verify  key.Binding
	Filter  key.Binding
	Back    key.Binding
}

func defaultKeys() keyMap {
	return keyMap{
		Up:      key.NewBinding(key.WithKeys("up", "k")),
		Down:    key.NewBinding(key.WithKeys("down", "j")),
		Toggle:  key.NewBinding(key.WithKeys("enter", " ")),
		Detail:  key.NewBinding(key.WithKeys("d")),
		Session: key.NewBinding(key.WithKeys("l")),
		Verify:  key.NewBinding(key.WithKeys("v")),
		Filter:  key.NewBinding(key.WithKeys("/")),
		Back:    key.NewBinding(key.WithKeys("esc")),
	}
}

type styles struct {
	bar    lipgloss.Style
	header lipgloss.Style
	cursor lipgloss.Style
	dim    lipgloss.Style
	normal lipgloss.Style
	panel  lipgloss.Style
	prod   lipgloss.Style
	ok     lipgloss.Style
	bad    lipgloss.Style
	deny   lipgloss.Style
	glyphs theme.Glyphs
}

func newStyles(r *lipgloss.Renderer) styles {
	return styles{
		bar:    r.NewStyle().Bold(true),
		header: r.NewStyle().Bold(true).Foreground(theme.Accent),
		cursor: r.NewStyle().Foreground(theme.Cursor).Bold(true),
		dim:    r.NewStyle().Foreground(theme.Dim),
		normal: r.NewStyle(),
		panel:  r.NewStyle().Border(lipgloss.RoundedBorder()).Padding(0, 1),
		prod:   r.NewStyle().Foreground(theme.Prod).Bold(true),
		ok:     r.NewStyle().Foreground(theme.Success).Bold(true),
		bad:    r.NewStyle().Foreground(theme.Danger).Bold(true),
		deny:   r.NewStyle().Foreground(theme.Deny).Bold(true),
		glyphs: theme.GlyphsFor(r),
	}
}

type verifyMsg struct {
	result audit.VerifyResult
	err    error
}

func verifyCmd(fn func() (audit.VerifyResult, error)) tea.Cmd {
	return func() tea.Msg {
		result, err := fn()
		return verifyMsg{result: result, err: err}
	}
}

type model struct {
	allRecords      []audit.Record
	hosts           map[string]HostMeta
	groups          []sessionGroup
	rows            []row
	cursor          int
	focus           focus
	filter          textinput.Model
	filterQuery     string
	prevFilterQuery string
	sessionFocus    string
	detail          viewport.Model
	keys            keyMap
	styles          styles
	verifying       bool
	verifyDone      bool
	verifyResult    audit.VerifyResult
	verifyErr       error
	brokenSeq       *uint64
	verifyFn        func() (audit.VerifyResult, error)
	w, h            int
	ready           bool
	expandedByID    map[string]bool
}

func newModel(records []audit.Record, hosts map[string]HostMeta, st styles, verify func() (audit.VerifyResult, error)) model {
	ti := textinput.New()
	ti.Placeholder = "free text · or host: skill: session: status:allow|deny|failed date:YYYY-MM-DD"
	ti.Prompt = "/ "

	m := model{
		allRecords:   records,
		hosts:        hosts,
		filter:       ti,
		keys:         defaultKeys(),
		styles:       st,
		verifyFn:     verify,
		verifying:    verify != nil,
		expandedByID: map[string]bool{},
	}
	// Build groups once; expand the most recent session by default for context.
	m.groups = buildGroups(records, "", "")
	if len(m.groups) > 0 {
		m.expandedByID[m.groups[0].id] = true
		m.groups[0].expanded = true
	}
	m.rebuildRows()
	return m
}

func (m *model) rebuildGroups() {
	m.groups = buildGroups(m.allRecords, m.filterQuery, m.sessionFocus)
	for i := range m.groups {
		if m.sessionFocus != "" {
			m.groups[i].expanded = true
			continue
		}
		m.groups[i].expanded = m.expandedByID[m.groups[i].id]
	}
	m.rebuildRows()
}

func (m *model) rebuildRows() {
	m.rows = m.rows[:0]
	for gi := range m.groups {
		m.rows = append(m.rows, row{kind: rowHeader, gi: gi})
		if m.groups[gi].expanded {
			for ri := range m.groups[gi].records {
				m.rows = append(m.rows, row{kind: rowRecord, gi: gi, ri: ri})
			}
		}
	}
	if m.cursor >= len(m.rows) {
		m.cursor = len(m.rows) - 1
	}
	if m.cursor < 0 {
		m.cursor = 0
	}
}

func (m model) verifyCommand() tea.Cmd {
	if m.verifyFn == nil {
		return nil
	}
	return verifyCmd(m.verifyFn)
}

// Init kicks off an automatic chain verification so the integrity badge resolves
// to ✓/✗ on launch — a tamper-evidence tool must not show "unknown" by default.
// Returns nil when no verify function is wired (e.g. in tests).
func (m model) Init() tea.Cmd { return m.verifyCommand() }

func (m model) title() string { return "Audit" }

func (m model) capturing() bool { return m.focus == focusFilter }

func (m model) withSessionFilter(id string) model {
	m.sessionFocus = id
	m.filterQuery = ""
	m.prevFilterQuery = ""
	m.filter.SetValue("")
	m.filter.Blur()
	m.focus = focusList
	m.cursor = 0
	m.rebuildGroups()
	return m
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.w, m.h = msg.Width, msg.Height
		dw := msg.Width/2 - 4
		if dw < 10 {
			dw = 10
		}
		dh := msg.Height - 5
		if dh < 3 {
			dh = 3
		}
		if !m.ready {
			m.detail = viewport.New(dw, dh)
			m.ready = true
		} else {
			m.detail.Width, m.detail.Height = dw, dh
		}
		return m, nil
	case verifyMsg:
		m.applyVerify(msg)
		return m, nil
	case tea.KeyMsg:
		switch m.focus {
		case focusFilter:
			return m.updateFilter(msg)
		case focusDetail:
			return m.updateDetail(msg)
		default:
			return m.updateList(msg)
		}
	}
	// Forward non-key messages (e.g. the text cursor blink tick) to the filter
	// while it is focused so its blink animation keeps running.
	if m.focus == focusFilter {
		var cmd tea.Cmd
		m.filter, cmd = m.filter.Update(msg)
		return m, cmd
	}
	return m, nil
}

func (m model) updateList(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch {
	case key.Matches(msg, m.keys.Up):
		if m.cursor > 0 {
			m.cursor--
		}
	case key.Matches(msg, m.keys.Down):
		if m.cursor < len(m.rows)-1 {
			m.cursor++
		}
	case key.Matches(msg, m.keys.Toggle):
		if len(m.rows) == 0 {
			return m, nil
		}
		r := m.rows[m.cursor]
		if r.kind == rowHeader {
			id := m.groups[r.gi].id
			m.groups[r.gi].expanded = !m.groups[r.gi].expanded
			m.expandedByID[id] = m.groups[r.gi].expanded
			m.rebuildRows()
		} else {
			m.openDetail(r)
		}
	case key.Matches(msg, m.keys.Detail):
		if len(m.rows) > 0 {
			if r := m.rows[m.cursor]; r.kind == rowRecord {
				m.openDetail(r)
			}
		}
	case key.Matches(msg, m.keys.Session):
		if len(m.rows) > 0 {
			if m.sessionFocus == "" {
				// The synthetic no-session group has id "" which doubles as the
				// no-focus sentinel, so it cannot be focused.
				if id := m.groups[m.rows[m.cursor].gi].id; id != "" {
					m.sessionFocus = id
					m.cursor = 0
					m.rebuildGroups()
				}
			} else {
				m.sessionFocus = ""
				m.cursor = 0
				m.rebuildGroups()
			}
		}
	case key.Matches(msg, m.keys.Verify):
		if m.verifyFn != nil {
			m.verifying = true
		}
		return m, m.verifyCommand()
	case key.Matches(msg, m.keys.Filter):
		m.focus = focusFilter
		m.prevFilterQuery = m.filterQuery
		m.filter.SetValue(m.filterQuery)
		return m, m.filter.Focus()
	case key.Matches(msg, m.keys.Back):
		switch {
		case m.sessionFocus != "":
			m.sessionFocus = ""
			m.cursor = 0
			m.rebuildGroups()
		case m.filterQuery != "":
			m.filterQuery = ""
			m.filter.SetValue("")
			m.cursor = 0
			m.rebuildGroups()
		}
	}
	return m, nil
}

func (m *model) openDetail(r row) {
	rec := m.groups[r.gi].records[r.ri]
	m.detail.SetContent(renderDetail(rec, m.hosts))
	m.detail.GotoTop()
	m.focus = focusDetail
}

func (m model) updateDetail(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch {
	case key.Matches(msg, m.keys.Back), key.Matches(msg, m.keys.Detail):
		m.focus = focusList
		return m, nil
	case key.Matches(msg, m.keys.Verify):
		if m.verifyFn != nil {
			m.verifying = true
		}
		return m, m.verifyCommand()
	}
	var cmd tea.Cmd
	m.detail, cmd = m.detail.Update(msg)
	return m, cmd
}

func (m model) updateFilter(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch {
	case msg.Type == tea.KeyEnter:
		m.filterQuery = m.filter.Value()
		m.filter.Blur()
		m.focus = focusList
		m.cursor = 0
		m.rebuildGroups()
		return m, nil
	case key.Matches(msg, m.keys.Back):
		// Cancel: revert to the query committed before filter mode was entered.
		m.filter.Blur()
		m.filterQuery = m.prevFilterQuery
		m.filter.SetValue(m.prevFilterQuery)
		m.focus = focusList
		m.cursor = 0
		m.rebuildGroups()
		return m, nil
	}
	var cmd tea.Cmd
	m.filter, cmd = m.filter.Update(msg)
	// Live filtering as the user types.
	m.filterQuery = m.filter.Value()
	m.cursor = 0
	m.rebuildGroups()
	return m, cmd
}

func (m *model) applyVerify(msg verifyMsg) {
	m.verifying = false
	m.verifyDone = true
	m.verifyResult = msg.result
	m.verifyErr = msg.err
	m.brokenSeq = nil
	if msg.err == nil && !msg.result.OK {
		seq := msg.result.BrokenSeq
		m.brokenSeq = &seq
	}
}

func (m model) View() string {
	if !m.ready {
		return "loading…"
	}
	bar := m.styles.bar.Render(m.statusBar())

	var right string
	if m.focus == focusDetail {
		right = m.styles.panel.Render(m.detail.View())
	} else {
		right = m.styles.panel.Render(m.detailHint())
	}
	left := m.styles.normal.Width(m.leftWidth()).Render(m.renderList())
	body := lipgloss.JoinHorizontal(lipgloss.Top, left, right)

	if m.focus == focusFilter {
		return lipgloss.JoinVertical(lipgloss.Left, bar, body, m.filter.View())
	}
	return lipgloss.JoinVertical(lipgloss.Left, bar, body)
}

func (m model) statusBar() string {
	records := 0
	for _, g := range m.groups {
		records += len(g.records)
	}
	parts := []string{fmt.Sprintf("AgentSSH · Audit · %d records · %d sessions", records, len(m.groups))}
	parts = append(parts, m.chainStatus())
	if m.filterQuery != "" {
		parts = append(parts, fmt.Sprintf("filter=%q", m.filterQuery))
	}
	if m.sessionFocus != "" {
		parts = append(parts, "session focus")
	}
	return strings.Join(parts, " · ")
}

func (m model) chainStatus() string {
	if !m.verifyDone {
		if m.verifying {
			return m.styles.dim.Render("链 … 校验中")
		}
		return m.styles.dim.Render("链 ? (press v)")
	}
	if m.verifyErr != nil {
		return m.styles.bad.Render("链 verify error")
	}
	if m.verifyResult.OK {
		if m.verifyResult.Count == 0 {
			return m.styles.ok.Render("链 " + m.styles.glyphs.Check + " 完整 (empty)")
		}
		return m.styles.ok.Render(fmt.Sprintf("链 %s 完整 (0..%d)", m.styles.glyphs.Check, m.verifyResult.Count-1))
	}
	return m.styles.bad.Render(fmt.Sprintf("链 %s 断于 seq=%d · %s", m.styles.glyphs.Cross, m.verifyResult.BrokenSeq, reasonText(m.verifyResult.Reason)))
}

func (m model) helpKeyMap() help.KeyMap {
	switch {
	case m.focus == focusFilter:
		return helpMap{short: []key.Binding{hk("enter", "apply"), hk("esc", "cancel")}}
	case m.focus == focusDetail:
		return helpMap{short: []key.Binding{hk("esc", "back"), hk("v", "verify")}}
	case m.sessionFocus != "":
		return helpMap{short: []key.Binding{hk("j/k", "move"), hk("enter", "detail"), hk("v", "verify"), hk("esc", "exit focus")}}
	default:
		return helpMap{short: []key.Binding{hk("j/k", "move"), hk("enter", "expand"), hk("d", "detail"), hk("l", "focus session"), hk("v", "verify"), hk("/", "filter")}}
	}
}

func (m model) detailHint() string {
	if len(m.rows) == 0 {
		return "no audit records — run 'agentssh run …' first"
	}
	return "select a run and press enter (or d) for details"
}

func (m model) leftWidth() int {
	if m.w <= 0 {
		return 40
	}
	w := m.w/2 - 2
	if w < 20 {
		w = 20
	}
	return w
}

func (m model) listHeight() int {
	h := m.h - 4
	if h < 1 {
		h = 1
	}
	return h
}

func (m model) renderList() string {
	if len(m.rows) == 0 {
		return m.styles.dim.Render("No audit records yet.\nThey appear after the agent runs: agentssh run <host> -- <cmd>")
	}
	height := m.listHeight()
	start := 0
	if m.cursor >= height {
		start = m.cursor - height + 1
	}
	end := start + height
	if end > len(m.rows) {
		end = len(m.rows)
	}
	var b strings.Builder
	for i := start; i < end; i++ {
		b.WriteString(m.renderRow(i))
		b.WriteString("\n")
	}
	return b.String()
}

func (m model) renderRow(i int) string {
	r := m.rows[i]
	g := m.groups[r.gi]
	cursor := "  "
	if i == m.cursor {
		cursor = m.styles.cursor.Render("> ")
	}
	if r.kind == rowHeader {
		mark := "▸"
		if g.expanded {
			mark = "▾"
		}
		label := labelOr(g.label)
		var head string
		if g.id == "" {
			head = fmt.Sprintf("%s %s  %s  %s–%s  %d cmd",
				mark, label, orDash(g.agent), clockOf(g.start), clockOf(g.end), g.commandCount)
		} else {
			head = fmt.Sprintf("%s %s  %q  %s  %s–%s  %d cmd",
				mark, g.id, label, orDash(g.agent), clockOf(g.start), clockOf(g.end), g.commandCount)
		}
		line := cursor + m.styles.header.Render(head)
		if !g.expanded && (g.denied > 0 || g.failed > 0) {
			line += "\n     " + m.styles.bad.Render(anomalySummary(g))
		}
		return line
	}

	rec := g.records[r.ri]
	host := rec.Host
	if isProd(m.hosts, rec.Host) {
		host += " " + m.styles.prod.Render("[prod]")
	}
	skill := orDash(rec.Skill)
	exit := "-"
	if rec.ExitCode != nil {
		exit = strconv.Itoa(*rec.ExitCode)
	}
	body := fmt.Sprintf("    %s %s  %s  %s  %s  %s/%s · exit %s · %s",
		iconFor(m.styles.glyphs, rec.Event), clockOf(rec.TS), host, skill, truncate(rec.Cmd, 40),
		rec.PolicyAction, rec.PolicyRule, exit, durStr(rec.DurationMS))

	style := m.styles.normal
	switch {
	case m.brokenSeq != nil && *m.brokenSeq == rec.Seq:
		body += "  " + m.styles.glyphs.Warn + " TAMPERED"
		style = m.styles.bad
	case rec.Event == audit.EventDenied:
		style = m.styles.deny
	case rec.Event == audit.EventFailed:
		style = m.styles.bad
	}
	return cursor + style.Render(body)
}

// ---- pure helpers (unit-tested) ----

func buildGroups(records []audit.Record, query string, sessionFocus string) []sessionGroup {
	filtered := make([]audit.Record, 0, len(records))
	for _, r := range records {
		if recordMatches(r, query) {
			filtered = append(filtered, r)
		}
	}

	groups := make([]sessionGroup, 0)
	for _, summary := range session.Summaries(filtered) {
		recs := audit.FilterRecords(filtered, audit.Filters{SessionID: summary.ID})
		groups = append(groups, makeGroup(summary.ID, summary.Label, summary.Start, summary.End, summary.CommandCount, recs))
	}

	var noSession []audit.Record
	for _, r := range filtered {
		if r.SessionID == "" {
			noSession = append(noSession, r)
		}
	}
	if len(noSession) > 0 {
		start, end := spanOf(noSession)
		groups = append(groups, makeGroup("", "(no session)", start, end, countReqIDs(noSession), noSession))
	}

	if sessionFocus != "" {
		focused := make([]sessionGroup, 0, 1)
		for _, g := range groups {
			if g.id == sessionFocus {
				focused = append(focused, g)
			}
		}
		return focused
	}
	return groups
}

func makeGroup(id, label, start, end string, commandCount int, recs []audit.Record) sessionGroup {
	g := sessionGroup{id: id, label: label, start: start, end: end, commandCount: commandCount}
	// Display most-recent-first.
	g.records = make([]audit.Record, len(recs))
	for i, r := range recs {
		g.records[len(recs)-1-i] = r
	}
	for _, r := range g.records {
		if r.Agent != "" && g.agent == "" {
			g.agent = r.Agent
		}
		switch r.Event {
		case audit.EventDenied:
			g.denied++
		case audit.EventFailed:
			g.failed++
		}
	}
	return g
}

// filterSpec is a parsed filter query: optional scoped dimensions plus free text.
type filterSpec struct {
	free    []string
	host    string
	skill   string
	session string
	status  string
	date    string
}

func parseFilter(query string) filterSpec {
	var spec filterSpec
	for _, token := range strings.Fields(query) {
		lower := strings.ToLower(token)
		switch {
		case strings.HasPrefix(lower, "host:"):
			spec.host = lower[len("host:"):]
		case strings.HasPrefix(lower, "skill:"):
			spec.skill = lower[len("skill:"):]
		case strings.HasPrefix(lower, "session:"):
			spec.session = lower[len("session:"):]
		case strings.HasPrefix(lower, "status:"):
			spec.status = lower[len("status:"):]
		case strings.HasPrefix(lower, "date:"):
			spec.date = token[len("date:"):]
		default:
			spec.free = append(spec.free, lower)
		}
	}
	return spec
}

func recordMatches(r audit.Record, query string) bool {
	spec := parseFilter(query)
	if spec.host != "" && !strings.Contains(strings.ToLower(r.Host), spec.host) {
		return false
	}
	if spec.skill != "" && !strings.Contains(strings.ToLower(r.Skill), spec.skill) {
		return false
	}
	if spec.session != "" &&
		!strings.Contains(strings.ToLower(r.SessionID), spec.session) &&
		!strings.Contains(strings.ToLower(r.SessionLabel), spec.session) {
		return false
	}
	if spec.status != "" && !statusMatches(r, spec.status) {
		return false
	}
	if spec.date != "" && !strings.HasPrefix(r.TS, spec.date) {
		return false
	}
	for _, token := range spec.free {
		if !anyFieldContains(r, token) {
			return false
		}
	}
	return true
}

// statusMatches maps the spec'd status vocabulary to the right field: allow/deny
// compare the policy action, lifecycle events compare the event.
func statusMatches(r audit.Record, status string) bool {
	switch status {
	case "allow", "deny":
		return strings.EqualFold(r.PolicyAction, status)
	case "started", "completed", "failed", "denied":
		return string(r.Event) == status
	default:
		return strings.Contains(strings.ToLower(string(r.Event)), status) ||
			strings.Contains(strings.ToLower(r.PolicyAction), status)
	}
}

func anyFieldContains(r audit.Record, token string) bool {
	fields := []string{
		r.Host, r.Skill, r.SessionID, r.SessionLabel, r.Cmd,
		string(r.Event), r.TS, r.PolicyAction, r.PolicyRule, r.ReqID,
	}
	for _, f := range fields {
		if strings.Contains(strings.ToLower(f), token) {
			return true
		}
	}
	return false
}

func renderDetail(rec audit.Record, hosts map[string]HostMeta) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Record seq %d · req %s\n\n", rec.Seq, orDash(rec.ReqID))
	fmt.Fprintf(&b, "Agent    %s\n", orDash(rec.Agent))
	fmt.Fprintf(&b, "Time     %s\n", orDash(rec.TS))
	fmt.Fprintf(&b, "Session  %s %s\n", orDash(rec.SessionID), labelOr(rec.SessionLabel))
	fmt.Fprintf(&b, "Skill    %s\n", orDash(rec.Skill))
	fmt.Fprintf(&b, "Host     %s\n", hostLine(rec.Host, hosts))
	if meta, ok := hosts[rec.Host]; ok && len(meta.Tags) > 0 {
		fmt.Fprintf(&b, "Tags     %s\n", strings.Join(meta.Tags, ", "))
	}
	fmt.Fprintf(&b, "Command  %s\n", rec.Cmd)
	fmt.Fprintf(&b, "Policy   %s ← %s\n", rec.PolicyAction, orDash(rec.PolicyRule))
	exit := "-"
	if rec.ExitCode != nil {
		exit = strconv.Itoa(*rec.ExitCode)
	}
	fmt.Fprintf(&b, "Exit     %s · %s · truncated %t · redactions %d\n",
		exit, durStr(rec.DurationMS), rec.OutputTruncated, rec.Redactions)
	fmt.Fprintf(&b, "Output   sha256 %s\n", orDash(rec.OutputSHA256))
	fmt.Fprintf(&b, "Chain    prev %s\n", orDash(rec.PrevHash))
	fmt.Fprintf(&b, "         hash %s\n", orDash(rec.Hash))
	return b.String()
}

func reasonText(reason string) string {
	switch reason {
	case "seq":
		return "seq out of order"
	case "prev_hash":
		return "chain link broken (record deleted/inserted?)"
	case "hash":
		return "record body altered"
	default:
		return reason
	}
}

func iconFor(g theme.Glyphs, event audit.Event) string {
	switch event {
	case audit.EventCompleted:
		return g.Check
	case audit.EventFailed:
		return g.Cross
	case audit.EventDenied:
		return g.Deny
	case audit.EventStarted:
		return g.OK
	default:
		return g.Absent
	}
}

func isProd(hosts map[string]HostMeta, host string) bool {
	meta, ok := hosts[host]
	if !ok {
		return false
	}
	for _, tag := range meta.Tags {
		if tag == "prod" {
			return true
		}
	}
	return false
}

func anomalySummary(g sessionGroup) string {
	var parts []string
	if g.denied > 0 {
		parts = append(parts, fmt.Sprintf("%d denied", g.denied))
	}
	if g.failed > 0 {
		parts = append(parts, fmt.Sprintf("%d failed", g.failed))
	}
	return "⚠ " + strings.Join(parts, " · ")
}

func hostLine(host string, hosts map[string]HostMeta) string {
	meta, ok := hosts[host]
	if !ok || (meta.User == "" && meta.Addr == "") {
		return host
	}
	target := meta.Addr
	if meta.User != "" {
		target = meta.User + "@" + meta.Addr
	}
	line := fmt.Sprintf("%s (%s)", host, target)
	if isProd(hosts, host) {
		line += " [prod]"
	}
	return line
}

func countReqIDs(records []audit.Record) int {
	seen := map[string]struct{}{}
	for _, r := range records {
		if r.ReqID != "" {
			seen[r.ReqID] = struct{}{}
		}
	}
	return len(seen)
}

func spanOf(records []audit.Record) (string, string) {
	if len(records) == 0 {
		return "", ""
	}
	start, end := records[0].TS, records[0].TS
	for _, r := range records {
		if r.TS < start {
			start = r.TS
		}
		if r.TS > end {
			end = r.TS
		}
	}
	return start, end
}

func clockOf(ts string) string {
	if ts == "" {
		return "--:--:--"
	}
	t, err := time.Parse(time.RFC3339, ts)
	if err != nil {
		return ts
	}
	return t.Format("15:04:05")
}

func durStr(ms int64) string {
	if ms <= 0 {
		return "-"
	}
	if ms < 1000 {
		return fmt.Sprintf("%dms", ms)
	}
	return fmt.Sprintf("%.1fs", float64(ms)/1000)
}

func labelOr(label string) string {
	if label == "" {
		return "(none)"
	}
	return label
}

func orDash(value string) string {
	if value == "" {
		return "-"
	}
	return value
}

func truncate(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	if n <= 1 {
		return string(r[:n])
	}
	return string(r[:n-1]) + "…"
}
