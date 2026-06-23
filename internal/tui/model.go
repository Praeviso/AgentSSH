package tui

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Praeviso/AgentSSH/internal/audit"
	"github.com/Praeviso/AgentSSH/internal/theme"
	"github.com/charmbracelet/bubbles/help"
	"github.com/charmbracelet/bubbles/key"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
)

// sessionGroup is one operator-facing session row. runs are held in
// most-recent-first order and render as command results in the session detail.
type sessionGroup struct {
	id           string
	label        string
	agent        string
	start        string
	end          string
	commandCount int
	runs         []runSummary
	denied       int
	failed       int
	running      int
}

// runSummary is the operator-facing unit in Audit: one agentssh run request,
// backed by one or more append-only audit records for hash-chain evidence.
type runSummary struct {
	reqID   string
	records []audit.Record // chronological / seq-ascending
	latest  audit.Record
	start   string
	end     string
}

// row is the visible session-list projection. Audit intentionally does not put
// runs in this top-level list; commands only appear inside a selected session.
type row struct {
	gi int // group index
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
	detailGroup     int
	runCursor       int
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
}

func newModel(records []audit.Record, hosts map[string]HostMeta, st styles, verify func() (audit.VerifyResult, error)) model {
	ti := textinput.New()
	ti.Placeholder = "free text · or host: session: status:allow|deny|failed date:YYYY-MM-DD"
	ti.Prompt = "/ "

	m := model{
		allRecords:  records,
		hosts:       hosts,
		filter:      ti,
		keys:        defaultKeys(),
		styles:      st,
		verifyFn:    verify,
		verifying:   verify != nil,
		detailGroup: -1,
	}
	m.groups = buildGroups(records, "", "")
	m.rebuildRows()
	return m
}

func (m *model) rebuildGroups() {
	m.groups = buildGroups(m.allRecords, m.filterQuery, m.sessionFocus)
	m.rebuildRows()
}

func (m *model) rebuildRows() {
	m.rows = m.rows[:0]
	for gi := range m.groups {
		m.rows = append(m.rows, row{gi: gi})
	}
	if m.cursor >= len(m.rows) {
		m.cursor = len(m.rows) - 1
	}
	if m.cursor < 0 {
		m.cursor = 0
	}
	if m.detailGroup >= len(m.groups) {
		m.detailGroup = -1
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
		m.ready = true
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
		m.openSessionDetail(m.rows[m.cursor].gi)
	case key.Matches(msg, m.keys.Detail):
		if len(m.rows) > 0 {
			m.openSessionDetail(m.rows[m.cursor].gi)
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

func (m *model) openSessionDetail(groupIndex int) {
	if groupIndex < 0 || groupIndex >= len(m.groups) {
		return
	}
	m.detailGroup = groupIndex
	m.runCursor = 0
	m.focus = focusDetail
}

func (m model) updateDetail(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch {
	case key.Matches(msg, m.keys.Back), key.Matches(msg, m.keys.Detail):
		m.focus = focusList
		m.detailGroup = -1
		return m, nil
	case key.Matches(msg, m.keys.Up):
		if m.runCursor > 0 {
			m.runCursor--
		}
	case key.Matches(msg, m.keys.Down):
		if g, ok := m.detailSession(); ok && m.runCursor < len(g.runs)-1 {
			m.runCursor++
		}
	case key.Matches(msg, m.keys.Verify):
		if m.verifyFn != nil {
			m.verifying = true
		}
		return m, m.verifyCommand()
	}
	return m, nil
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
	if m.focus == focusDetail {
		return lipgloss.JoinVertical(lipgloss.Left, bar, m.renderSessionDetail())
	}
	// MaxWidth (not Width) truncates an over-wide line instead of wrapping it, so a
	// row that can't fit even at all-min columns (a sub-resize terminal) clips at
	// the frame edge rather than spilling onto a second line.
	body := m.styles.normal.MaxWidth(m.contentWidth()).Render(m.renderList())

	if m.focus == focusFilter {
		return lipgloss.JoinVertical(lipgloss.Left, bar, body, m.filter.View())
	}
	return lipgloss.JoinVertical(lipgloss.Left, bar, body)
}

func (m model) statusBar() string {
	parts := []string{"Audit"}
	if m.filterQuery != "" {
		parts = append(parts, fmt.Sprintf("filter=%q", m.filterQuery))
	}
	if m.sessionFocus != "" {
		parts = append(parts, "session focus")
	}
	if chain := m.chainBadge(); chain != "" {
		parts = append(parts, chain)
	}
	return strings.Join(parts, " · ")
}

func (m model) chainBadge() string {
	if !m.verifyDone {
		if m.verifying {
			return m.styles.dim.Render("审计日志校验中")
		}
		return ""
	}
	if m.verifyErr != nil {
		return m.styles.bad.Render("审计日志校验失败")
	}
	if m.verifyResult.OK {
		return ""
	}
	return m.styles.bad.Render(fmt.Sprintf("审计日志异常 seq=%d", m.verifyResult.BrokenSeq))
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
		return helpMap{short: []key.Binding{hk("j/k", "commands"), hk("esc", "sessions"), hk("v", "verify")}}
	case m.sessionFocus != "":
		return helpMap{short: []key.Binding{hk("j/k", "move"), hk("enter", "open"), hk("v", "verify"), hk("esc", "exit focus")}}
	default:
		return helpMap{short: []key.Binding{hk("j/k", "move"), hk("enter", "open"), hk("d", "open"), hk("l", "focus session"), hk("v", "verify"), hk("/", "filter")}}
	}
}

func (m model) contentWidth() int {
	if m.w <= 0 {
		return 80
	}
	if m.w < 20 {
		return 20
	}
	return m.w
}

// detailWidth is the column budget for the session-detail view. Unlike
// contentWidth it returns a no-clamp sentinel when the size is unknown (w<=0), so
// a direct unit render (no WindowSizeMsg yet) keeps full content instead of
// truncating to a default width.
func (m model) detailWidth() int {
	if m.w <= 0 {
		return 1 << 20
	}
	return m.w
}

func (m model) detailCommandHeight() int {
	// Reserve space for the status bar, session title, summary, divider, and
	// footer. Each command result currently renders as two lines plus spacing.
	h := m.h - 7
	if h < 2 {
		return 1
	}
	rows := h / 3
	if rows < 1 {
		return 1
	}
	return rows
}

func (m model) listHeight() int {
	// The audit body is the status bar line plus the list (plus the filter input
	// when filtering); m.h is the height the shell allocated to this section.
	h := m.h - 1
	if m.focus == focusFilter {
		h--
	}
	if h < 1 {
		h = 1
	}
	return h
}

func (m model) renderList() string {
	if len(m.rows) == 0 {
		return m.styles.dim.Render("No audited sessions yet.\nThey appear after the agent runs: agentssh run <host> -- <cmd>")
	}
	height := m.listHeight() - 1 // reserve one line for the column header
	if height < 1 {
		height = 1
	}
	start := 0
	if m.cursor >= height {
		start = m.cursor - height + 1
	}
	end := start + height
	if end > len(m.rows) {
		end = len(m.rows)
	}
	var b strings.Builder
	widths := auditListWidths(m.styles.glyphs, m.groups[start:end], m.hosts, m.contentWidth())
	b.WriteString(m.styles.dim.Render(auditListHeader(widths)))
	b.WriteString("\n")
	for i := start; i < end; i++ {
		b.WriteString(m.renderRow(i, widths))
		b.WriteString("\n")
	}
	return b.String()
}

func (m model) renderRow(i int, widths auditListColumnWidths) string {
	r := m.rows[i]
	g := m.groups[r.gi]
	cursor := "  "
	if i == m.cursor {
		cursor = m.styles.cursor.Render("> ")
	}
	label := labelOr(g.label)
	unit := "commands"
	if g.commandCount == 1 {
		unit = "command"
	}
	status := sessionStatus(m.styles.glyphs, g)
	updated := "updated " + clockOf(g.end)
	host := sessionHosts(g, m.hosts)
	counts := sessionCounts(g)
	sessionID := g.id
	if sessionID == "" {
		sessionID = "(none)"
	}
	cmds := fmt.Sprintf("%d %s", g.commandCount, unit)
	cells := []string{
		padRight(truncate(status, widths.status), widths.status),
		padRight(truncate(sessionID, widths.session), widths.session),
		padRight(truncate(label, widths.label), widths.label),
		padRight(truncate(updated, widths.updated), widths.updated),
		padRight(truncate(cmds, widths.commands), widths.commands),
		padRight(truncate(host, widths.hosts), widths.hosts),
		truncate(counts, widths.flags),
	}
	head := strings.Join(cells, "  ")
	if counts == "" {
		head = strings.TrimRight(head, " ")
	}
	switch {
	case sessionHasBrokenSeq(g, m.brokenSeq):
		return cursor + m.styles.bad.Render(head+"  "+m.styles.glyphs.Warn+" TAMPERED")
	case g.failed > 0:
		return cursor + m.styles.bad.Render(head)
	case g.denied > 0:
		return cursor + m.styles.deny.Render(head)
	case g.running > 0:
		return cursor + m.styles.header.Render(head)
	default:
		return cursor + head
	}
}

type auditListColumnWidths struct {
	status   int
	session  int
	label    int
	updated  int
	commands int
	hosts    int
	flags    int
}

// auditListWidths fits the seven session-list columns into availableWidth so the
// row stays on one line at the default terminal size and spreads to fill a wide
// one (see fitColumns). LABEL and HOSTS carry the scanning value, so they take
// the lion's share of slack and the brunt of the squeeze; STATUS/UPDATED/COMMANDS
// are rigid so the glyph word, the clock, and the count never truncate.
func auditListWidths(glyphs theme.Glyphs, groups []sessionGroup, hosts map[string]HostMeta, availableWidth int) auditListColumnWidths {
	nat := auditListColumnWidths{
		status:   lipgloss.Width("STATUS"),
		session:  lipgloss.Width("SESSION"),
		label:    lipgloss.Width("LABEL"),
		updated:  lipgloss.Width("UPDATED"),
		commands: lipgloss.Width("COMMANDS"),
		hosts:    lipgloss.Width("HOSTS"),
		flags:    lipgloss.Width("FLAGS"),
	}
	for _, g := range groups {
		sessionID := g.id
		if sessionID == "" {
			sessionID = "(none)"
		}
		unit := "commands"
		if g.commandCount == 1 {
			unit = "command"
		}
		nat.status = maxInt(nat.status, lipgloss.Width(sessionStatus(glyphs, g)))
		nat.session = maxInt(nat.session, lipgloss.Width(sessionID))
		nat.label = maxInt(nat.label, lipgloss.Width(labelOr(g.label)))
		nat.updated = maxInt(nat.updated, lipgloss.Width("updated "+clockOf(g.end)))
		nat.commands = maxInt(nat.commands, lipgloss.Width(fmt.Sprintf("%d %s", g.commandCount, unit)))
		nat.hosts = maxInt(nat.hosts, lipgloss.Width(sessionHosts(g, hosts)))
		nat.flags = maxInt(nat.flags, lipgloss.Width(sessionCounts(g)))
	}

	fits := []colFit{
		{min: nat.status, max: nat.status},                   // STATUS: rigid at content
		{min: lipgloss.Width("SESSION"), max: 16, weight: 1}, // SESSION
		{min: lipgloss.Width("LABEL"), max: 48, weight: 3},   // LABEL
		{min: nat.updated, max: nat.updated},                 // UPDATED: rigid (fixed clock)
		{min: nat.commands, max: nat.commands},               // COMMANDS: rigid
		{min: lipgloss.Width("HOSTS"), max: 48, weight: 2},   // HOSTS
		{min: lipgloss.Width("FLAGS"), max: 24, weight: 1},   // FLAGS (anomaly counts)
	}
	natural := []int{nat.status, nat.session, nat.label, nat.updated, nat.commands, nat.hosts, nat.flags}
	// Budget = availableWidth minus the 2-col cursor and the six 2-space gutters
	// between the seven columns.
	w := fitColumns(fits, natural, availableWidth-2-2*6)
	return auditListColumnWidths{
		status:   w[0],
		session:  w[1],
		label:    w[2],
		updated:  w[3],
		commands: w[4],
		hosts:    w[5],
		flags:    w[6],
	}
}

func auditListHeader(w auditListColumnWidths) string {
	cells := []string{
		padRight("STATUS", w.status),
		padRight("SESSION", w.session),
		padRight("LABEL", w.label),
		padRight("UPDATED", w.updated),
		padRight("COMMANDS", w.commands),
		padRight("HOSTS", w.hosts),
		"FLAGS",
	}
	return "  " + strings.Join(cells, "  ")
}

func padRight(value string, width int) string {
	padding := width - lipgloss.Width(value)
	if padding <= 0 {
		return value
	}
	return value + strings.Repeat(" ", padding)
}

// ---- pure helpers (unit-tested) ----

func buildGroups(records []audit.Record, query string, sessionFocus string) []sessionGroup {
	runs := buildRuns(records)
	filtered := make([]runSummary, 0, len(runs))
	for _, run := range runs {
		if runMatches(run, query) {
			filtered = append(filtered, run)
		}
	}

	grouped := map[string][]runSummary{}
	for _, run := range filtered {
		grouped[run.latest.SessionID] = append(grouped[run.latest.SessionID], run)
	}

	groups := make([]sessionGroup, 0, len(grouped))
	for id, runs := range grouped {
		if id == "" {
			continue
		}
		groups = append(groups, makeGroup(id, runs))
	}
	sort.Slice(groups, func(i, j int) bool {
		return groups[i].end > groups[j].end
	})

	if noSession := grouped[""]; len(noSession) > 0 {
		groups = append(groups, makeGroup("", noSession))
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

func buildRuns(records []audit.Record) []runSummary {
	byReq := map[string][]audit.Record{}
	order := make([]string, 0)
	for _, record := range records {
		id := record.ReqID
		if id == "" {
			id = fmt.Sprintf("seq:%d", record.Seq)
		}
		if _, ok := byReq[id]; !ok {
			order = append(order, id)
		}
		byReq[id] = append(byReq[id], record)
	}

	runs := make([]runSummary, 0, len(byReq))
	for _, id := range order {
		recs := append([]audit.Record(nil), byReq[id]...)
		sort.Slice(recs, func(i, j int) bool {
			return recs[i].Seq < recs[j].Seq
		})
		run := runSummary{reqID: recs[len(recs)-1].ReqID, records: recs, latest: recs[len(recs)-1]}
		run.start, run.end = spanOf(recs)
		runs = append(runs, run)
	}
	sort.SliceStable(runs, func(i, j int) bool {
		return runs[i].end > runs[j].end
	})
	return runs
}

func makeGroup(id string, runs []runSummary) sessionGroup {
	g := sessionGroup{id: id, label: "(no session)", commandCount: len(runs)}
	if id != "" {
		g.label = firstNonEmptyLabel(runs)
	}
	g.runs = append([]runSummary(nil), runs...)
	sort.SliceStable(g.runs, func(i, j int) bool {
		return g.runs[i].end > g.runs[j].end
	})
	if len(g.runs) > 0 {
		g.start = g.runs[0].start
		g.end = g.runs[0].end
	}
	for _, run := range g.runs {
		if run.start < g.start || g.start == "" {
			g.start = run.start
		}
		if run.end > g.end {
			g.end = run.end
		}
		if run.latest.Agent != "" && g.agent == "" {
			g.agent = run.latest.Agent
		}
		switch run.latest.Event {
		case audit.EventDenied:
			g.denied++
		case audit.EventFailed:
			g.failed++
		case audit.EventStarted:
			g.running++
		}
	}
	return g
}

func firstNonEmptyLabel(runs []runSummary) string {
	for _, run := range runs {
		if run.latest.SessionLabel != "" {
			return run.latest.SessionLabel
		}
	}
	return ""
}

// filterSpec is a parsed filter query: optional scoped dimensions plus free text.
type filterSpec struct {
	free    []string
	host    string
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

func runMatches(run runSummary, query string) bool {
	r := run.latest
	spec := parseFilter(query)
	if spec.host != "" && !strings.Contains(strings.ToLower(r.Host), spec.host) {
		return false
	}
	if spec.session != "" &&
		!strings.Contains(strings.ToLower(r.SessionID), spec.session) &&
		!strings.Contains(strings.ToLower(r.SessionLabel), spec.session) {
		return false
	}
	if spec.status != "" && !statusMatches(run, spec.status) {
		return false
	}
	if spec.date != "" && !runDateMatches(run, spec.date) {
		return false
	}
	for _, token := range spec.free {
		if !anyRunFieldContains(run, token) {
			return false
		}
	}
	return true
}

// statusMatches maps the spec'd status vocabulary to the right field: allow/deny
// compare the policy action, lifecycle events compare the run's latest event.
func statusMatches(run runSummary, status string) bool {
	r := run.latest
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

func runDateMatches(run runSummary, date string) bool {
	for _, r := range run.records {
		if strings.HasPrefix(r.TS, date) {
			return true
		}
	}
	return false
}

func anyRunFieldContains(run runSummary, token string) bool {
	r := run.latest
	fields := []string{
		run.reqID, r.Host, r.SessionID, r.SessionLabel, r.Cmd,
		string(r.Event), r.TS, r.PolicyAction, r.PolicyRule, r.ReqID,
	}
	for _, f := range fields {
		if strings.Contains(strings.ToLower(f), token) {
			return true
		}
	}
	return false
}

func (m model) detailSession() (sessionGroup, bool) {
	if m.detailGroup >= 0 && m.detailGroup < len(m.groups) {
		return m.groups[m.detailGroup], true
	}
	if m.cursor >= 0 && m.cursor < len(m.rows) {
		return m.groups[m.rows[m.cursor].gi], true
	}
	return sessionGroup{}, false
}

func (m model) renderSessionDetail() string {
	g, ok := m.detailSession()
	if !ok {
		return m.styles.dim.Render("No session selected.")
	}
	m.runCursor = clamp(m.runCursor, 0, len(g.runs)-1)
	w := m.detailWidth()
	var b strings.Builder
	title := fmt.Sprintf("Session %s · %s", orDash(g.id), labelOr(g.label))
	fmt.Fprintf(&b, "%s\n", m.styles.header.Render(truncate(title, w)))
	// Keep the hint short enough to fit one line at the default width; the full
	// "records stay hidden" caveat lives in the docs and the v/verify affordance.
	fmt.Fprintf(&b, "%s\n\n", m.styles.dim.Render(truncate("Commands in this session, newest first. Press v to verify the chain.", w)))
	fmt.Fprintf(&b, "%s\n", m.renderSessionSummary(g))
	fmt.Fprintf(&b, "%s\n\n", m.styles.dim.Render(strings.Repeat("─", clamp(w, 1, 72))))
	start, end := scrollWindow(m.runCursor, len(g.runs), m.detailCommandHeight())
	for i := start; i < end; i++ {
		run := g.runs[i]
		if i > 0 {
			b.WriteString("\n")
		}
		b.WriteString(m.renderCommandResult(run, i == m.runCursor))
	}
	if len(g.runs) == 0 {
		fmt.Fprintf(&b, "%s\n", m.styles.dim.Render("No commands matched this session."))
	}
	// Clamp every line to the frame so a long summary/meta line truncates (ANSI
	// aware) instead of wrapping onto a second row under the shell's Width().
	return m.styles.normal.MaxWidth(w).Render(b.String())
}

func (m model) renderSessionSummary(g sessionGroup) string {
	parts := []string{
		fmt.Sprintf("%d %s", g.commandCount, plural(g.commandCount, "command", "commands")),
		"updated " + clockOf(g.end),
		"agent " + orDash(g.agent),
	}
	if hosts := sessionHosts(g, m.hosts); hosts != "" {
		parts = append(parts, "hosts "+hosts)
	}
	if totals := sessionCounts(g); totals != "" {
		parts = append(parts, totals)
	}
	if sessionHasBrokenSeq(g, m.brokenSeq) {
		parts = append(parts, m.styles.bad.Render(m.styles.glyphs.Warn+" tamper evidence in this session"))
	}
	return strings.Join(parts, " · ")
}

func (m model) renderCommandResult(run runSummary, selected bool) string {
	rec := run.latest
	cursor := "  "
	if selected {
		cursor = m.styles.cursor.Render("> ")
	}
	status := commandStatus(m.styles.glyphs, run)
	line := fmt.Sprintf("%s%s  %s", cursor, status, truncate(rec.Cmd, commandWidth(m.w)))
	if runHasSeq(run, m.brokenSeq) {
		line += "  " + m.styles.glyphs.Warn + " TAMPERED"
	}
	meta := fmt.Sprintf("    %s · host %s · policy %s/%s · exit %s · %s · %s",
		clockOf(run.end), hostLine(rec.Host, m.hosts), orDash(rec.PolicyAction), orDash(rec.PolicyRule),
		runExit(run), durStr(rec.DurationMS), outputSummary(rec))
	if rec.Event == audit.EventDenied {
		meta += " · not executed"
	}
	// The meta line is the widest part of a command result; cap it to the frame so
	// it never wraps. (Plain text here — safe to rune-truncate before styling.)
	meta = truncate(meta, m.detailWidth())
	out := line + "\n" + m.styles.dim.Render(meta)
	switch {
	case runHasSeq(run, m.brokenSeq):
		return m.styles.bad.Render(out)
	case rec.Event == audit.EventDenied:
		return m.styles.deny.Render(out)
	case rec.Event == audit.EventFailed:
		return m.styles.bad.Render(out)
	case rec.Event == audit.EventCompleted:
		return m.styles.normal.Render(out)
	default:
		return m.styles.header.Render(out)
	}
}

func sessionStatus(g theme.Glyphs, group sessionGroup) string {
	switch {
	case group.failed > 0:
		return g.Cross + " FAIL"
	case group.denied > 0:
		return g.Deny + " DENIED"
	case group.running > 0:
		return g.OK + " LIVE"
	default:
		return g.Check + " OK"
	}
}

func commandStatus(g theme.Glyphs, run runSummary) string {
	switch run.latest.Event {
	case audit.EventCompleted:
		return g.Check + " OK"
	case audit.EventFailed:
		return g.Cross + " FAILED"
	case audit.EventDenied:
		return g.Deny + " DENIED"
	case audit.EventStarted:
		return g.OK + " RUNNING"
	default:
		return g.Absent + " " + string(run.latest.Event)
	}
}

func sessionCounts(g sessionGroup) string {
	var parts []string
	if g.denied > 0 {
		parts = append(parts, fmt.Sprintf("%d denied", g.denied))
	}
	if g.failed > 0 {
		parts = append(parts, fmt.Sprintf("%d failed", g.failed))
	}
	if g.running > 0 {
		parts = append(parts, fmt.Sprintf("%d running", g.running))
	}
	return strings.Join(parts, " · ")
}

func sessionHosts(g sessionGroup, hosts map[string]HostMeta) string {
	seen := map[string]struct{}{}
	values := make([]string, 0, 2)
	for _, run := range g.runs {
		host := run.latest.Host
		if host == "" {
			continue
		}
		if _, ok := seen[host]; ok {
			continue
		}
		seen[host] = struct{}{}
		if len(values) < 2 {
			label := host
			if isProd(hosts, host) {
				label += " [prod]"
			}
			values = append(values, label)
		}
	}
	if len(seen) > len(values) {
		values = append(values, fmt.Sprintf("+%d", len(seen)-len(values)))
	}
	return strings.Join(values, ", ")
}

func sessionHasBrokenSeq(g sessionGroup, seq *uint64) bool {
	for _, run := range g.runs {
		if runHasSeq(run, seq) {
			return true
		}
	}
	return false
}

func outputSummary(record audit.Record) string {
	var parts []string
	if record.OutputTruncated {
		parts = append(parts, "output truncated")
	}
	if record.Redactions > 0 {
		parts = append(parts, fmt.Sprintf("redactions %d", record.Redactions))
	}
	if len(parts) == 0 {
		return "output clean"
	}
	return strings.Join(parts, " · ")
}

func runExit(run runSummary) string {
	if run.latest.ExitCode != nil {
		return strconv.Itoa(*run.latest.ExitCode)
	}
	if run.latest.Event == audit.EventDenied {
		return "6"
	}
	return "-"
}

func runHasSeq(run runSummary, seq *uint64) bool {
	if seq == nil {
		return false
	}
	for _, record := range run.records {
		if record.Seq == *seq {
			return true
		}
	}
	return false
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

func commandWidth(w int) int {
	if w <= 0 {
		return 76
	}
	if w < 64 {
		return 36
	}
	return w - 24
}

func clamp(value, min, max int) int {
	if max < min {
		return min
	}
	if value < min {
		return min
	}
	if value > max {
		return max
	}
	return value
}

func plural(n int, one string, many string) string {
	if n == 1 {
		return one
	}
	return many
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
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

// truncate caps a string to n display columns (not runes), appending an ellipsis
// when it has to cut. Measuring in display width — the same unit lipgloss.Width
// and every column budget use — is what keeps a wide-rune (CJK/emoji) cell from
// rendering at twice its allotted width and wrapping the row. ANSI-aware, so it
// is safe on already-styled strings too.
func truncate(s string, n int) string {
	if n <= 0 {
		return ""
	}
	if lipgloss.Width(s) <= n {
		return s
	}
	if n == 1 {
		return ansi.Truncate(s, 1, "")
	}
	return ansi.Truncate(s, n, "…")
}
