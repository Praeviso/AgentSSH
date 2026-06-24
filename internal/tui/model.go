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
	hostFilter      string // when set, only sessions bound to this host are shown
	detailGroup     int
	runCursor       int
	keys            keyMap
	styles          styles
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
		detailGroup: -1,
	}
	m.groups = buildGroups(records, "", "")
	m.rebuildRows()
	return m
}

func (m *model) rebuildGroups() {
	records := m.allRecords
	if m.hostFilter != "" {
		records = recordsForHost(records, m.hostFilter)
	}
	m.groups = buildGroups(records, m.filterQuery, m.sessionFocus)
	m.rebuildRows()
}

// recordsForHost keeps only the audit records bound to host (exact match), so the
// session viewer in a host's detail shows that host's sessions and no others.
func recordsForHost(records []audit.Record, host string) []audit.Record {
	out := make([]audit.Record, 0, len(records))
	for _, r := range records {
		if r.Host == host {
			out = append(out, r)
		}
	}
	return out
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

func (m model) title() string { return "Sessions" }

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

// withHostFilter scopes the viewer to the sessions bound to host, resetting any
// active text filter, session focus, and cursor. Used by the host detail screen.
func (m model) withHostFilter(host string) model {
	m.hostFilter = host
	m.sessionFocus = ""
	m.filterQuery = ""
	m.prevFilterQuery = ""
	m.filter.SetValue("")
	m.filter.Blur()
	m.focus = focusList
	m.cursor = 0
	m.detailGroup = -1
	m.rebuildGroups()
	return m
}

// atRoot reports whether the viewer is at its base list (no command detail, text
// filter, or session focus open), so the shell's esc exits the detail screen.
func (m model) atRoot() bool {
	return m.focus == focusList && m.sessionFocus == "" && m.filterQuery == ""
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
	// The bare "Sessions" label is redundant with the breadcrumb above, so the
	// status bar appears only when it carries state (active filter, session focus,
	// or an audit-integrity warning).
	var parts []string
	if bar := m.statusBar(); bar != "" {
		parts = append(parts, m.styles.bar.Render(bar))
	}
	if m.focus == focusDetail {
		parts = append(parts, m.renderSessionDetail())
		return lipgloss.JoinVertical(lipgloss.Left, parts...)
	}
	// MaxWidth (not Width) truncates an over-wide line instead of wrapping it, so a
	// row that can't fit even at all-min columns (a sub-resize terminal) clips at
	// the frame edge rather than spilling onto a second line.
	parts = append(parts, m.styles.normal.MaxWidth(m.contentWidth()).Render(m.renderList()))
	if m.focus == focusFilter {
		parts = append(parts, m.filter.View())
	}
	return lipgloss.JoinVertical(lipgloss.Left, parts...)
}

// statusBar is the contextual rail above the list/detail: it shows an active
// filter, session focus, or an audit-integrity warning, and is empty otherwise
// (the pane identity already lives in the shell breadcrumb).
func (m model) statusBar() string {
	var parts []string
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

// barLines is the number of lines the status bar occupies (0 when it is empty).
func (m model) barLines() int {
	if m.statusBar() == "" {
		return 0
	}
	return 1
}

// chainBadge is the audit integrity signal. Verification runs automatically on
// launch and is transparent to the operator: while it is in flight, or once it
// confirms the chain is intact, this shows nothing. It surfaces only when there is
// a problem to report — a verification error, or a detected tamper break.
func (m model) chainBadge() string {
	if !m.verifyDone {
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

func (m model) helpKeyMap() help.KeyMap {
	switch {
	case m.focus == focusFilter:
		return helpMap{short: []key.Binding{hk("enter", "apply"), hk("esc", "cancel")}}
	case m.focus == focusDetail:
		return helpMap{short: []key.Binding{hk("j/k", "commands"), hk("esc", "sessions")}}
	case m.sessionFocus != "":
		return helpMap{short: []key.Binding{hk("j/k", "move"), hk("enter", "open"), hk("esc", "exit focus")}}
	default:
		return helpMap{short: []key.Binding{hk("j/k", "move"), hk("enter", "open"), hk("d", "open"), hk("l", "focus session"), hk("/", "filter")}}
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
	// Chrome above the command rows: the one-line session header, the divider and
	// its blank line, and the table header (four lines), plus the optional status
	// bar. Each command renders as a single table row.
	rows := m.h - 4 - m.barLines()
	if rows < 1 {
		return 1
	}
	return rows
}

func (m model) listHeight() int {
	// The audit body is the (optional) status bar plus the list (plus the filter
	// input when filtering); m.h is the height the shell allocated to this section.
	h := m.h - m.barLines()
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
		if m.hostFilter != "" {
			return m.styles.dim.Render(fmt.Sprintf("No sessions for %s yet.\nThey appear after the agent runs: agentssh run %s -- <cmd>", m.hostFilter, m.hostFilter))
		}
		return m.styles.dim.Render("No sessions recorded yet.\nThey appear after the agent runs: agentssh run <host> -- <cmd>")
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
	widths := sessionListWidths(m.styles.glyphs, m.groups[start:end], m.contentWidth())
	b.WriteString(m.styles.dim.Render(sessionListHeader(widths)))
	b.WriteString("\n")
	for i := start; i < end; i++ {
		b.WriteString(m.renderRow(i, widths))
		b.WriteString("\n")
	}
	return b.String()
}

func (m model) renderRow(i int, widths sessionListColumnWidths) string {
	r := m.rows[i]
	g := m.groups[r.gi]
	cursor := "  "
	if i == m.cursor {
		cursor = m.styles.cursor.Render("> ")
	}
	cells := []string{
		padRight(truncate(sessionListID(g), widths.id), widths.id),
		padRight(truncate(labelOr(g.label), widths.label), widths.label),
		padRight(truncate(sessionWindow(g), widths.window), widths.window),
		padLeft(strconv.Itoa(g.commandCount), widths.cmds),
		padLeft(sessionCountCell(m.styles.glyphs, g.denied), widths.den),
		padLeft(sessionCountCell(m.styles.glyphs, g.failed), widths.fail),
	}
	head := strings.Join(cells, "  ")
	// Calm palette: rows render in the default color. Only a tamper-evidence break
	// — the one state an audit viewer must never let blend in — is flagged in red.
	if sessionHasBrokenSeq(g, m.brokenSeq) {
		return cursor + m.styles.bad.Render(head+"  "+m.styles.glyphs.Warn+" TAMPERED")
	}
	return cursor + head
}

type sessionListColumnWidths struct {
	id     int
	label  int
	window int
	cmds   int
	den    int
	fail   int
}

// sessionListWidths fits the six session-list columns into availableWidth so the
// row stays on one line at the default terminal size and spreads to fill a wide one
// (see fitColumns). LABEL carries the scanning value, so it absorbs the slack on a
// wide frame and the brunt of a narrow squeeze; WINDOW and the CMDS/DEN/FAIL counts
// are rigid so the clock span and the numbers never truncate. The list is always
// scoped to one host (the detail screen), so it has no HOSTS column.
func sessionListWidths(glyphs theme.Glyphs, groups []sessionGroup, availableWidth int) sessionListColumnWidths {
	nat := sessionListColumnWidths{
		id:     lipgloss.Width("ID"),
		label:  lipgloss.Width("LABEL"),
		window: lipgloss.Width("WINDOW"),
		cmds:   lipgloss.Width("CMDS"),
		den:    lipgloss.Width("DEN"),
		fail:   lipgloss.Width("FAIL"),
	}
	for _, g := range groups {
		nat.id = maxInt(nat.id, lipgloss.Width(sessionListID(g)))
		nat.label = maxInt(nat.label, lipgloss.Width(labelOr(g.label)))
		nat.window = maxInt(nat.window, lipgloss.Width(sessionWindow(g)))
		nat.cmds = maxInt(nat.cmds, lipgloss.Width(strconv.Itoa(g.commandCount)))
		nat.den = maxInt(nat.den, lipgloss.Width(sessionCountCell(glyphs, g.denied)))
		nat.fail = maxInt(nat.fail, lipgloss.Width(sessionCountCell(glyphs, g.failed)))
	}

	fits := []colFit{
		// ID is rigid at its (capped) content width: a session identifier must never
		// truncate to a stub the operator can't act on, so it holds its width and the
		// squeeze falls on LABEL instead.
		{min: lipgloss.Width("ID"), max: 18, weight: 0},
		// LABEL is the uncapped stretch column: it takes the brunt of a narrow squeeze
		// and absorbs all the slack on a wide frame, so the row fills the terminal
		// naturally instead of capping short and leaving a dead strip on the right.
		{min: lipgloss.Width("LABEL"), max: 0, weight: 3},
		{min: nat.window, max: nat.window}, // WINDOW: rigid clock span
		{min: nat.cmds, max: nat.cmds},     // CMDS: rigid count
		{min: nat.den, max: nat.den},       // DEN: rigid count
		{min: nat.fail, max: nat.fail},     // FAIL: rigid count
	}
	natural := []int{nat.id, nat.label, nat.window, nat.cmds, nat.den, nat.fail}
	// Budget = availableWidth minus the 2-col cursor and the five 2-space gutters
	// between the six columns.
	w := fitColumns(fits, natural, availableWidth-2-2*5)
	return sessionListColumnWidths{
		id:     w[0],
		label:  w[1],
		window: w[2],
		cmds:   w[3],
		den:    w[4],
		fail:   w[5],
	}
}

func sessionListHeader(w sessionListColumnWidths) string {
	cells := []string{
		padRight("ID", w.id),
		padRight("LABEL", w.label),
		padRight("WINDOW", w.window),
		padLeft("CMDS", w.cmds),
		padLeft("DEN", w.den),
		padLeft("FAIL", w.fail),
	}
	return "  " + strings.Join(cells, "  ")
}

// sessionListID is the session identifier shown in the list; the synthetic
// no-session bucket (id "") renders as "(none)".
func sessionListID(g sessionGroup) string {
	if g.id == "" {
		return "(none)"
	}
	return g.id
}

// sessionWindow renders a session's active span as start–end wall clocks, far
// narrower than two RFC3339 stamps and stable in width for a rigid column.
func sessionWindow(g sessionGroup) string {
	return clockOf(g.start) + "–" + clockOf(g.end)
}

// sessionCountCell shows n, or the absent glyph ("·"/".") when zero, so a non-zero
// denied/failed count stands out in a column of mostly-zeros without needing color.
func sessionCountCell(glyphs theme.Glyphs, n int) string {
	if n == 0 {
		return glyphs.Absent
	}
	return strconv.Itoa(n)
}

func padRight(value string, width int) string {
	padding := width - lipgloss.Width(value)
	if padding <= 0 {
		return value
	}
	return value + strings.Repeat(" ", padding)
}

func padLeft(value string, width int) string {
	padding := width - lipgloss.Width(value)
	if padding <= 0 {
		return value
	}
	return strings.Repeat(" ", padding) + value
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
	// Single-line header: session id + label and the bound host with its user@ip,
	// all on one row. Over-wide content is clamped by the final MaxWidth below.
	fmt.Fprintf(&b, "%s\n", m.renderSessionHeader(g))
	fmt.Fprintf(&b, "%s\n\n", m.styles.dim.Render(strings.Repeat("─", clamp(w, 1, 72))))
	b.WriteString(m.renderCommandList(g))
	// Clamp every line to the frame so an over-wide row truncates (ANSI aware)
	// instead of wrapping onto a second row under the shell's Width().
	return m.styles.normal.MaxWidth(w).Render(b.String())
}

// renderCommandList renders the session's commands as a responsive, aligned table
// (one row per command, newest first) that fits the frame the same way the session
// list does — columns squeeze on a narrow terminal and spread on a wide one.
func (m model) renderCommandList(g sessionGroup) string {
	if len(g.runs) == 0 {
		return m.styles.dim.Render("No commands matched this session.")
	}
	avail := m.contentWidth()
	start, end := scrollWindow(m.runCursor, len(g.runs), m.detailCommandHeight())
	widths := commandListWidths(m.styles.glyphs, g.runs[start:end], avail)
	var b strings.Builder
	b.WriteString(m.styles.dim.Render(commandListHeader(widths)))
	for i := start; i < end; i++ {
		b.WriteString("\n")
		b.WriteString(m.renderCommandRow(g.runs[i], widths, i == m.runCursor))
	}
	return b.String()
}

// renderSessionHeader is the session detail's single identity line: the session id
// and label (bold), then the bound host with its user@ip connection (dim context).
// Aggregate statistics (command/denied/failed counts, last-activity clock) are
// intentionally omitted — each command below shows its own status and time. Tamper
// evidence stays: it is a security signal, not a statistic.
func (m model) renderSessionHeader(g sessionGroup) string {
	parts := []string{m.styles.header.Render(orDash(g.id) + " · " + labelOr(g.label))}
	if host := sessionHost(g); host != "" {
		parts = append(parts, m.styles.dim.Render(hostLine(host, m.hosts)))
	}
	if sessionHasBrokenSeq(g, m.brokenSeq) {
		parts = append(parts, m.styles.bad.Render(m.styles.glyphs.Warn+" tamper evidence in this session"))
	}
	return strings.Join(parts, m.styles.dim.Render(" · "))
}

type commandListColumnWidths struct {
	status int
	cmd    int
	policy int
	exit   int
	dur    int
	clock  int
	notes  int
}

// commandListWidths fits the seven command columns into availableWidth so each
// command row stays on one line at the default size and spreads to fill a wide
// one. COMMAND is the uncapped stretch column (it takes the slack and the brunt of
// a squeeze); STATUS/EXIT/DUR/TIME are rigid so the outcome, codes, and clock never
// truncate; POLICY and OUTPUT flex within caps.
func commandListWidths(glyphs theme.Glyphs, runs []runSummary, availableWidth int) commandListColumnWidths {
	nat := commandListColumnWidths{
		status: lipgloss.Width("STATUS"),
		cmd:    lipgloss.Width("COMMAND"),
		policy: lipgloss.Width("POLICY"),
		exit:   lipgloss.Width("EXIT"),
		dur:    lipgloss.Width("DUR"),
		clock:  lipgloss.Width("TIME"),
		notes:  lipgloss.Width("OUTPUT"),
	}
	for _, run := range runs {
		nat.status = maxInt(nat.status, lipgloss.Width(commandStatus(glyphs, run)))
		nat.cmd = maxInt(nat.cmd, lipgloss.Width(run.latest.Cmd))
		nat.policy = maxInt(nat.policy, lipgloss.Width(commandPolicyCell(run)))
		nat.exit = maxInt(nat.exit, lipgloss.Width(runExit(run)))
		nat.dur = maxInt(nat.dur, lipgloss.Width(durStr(run.latest.DurationMS)))
		nat.clock = maxInt(nat.clock, lipgloss.Width(clockOf(run.end)))
		nat.notes = maxInt(nat.notes, lipgloss.Width(commandOutputCell(glyphs, run.latest)))
	}
	fits := []colFit{
		{min: nat.status, max: nat.status},                  // STATUS: rigid outcome
		{min: lipgloss.Width("COMMAND"), max: 0, weight: 3}, // COMMAND: stretch column
		{min: lipgloss.Width("POLICY"), max: 28, weight: 2}, // POLICY: action/rule
		{min: nat.exit, max: nat.exit},                      // EXIT: rigid code
		{min: nat.dur, max: nat.dur},                        // DUR: rigid
		{min: nat.clock, max: nat.clock},                    // TIME: rigid clock
		{min: lipgloss.Width("OUTPUT"), max: 24, weight: 1}, // OUTPUT: squeezable notes
	}
	natural := []int{nat.status, nat.cmd, nat.policy, nat.exit, nat.dur, nat.clock, nat.notes}
	// Budget = availableWidth minus the 2-col cursor and the six 2-space gutters.
	w := fitColumns(fits, natural, availableWidth-2-2*6)
	return commandListColumnWidths{
		status: w[0], cmd: w[1], policy: w[2], exit: w[3], dur: w[4], clock: w[5], notes: w[6],
	}
}

func commandListHeader(w commandListColumnWidths) string {
	cells := []string{
		padRight("STATUS", w.status),
		padRight("COMMAND", w.cmd),
		padRight("POLICY", w.policy),
		padLeft("EXIT", w.exit),
		padLeft("DUR", w.dur),
		padRight("TIME", w.clock),
		padRight("OUTPUT", w.notes),
	}
	return "  " + strings.Join(cells, "  ")
}

func (m model) renderCommandRow(run runSummary, w commandListColumnWidths, selected bool) string {
	rec := run.latest
	cursor := "  "
	if selected {
		cursor = m.styles.cursor.Render("> ")
	}
	cells := []string{
		padRight(truncate(commandStatus(m.styles.glyphs, run), w.status), w.status),
		padRight(truncate(rec.Cmd, w.cmd), w.cmd),
		padRight(truncate(commandPolicyCell(run), w.policy), w.policy),
		padLeft(truncate(runExit(run), w.exit), w.exit),
		padLeft(truncate(durStr(rec.DurationMS), w.dur), w.dur),
		padRight(truncate(clockOf(run.end), w.clock), w.clock),
		padRight(truncate(commandOutputCell(m.styles.glyphs, rec), w.notes), w.notes),
	}
	head := strings.Join(cells, "  ")
	// Calm palette: the STATUS glyph (✓/✗/⊘) carries the outcome, so rows render in
	// the default color. Only a tamper break or a genuine failure takes a color.
	if runHasSeq(run, m.brokenSeq) {
		return cursor + m.styles.bad.Render(head+"  "+m.styles.glyphs.Warn+" TAMPERED")
	}
	if rec.Event == audit.EventFailed {
		return cursor + m.styles.bad.Render(head)
	}
	return cursor + head
}

// commandPolicyCell is the POLICY column: the decision and the rule that made it.
func commandPolicyCell(run runSummary) string {
	return orDash(run.latest.PolicyAction) + "/" + orDash(run.latest.PolicyRule)
}

// commandOutputCell is the OUTPUT column: a compact note on output handling. Clean
// output reads as the absent glyph so only truncation or redaction draws the eye.
func commandOutputCell(glyphs theme.Glyphs, rec audit.Record) string {
	var parts []string
	if rec.OutputTruncated {
		parts = append(parts, "trunc")
	}
	if rec.Redactions > 0 {
		parts = append(parts, fmt.Sprintf("red %d", rec.Redactions))
	}
	if len(parts) == 0 {
		return glyphs.Absent
	}
	return strings.Join(parts, " · ")
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

// sessionHost is the single host a session is bound to: the first non-empty host
// across its runs. Sessions are one-host by construction, so this is unambiguous.
func sessionHost(g sessionGroup) string {
	for _, run := range g.runs {
		if run.latest.Host != "" {
			return run.latest.Host
		}
	}
	return ""
}

func sessionHasBrokenSeq(g sessionGroup, seq *uint64) bool {
	for _, run := range g.runs {
		if runHasSeq(run, seq) {
			return true
		}
	}
	return false
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

func hostLine(host string, hosts map[string]HostMeta) string {
	meta, ok := hosts[host]
	if !ok || (meta.User == "" && meta.Addr == "") {
		return host
	}
	target := meta.Addr
	if meta.User != "" {
		target = meta.User + "@" + meta.Addr
	}
	return fmt.Sprintf("%s (%s)", host, target)
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
