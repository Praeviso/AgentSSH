package tui

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/Praeviso/AgentSSH/internal/audit"
	"github.com/Praeviso/AgentSSH/internal/config"
	"github.com/Praeviso/AgentSSH/internal/inventory"
	"github.com/Praeviso/AgentSSH/internal/policy"
	"github.com/Praeviso/AgentSSH/internal/theme"
	"github.com/charmbracelet/bubbles/help"
	"github.com/charmbracelet/bubbles/key"
	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"gopkg.in/yaml.v3"
)

// helpMap adapts explicit short/full binding sets to bubbles/help.KeyMap.
type helpMap struct {
	short []key.Binding
	full  [][]key.Binding
}

func (h helpMap) ShortHelp() []key.Binding { return h.short }

func (h helpMap) FullHelp() [][]key.Binding {
	if h.full != nil {
		return h.full
	}
	return [][]key.Binding{h.short}
}

// hk is a terse constructor for a help-only key binding (the keys it lists are
// for display; actual handling lives in each section's Update).
func hk(keys, desc string) key.Binding {
	return key.NewBinding(key.WithKeys(keys), key.WithHelp(keys, desc))
}

// globalHelpKeys are the cross-screen bindings shown on the right of the footer.
func globalHelpKeys() []key.Binding {
	return []key.Binding{hk("?", "help"), hk("q", "quit")}
}

// combinedHelp merges a screen's bindings with the global ones for the footer.
type combinedHelp struct {
	section help.KeyMap
	global  []key.Binding
}

func (c combinedHelp) ShortHelp() []key.Binding {
	return append(c.section.ShortHelp(), c.global...)
}

func (c combinedHelp) FullHelp() [][]key.Binding {
	return append(c.section.FullHelp(), c.global)
}

// screen is the top-level navigation state: the entry tabs, or the split-pane
// detail of one selected host.
type screen int

const (
	screenEntry screen = iota
	screenDetail
)

const screenGrid = screenEntry

// entryTab is the active top-level tab on the entry screen.
type entryTab int

const (
	entryHosts entryTab = iota
	entryPolicy
)

func (t entryTab) title() string {
	if t == entryPolicy {
		return "Policy"
	}
	return "Hosts"
}

// detailPane is the active sub-view inside a host's detail screen.
type detailPane int

const (
	paneInfo detailPane = iota
	paneSessions
	panePolicy
)

func (p detailPane) title() string {
	switch p {
	case paneSessions:
		return "Sessions"
	case panePolicy:
		return "Policy"
	default:
		return "Info"
	}
}

// Minimum usable frame. Below this the chrome leaves no room for content, so we
// show a "resize" card instead of a broken layout.
const (
	minFrameWidth  = 40
	minFrameHeight = 11
)

const toastTTL = 3 * time.Second

// toastMsg asks the shell to show a transient success confirmation in the footer.
type toastMsg struct{ text string }

// toastExpiredMsg clears the toast if it is still the current one.
type toastExpiredMsg struct{ id int }

func toastCmd(text string) tea.Cmd {
	return func() tea.Msg { return toastMsg{text: text} }
}

type appModel struct {
	paths    config.Paths
	renderer *lipgloss.Renderer
	styles   appStyles
	hosts    hostsSection  // host card grid + add/discover/confirm overlays + host CRUD
	sessions model         // audit/session viewer (filtered to the selected host in detail)
	policy   policySection // global policy viewer (scoped to the selected host in detail)
	help     help.Model
	toast    string
	toastID  int
	w, h     int
	ready    bool
	firstRun bool // show the one-time welcome banner until the first keypress

	screen     screen
	entryTab   entryTab
	pane       detailPane
	detailHost string // the host whose detail screen is open
}

type appStyles struct {
	activeTab  lipgloss.Style
	inactive   lipgloss.Style
	crumb      lipgloss.Style
	err        lipgloss.Style
	ok         lipgloss.Style
	header     lipgloss.Style
	cursor     lipgloss.Style
	dim        lipgloss.Style
	panel      lipgloss.Style
	confirm    lipgloss.Style
	deny       lipgloss.Style
	card       lipgloss.Style
	cardSel    lipgloss.Style
	statusBar  lipgloss.Style
	background lipgloss.Style
	// table cell styles, shared by the aligned list renderer (see table.go).
	tableHeader lipgloss.Style
	tableSel    lipgloss.Style
	tableCell   lipgloss.Style
	// glyphs is the renderer-resolved status-glyph set (ASCII under NO_COLOR).
	glyphs theme.Glyphs
}

func newAppStyles(r *lipgloss.Renderer) appStyles {
	return appStyles{
		activeTab:  r.NewStyle().Padding(0, 1).Bold(true).Foreground(theme.AccentText).Background(theme.Accent),
		inactive:   r.NewStyle().Padding(0, 1).Foreground(theme.Dim),
		crumb:      r.NewStyle().Bold(true).Foreground(theme.Accent),
		err:        r.NewStyle().Foreground(theme.Danger).Bold(true),
		ok:         r.NewStyle().Foreground(theme.Success).Bold(true),
		header:     r.NewStyle().Bold(true).Foreground(theme.Accent),
		cursor:     r.NewStyle().Foreground(theme.Cursor).Bold(true),
		dim:        r.NewStyle().Foreground(theme.Dim),
		panel:      r.NewStyle().Border(lipgloss.RoundedBorder()).Padding(0, 1),
		confirm:    r.NewStyle().Foreground(theme.Warn).Bold(true),
		deny:       r.NewStyle().Foreground(theme.Deny).Bold(true),
		card:       r.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(theme.Border).Padding(0, 1),
		cardSel:    r.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(theme.Accent).Padding(0, 1),
		statusBar:  r.NewStyle().Border(lipgloss.NormalBorder(), false, false, true, false).BorderForeground(theme.Border),
		background: r.NewStyle(),

		tableHeader: r.NewStyle().Padding(0, 1).Bold(true).Foreground(theme.Dim),
		tableSel:    r.NewStyle().Padding(0, 1).Background(theme.SelBg),
		tableCell:   r.NewStyle().Padding(0, 1),

		glyphs: theme.GlyphsFor(r),
	}
}

// keyHint renders an actionable "[key] description" chip for empty states.
func keyHint(st appStyles, key, desc string) string {
	return st.cursor.Render("["+key+"]") + " " + st.dim.Render(desc)
}

func newAppModel(paths config.Paths, renderer *lipgloss.Renderer) appModel {
	st := newAppStyles(renderer)
	inv, invErr := inventory.Load(paths.InventoryFile)
	pol, polErr := loadPolicy(paths.PolicyFile)
	store := audit.NewStore(paths.AuditFile)
	records, _ := store.ReadAll()
	hosts := hostMetaFromInventory(inv)

	return appModel{
		paths:    paths,
		renderer: renderer,
		styles:   st,
		help:     help.New(),
		hosts:    newHostsSection(paths, renderer, st, inv, invErr),
		sessions: newModel(records, hosts, newStyles(renderer), func() (audit.VerifyResult, error) {
			return store.Verify()
		}),
		policy: newPolicySection(paths.PolicyFile, inv, pol, st, firstErr(invErr, polErr)),
	}
}

func loadPolicy(path string) (policy.Config, error) {
	var cfg policy.Config
	file, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return cfg, nil
	}
	if err != nil {
		return cfg, err
	}
	defer func() {
		_ = file.Close()
	}()
	if err := yaml.NewDecoder(file).Decode(&cfg); err != nil {
		return cfg, err
	}
	return cfg, nil
}

func firstErr(errs ...error) error {
	for _, err := range errs {
		if err != nil {
			return err
		}
	}
	return nil
}

func hostMetaFromInventory(inv inventory.Inventory) map[string]HostMeta {
	hosts := make(map[string]HostMeta, len(inv.Hosts))
	for name, host := range inv.Hosts {
		hosts[name] = HostMeta{User: host.User, Addr: host.Addr, Tags: host.Tags}
	}
	return hosts
}

func (m appModel) Init() tea.Cmd {
	return tea.Batch(m.hosts.Init(), m.sessions.Init(), m.policy.Init())
}

func (m appModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.w, m.h, m.ready = msg.Width, msg.Height, true
		m.help.Width = msg.Width
		return m.propagateSize()
	case inventoryChangedMsg:
		m.applyInventoryChange(msg.inventory)
		return m, nil
	case policyChangedMsg:
		m.policy.config = msg.config
		if msg.text != "" {
			return m, toastCmd(msg.text)
		}
		return m, nil
	case toastMsg:
		m.toastID++
		m.toast = msg.text
		id := m.toastID
		return m, tea.Tick(toastTTL, func(time.Time) tea.Msg { return toastExpiredMsg{id: id} })
	case toastExpiredMsg:
		if msg.id == m.toastID {
			m.toast = ""
		}
		return m, nil
	case verifyMsg:
		// Chain verification result — deliver to the sessions viewer regardless of
		// the active screen (it auto-verifies on launch while the grid is showing).
		return m.updateSessions(msg)
	case hostProbeMsg, discoveryLoadedMsg, discoveryProbedMsg, spinner.TickMsg:
		// Async Hosts results and the spinner tick must reach the Hosts section
		// regardless of screen; runID/host guards make stale delivery safe.
		return m.updateHosts(msg)
	case tea.KeyMsg:
		if msg.Type == tea.KeyCtrlC {
			return m, tea.Quit
		}
		if m.firstRun {
			// "press any key to begin": dismiss the one-time banner and re-propagate
			// sizes (its line is gone). The keystroke isn't wasted — it also performs
			// its normal action so the first key gets you moving, except q, so a
			// curious keypress can't quit on the greeting.
			m.firstRun = false
			var sizeCmd tea.Cmd
			m, sizeCmd = m.propagateSize()
			if msg.String() == "q" {
				return m, sizeCmd
			}
			next, keyCmd := m.updateKey(msg)
			return next, tea.Batch(sizeCmd, keyCmd)
		}
		return m.updateKey(msg)
	}
	// Non-key, non-async messages route to the active screen's components.
	if m.screen == screenDetail {
		return m.routeDetail(msg)
	}
	if m.entryTab == entryPolicy {
		return m.updatePolicy(msg)
	}
	return m.updateHosts(msg)
}

// updateKey dispatches a keypress to the active screen.
func (m appModel) updateKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	if m.screen == screenDetail {
		return m.updateDetailKey(msg)
	}
	return m.updateEntryKey(msg)
}

// updateEntryKey handles a keypress on the entry screen. The shell owns
// top-level tab navigation unless the active section is capturing text/modal
// input; section-specific keys are forwarded afterward.
func (m appModel) updateEntryKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	if !m.entryCapturing() {
		switch msg.String() {
		case "?":
			m.help.ShowAll = !m.help.ShowAll
			return m.propagateSize()
		case "q":
			return m, tea.Quit
		case "tab":
			m.entryTab = (m.entryTab + 1) % 2
			if m.entryTab == entryPolicy {
				m.policy = m.policy.withHost("")
			}
			return m.propagateSize()
		case "shift+tab":
			m.entryTab = (m.entryTab + 1) % 2
			if m.entryTab == entryPolicy {
				m.policy = m.policy.withHost("")
			}
			return m.propagateSize()
		case "1":
			m.entryTab = entryHosts
			return m.propagateSize()
		case "2":
			m.entryTab = entryPolicy
			m.policy = m.policy.withHost("")
			return m.propagateSize()
		}
	}
	if m.entryTab == entryPolicy {
		return m.updatePolicy(msg)
	}
	next, cmd := m.updateHosts(msg)
	mm := next.(appModel)
	// The Hosts tab signals "open this host" via hosts.open; transition to detail.
	if mm.hosts.open {
		mm.hosts.open = false
		return mm.enterDetail(mm.hosts.selectedHost())
	}
	return mm, cmd
}

// enterDetail opens the split-pane detail for host, scoping the sessions viewer
// and the policy pane to it, then resizes the panes to the detail layout.
func (m appModel) enterDetail(host string) (tea.Model, tea.Cmd) {
	if host == "" {
		return m, nil
	}
	m.screen = screenDetail
	m.pane = paneInfo
	m.detailHost = host
	m.hosts = m.hosts.resetInfoEdit()
	m.sessions = m.sessions.withHostFilter(host)
	m.policy = m.policy.withHost(host)
	return m.propagateSize()
}

// updateDetailKey handles keys on the detail screen: the active pane gets first
// refusal when it's capturing (a text input is open); otherwise the shell handles
// pane switching, back, and quit, and forwards the rest to the active pane.
func (m appModel) updateDetailKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	if m.paneCapturing() {
		return m.routeDetail(msg)
	}
	switch msg.String() {
	case "?":
		m.help.ShowAll = !m.help.ShowAll
		return m.propagateSize()
	case "q":
		return m, tea.Quit
	case "tab":
		m.pane = (m.pane + 1) % 3
		return m.propagateSize()
	case "shift+tab":
		m.pane = (m.pane + 2) % 3
		return m.propagateSize()
	case "1":
		m.pane = paneInfo
		return m.propagateSize()
	case "2":
		m.pane = paneSessions
		return m.propagateSize()
	case "3":
		m.pane = panePolicy
		return m.propagateSize()
	case "esc":
		// esc pops the active pane's own state first (e.g. a session's command
		// detail); only when the pane is already at its root does it exit to the grid.
		if m.paneAtRoot() {
			m.screen = screenEntry
			m.entryTab = entryHosts
			return m.propagateSize()
		}
		return m.routeDetail(msg)
	}
	return m.routeDetail(msg)
}

// routeDetail forwards a message to the active detail pane.
func (m appModel) routeDetail(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch m.pane {
	case paneInfo:
		return m.updateInfoPane(msg)
	case paneSessions:
		return m.updateSessions(msg)
	case panePolicy:
		return m.updatePolicy(msg)
	}
	return m, nil
}

// updateInfoPane handles keys for the Info pane, where the per-host actions live
// (the host's fields are on screen here, not on the card grid). The same field
// list is both the read view and the editor: j/k move a field cursor, enter edits
// the focused field in place, t probes, and d/x delete. Edits/probe/delete reuse
// the Hosts section's machinery (results land via hostProbeMsg/inventoryChangedMsg).
func (m appModel) updateInfoPane(msg tea.Msg) (tea.Model, tea.Cmd) {
	// The delete-confirm overlay owns the keyboard while open.
	if m.hosts.focus == hostFocusConfirm {
		return m.updateHosts(msg)
	}
	// An open inline field input owns the keyboard until it commits or cancels.
	if m.hosts.infoEditing {
		hs, cmd := m.hosts.updateInfoEdit(msg, m.detailHost)
		m.hosts = hs
		return m, cmd
	}
	keyMsg, ok := msg.(tea.KeyMsg)
	if !ok {
		return m, nil
	}
	switch keyMsg.String() {
	case "j", "down":
		m.hosts.infoFieldDown()
	case "k", "up":
		m.hosts.infoFieldUp()
	case "enter", "i":
		hs, cmd := m.hosts.beginInfoEdit(m.detailHost)
		m.hosts = hs
		return m, cmd
	case "t":
		hs, cmd := m.hosts.startProbe(m.detailHost)
		m.hosts = hs
		return m, cmd
	case "d", "x":
		m.hosts = m.hosts.startDelete(m.detailHost)
	}
	return m, nil
}

func (m appModel) updateHosts(msg tea.Msg) (tea.Model, tea.Cmd) {
	updated, cmd := m.hosts.Update(msg)
	if hs, ok := updated.(hostsSection); ok {
		m.hosts = hs
	}
	return m, cmd
}

func (m appModel) updateSessions(msg tea.Msg) (tea.Model, tea.Cmd) {
	updated, cmd := m.sessions.Update(msg)
	if sm, ok := updated.(model); ok {
		m.sessions = sm
	}
	return m, cmd
}

func (m appModel) updatePolicy(msg tea.Msg) (tea.Model, tea.Cmd) {
	updated, cmd := m.policy.Update(msg)
	if ps, ok := updated.(policySection); ok {
		m.policy = ps
	}
	return m, cmd
}

// paneCapturing reports whether the active detail pane owns the keyboard (a text
// input is open), so the shell must not steal tab/esc/q.
func (m appModel) paneCapturing() bool {
	switch m.pane {
	case paneSessions:
		return m.sessions.capturing()
	case panePolicy:
		return m.policy.capturing()
	case paneInfo:
		// The Info pane captures while editing a field inline or its delete-confirm is open.
		return m.hosts.infoEditing || m.hosts.focus == hostFocusConfirm
	default:
		return false
	}
}

// paneAtRoot reports whether the active pane is at its base state, so esc should
// exit the detail screen rather than pop an inner view.
func (m appModel) paneAtRoot() bool {
	switch m.pane {
	case paneSessions:
		return m.sessions.atRoot()
	case panePolicy:
		return m.policy.atRoot()
	default:
		return true
	}
}

// propagateSize forwards the current body dimensions to every component. Every
// screen and detail pane spans the full body — none carries an Info sidebar, so
// each gets the whole frame width.
func (m appModel) propagateSize() (appModel, tea.Cmd) {
	if m.w <= 0 || m.h <= 0 {
		return m, nil
	}
	var cmds []tea.Cmd
	body := m.bodyHeight()

	hs, cmd := m.hosts.Update(tea.WindowSizeMsg{Width: m.w, Height: body})
	if next, ok := hs.(hostsSection); ok {
		m.hosts = next
	}
	cmds = append(cmds, cmd)

	sm, cmd := m.sessions.Update(tea.WindowSizeMsg{Width: m.w, Height: body})
	if next, ok := sm.(model); ok {
		m.sessions = next
	}
	cmds = append(cmds, cmd)

	ps, cmd := m.policy.Update(tea.WindowSizeMsg{Width: m.w, Height: body})
	if next, ok := ps.(policySection); ok {
		m.policy = next
	}
	cmds = append(cmds, cmd)
	return m, tea.Batch(cmds...)
}

// bodyHeight is the height available to the body: the frame minus the status bar,
// the footer, and the one-time welcome banner.
func (m appModel) bodyHeight() int {
	h := m.h - lipgloss.Height(m.renderStatusBar()) - lipgloss.Height(m.renderFooter())
	if m.firstRun {
		h -= lipgloss.Height(m.welcomeBanner())
	}
	if h < 1 {
		h = 1
	}
	return h
}

func (m appModel) welcomeBanner() string {
	msg := m.styles.glyphs.Check + " Welcome to AgentSSH — created a starter inventory.yaml + policy.yaml. Press any key to begin."
	style := m.styles.ok
	if m.w > 0 {
		style = style.Width(m.w).MaxWidth(m.w)
	}
	return style.Render(msg)
}

func (m *appModel) applyInventoryChange(inv inventory.Inventory) {
	m.hosts.inventory = inv
	m.hosts.rebuildNames()
	m.sessions.hosts = hostMetaFromInventory(inv)
	m.policy.inventory = inv
	// A successful inventory change means inventory.yaml now parses, so clear a
	// stale parse error mirrored onto the policy pane.
	m.policy.err = nil
	// If the host whose detail is open was removed, fall back to the grid.
	if m.screen == screenDetail {
		if _, ok := inv.Hosts[m.detailHost]; !ok {
			m.screen = screenEntry
			m.entryTab = entryHosts
		}
	}
}

func (m appModel) View() string {
	if m.ready && (m.w < minFrameWidth || m.h < minFrameHeight) {
		return m.tooSmallView()
	}
	statusBar := m.renderStatusBar()
	footer := m.renderFooter()
	body := "loading..."
	if m.ready {
		if m.screen == screenDetail {
			body = m.renderDetail()
		} else if m.entryTab == entryPolicy {
			// The pane is already scoped to host "" whenever this tab is active (the
			// tab-switch handlers call withHost("")). Render it as-is — calling
			// withHost("") here would wipe the drilled-into card/group on every frame.
			body = m.policy.View()
		} else {
			body = m.hosts.View()
		}
	}

	if m.w > 0 && m.h > 0 {
		bodyH := m.bodyHeight()
		body = lipgloss.NewStyle().Width(m.w).MaxWidth(m.w).Height(bodyH).MaxHeight(bodyH).Render(body)
	}

	parts := make([]string, 0, 4)
	if m.firstRun {
		parts = append(parts, m.welcomeBanner())
	}
	parts = append(parts, statusBar, body, footer)
	return lipgloss.JoinVertical(lipgloss.Left, parts...)
}

// renderDetail renders the active pane of the selected host's detail screen. Each
// pane spans the full frame: Info is the host card, Sessions the audit viewer, and
// Policy the (host-scoped) permission model — none carries a sidebar.
func (m appModel) renderDetail() string {
	switch m.pane {
	case paneSessions:
		return m.sessions.View()
	case panePolicy:
		return m.policy.View()
	default:
		// The Info pane edits fields inline (rendered by infoView); only the
		// delete-confirm takes over the whole pane.
		if m.hosts.focus == hostFocusConfirm {
			return m.hosts.confirmCardView()
		}
		return m.hosts.infoView(m.detailHost, m.w-2, m.bodyHeight(), true)
	}
}

func (m appModel) tooSmallView() string {
	w, h := maxInt(m.w, 1), maxInt(m.h, 1)
	msg := fmt.Sprintf("Terminal too small.\nResize to at least %d×%d (have %d×%d).",
		minFrameWidth, minFrameHeight, m.w, m.h)
	clipped := make([]string, 0, 2)
	for _, ln := range strings.Split(msg, "\n") {
		clipped = append(clipped, truncate(ln, w))
	}
	placed := lipgloss.Place(w, h, lipgloss.Center, lipgloss.Center, m.styles.dim.Render(strings.Join(clipped, "\n")))
	return lipgloss.NewStyle().MaxWidth(w).MaxHeight(h).Render(placed)
}

// renderStatusBar is the persistent top rail: a breadcrumb. On the grid it names
// the app and host count; in detail it shows "AgentSSH › host" plus pane pips.
func (m appModel) renderStatusBar() string {
	var bar string
	if m.screen == screenDetail {
		crumb := m.styles.crumb.Render("AgentSSH") + m.styles.dim.Render(" › ") + m.detailCrumbHost()
		// In the Sessions pane, the drilled-into session's id rides on the breadcrumb
		// (its standalone identity line was removed in favor of this).
		if m.pane == paneSessions {
			if id, ok := m.sessions.detailSessionID(); ok && id != "" {
				crumb += m.styles.dim.Render(" › ") + m.styles.header.Render(id)
			}
		}
		pips := make([]string, 0, 3)
		for _, p := range []detailPane{paneInfo, paneSessions, panePolicy} {
			label := fmt.Sprintf("%d %s", int(p)+1, p.title())
			if p == m.pane {
				pips = append(pips, m.styles.activeTab.Render(label))
			} else {
				pips = append(pips, m.styles.inactive.Render(label))
			}
		}
		bar = lipgloss.JoinHorizontal(lipgloss.Top, crumb, "  ", lipgloss.JoinHorizontal(lipgloss.Top, pips...))
	} else {
		n := len(m.hosts.names)
		crumb := m.styles.crumb.Render("AgentSSH")
		tabs := make([]string, 0, 2)
		for _, tab := range []entryTab{entryHosts, entryPolicy} {
			label := fmt.Sprintf("%d %s", int(tab)+1, tab.title())
			if tab == m.entryTab {
				tabs = append(tabs, m.styles.activeTab.Render(label))
			} else {
				tabs = append(tabs, m.styles.inactive.Render(label))
			}
		}
		count := m.styles.dim.Render(fmt.Sprintf(" · %d %s", n, plural(n, "host", "hosts")))
		bar = lipgloss.JoinHorizontal(lipgloss.Top, crumb, "  ", lipgloss.JoinHorizontal(lipgloss.Top, tabs...), count)
		if m.hosts.filterActive() {
			bar += m.styles.dim.Render(fmt.Sprintf(" · %d shown", m.hosts.visibleCount()))
		}
		if chain := m.sessions.chainBadge(); chain != "" {
			bar += m.styles.dim.Render(" · ") + chain
		}
	}
	style := m.styles.statusBar
	if m.w > 0 {
		bar = truncate(bar, m.w)
		style = style.Width(m.w).MaxWidth(m.w)
	}
	return style.Render(bar)
}

// detailCrumbHost renders the breadcrumb's host segment: the host name (bold) plus
// its user@addr connection as dim context, e.g. "web-staging-1 (deploy@10.0.1.21)".
// The connection is dropped when the host has no inventory metadata.
func (m appModel) detailCrumbHost() string {
	name := m.styles.header.Render(m.detailHost)
	meta, ok := m.sessions.hosts[m.detailHost]
	if !ok || (meta.User == "" && meta.Addr == "") {
		return name
	}
	target := meta.Addr
	if meta.User != "" {
		target = meta.User + "@" + meta.Addr
	}
	return name + m.styles.dim.Render(fmt.Sprintf(" (%s)", target))
}

// renderFooter is the persistent bottom rail: the active screen's key bindings
// plus the global ones, with a transient toast right-aligned when present.
func (m appModel) renderFooter() string {
	km := combinedHelp{section: m.activeHelpKeyMap(), global: globalHelpKeys()}
	if m.toast == "" || m.w <= 0 {
		return m.fullWidthLine(m.help.View(km))
	}
	toast := m.styles.ok.Render(m.styles.glyphs.Check + " " + m.toast)
	toastW := lipgloss.Width(toast)
	helpW := m.w - toastW - 2
	if helpW < 1 {
		return m.fullWidthLine(m.help.View(km))
	}
	helpView := shortHelpFit(m.styles, km.ShortHelp(), helpW)
	pad := m.w - lipgloss.Width(helpView) - toastW
	if pad < 1 {
		pad = 1
	}
	return m.fullWidthLine(helpView + strings.Repeat(" ", pad) + toast)
}

// activeHelpKeyMap returns the help bindings for the active screen/pane. The
// footer (ShortHelp) stays terse — a few essential keys plus navigation — while
// the ? overlay (FullHelp) carries every binding, grouped into columns.
func (m appModel) activeHelpKeyMap() help.KeyMap {
	if m.screen != screenDetail {
		nav := []key.Binding{hk("tab/1-2", "tabs")}
		var section help.KeyMap
		if m.entryTab == entryPolicy {
			section = m.policy.helpKeyMap()
		} else {
			section = m.hosts.helpKeyMap()
		}
		return mergeHelp(section, nav)
	}
	nav := []key.Binding{hk("tab/1-3", "panes"), hk("esc", "back")}
	if m.paneCapturing() {
		// A pane that owns the keyboard (text input or overlay) consumes tab/esc, so
		// don't advertise pane-nav keys that won't fire while it is open.
		nav = nil
	}
	var pane help.KeyMap
	switch m.pane {
	case paneSessions:
		pane = m.sessions.helpKeyMap()
	case panePolicy:
		pane = m.policy.helpKeyMap()
	default:
		pane = m.infoPaneHelp()
	}
	return mergeHelp(pane, nav)
}

// infoPaneHelp is the Info pane's key help. It mirrors the pane's state: editing a
// field inline and the delete-confirm advertise their own keys; otherwise it lists
// the per-host actions, which now live on the detail screen with in-place editing.
func (m appModel) infoPaneHelp() help.KeyMap {
	if m.hosts.focus == hostFocusConfirm {
		return helpMap{short: []key.Binding{hk("y", "confirm"), hk("n/esc", "cancel")}}
	}
	if m.hosts.infoAuthChoosing {
		return helpMap{short: []key.Binding{hk("←/→", "mode"), hk("enter", "next"), hk("esc", "cancel")}}
	}
	if m.hosts.infoEditing {
		return helpMap{short: []key.Binding{hk("enter", "save"), hk("esc", "cancel")}}
	}
	return helpMap{
		short: []key.Binding{hk("enter", "edit"), hk("t", "test")},
		full:  [][]key.Binding{{hk("j/k", "field"), hk("enter", "edit field"), hk("t", "test"), hk("d/x", "delete")}},
	}
}

// mergeHelp appends nav bindings to a section's short help (footer) and adds them
// as a final column in its full help (?), so the footer stays terse while the
// overlay lists everything. Slices are copied so callers aren't mutated.
func mergeHelp(section help.KeyMap, nav []key.Binding) helpMap {
	short := append(append([]key.Binding{}, section.ShortHelp()...), nav...)
	full := append([][]key.Binding{}, section.FullHelp()...)
	full = append(full, nav)
	return helpMap{short: short, full: full}
}

func (m appModel) entryCapturing() bool {
	if m.entryTab == entryPolicy {
		return m.policy.capturing()
	}
	return m.hosts.capturing()
}

func (m appModel) fullWidthLine(value string) string {
	if m.w <= 0 {
		return value
	}
	return lipgloss.NewStyle().Width(m.w).MaxWidth(m.w).Render(value)
}

// shortHelpFit renders "key desc • key desc …" bounded to maxW columns.
func shortHelpFit(st appStyles, bindings []key.Binding, maxW int) string {
	var parts []string
	used := 0
	for _, kb := range bindings {
		h := kb.Help()
		if h.Key == "" && h.Desc == "" {
			continue
		}
		item := h.Key + " " + h.Desc
		cost := lipgloss.Width(item)
		if len(parts) > 0 {
			cost += 3
		}
		if used+cost+4 > maxW {
			parts = append(parts, "…")
			break
		}
		parts = append(parts, item)
		used += cost
	}
	return st.dim.Render(strings.Join(parts, " • "))
}
