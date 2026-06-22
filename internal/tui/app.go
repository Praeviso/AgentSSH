package tui

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/Praeviso/AgentSSH/internal/audit"
	"github.com/Praeviso/AgentSSH/internal/config"
	"github.com/Praeviso/AgentSSH/internal/discovery"
	"github.com/Praeviso/AgentSSH/internal/executor"
	"github.com/Praeviso/AgentSSH/internal/hostform"
	"github.com/Praeviso/AgentSSH/internal/inventory"
	"github.com/Praeviso/AgentSSH/internal/policy"
	"github.com/Praeviso/AgentSSH/internal/secrets"
	"github.com/Praeviso/AgentSSH/internal/session"
	"github.com/Praeviso/AgentSSH/internal/theme"
	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"gopkg.in/yaml.v3"
)

type section interface {
	tea.Model
	title() string
	capturing() bool
}

const (
	sectionHosts = iota
	sectionAudit
	sectionPolicy
	sectionSessions
)

type appModel struct {
	paths    config.Paths
	renderer *lipgloss.Renderer
	styles   appStyles
	sections []section
	active   int
	w, h     int
	ready    bool
	firstRun bool // show the one-time welcome banner until the first keypress
}

type appStyles struct {
	tabs       lipgloss.Style
	activeTab  lipgloss.Style
	inactive   lipgloss.Style
	err        lipgloss.Style
	ok         lipgloss.Style
	header     lipgloss.Style
	cursor     lipgloss.Style
	dim        lipgloss.Style
	panel      lipgloss.Style
	confirm    lipgloss.Style
	deny       lipgloss.Style
	prod       lipgloss.Style
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
		tabs:       r.NewStyle().Padding(0, 1).Bold(true),
		activeTab:  r.NewStyle().Padding(0, 1).Bold(true).Foreground(theme.AccentText).Background(theme.Accent),
		inactive:   r.NewStyle().Padding(0, 1).Foreground(theme.Dim),
		err:        r.NewStyle().Foreground(theme.Danger).Bold(true),
		ok:         r.NewStyle().Foreground(theme.Success).Bold(true),
		header:     r.NewStyle().Bold(true).Foreground(theme.Accent),
		cursor:     r.NewStyle().Foreground(theme.Cursor).Bold(true),
		dim:        r.NewStyle().Foreground(theme.Dim),
		panel:      r.NewStyle().Border(lipgloss.RoundedBorder()).Padding(0, 1),
		confirm:    r.NewStyle().Foreground(theme.Warn).Bold(true),
		deny:       r.NewStyle().Foreground(theme.Deny).Bold(true),
		prod:       r.NewStyle().Foreground(theme.Prod).Bold(true),
		background: r.NewStyle(),

		tableHeader: r.NewStyle().Padding(0, 1).Bold(true).Foreground(theme.Dim),
		tableSel:    r.NewStyle().Padding(0, 1).Background(theme.SelBg),
		tableCell:   r.NewStyle().Padding(0, 1),

		glyphs: theme.GlyphsFor(r),
	}
}

// keyHint renders an actionable "[key] description" chip for empty states and
// inline hints, with the key emphasized so the next action is obvious.
func keyHint(st appStyles, key, desc string) string {
	return st.cursor.Render("["+key+"]") + " " + st.dim.Render(desc)
}

func newAppModel(paths config.Paths, renderer *lipgloss.Renderer) appModel {
	st := newAppStyles(renderer)
	inv, invErr := inventory.Load(paths.InventoryFile)
	pol, polErr := loadPolicy(paths.PolicyFile)
	store := audit.NewStore(paths.AuditFile)
	records, auditErr := store.ReadAll()
	hosts := hostMetaFromInventory(inv)

	return appModel{
		paths:    paths,
		renderer: renderer,
		styles:   st,
		sections: []section{
			newHostsSection(paths, renderer, st, inv, invErr),
			newModel(records, hosts, newStyles(renderer), func() (audit.VerifyResult, error) {
				return store.Verify()
			}),
			newPolicySection(paths.PolicyFile, inv, pol, st, firstErr(invErr, polErr)),
			newSessionsSection(records, st, auditErr),
		},
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
	cmds := make([]tea.Cmd, 0, len(m.sections))
	for _, section := range m.sections {
		cmds = append(cmds, section.Init())
	}
	return tea.Batch(cmds...)
}

func (m appModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.w, m.h, m.ready = msg.Width, msg.Height, true
		inner := msg
		inner.Height -= lipgloss.Height(m.renderTabs())
		if inner.Height < 1 {
			inner.Height = 1
		}
		var cmds []tea.Cmd
		for i, activeSection := range m.sections {
			updated, cmd := activeSection.Update(inner)
			if next, ok := updated.(section); ok {
				m.sections[i] = next
			}
			cmds = append(cmds, cmd)
		}
		return m, tea.Batch(cmds...)
	case sessionSelectedMsg:
		m.focusAuditSession(msg.id)
		return m, nil
	case inventoryChangedMsg:
		m.applyInventoryChange(msg.inventory)
		return m, nil
	case verifyMsg:
		// Deliver to Audit even when it isn't the active tab — the launch-time
		// auto-verify (model.Init) lands while Hosts is active, and a manual
		// re-verify result can arrive after the operator has switched away.
		return m.updateSection(sectionAudit, msg)
	case hostProbeMsg, discoveryLoadedMsg, discoveryProbedMsg, spinner.TickMsg:
		// Async Hosts results — and the spinner tick that animates them — must
		// reach the Hosts section regardless of the active tab; a probe blocks up
		// to ProbeTimeout, during which the operator can switch tabs. Routing the
		// tick here keeps the spinner chain alive (its busy() gate stops it once
		// the op lands); runID guards make stale result delivery safe.
		return m.updateSection(sectionHosts, msg)
	case tea.KeyMsg:
		if msg.Type == tea.KeyCtrlC {
			return m, tea.Quit
		}
		if m.firstRun {
			// The welcome banner says "press any key to begin"; consume that one
			// keystroke so a natural 'q' doesn't quit the app just initialized.
			m.firstRun = false
			return m, nil
		}
		if !m.sections[m.active].capturing() {
			if next, ok := switchTarget(m.active, len(m.sections), msg); ok {
				m.active = next
				return m, nil
			}
			if msg.String() == "q" {
				return m, tea.Quit
			}
		}
	}
	return m.updateActive(msg)
}

func (m appModel) updateActive(msg tea.Msg) (tea.Model, tea.Cmd) {
	return m.updateSection(m.active, msg)
}

// updateSection delivers a message to a specific section by index, regardless of
// which tab is active — used to route async results back to their owning section.
func (m appModel) updateSection(i int, msg tea.Msg) (tea.Model, tea.Cmd) {
	updated, cmd := m.sections[i].Update(msg)
	if next, ok := updated.(section); ok {
		m.sections[i] = next
	}
	return m, cmd
}

func (m *appModel) focusAuditSession(id string) {
	if auditModel, ok := m.sections[sectionAudit].(model); ok {
		m.sections[sectionAudit] = auditModel.withSessionFilter(id)
		m.active = sectionAudit
	}
}

func (m *appModel) applyInventoryChange(inv inventory.Inventory) {
	if auditModel, ok := m.sections[sectionAudit].(model); ok {
		auditModel.hosts = hostMetaFromInventory(inv)
		m.sections[sectionAudit] = auditModel
	}
	if policyModel, ok := m.sections[sectionPolicy].(policySection); ok {
		policyModel.inventory = inv
		m.sections[sectionPolicy] = policyModel
	}
}

func (m appModel) View() string {
	if len(m.sections) == 0 {
		return "loading..."
	}
	tabs := m.renderTabs()
	body := m.sections[m.active].View()
	if !m.ready {
		body = "loading..."
	}
	if m.firstRun {
		welcome := m.styles.ok.Render("✓ Welcome to AgentSSH — created a starter inventory.yaml + policy.yaml. Press any key to begin.")
		return lipgloss.JoinVertical(lipgloss.Left, welcome, tabs, body)
	}
	return lipgloss.JoinVertical(lipgloss.Left, tabs, body)
}

func (m appModel) renderTabs() string {
	labels := make([]string, 0, len(m.sections))
	for i, section := range m.sections {
		label := fmt.Sprintf("%d %s", i+1, section.title())
		if i == m.active {
			labels = append(labels, m.styles.activeTab.Render(label))
		} else {
			labels = append(labels, m.styles.inactive.Render(label))
		}
	}
	help := m.styles.dim.Render("tab/shift+tab or 1-4 switch · q quit")
	return lipgloss.JoinHorizontal(lipgloss.Top, append(labels, help)...)
}

func switchTarget(active, n int, msg tea.KeyMsg) (int, bool) {
	if n <= 0 {
		return active, false
	}
	switch msg.String() {
	case "tab":
		return (active + 1) % n, true
	case "shift+tab":
		return (active + n - 1) % n, true
	}
	if d, err := strconv.Atoi(msg.String()); err == nil && d >= 1 && d <= n {
		return d - 1, true
	}
	return active, false
}

type hostsSection struct {
	paths       config.Paths
	renderer    *lipgloss.Renderer
	styles      appStyles
	inventory   inventory.Inventory
	names       []string
	cursor      int
	status      string
	err         error
	form        hostform.Model
	adding      bool
	confirm     bool
	testing     bool // a host connectivity probe is in flight
	discover    discoveryOverlay
	discoverSeq int
	spinner     spinner.Model
	w, h        int
}

// busy reports whether any async Hosts operation is in flight, driving the
// spinner's tick loop and its visibility.
func (s hostsSection) busy() bool {
	return s.testing || s.discover.loading || s.discover.probing
}

type inventoryChangedMsg struct {
	inventory inventory.Inventory
}

type discoveryOverlay struct {
	active     bool
	loading    bool
	probing    bool
	runID      int
	candidates []discovery.Candidate
	notes      []string
	selected   map[int]bool
	cursor     int
	status     string
	err        error
}

type discoveryLoadedMsg struct {
	runID  int
	result discovery.Result
	err    error
}

type discoveryProbedMsg struct {
	runID      int
	candidates []discovery.Candidate
	err        error
}

type hostProbeMsg struct {
	name string
	hint string
	err  error
	ok   bool
}

func newHostsSection(paths config.Paths, renderer *lipgloss.Renderer, st appStyles, inv inventory.Inventory, loadErr error) hostsSection {
	s := hostsSection{paths: paths, renderer: renderer, styles: st, inventory: inv, err: loadErr}
	sp := spinner.New(spinner.WithSpinner(spinner.Line)) // ASCII frames degrade cleanly under NO_COLOR
	if renderer != nil {
		sp.Style = renderer.NewStyle().Foreground(lipgloss.Color("212"))
	}
	s.spinner = sp
	s.rebuildNames()
	return s
}

func (s hostsSection) title() string { return "Hosts" }

func (s hostsSection) capturing() bool { return s.adding || s.confirm || s.discover.active }

func (s hostsSection) Init() tea.Cmd { return nil }

func (s hostsSection) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	if ws, ok := msg.(tea.WindowSizeMsg); ok {
		// Keep the size current even while the add-form owns the screen, so the
		// list viewport is sized correctly after the form closes.
		s.w, s.h = ws.Width, ws.Height
	}
	if s.adding {
		updated, cmd := s.form.Update(msg)
		if form, ok := updated.(hostform.Model); ok {
			s.form = form
		}
		if s.form.Done() {
			result := s.form.Result()
			s.adding = false
			s.form = hostform.Model{}
			if result.Submitted {
				if err := s.addHost(result); err != nil {
					s.err = err
					s.status = ""
				} else {
					s.status = "host added: " + result.Name
					s.err = nil
					return s, inventoryChangedCmd(s.inventory)
				}
			} else {
				s.status = "add cancelled"
			}
			return s, nil
		}
		return s, cmd
	}
	switch msg := msg.(type) {
	case spinner.TickMsg:
		// Keep ticking only while an async op is in flight; once it lands, the
		// dropped tick lets the spinner chain stop on its own.
		if s.busy() {
			var cmd tea.Cmd
			s.spinner, cmd = s.spinner.Update(msg)
			return s, cmd
		}
		return s, nil
	case discoveryLoadedMsg:
		// Ignore results from a closed or superseded overlay (the user may have
		// closed and reopened discovery before this async load returned).
		if !s.discover.active || msg.runID != s.discover.runID {
			return s, nil
		}
		s.discover.loading = false
		if msg.err != nil {
			s.discover.err = msg.err
			s.discover.status = ""
			return s, nil
		}
		s.discover.candidates = msg.result.Candidates
		s.discover.notes = msg.result.Notes
		s.discover.selected = defaultDiscoverySelection(msg.result.Candidates)
		s.discover.status = fmt.Sprintf("discovered %d candidate(s)", len(msg.result.Candidates))
		return s, nil
	case discoveryProbedMsg:
		if !s.discover.active || msg.runID != s.discover.runID {
			return s, nil
		}
		s.discover.probing = false
		if msg.err != nil {
			s.discover.err = msg.err
			s.discover.status = ""
			return s, nil
		}
		// Merge by stable candidate identity, not by the (mutable) selection map,
		// so a selection change while probing can't write results into wrong rows.
		s.discover.candidates = mergeProbedCandidates(s.discover.candidates, msg.candidates)
		s.discover.status = "probe complete"
		return s, nil
	case hostProbeMsg:
		s.testing = false
		if msg.ok {
			s.err = nil
			s.status = "OK " + msg.name
		} else if msg.hint != "" {
			s.err = nil
			s.status = "FAILED " + msg.name + ": " + msg.hint
		} else if msg.err != nil {
			s.err = nil
			s.status = "FAILED " + msg.name + ": " + executor.ConnectHint(msg.err)
		}
		return s, nil
	}
	if s.discover.active {
		return s.updateDiscovery(msg)
	}
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		s.w, s.h = msg.Width, msg.Height
	case tea.KeyMsg:
		switch msg.String() {
		case "j", "down":
			if s.cursor < len(s.names)-1 {
				s.cursor++
			}
			s.confirm = false
		case "k", "up":
			if s.cursor > 0 {
				s.cursor--
			}
			s.confirm = false
		case "a":
			if s.err != nil {
				s.status = "fix inventory.yaml before editing hosts"
				return s, nil
			}
			s.adding = true
			s.confirm = false
			s.form = hostform.New(hostform.Options{ExistingNames: inventory.HostNames(s.inventory)}, s.renderer)
			return s, s.form.Init()
		case "d":
			if s.err != nil {
				s.status = "fix inventory.yaml before discovering hosts"
				return s, nil
			}
			s.confirm = false
			s.discoverSeq++
			s.discover = discoveryOverlay{
				active:   true,
				loading:  true,
				runID:    s.discoverSeq,
				selected: map[int]bool{},
				status:   "discovering from ssh config and known_hosts…",
			}
			return s, tea.Batch(s.loadDiscoveryCmd(), s.spinner.Tick)
		case "t":
			if s.testing {
				// A probe is already in flight; ignore re-presses so we don't
				// double-start the spinner tick loop (it would then run at 2x).
				return s, nil
			}
			if len(s.names) == 0 {
				s.status = "no host selected"
				return s, nil
			}
			name := s.names[s.cursor]
			s.status = "testing " + name + "…"
			s.err = nil
			s.testing = true
			return s, tea.Batch(s.probeHostCmd(name), s.spinner.Tick)
		case "r", "x":
			if s.err != nil {
				s.status = "fix inventory.yaml before editing hosts"
				return s, nil
			}
			if len(s.names) > 0 {
				s.confirm = true
				s.status = "remove " + s.names[s.cursor] + "? press y to confirm, n/esc to cancel"
			}
		case "y":
			if s.confirm {
				if s.removeSelected() {
					return s, inventoryChangedCmd(s.inventory)
				}
			}
		case "n", "esc":
			s.confirm = false
			s.status = ""
		}
	}
	return s, nil
}

func inventoryChangedCmd(inv inventory.Inventory) tea.Cmd {
	return func() tea.Msg {
		return inventoryChangedMsg{inventory: inv}
	}
}

func (s hostsSection) loadDiscoveryCmd() tea.Cmd {
	runID := s.discover.runID
	return func() tea.Msg {
		cfgPath, knownHostsPath, home := sshClientPaths()
		result, err := discovery.Static(discovery.Options{
			ConfigPath:     cfgPath,
			KnownHostsPath: knownHostsPath,
			Home:           home,
			Inventory:      s.inventory,
		})
		return discoveryLoadedMsg{runID: runID, result: result, err: err}
	}
}

func (s hostsSection) probeDiscoveryCmd(candidates []discovery.Candidate) tea.Cmd {
	runID := s.discover.runID
	return func() tea.Msg {
		cfgPath, knownHostsPath, _ := sshClientPaths()
		exec := executor.NewNativeExecutor(executor.NativeOptions{
			ConfigPath:     cfgPath,
			KnownHostsPath: knownHostsPath,
			ConnectTimeout: executor.ProbeTimeout,
			HostKeyPolicy:  s.inventory.HostKeyPolicy,
			PasswordSource: secrets.EnvPasswordSource(s.paths.SecretsFile),
		})
		probed := discovery.Probe(context.Background(), candidates, discovery.ProbeOptions{
			Executor:    exec,
			Timeout:     executor.ProbeTimeout,
			Concurrency: 4,
		})
		return discoveryProbedMsg{runID: runID, candidates: probed}
	}
}

func (s hostsSection) probeHostCmd(name string) tea.Cmd {
	host := s.inventory.Hosts[name]
	return func() tea.Msg {
		cfgPath, knownHostsPath, _ := sshClientPaths()
		exec := executor.NewNativeExecutor(executor.NativeOptions{
			ConfigPath:     cfgPath,
			KnownHostsPath: knownHostsPath,
			ConnectTimeout: executor.ProbeTimeout,
			HostKeyPolicy:  s.inventory.HostKeyPolicy,
			PasswordSource: secrets.EnvPasswordSource(s.paths.SecretsFile),
		})
		ctx, cancel := context.WithTimeout(context.Background(), executor.ProbeTimeout)
		defer cancel()
		result := exec.Probe(ctx, inventory.Target{Name: name, Host: host})
		if result.Err == nil && result.ExitCode == 0 {
			return hostProbeMsg{name: name, ok: true}
		}
		if result.Err != nil {
			return hostProbeMsg{name: name, err: result.Err, hint: executor.ConnectHint(result.Err)}
		}
		return hostProbeMsg{name: name, hint: fmt.Sprintf("probe command exited %d", result.ExitCode)}
	}
}

func sshClientPaths() (configPath string, knownHostsPath string, home string) {
	home = os.Getenv("HOME")
	if home == "" {
		if resolved, err := os.UserHomeDir(); err == nil {
			home = resolved
		}
	}
	return filepath.Join(home, ".ssh", "config"), filepath.Join(home, ".ssh", "known_hosts"), home
}

func defaultDiscoverySelection(candidates []discovery.Candidate) map[int]bool {
	selected := map[int]bool{}
	for i, candidate := range candidates {
		if !candidate.InInventory {
			selected[i] = true
		}
	}
	return selected
}

func (s hostsSection) updateDiscovery(msg tea.Msg) (tea.Model, tea.Cmd) {
	keyMsg, ok := msg.(tea.KeyMsg)
	if !ok {
		return s, nil
	}
	switch keyMsg.String() {
	case "j", "down":
		if s.discover.cursor < len(s.discover.candidates)-1 {
			s.discover.cursor++
		}
	case "k", "up":
		if s.discover.cursor > 0 {
			s.discover.cursor--
		}
	case " ":
		if len(s.discover.candidates) > 0 {
			if s.discover.selected == nil {
				s.discover.selected = map[int]bool{}
			}
			if s.discover.selected[s.discover.cursor] {
				delete(s.discover.selected, s.discover.cursor)
			} else {
				s.discover.selected[s.discover.cursor] = true
			}
		}
	case "p":
		if s.discover.loading || s.discover.probing {
			return s, nil
		}
		selected := s.selectedDiscoveryCandidates()
		if len(selected) == 0 {
			s.discover.status = "select candidates with space before probing"
			return s, nil
		}
		s.discover.probing = true
		s.discover.err = nil
		s.discover.status = fmt.Sprintf("probing %d candidate(s)…", len(selected))
		return s, tea.Batch(s.probeDiscoveryCmd(selected), s.spinner.Tick)
	case "enter", "i":
		if s.discover.loading || s.discover.probing {
			return s, nil
		}
		changed, err := s.importDiscoverySelected()
		if err != nil {
			s.discover.err = err
			s.discover.status = ""
			return s, nil
		}
		if changed {
			s.discover.active = false
			return s, inventoryChangedCmd(s.inventory)
		}
	case "esc", "q":
		s.discover = discoveryOverlay{}
		s.status = "discover cancelled"
	}
	return s, nil
}

func (s hostsSection) selectedDiscoveryCandidates() []discovery.Candidate {
	if len(s.discover.selected) == 0 {
		return nil
	}
	selected := make([]discovery.Candidate, 0, len(s.discover.selected))
	for i, candidate := range s.discover.candidates {
		if s.discover.selected[i] {
			selected = append(selected, candidate)
		}
	}
	return selected
}

func (s *hostsSection) importDiscoverySelected() (bool, error) {
	if len(s.discover.selected) == 0 {
		s.discover.status = "select connectable candidates before importing"
		return false, nil
	}
	base, err := inventory.Load(s.paths.InventoryFile)
	if err != nil {
		return false, err
	}
	next := base
	seen := discovery.EndpointKeys(base)
	imported := 0
	for i, candidate := range s.discover.candidates {
		if !s.discover.selected[i] || candidate.ProbeStatus != executor.ProbeConnectable {
			continue
		}
		// Re-check membership against the just-reloaded (and incrementally built)
		// inventory rather than the stale flag captured when discovery ran; this
		// also catches alias-only hosts that endpoint keys can't see.
		if discovery.InInventory(next, candidate.Name) {
			continue
		}
		key := discovery.EndpointKey(candidate.Addr, candidate.Port)
		if key != "" && seen[key] {
			continue
		}
		var addErr error
		next, addErr = inventory.AddHost(next, candidate.Name, discovery.ImportHost(candidate))
		if errors.Is(addErr, inventory.ErrHostExists) {
			continue
		}
		if addErr != nil {
			return false, addErr
		}
		if key != "" {
			seen[key] = true
		}
		imported++
	}
	if imported == 0 {
		s.discover.status = "no selected connectable candidates to import"
		return false, nil
	}
	if err := inventory.Save(s.paths.InventoryFile, next); err != nil {
		return false, err
	}
	reloaded, err := inventory.Load(s.paths.InventoryFile)
	if err != nil {
		return false, err
	}
	s.inventory = reloaded
	s.rebuildNames()
	s.err = nil
	s.status = fmt.Sprintf("imported %d host(s)", imported)
	return true, nil
}

// mergeProbedCandidates folds probe results back into the candidate list by
// stable identity (source+name), not by position or selection, so that changing
// the selection while a probe is in flight cannot land a result on the wrong row.
func mergeProbedCandidates(current []discovery.Candidate, probed []discovery.Candidate) []discovery.Candidate {
	byKey := make(map[string]discovery.Candidate, len(probed))
	for _, p := range probed {
		byKey[candidateKey(p)] = p
	}
	merged := append([]discovery.Candidate(nil), current...)
	for i := range merged {
		if p, ok := byKey[candidateKey(merged[i])]; ok {
			merged[i] = p
		}
	}
	return merged
}

func candidateKey(c discovery.Candidate) string {
	return c.Source + "\x00" + c.Name
}

func (s *hostsSection) addHost(result hostform.Result) error {
	// Reload from disk so a concurrent external edit isn't clobbered.
	base, err := inventory.Load(s.paths.InventoryFile)
	if err != nil {
		return err
	}
	if result.Password != "" {
		master := os.Getenv("AGENTSSH_MASTER_PASSWORD")
		if master == "" {
			return fmt.Errorf("set AGENTSSH_MASTER_PASSWORD to store a password in the TUI, or use `agentssh secret set <host>`")
		}
		store, err := secrets.Open(s.paths.SecretsFile, master)
		if errors.Is(err, secrets.ErrWrongMaster) {
			return fmt.Errorf("cannot open secrets: wrong master password or corrupt secrets file")
		}
		if err != nil {
			return err
		}
		if err := s.addInventoryHost(base, result); err != nil {
			return err
		}
		store.Set(result.Name, result.Password)
		if err := store.Save(master); err != nil {
			if rbErr := s.removeHostByName(result.Name); rbErr != nil {
				return fmt.Errorf("failed to store password (%v) and to roll back inventory add: %w", err, rbErr)
			}
			return fmt.Errorf("failed to store password; rolled back inventory add: %w", err)
		}
		return nil
	}
	return s.addInventoryHost(base, result)
}

func (s *hostsSection) addInventoryHost(base inventory.Inventory, result hostform.Result) error {
	next, err := inventory.AddHost(base, result.Name, inventory.Host{
		Addr:           result.Addr,
		User:           result.User,
		Port:           result.Port,
		SSHConfigAlias: result.Alias,
		IdentityFile:   result.Identity,
		Tags:           result.Tags,
	})
	if err != nil {
		return err
	}
	if err := inventory.Save(s.paths.InventoryFile, next); err != nil {
		return err
	}
	s.inventory = next
	s.rebuildNames()
	return nil
}

func (s *hostsSection) removeHostByName(name string) error {
	base, err := inventory.Load(s.paths.InventoryFile)
	if err != nil {
		return err
	}
	next, err := inventory.RemoveHost(base, name)
	if err != nil {
		return err
	}
	if err := inventory.Save(s.paths.InventoryFile, next); err != nil {
		return err
	}
	s.inventory = next
	s.rebuildNames()
	return nil
}

func (s *hostsSection) removeSelected() bool {
	if len(s.names) == 0 {
		return false
	}
	name := s.names[s.cursor]
	// Reload from disk so a concurrent external edit isn't clobbered.
	base, err := inventory.Load(s.paths.InventoryFile)
	if err != nil {
		s.err = err
		s.status = ""
		s.confirm = false
		return false
	}
	next, err := inventory.RemoveHost(base, name)
	if err != nil {
		s.err = err
		s.status = ""
		s.confirm = false
		return false
	}
	if err := inventory.Save(s.paths.InventoryFile, next); err != nil {
		s.err = err
		s.status = ""
		s.confirm = false
		return false
	}
	s.inventory = next
	s.rebuildNames()
	s.confirm = false
	s.err = nil
	s.status = "host removed: " + name
	return true
}

func (s *hostsSection) rebuildNames() {
	s.names = sortedHostNames(s.inventory.Hosts)
	if s.cursor >= len(s.names) {
		s.cursor = len(s.names) - 1
	}
	if s.cursor < 0 {
		s.cursor = 0
	}
}

func (s hostsSection) View() string {
	if s.adding {
		return s.form.View()
	}
	if s.discover.active {
		return s.discoveryView()
	}
	var b strings.Builder
	b.WriteString(s.styles.header.Render("Hosts"))
	b.WriteString("\n")
	if s.inventory.Transport != "" || s.inventory.HostKeyPolicy != "" {
		var parts []string
		if s.inventory.Transport != "" {
			parts = append(parts, "transport="+s.inventory.Transport)
		}
		if s.inventory.HostKeyPolicy != "" {
			parts = append(parts, "host_key_policy="+s.inventory.HostKeyPolicy)
		}
		b.WriteString(s.styles.dim.Render(strings.Join(parts, " ")))
		b.WriteString("\n")
	}
	if s.err != nil {
		b.WriteString(s.styles.err.Render(s.err.Error()))
		b.WriteString("\n")
	}
	if s.status != "" {
		style := s.styles.ok
		if s.confirm {
			style = s.styles.confirm
		}
		if s.testing {
			b.WriteString(s.spinner.View())
			b.WriteString(" ")
		}
		b.WriteString(style.Render(s.status))
		b.WriteString("\n")
	}
	if len(s.names) == 0 {
		b.WriteString(s.styles.dim.Render("No hosts yet."))
		b.WriteString("\n")
		b.WriteString(keyHint(s.styles, "a", "add a host"))
		b.WriteString("    ")
		b.WriteString(keyHint(s.styles, "d", "discover hosts you can already reach"))
		b.WriteString("\n")
	} else {
		window, start := s.hostWindow()
		rows := make([][]string, 0, len(window))
		for _, name := range window {
			rows = append(rows, hostRow(name, s.inventory.Hosts[name]))
		}
		b.WriteString(renderTable(s.styles, hostColumns, rows, s.cursor-start))
		b.WriteString("\n")
	}
	if len(s.inventory.Groups) > 0 {
		b.WriteString("\n")
		b.WriteString(s.styles.header.Render("Groups"))
		b.WriteString("\n")
		for _, name := range sortedGroupNames(s.inventory.Groups) {
			b.WriteString("  ")
			b.WriteString(name)
			if len(s.inventory.Groups[name].Tags) > 0 {
				b.WriteString(" tags=")
				b.WriteString(strings.Join(s.inventory.Groups[name].Tags, ","))
			}
			b.WriteString("\n")
		}
	}
	b.WriteString("\n")
	b.WriteString(s.styles.dim.Render("j/k move · a add · d discover · t test · r/x remove · tab switch"))
	return b.String()
}

func (s hostsSection) discoveryView() string {
	var b strings.Builder
	b.WriteString(s.styles.header.Render("Discover Hosts"))
	b.WriteString("\n")
	if s.discover.err != nil {
		b.WriteString(s.styles.err.Render(s.discover.err.Error()))
		b.WriteString("\n")
	}
	if s.discover.status != "" {
		if s.discover.loading || s.discover.probing {
			b.WriteString(s.spinner.View())
			b.WriteString(" ")
		}
		b.WriteString(s.styles.ok.Render(s.discover.status))
		b.WriteString("\n")
	}
	if s.discover.loading {
		b.WriteString(s.styles.dim.Render("scanning ssh config and known_hosts…"))
		b.WriteString("\n")
	} else if len(s.discover.candidates) == 0 {
		b.WriteString(s.styles.dim.Render("No hosts found in ~/.ssh/config or known_hosts."))
		b.WriteString("\n")
		b.WriteString(s.styles.dim.Render("Press esc to close, then a on the Hosts tab to add one by hand."))
		b.WriteString("\n")
	} else {
		window, start := s.discoverWindow()
		rows := make([][]string, 0, len(window))
		for i, candidate := range window {
			rows = append(rows, discoverRow(s.styles.glyphs, candidate, s.discover.selected[start+i]))
		}
		b.WriteString(renderTable(s.styles, discoverColumns, rows, s.discover.cursor-start))
		b.WriteString("\n")
		// The per-row hint can't live inside the table; show the current row's.
		if cur := s.discover.cursor; cur >= 0 && cur < len(s.discover.candidates) {
			if h := s.discover.candidates[cur].Hint; h != "" {
				b.WriteString(s.styles.dim.Render("  " + h))
				b.WriteString("\n")
			}
		}
	}
	for _, note := range s.discover.notes {
		b.WriteString(s.styles.dim.Render("note: " + note))
		b.WriteString("\n")
	}
	b.WriteString("\n")
	b.WriteString(s.styles.dim.Render("j/k move · space select · p probe · enter/i import connectable · esc/q close"))
	return b.String()
}

func (s hostsSection) discoverWindow() (candidates []discovery.Candidate, start int) {
	height := s.h - 8
	if s.h <= 0 {
		height = len(s.discover.candidates) // size unknown: show all
	} else if height < 3 {
		height = 3
	}
	start, end := scrollWindow(s.discover.cursor, len(s.discover.candidates), height)
	return s.discover.candidates[start:end], start
}

var discoverColumns = []tableColumn{
	{header: "SEL"},
	{header: "NAME"},
	{header: "SOURCE"},
	{header: "ADDR"},
	{header: "KEY"},
	{header: "KNW"},
	{header: "INV"},
	{header: "STATUS"},
}

func discoverRow(g theme.Glyphs, candidate discovery.Candidate, selected bool) []string {
	sel := "[ ]"
	if selected {
		sel = "[x]"
	}
	return []string{
		sel,
		truncate(candidate.Name, 22),
		candidate.Source,
		truncate(formatDiscoveryAddr(candidate), 22),
		glyphBool(g, candidate.HasKey),
		glyphBool(g, candidate.InKnownHosts),
		glyphBool(g, candidate.InInventory),
		discoveryStatusCell(g, candidate),
	}
}

func formatDiscoveryAddr(candidate discovery.Candidate) string {
	if candidate.Port == 0 || candidate.Port == 22 {
		return candidate.Addr
	}
	return fmt.Sprintf("%s:%d", candidate.Addr, candidate.Port)
}

// glyphBool renders a present/absent column as a glyph that survives NO_COLOR
// (the glyph itself degrades to ASCII via the resolver).
func glyphBool(g theme.Glyphs, ok bool) string {
	if ok {
		return g.OK
	}
	return g.Absent
}

// discoveryStatusCell renders the probe/known state as a glyph + word so the
// STATUS column is scannable. Per-cell coloring is a lipgloss/table limitation;
// the glyph + word carries the meaning.
func discoveryStatusCell(g theme.Glyphs, candidate discovery.Candidate) string {
	switch candidate.ProbeStatus {
	case executor.ProbeConnectable:
		return g.OK + " reachable"
	case executor.ProbeAuthFailed:
		return g.Warn + " auth-failed"
	case executor.ProbeHostKeyIssue:
		return g.Warn + " host-key"
	case executor.ProbeUnreachable:
		return g.Fail + " unreachable"
	}
	switch {
	case candidate.InInventory:
		return g.Absent + " in inventory"
	case candidate.HasKey:
		return g.Maybe + " looks-connectable"
	default:
		return g.Absent + " needs-auth"
	}
}

// hostWindow returns the visible slice of host names and its start offset, so
// the table cursor can be expressed relative to the window.
func (s hostsSection) hostWindow() (names []string, start int) {
	height := s.h - 8
	if s.h <= 0 {
		height = len(s.names) // size unknown: show all
	} else if height < 3 {
		height = 3
	}
	start, end := scrollWindow(s.cursor, len(s.names), height)
	return s.names[start:end], start
}

var hostColumns = []tableColumn{
	{header: "NAME"},
	{header: "ADDR"},
	{header: "PORT", right: true},
	{header: "USER"},
	{header: "AUTH"},
	{header: "TAGS"},
}

// hostRow projects an inventory host into aligned table cells. AUTH names the
// method (key/alias) without ever exposing the key path's secrecy — identity_file
// is a path, surfaced in full only by the P1 detail panel.
func hostRow(name string, host inventory.Host) []string {
	display := name
	if hostHasTag(host, "prod") {
		display += " [prod]"
	}
	port := "22"
	if host.Port != 0 {
		port = strconv.Itoa(host.Port)
	}
	auth := "-"
	switch {
	case host.IdentityFile != "":
		auth = "key"
	case host.SSHConfigAlias != "":
		auth = "alias:" + host.SSHConfigAlias
	}
	return []string{
		truncate(display, 28),
		truncate(orDash(host.Addr), 24),
		port,
		orDash(host.User),
		truncate(auth, 18),
		truncate(strings.Join(host.Tags, ","), 20),
	}
}

func hostHasTag(host inventory.Host, tag string) bool {
	for _, t := range host.Tags {
		if t == tag {
			return true
		}
	}
	return false
}

type policySection struct {
	path      string
	inventory inventory.Inventory
	config    policy.Config
	styles    appStyles
	input     textinput.Model
	result    string
	err       error
	w, h      int
}

func newPolicySection(path string, inv inventory.Inventory, cfg policy.Config, st appStyles, err error) policySection {
	ti := textinput.New()
	ti.Placeholder = "host:cmd or cmd"
	ti.Prompt = "test> "
	return policySection{path: path, inventory: inv, config: cfg, styles: st, input: ti, err: err}
}

func (s policySection) title() string { return "Policy" }

func (s policySection) capturing() bool { return s.input.Focused() }

func (s policySection) Init() tea.Cmd { return nil }

func (s policySection) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		s.w, s.h = msg.Width, msg.Height
	case tea.KeyMsg:
		if s.input.Focused() {
			switch msg.String() {
			case "enter":
				s.evaluate()
				s.input.Blur()
				return s, nil
			case "esc":
				s.input.Blur()
				return s, nil
			}
			var cmd tea.Cmd
			s.input, cmd = s.input.Update(msg)
			return s, cmd
		}
		switch msg.String() {
		case "t", "/":
			return s, s.input.Focus()
		}
	}
	if s.input.Focused() {
		var cmd tea.Cmd
		s.input, cmd = s.input.Update(msg)
		return s, cmd
	}
	return s, nil
}

func (s *policySection) evaluate() {
	// Reflect current policy.yaml (it may have changed since launch). Skip when
	// there is no backing file (e.g. an in-memory section in tests).
	if s.path != "" {
		if cfg, err := loadPolicy(s.path); err == nil {
			s.config = cfg
		}
	}
	engine, err := policy.NewEngine(s.config, s.inventory)
	if err != nil {
		s.err = err
		s.result = ""
		return
	}
	host, command := parsePolicyTestInput(s.input.Value())
	if strings.TrimSpace(command) == "" {
		s.err = errors.New("enter a command to test")
		s.result = ""
		return
	}
	decision, err := engine.Evaluate(host, command)
	if err != nil {
		s.err = err
		s.result = ""
		return
	}
	s.err = nil
	if host != "" {
		s.result = fmt.Sprintf("%s · rule=%s · host=%s", decision.Action, decision.Rule, host)
	} else {
		s.result = fmt.Sprintf("%s · rule=%s", decision.Action, decision.Rule)
	}
}

func parsePolicyTestInput(value string) (string, string) {
	value = strings.TrimSpace(value)
	host, command, ok := strings.Cut(value, ":")
	if ok && host != "" && !strings.ContainsAny(host, " \t\r\n") {
		return strings.TrimSpace(host), strings.TrimSpace(command)
	}
	return "", value
}

func (s policySection) View() string {
	var b strings.Builder
	b.WriteString(s.styles.header.Render("Policy"))
	b.WriteString("\n")
	b.WriteString(renderPolicyConfig(s.styles, s.config))
	b.WriteString("\n")
	if s.err != nil {
		b.WriteString(s.styles.err.Render(s.err.Error()))
		b.WriteString("\n")
	}
	if s.result != "" {
		style := s.styles.ok
		if strings.HasPrefix(s.result, string(policy.ActionDeny)) {
			style = s.styles.deny
		}
		b.WriteString(style.Render(s.result))
		b.WriteString("\n")
	}
	if s.input.Focused() {
		b.WriteString(s.input.View())
	} else {
		value := s.input.Value()
		if value == "" {
			value = "press t to test a command"
		}
		b.WriteString(s.styles.dim.Render(value))
	}
	b.WriteString("\n")
	b.WriteString(s.styles.dim.Render("t or / test · enter evaluate · esc cancel input"))
	return b.String()
}

var policyRuleColumns = []tableColumn{
	{header: "NAME"},
	{header: "ACTION"},
	{header: "CMD REGEX"},
}

// policyActionCell renders a policy action as a glyph + word so deny reads as a
// distinct verdict (per-cell coloring is a lipgloss/table limitation).
func policyActionCell(g theme.Glyphs, action policy.Action) string {
	if action == policy.ActionDeny {
		return g.Deny + " DENY"
	}
	return g.OK + " ALLOW"
}

func renderPolicyConfig(st appStyles, cfg policy.Config) string {
	var b strings.Builder
	defaultPolicy := cfg.Defaults.Policy
	if defaultPolicy == "" {
		defaultPolicy = policy.ActionAllow
	}
	fmt.Fprintf(&b, "default posture: %s\n\n", policyActionCell(st.glyphs, defaultPolicy))

	if len(cfg.Rules) == 0 {
		b.WriteString(st.dim.Render("rules: (none)"))
		b.WriteString("\n")
	} else {
		rows := make([][]string, 0, len(cfg.Rules))
		for i, rule := range cfg.Rules {
			name := rule.Name
			if name == "" {
				name = fmt.Sprintf("[%d]", i)
			}
			rows = append(rows, []string{
				truncate(name, 22),
				policyActionCell(st.glyphs, rule.Action),
				truncate(rule.Match.CmdRegex, 44),
			})
		}
		b.WriteString(renderTable(st, policyRuleColumns, rows, -1))
		b.WriteString("\n")
	}

	if len(cfg.HostOverrides) > 0 {
		b.WriteString("\n")
		b.WriteString(st.dim.Render("host overrides:"))
		b.WriteString("\n")
		for _, name := range sortedOverrideNames(cfg.HostOverrides) {
			override := cfg.HostOverrides[name]
			fmt.Fprintf(&b, "  %s → %s (%d allow rules)\n",
				name, policyActionCell(st.glyphs, override.Policy), len(override.AllowRules))
		}
	}
	fmt.Fprintf(&b, "\noutput: max_bytes=%d · redactions=%d\n", cfg.Output.MaxBytes, len(cfg.Output.Redact))
	return b.String()
}

func sortedOverrideNames(overrides map[string]policy.HostOverride) []string {
	names := make([]string, 0, len(overrides))
	for name := range overrides {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

type sessionsSection struct {
	summaries []session.Summary
	styles    appStyles
	err       error
	cursor    int
	w, h      int
}

type sessionSelectedMsg struct {
	id string
}

func newSessionsSection(records []audit.Record, st appStyles, err error) sessionsSection {
	return sessionsSection{summaries: session.Summaries(records), styles: st, err: err}
}

func (s sessionsSection) title() string { return "Sessions" }

func (s sessionsSection) capturing() bool { return false }

func (s sessionsSection) Init() tea.Cmd { return nil }

func (s sessionsSection) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		s.w, s.h = msg.Width, msg.Height
	case tea.KeyMsg:
		switch msg.String() {
		case "j", "down":
			if s.cursor < len(s.summaries)-1 {
				s.cursor++
			}
		case "k", "up":
			if s.cursor > 0 {
				s.cursor--
			}
		case "enter":
			if len(s.summaries) > 0 {
				id := s.summaries[s.cursor].ID
				return s, func() tea.Msg { return sessionSelectedMsg{id: id} }
			}
		}
	}
	return s, nil
}

func (s sessionsSection) View() string {
	var b strings.Builder
	b.WriteString(s.styles.header.Render("Sessions"))
	b.WriteString("\n")
	if s.err != nil {
		b.WriteString(s.styles.err.Render(s.err.Error()))
		b.WriteString("\n")
	}
	if len(s.summaries) == 0 {
		b.WriteString(s.styles.dim.Render("No sessions recorded yet."))
		b.WriteString("\n")
		b.WriteString(s.styles.dim.Render("Sessions appear here after the agent runs: agentssh run <host> -- <cmd>"))
		b.WriteString("\n")
	} else {
		window, start := s.sessionWindow()
		rows := make([][]string, 0, len(window))
		for _, summary := range window {
			rows = append(rows, sessionRow(summary))
		}
		b.WriteString(renderTable(s.styles, sessionColumns, rows, s.cursor-start))
		b.WriteString("\n")
	}
	b.WriteString("\n")
	b.WriteString(s.styles.dim.Render("j/k move · enter open in Audit"))
	return b.String()
}

var sessionColumns = []tableColumn{
	{header: "ID"},
	{header: "LABEL"},
	{header: "WINDOW"},
	{header: "CMDS", right: true},
}

// sessionRow projects a session summary into aligned cells. WINDOW uses HH:MM:SS
// clocks instead of two overflowing RFC3339 stamps. AGENT/DEN/FAIL columns need
// data plumbing on session.Summary (P2) and are intentionally omitted for now.
func sessionRow(summary session.Summary) []string {
	label := summary.Label
	if label == "" {
		label = "-"
	}
	return []string{
		truncate(summary.ID, 16),
		truncate(label, 28),
		clockOf(summary.Start) + "–" + clockOf(summary.End),
		strconv.Itoa(summary.CommandCount),
	}
}

func (s sessionsSection) sessionWindow() (summaries []session.Summary, start int) {
	height := s.h - 4
	if s.h <= 0 {
		height = len(s.summaries) // size unknown: show all
	} else if height < 3 {
		height = 3
	}
	start, end := scrollWindow(s.cursor, len(s.summaries), height)
	return s.summaries[start:end], start
}

func sortedHostNames(hosts map[string]inventory.Host) []string {
	names := make([]string, 0, len(hosts))
	for name := range hosts {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func sortedGroupNames(groups map[string]inventory.Group) []string {
	names := make([]string, 0, len(groups))
	for name := range groups {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}
