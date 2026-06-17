package tui

import (
	"errors"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/Praeviso/AgentSSH/internal/audit"
	"github.com/Praeviso/AgentSSH/internal/config"
	"github.com/Praeviso/AgentSSH/internal/hostform"
	"github.com/Praeviso/AgentSSH/internal/inventory"
	"github.com/Praeviso/AgentSSH/internal/policy"
	"github.com/Praeviso/AgentSSH/internal/session"
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
	background lipgloss.Style
}

func newAppStyles(r *lipgloss.Renderer) appStyles {
	return appStyles{
		tabs:       r.NewStyle().Padding(0, 1).Bold(true),
		activeTab:  r.NewStyle().Padding(0, 1).Bold(true).Foreground(lipgloss.Color("15")).Background(lipgloss.Color("63")),
		inactive:   r.NewStyle().Padding(0, 1).Foreground(lipgloss.Color("244")),
		err:        r.NewStyle().Foreground(lipgloss.Color("196")).Bold(true),
		ok:         r.NewStyle().Foreground(lipgloss.Color("42")).Bold(true),
		header:     r.NewStyle().Bold(true).Foreground(lipgloss.Color("63")),
		cursor:     r.NewStyle().Foreground(lipgloss.Color("212")).Bold(true),
		dim:        r.NewStyle().Foreground(lipgloss.Color("241")),
		panel:      r.NewStyle().Border(lipgloss.RoundedBorder()).Padding(0, 1),
		confirm:    r.NewStyle().Foreground(lipgloss.Color("220")).Bold(true),
		background: r.NewStyle(),
	}
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
	case tea.KeyMsg:
		if msg.Type == tea.KeyCtrlC {
			return m, tea.Quit
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
	updated, cmd := m.sections[m.active].Update(msg)
	if next, ok := updated.(section); ok {
		m.sections[m.active] = next
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
	paths     config.Paths
	renderer  *lipgloss.Renderer
	styles    appStyles
	inventory inventory.Inventory
	names     []string
	cursor    int
	status    string
	err       error
	form      hostform.Model
	adding    bool
	confirm   bool
	w, h      int
}

type inventoryChangedMsg struct {
	inventory inventory.Inventory
}

func newHostsSection(paths config.Paths, renderer *lipgloss.Renderer, st appStyles, inv inventory.Inventory, loadErr error) hostsSection {
	s := hostsSection{paths: paths, renderer: renderer, styles: st, inventory: inv, err: loadErr}
	s.rebuildNames()
	return s
}

func (s hostsSection) title() string { return "Hosts" }

func (s hostsSection) capturing() bool { return s.adding || s.confirm }

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
		case "d", "x":
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

func (s *hostsSection) addHost(result hostform.Result) error {
	// Reload from disk so a concurrent external edit isn't clobbered.
	base, err := inventory.Load(s.paths.InventoryFile)
	if err != nil {
		return err
	}
	next, err := inventory.AddHost(base, result.Name, inventory.Host{
		Addr:           result.Addr,
		User:           result.User,
		Port:           result.Port,
		SSHConfigAlias: result.Alias,
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
		b.WriteString(style.Render(s.status))
		b.WriteString("\n")
	}
	if len(s.names) == 0 {
		b.WriteString(s.styles.dim.Render("(no hosts)"))
		b.WriteString("\n")
	} else {
		for _, name := range s.visibleNames() {
			cursor := "  "
			if name == s.names[s.cursor] {
				cursor = s.styles.cursor.Render("> ")
			}
			b.WriteString(cursor)
			b.WriteString(renderHostLine(name, s.inventory.Hosts[name]))
			b.WriteString("\n")
		}
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
	b.WriteString(s.styles.dim.Render("j/k move · a add · d/x remove · tab switch"))
	return b.String()
}

func (s hostsSection) visibleNames() []string {
	if s.h <= 0 || len(s.names) == 0 {
		return s.names
	}
	height := s.h - 8
	if height < 3 {
		height = 3
	}
	if height >= len(s.names) {
		return s.names
	}
	start := 0
	if s.cursor >= height {
		start = s.cursor - height + 1
	}
	end := start + height
	if end > len(s.names) {
		end = len(s.names)
	}
	return s.names[start:end]
}

func renderHostLine(name string, host inventory.Host) string {
	parts := []string{name}
	if host.Addr != "" {
		parts = append(parts, "addr="+host.Addr)
	}
	if host.User != "" {
		parts = append(parts, "user="+host.User)
	}
	if host.Port != 0 {
		parts = append(parts, "port="+strconv.Itoa(host.Port))
	}
	if host.SSHConfigAlias != "" {
		parts = append(parts, "alias="+host.SSHConfigAlias)
	}
	if len(host.Tags) > 0 {
		parts = append(parts, "tags="+strings.Join(host.Tags, ","))
	}
	return strings.Join(parts, " ")
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
	b.WriteString(renderPolicyConfig(s.config))
	b.WriteString("\n")
	if s.err != nil {
		b.WriteString(s.styles.err.Render(s.err.Error()))
		b.WriteString("\n")
	}
	if s.result != "" {
		style := s.styles.ok
		if strings.HasPrefix(s.result, string(policy.ActionDeny)) {
			style = s.styles.err
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

func renderPolicyConfig(cfg policy.Config) string {
	var b strings.Builder
	defaultPolicy := cfg.Defaults.Policy
	if defaultPolicy == "" {
		defaultPolicy = policy.ActionAllow
	}
	fmt.Fprintf(&b, "defaults.policy=%s\n", defaultPolicy)
	if len(cfg.Rules) == 0 {
		b.WriteString("rules: (none)\n")
	} else {
		b.WriteString("rules:\n")
		for i, rule := range cfg.Rules {
			name := rule.Name
			if name == "" {
				name = fmt.Sprintf("[%d]", i)
			}
			fmt.Fprintf(&b, "  - %s action=%s cmd_regex=%q\n", name, rule.Action, rule.Match.CmdRegex)
		}
	}
	if len(cfg.HostOverrides) == 0 {
		b.WriteString("host_overrides: (none)\n")
	} else {
		b.WriteString("host_overrides:\n")
		names := sortedOverrideNames(cfg.HostOverrides)
		for _, name := range names {
			override := cfg.HostOverrides[name]
			fmt.Fprintf(&b, "  - %s policy=%s allow_rules=%d\n", name, override.Policy, len(override.AllowRules))
		}
	}
	fmt.Fprintf(&b, "output.max_bytes=%d redactions=%d\n", cfg.Output.MaxBytes, len(cfg.Output.Redact))
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
		b.WriteString(s.styles.dim.Render("(no sessions)"))
		b.WriteString("\n")
	} else {
		for _, summary := range s.visibleSummaries() {
			cursor := "  "
			if summary.ID == s.summaries[s.cursor].ID {
				cursor = s.styles.cursor.Render("> ")
			}
			label := summary.Label
			if label == "" {
				label = "(none)"
			}
			fmt.Fprintf(&b, "%s%s label=%q start=%s end=%s commands=%d\n",
				cursor, summary.ID, label, summary.Start, summary.End, summary.CommandCount)
		}
	}
	b.WriteString("\n")
	b.WriteString(s.styles.dim.Render("j/k move · enter open in Audit"))
	return b.String()
}

func (s sessionsSection) visibleSummaries() []session.Summary {
	if s.h <= 0 || len(s.summaries) == 0 {
		return s.summaries
	}
	height := s.h - 4
	if height < 3 {
		height = 3
	}
	if height >= len(s.summaries) {
		return s.summaries
	}
	start := 0
	if s.cursor >= height {
		start = s.cursor - height + 1
	}
	end := start + height
	if end > len(s.summaries) {
		end = len(s.summaries)
	}
	return s.summaries[start:end]
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
