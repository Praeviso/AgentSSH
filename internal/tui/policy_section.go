package tui

import (
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/Praeviso/AgentSSH/internal/inventory"
	"github.com/Praeviso/AgentSSH/internal/policy"
	"github.com/Praeviso/AgentSSH/internal/theme"
	"github.com/charmbracelet/bubbles/help"
	"github.com/charmbracelet/bubbles/key"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// policySection renders the single global policy (the permission model). In a
// host's detail screen it is scoped to that host: the command test evaluates as
// the host, and the header names it. The policy itself is global; only the
// evaluation context is per-host.
type policySection struct {
	path      string
	inventory inventory.Inventory
	config    policy.Config
	styles    appStyles
	input     textinput.Model
	host      string // the host this pane is scoped to (detail screen); "" = global
	result    string
	err       error
	w, h      int
}

func newPolicySection(path string, inv inventory.Inventory, cfg policy.Config, st appStyles, err error) policySection {
	ti := textinput.New()
	ti.Placeholder = "command to test (or host:cmd)"
	ti.Prompt = "test> "
	return policySection{path: path, inventory: inv, config: cfg, styles: st, input: ti, err: err}
}

func (s policySection) capturing() bool { return s.input.Focused() }

// atRoot reports whether the pane is at its base state (no test input open), so
// the shell's esc exits the detail screen rather than blurring the input.
func (s policySection) atRoot() bool { return !s.input.Focused() }

// withHost scopes this pane to host (its command test evaluates as that host).
func (s policySection) withHost(host string) policySection {
	s.host = host
	s.result = ""
	s.input.SetValue("")
	s.input.Blur()
	return s
}

func (s policySection) helpKeyMap() help.KeyMap {
	if s.input.Focused() {
		return helpMap{short: []key.Binding{hk("enter", "evaluate"), hk("esc", "cancel")}}
	}
	return helpMap{short: []key.Binding{hk("t", "test a command")}}
}

func (s policySection) Init() tea.Cmd { return nil }

func (s policySection) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		s.w, s.h = msg.Width, msg.Height
		if s.w > 0 {
			w := s.w - lipgloss.Width(s.input.Prompt) - 1
			if w < 8 {
				w = 8
			}
			s.input.Width = w
		}
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
	if s.path != "" {
		cfg, err := loadPolicy(s.path)
		if err != nil {
			s.err = err
			s.result = ""
			return
		}
		s.config = cfg
	}
	engine, err := policy.NewEngine(s.config, s.inventory)
	if err != nil {
		s.err = err
		s.result = ""
		return
	}
	host, command := parsePolicyTestInput(s.input.Value())
	if host == "" {
		host = s.host // scope to the detail host when the input omits one
	}
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
	fit := func(line string) string {
		if s.w > 0 {
			return truncate(line, s.w)
		}
		return line
	}

	// The pane identity ("Policy" + the host) already lives in the shell breadcrumb,
	// so the body starts directly with the policy panels.
	lines := strings.Split(s.renderPolicyBody(), "\n")

	// The test area appears below the policy body, set off by a blank line, and only
	// while a test is active (input focused) or there is a result/error to show. The
	// static "press t" affordance lives in the footer help bar, not in the body.
	var test []string
	if s.input.Focused() {
		test = append(test, s.input.View())
	}
	if s.err != nil {
		test = append(test, fit(s.styles.err.Render(s.err.Error())))
	}
	if s.result != "" {
		style := s.styles.ok
		if strings.HasPrefix(s.result, string(policy.ActionDeny)) {
			style = s.styles.deny
		}
		test = append(test, fit(style.Render(s.result)))
	}
	if len(test) > 0 {
		lines = append(lines, "")
		lines = append(lines, test...)
	}
	// The shell clamps the body to the pane height (MaxHeight); on a short terminal
	// the lower panels simply clip.
	return strings.Join(lines, "\n")
}

// panel wraps body in a full-width rounded-border box (the same style as the host
// info card), so each policy section is clearly framed instead of bunched together.
func (s policySection) panel(body string) string {
	boxW := s.w - 2 // border adds one column each side, outside Width
	if boxW < 12 {
		boxW = 12
	}
	return s.styles.panel.Width(boxW).Render(body)
}

// renderPolicyBody lays the global policy out as a stack of full-width bordered
// panels — defaults (posture + output), rules, and host overrides — each separated
// by a blank line. The tables fill their panel and shrink responsively.
func (s policySection) renderPolicyBody() string {
	cfg := s.config
	inner := s.w - 4 // panel content width: frame minus border (2) and padding (2)
	if inner < 8 {
		inner = 8
	}

	defaultPolicy := cfg.Defaults.Policy
	if defaultPolicy == "" {
		defaultPolicy = policy.ActionAllow
	}

	const kw = 16 // key column width for the aligned defaults rows
	facts := s.styles.dim.Render(padRight("Default posture", kw)) + policyActionCell(s.styles.glyphs, defaultPolicy) + "\n" +
		s.styles.dim.Render(padRight("Output", kw)) + fmt.Sprintf("max_bytes=%d · redactions=%d", cfg.Output.MaxBytes, len(cfg.Output.Redact))

	panels := []string{
		s.panel(facts),
		s.panel(s.styles.dim.Render("Rules") + "\n" + renderPolicyRules(s.styles, cfg, inner)),
	}
	if ov := renderPolicyOverrides(s.styles, cfg, inner); ov != "" {
		panels = append(panels, s.panel(s.styles.dim.Render("Host overrides")+"\n"+ov))
	}
	return strings.Join(panels, "\n\n")
}

var policyRuleColumns = []tableColumn{
	{header: "NAME", min: 6, max: 24, weight: 1},
	{header: "ACTION", min: 7},
	{header: "CMD REGEX", min: 10, max: 80, weight: 3},
}

func policyActionCell(g theme.Glyphs, action policy.Action) string {
	if action == policy.ActionDeny {
		return g.Deny + " DENY"
	}
	return g.OK + " ALLOW"
}

func renderPolicyRules(st appStyles, cfg policy.Config, avail int) string {
	if len(cfg.Rules) == 0 {
		return st.dim.Render("(none)")
	}
	rows := make([][]string, 0, len(cfg.Rules))
	for i, rule := range cfg.Rules {
		name := rule.Name
		if name == "" {
			name = fmt.Sprintf("[%d]", i)
		}
		rows = append(rows, []string{
			name,
			policyActionCell(st.glyphs, rule.Action),
			rule.Match.CmdRegex,
		})
	}
	return renderTable(st, policyRuleColumns, rows, -1, avail, true)
}

func renderPolicyOverrides(st appStyles, cfg policy.Config, avail int) string {
	if len(cfg.HostOverrides) == 0 {
		return ""
	}
	rows := make([][]string, 0, len(cfg.HostOverrides))
	for _, name := range sortedOverrideNames(cfg.HostOverrides) {
		override := cfg.HostOverrides[name]
		rows = append(rows, []string{
			name,
			policyActionCell(st.glyphs, override.Policy),
			strconv.Itoa(len(override.AllowRules)),
		})
	}
	return renderTable(st, hostOverrideColumns, rows, -1, avail, true)
}

var hostOverrideColumns = []tableColumn{
	{header: "HOST", min: 6, max: 40, weight: 2},
	{header: "POLICY", min: 7},
	{header: "ALLOW", right: true, min: 5},
}

func sortedOverrideNames(overrides map[string]policy.HostOverride) []string {
	names := make([]string, 0, len(overrides))
	for name := range overrides {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}
