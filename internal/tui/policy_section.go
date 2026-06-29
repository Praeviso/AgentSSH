package tui

import (
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/Praeviso/AgentSSH/internal/inventory"
	"github.com/Praeviso/AgentSSH/internal/policy"
	"github.com/charmbracelet/bubbles/help"
	"github.com/charmbracelet/bubbles/key"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// policySection renders either the top-level Policy tab (host == "") or the
// host-scoped Policy pane in a detail screen. Rule groups are authoring presets;
// only global rules and stamped/host-overrides participate in evaluation.
type policySection struct {
	path      string
	inventory inventory.Inventory
	config    policy.Config
	styles    appStyles
	input     textinput.Model
	mode      policyMode
	host      string // detail host; "" means top-level Policy tab

	cardCursor  int
	ruleCursor  int
	groupCursor int
	target      policyTarget

	result string
	err    error
	w, h   int
}

type policyChangedMsg struct {
	config policy.Config
	text   string
}

type policyMode int

const (
	policyModeBrowse policyMode = iota
	policyModeTest
	policyModeRuleAdd
	policyModeRuleEdit
	policyModeGroupCreate
	policyModeGroupPicker
	policyModeConfirmHostDelete
	policyModeConfirmGroupDelete
)

type policyTargetKind int

const (
	policyTargetNone policyTargetKind = iota
	policyTargetGlobal
	policyTargetGroup
)

type policyTarget struct {
	kind  policyTargetKind
	group string
}

func newPolicySection(path string, inv inventory.Inventory, cfg policy.Config, st appStyles, err error) policySection {
	ti := textinput.New()
	ti.Placeholder = "command to test (or host:cmd)"
	ti.Prompt = "test> "
	return policySection{path: path, inventory: inv, config: cfg, styles: st, input: ti, err: err}
}

func (s policySection) capturing() bool { return s.mode != policyModeBrowse || s.input.Focused() }

// atRoot reports whether the pane is at its base state, so the detail shell's
// esc can exit the host screen. The top-level Policy tab handles its own esc.
func (s policySection) atRoot() bool {
	return s.mode == policyModeBrowse && !s.input.Focused() && (s.host != "" || s.target.kind == policyTargetNone)
}

// withHost scopes this pane to host. Passing "" returns it to the top-level
// Policy tab and clears any open group/global rule list.
func (s policySection) withHost(host string) policySection {
	s.host = host
	s.result = ""
	s.err = nil
	s.input.SetValue("")
	s.input.Blur()
	s.mode = policyModeBrowse
	s.ruleCursor = 0
	s.groupCursor = 0
	s.target = policyTarget{}
	return s
}

func (s policySection) helpKeyMap() help.KeyMap {
	switch s.mode {
	case policyModeTest:
		return helpMap{short: []key.Binding{hk("enter", "evaluate"), hk("esc", "cancel")}}
	case policyModeRuleAdd:
		return helpMap{short: []key.Binding{hk("enter", "add rule"), hk("esc", "cancel")}}
	case policyModeRuleEdit:
		return helpMap{short: []key.Binding{hk("enter", "save rule"), hk("esc", "cancel")}}
	case policyModeGroupCreate:
		return helpMap{short: []key.Binding{hk("enter", "create group"), hk("esc", "cancel")}}
	case policyModeGroupPicker:
		return helpMap{short: []key.Binding{hk("j/k", "choose group"), hk("enter", "stamp"), hk("esc", "cancel")}}
	case policyModeConfirmHostDelete, policyModeConfirmGroupDelete:
		return helpMap{short: []key.Binding{hk("y", "confirm"), hk("n/esc", "cancel")}}
	}
	if s.host != "" {
		// Host detail Policy pane: footer shows the few core edits; ? lists all,
		// grouped by navigation / host-rule edits / authoring / testing.
		short := []key.Binding{hk("a", "add rule"), hk("p", "from group"), hk("r", "remove")}
		full := [][]key.Binding{
			{hk("j/k", "select"), hk("g/G", "home/end"), hk("t", "test")},
			{hk("a", "add host rule"), hk("p", "add from group")},
			{hk("r", "remove rule"), hk("R", "remove group"), hk("x", "remove all")},
		}
		return helpMap{short: short, full: full}
	}
	if s.target.kind != policyTargetNone {
		// Drilled into the Global card or a rule group: edit its rule list.
		short := []key.Binding{hk("a", "add"), hk("e", "edit"), hk("r", "remove")}
		full := [][]key.Binding{
			{hk("j/k", "select"), hk("g/G", "home/end")},
			{hk("a", "add rule"), hk("e", "edit rule"), hk("r", "remove rule")},
			{hk("t", "test"), hk("esc", "back to cards")},
		}
		return helpMap{short: short, full: full}
	}
	// Policy cards overview.
	short := []key.Binding{hk("enter", "open"), hk("n", "new group"), hk("t", "test")}
	full := [][]key.Binding{
		{hk("↑↓←→/hjkl", "move"), hk("g/G", "home/end")},
		{hk("enter", "open card"), hk("n", "new group"), hk("d", "delete group")},
		{hk("t", "test a command")},
	}
	return helpMap{short: short, full: full}
}

func (s policySection) Init() tea.Cmd { return nil }

func (s policySection) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		s.w, s.h = msg.Width, msg.Height
		s.resizeInput()
	case tea.KeyMsg:
		if s.input.Focused() {
			return s.updateInput(msg)
		}
		switch s.mode {
		case policyModeGroupPicker:
			return s.updateGroupPicker(msg)
		case policyModeConfirmHostDelete:
			return s.updateHostDeleteConfirm(msg)
		case policyModeConfirmGroupDelete:
			return s.updateGroupDeleteConfirm(msg)
		}
		if s.host != "" {
			return s.updateHostKeys(msg)
		}
		return s.updateTopLevelKeys(msg)
	}
	if s.input.Focused() {
		var cmd tea.Cmd
		s.input, cmd = s.input.Update(msg)
		return s, cmd
	}
	return s, nil
}

func (s *policySection) resizeInput() {
	if s.w <= 0 {
		return
	}
	w := s.w - 4 - lipgloss.Width(s.input.Prompt)
	if w < 8 {
		w = 8
	}
	s.input.Width = w
}

func (s policySection) updateInput(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "enter":
		var saveCmd tea.Cmd
		switch s.mode {
		case policyModeRuleAdd:
			saveCmd = s.addRuleFromInput()
		case policyModeRuleEdit:
			saveCmd = s.editRuleFromInput()
		case policyModeGroupCreate:
			saveCmd = s.createGroupFromInput()
		default:
			s.evaluate()
		}
		s.input.Blur()
		s.mode = policyModeBrowse
		return s, saveCmd
	case "esc":
		s.input.Blur()
		s.mode = policyModeBrowse
		return s, nil
	}
	var cmd tea.Cmd
	s.input, cmd = s.input.Update(msg)
	return s, cmd
}

func (s policySection) updateTopLevelKeys(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	if s.target.kind != policyTargetNone {
		switch msg.String() {
		case "esc":
			s.target = policyTarget{}
			s.ruleCursor = 0
			s.result = ""
			return s, nil
		case "a":
			s.beginRuleInput(policyModeRuleAdd, policy.Rule{})
			return s, s.input.Focus()
		case "e":
			rule, ok := s.selectedTargetRule()
			if !ok {
				s.result = "no rule selected"
				s.err = nil
				return s, nil
			}
			s.beginRuleInput(policyModeRuleEdit, rule)
			return s, s.input.Focus()
		case "r", "delete", "backspace":
			return s.removeSelectedTargetRule()
		case "j", "down":
			s.moveRuleCursor(1, len(s.targetRules()))
		case "k", "up":
			s.moveRuleCursor(-1, len(s.targetRules()))
		case "g", "home":
			s.ruleCursor = 0
		case "G", "end":
			s.ruleCursor = maxInt(len(s.targetRules())-1, 0)
		case "t", "/":
			s.beginTestInput()
			return s, s.input.Focus()
		}
		return s, nil
	}

	switch msg.String() {
	case "t", "/":
		s.beginTestInput()
		return s, s.input.Focus()
	case "n":
		s.err = nil
		s.result = ""
		s.mode = policyModeGroupCreate
		s.input.SetValue("")
		s.input.Placeholder = "readonly"
		s.input.Prompt = "group> "
		s.resizeInput()
		return s, s.input.Focus()
	case "d", "delete", "backspace":
		targets := s.policyTargets()
		if len(targets) == 0 || s.cardCursor >= len(targets) || targets[s.cardCursor].kind != policyTargetGroup {
			s.err = nil
			s.result = "global policy cannot be deleted"
			return s, nil
		}
		s.err = nil
		s.mode = policyModeConfirmGroupDelete
		s.result = fmt.Sprintf("delete rule group %s? y/n", targets[s.cardCursor].group)
	case "enter", "i":
		targets := s.policyTargets()
		if len(targets) == 0 {
			return s, nil
		}
		if s.cardCursor >= len(targets) {
			s.cardCursor = len(targets) - 1
		}
		s.target = targets[s.cardCursor]
		s.ruleCursor = 0
		s.result = ""
	case "left", "h":
		if s.cardCursor > 0 {
			s.cardCursor--
		}
	case "right", "l":
		if s.cardCursor < len(s.policyTargets())-1 {
			s.cardCursor++
		}
	case "up", "k":
		cols := s.policyGridCols()
		if s.cardCursor-cols >= 0 {
			s.cardCursor -= cols
		}
	case "down", "j":
		cols := s.policyGridCols()
		last := len(s.policyTargets()) - 1
		if s.cardCursor+cols <= last {
			s.cardCursor += cols
		} else if s.cardCursor != last && cols > 0 && s.cardCursor/cols < last/cols {
			s.cardCursor = last
		}
	case "home", "g":
		s.cardCursor = 0
	case "end", "G":
		s.cardCursor = maxInt(len(s.policyTargets())-1, 0)
	}
	return s, nil
}

func (s policySection) updateHostKeys(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "t", "/":
		s.beginTestInput()
		return s, s.input.Focus()
	case "a":
		s.beginRuleInput(policyModeRuleAdd, policy.Rule{})
		return s, s.input.Focus()
	case "p":
		groups := s.sortedRuleGroupNames()
		if len(groups) == 0 {
			s.err = nil
			s.result = "no rule groups"
			return s, nil
		}
		if s.groupCursor >= len(groups) {
			s.groupCursor = len(groups) - 1
		}
		s.err = nil
		s.result = ""
		s.mode = policyModeGroupPicker
	case "j", "down":
		s.moveRuleCursor(1, len(s.hostPolicyRows()))
	case "k", "up":
		s.moveRuleCursor(-1, len(s.hostPolicyRows()))
	case "g", "home":
		s.ruleCursor = 0
	case "G", "end":
		s.ruleCursor = maxInt(len(s.hostPolicyRows())-1, 0)
	case "r":
		return s.removeSelectedHostRule()
	case "R":
		return s.removeSelectedHostGroup()
	case "x":
		if _, ok := s.hostRuleSet(); ok {
			s.mode = policyModeConfirmHostDelete
			s.err = nil
			s.result = "delete host policy rules? y/n"
		} else {
			s.err = nil
			s.result = "host has no rules"
		}
	}
	return s, nil
}

func (s policySection) updateGroupPicker(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	groups := s.sortedRuleGroupNames()
	switch msg.String() {
	case "j", "down":
		if s.groupCursor < len(groups)-1 {
			s.groupCursor++
		}
	case "k", "up":
		if s.groupCursor > 0 {
			s.groupCursor--
		}
	case "g", "home":
		s.groupCursor = 0
	case "G", "end":
		s.groupCursor = maxInt(len(groups)-1, 0)
	case "enter":
		if len(groups) == 0 {
			s.mode = policyModeBrowse
			s.result = "no rule groups"
			return s, nil
		}
		return s.stampSelectedGroup(groups[s.groupCursor])
	case "esc":
		s.mode = policyModeBrowse
		s.result = ""
	}
	return s, nil
}

func (s policySection) updateHostDeleteConfirm(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "y":
		return s.removeHostRuleSet()
	case "n", "esc":
		s.mode = policyModeBrowse
		s.result = ""
	}
	return s, nil
}

func (s policySection) updateGroupDeleteConfirm(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "y":
		return s.deleteSelectedGroup()
	case "n", "esc":
		s.mode = policyModeBrowse
		s.result = ""
	}
	return s, nil
}

func (s *policySection) beginTestInput() {
	s.err = nil
	s.result = ""
	s.mode = policyModeTest
	s.input.SetValue("")
	s.input.Placeholder = "command to test (or host:cmd)"
	s.input.Prompt = "test> "
	s.resizeInput()
}

func (s *policySection) beginRuleInput(mode policyMode, rule policy.Rule) {
	s.err = nil
	s.result = ""
	s.mode = mode
	if mode == policyModeRuleEdit {
		s.input.SetValue(formatRuleInput(rule))
	} else {
		s.input.SetValue("")
	}
	s.input.Placeholder = "allow 0 ^systemctl status\\b"
	s.input.Prompt = "rule> "
	s.resizeInput()
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
		host = s.host
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

func (s policySection) hostRuleSet() (policy.HostRuleSet, bool) {
	return policy.LookupHostRules(policy.Bundle{Policy: s.config, Inventory: s.inventory}, s.host)
}

func (s *policySection) reloadForWrite() (policy.Bundle, error) {
	cfg := s.config
	if s.path != "" {
		loaded, err := policy.Load(s.path)
		if err != nil {
			return policy.Bundle{}, err
		}
		cfg = loaded
		s.config = loaded
	}
	return policy.Bundle{Policy: cfg, Inventory: s.inventory}, nil
}

func (s *policySection) savePolicy(next policy.Config) error {
	if s.path == "" {
		s.config = next
		return nil
	}
	return policy.Save(s.path, next)
}

func (s *policySection) addRuleFromInput() tea.Cmd {
	rule, err := parseRuleInput(s.input.Value())
	if err != nil {
		s.err = err
		s.result = ""
		return nil
	}
	if err := validateTUIRule(rule); err != nil {
		s.err = err
		s.result = ""
		return nil
	}
	bundle, err := s.reloadForWrite()
	if err != nil {
		s.err = err
		s.result = ""
		return nil
	}

	var next policy.Bundle
	switch {
	case s.host != "":
		next, err = policy.AddHostRule(bundle, s.host, rule)
	case s.target.kind == policyTargetGlobal:
		next = cloneBundleForTUI(bundle)
		next.Policy.Rules = append(next.Policy.Rules, rule)
	case s.target.kind == policyTargetGroup:
		next, err = policy.AddGroupRule(bundle, s.target.group, rule)
	default:
		s.err = errors.New("open a policy target before adding a rule")
		s.result = ""
		return nil
	}
	if err != nil {
		s.err = err
		s.result = ""
		return nil
	}
	if err := validatePolicyForTUI(next.Policy, s.inventory); err != nil {
		s.err = err
		s.result = ""
		return nil
	}
	if err := s.savePolicy(next.Policy); err != nil {
		s.err = err
		s.result = ""
		return nil
	}
	s.config = next.Policy
	s.err = nil
	s.result = "rule added"
	if s.host != "" {
		s.ruleCursor = hostRowIndexForSource(s.hostPolicyRows(), policy.HostRulesKey(s.host), len(s.hostRuleSetRules())-1)
	} else {
		s.ruleCursor = maxInt(len(s.targetRules())-1, 0)
	}
	return policyChangedCmd(next.Policy, s.result)
}

func (s *policySection) editRuleFromInput() tea.Cmd {
	if s.host != "" {
		return nil
	}
	rule, err := parseRuleInput(s.input.Value())
	if err != nil {
		s.err = err
		s.result = ""
		return nil
	}
	if err := validateTUIRule(rule); err != nil {
		s.err = err
		s.result = ""
		return nil
	}
	bundle, err := s.reloadForWrite()
	if err != nil {
		s.err = err
		s.result = ""
		return nil
	}
	next := cloneBundleForTUI(bundle)
	switch s.target.kind {
	case policyTargetGlobal:
		if s.ruleCursor < 0 || s.ruleCursor >= len(next.Policy.Rules) {
			s.err = errors.New("no rule selected")
			s.result = ""
			return nil
		}
		rule.Name = next.Policy.Rules[s.ruleCursor].Name
		next.Policy.Rules[s.ruleCursor] = rule
	case policyTargetGroup:
		group := bundle.Policy.RuleGroups[strings.TrimSpace(s.target.group)]
		if s.ruleCursor >= 0 && s.ruleCursor < len(group.Rules) {
			rule.Name = group.Rules[s.ruleCursor].Name
		}
		next, err = policy.UpdateGroupRule(bundle, s.target.group, s.ruleCursor, rule)
		if err != nil {
			s.err = err
			s.result = ""
			return nil
		}
	default:
		s.err = errors.New("open a policy target before editing a rule")
		s.result = ""
		return nil
	}
	if err := validatePolicyForTUI(next.Policy, s.inventory); err != nil {
		s.err = err
		s.result = ""
		return nil
	}
	if err := s.savePolicy(next.Policy); err != nil {
		s.err = err
		s.result = ""
		return nil
	}
	s.config = next.Policy
	s.err = nil
	s.result = "rule updated"
	s.clampRuleCursor(len(s.targetRules()))
	return policyChangedCmd(next.Policy, s.result)
}

func (s policySection) removeSelectedTargetRule() (tea.Model, tea.Cmd) {
	if s.host != "" || s.target.kind == policyTargetNone {
		return s, nil
	}
	if len(s.targetRules()) == 0 {
		s.err = nil
		s.result = "no rule selected"
		return s, nil
	}
	bundle, err := s.reloadForWrite()
	if err != nil {
		s.err = err
		s.result = ""
		return s, nil
	}
	next := cloneBundleForTUI(bundle)
	switch s.target.kind {
	case policyTargetGlobal:
		if s.ruleCursor < 0 || s.ruleCursor >= len(next.Policy.Rules) {
			s.err = errors.New("no rule selected")
			s.result = ""
			return s, nil
		}
		next.Policy.Rules = append(next.Policy.Rules[:s.ruleCursor], next.Policy.Rules[s.ruleCursor+1:]...)
	case policyTargetGroup:
		next, err = policy.RemoveGroupRule(bundle, s.target.group, s.ruleCursor)
		if err != nil {
			s.err = err
			s.result = ""
			return s, nil
		}
	}
	if err := validatePolicyForTUI(next.Policy, s.inventory); err != nil {
		s.err = err
		s.result = ""
		return s, nil
	}
	if err := s.savePolicy(next.Policy); err != nil {
		s.err = err
		s.result = ""
		return s, nil
	}
	s.config = next.Policy
	s.clampRuleCursor(len(s.targetRules()))
	s.err = nil
	s.result = "rule removed"
	return s, policyChangedCmd(next.Policy, s.result)
}

func (s *policySection) createGroupFromInput() tea.Cmd {
	name := strings.TrimSpace(s.input.Value())
	bundle, err := s.reloadForWrite()
	if err != nil {
		s.err = err
		s.result = ""
		return nil
	}
	next, err := policy.CreateGroup(bundle, name)
	if err != nil {
		s.err = err
		s.result = ""
		return nil
	}
	if err := s.savePolicy(next.Policy); err != nil {
		s.err = err
		s.result = ""
		return nil
	}
	s.config = next.Policy
	s.cardCursor = targetIndex(s.policyTargets(), policyTarget{kind: policyTargetGroup, group: name})
	s.err = nil
	s.result = "group created"
	return policyChangedCmd(next.Policy, s.result)
}

func (s policySection) deleteSelectedGroup() (tea.Model, tea.Cmd) {
	targets := s.policyTargets()
	if len(targets) == 0 || s.cardCursor >= len(targets) || targets[s.cardCursor].kind != policyTargetGroup {
		s.mode = policyModeBrowse
		s.result = "global policy cannot be deleted"
		return s, nil
	}
	groupName := targets[s.cardCursor].group
	bundle, err := s.reloadForWrite()
	if err != nil {
		s.err = err
		s.result = ""
		s.mode = policyModeBrowse
		return s, nil
	}
	next, err := policy.DeleteGroup(bundle, groupName)
	if err != nil {
		s.err = err
		s.result = ""
		s.mode = policyModeBrowse
		return s, nil
	}
	if err := s.savePolicy(next.Policy); err != nil {
		s.err = err
		s.result = ""
		s.mode = policyModeBrowse
		return s, nil
	}
	s.config = next.Policy
	s.mode = policyModeBrowse
	s.cardCursor = maxInt(minInt(s.cardCursor, len(s.policyTargets())-1), 0)
	s.err = nil
	s.result = "group deleted"
	return s, policyChangedCmd(next.Policy, s.result)
}

func (s policySection) stampSelectedGroup(groupName string) (tea.Model, tea.Cmd) {
	bundle, err := s.reloadForWrite()
	if err != nil {
		s.err = err
		s.result = ""
		s.mode = policyModeBrowse
		return s, nil
	}
	next, err := policy.StampGroupOntoHost(bundle, s.host, groupName)
	if err != nil {
		s.err = err
		s.result = ""
		s.mode = policyModeBrowse
		return s, nil
	}
	if err := validatePolicyForTUI(next.Policy, s.inventory); err != nil {
		s.err = err
		s.result = ""
		s.mode = policyModeBrowse
		return s, nil
	}
	if err := s.savePolicy(next.Policy); err != nil {
		s.err = err
		s.result = ""
		s.mode = policyModeBrowse
		return s, nil
	}
	s.config = next.Policy
	s.mode = policyModeBrowse
	s.err = nil
	s.result = "group stamped"
	s.ruleCursor = firstHostGroupRow(s.hostPolicyRows(), groupName)
	return s, policyChangedCmd(next.Policy, s.result)
}

func (s policySection) removeSelectedHostRule() (tea.Model, tea.Cmd) {
	row, ok := s.selectedHostPolicyRow()
	if !ok {
		s.err = nil
		s.result = "no host rule selected"
		return s, nil
	}
	if row.Scope != "host" {
		s.err = nil
		s.result = "global rows are read-only here"
		return s, nil
	}
	bundle, err := s.reloadForWrite()
	if err != nil {
		s.err = err
		s.result = ""
		return s, nil
	}
	var next policy.Bundle
	if row.Source == policy.HostRulesKey(s.host) {
		next, err = policy.RemoveHostRule(bundle, s.host, row.Index)
	} else {
		next, err = removeHostOverrideRuleForTUI(bundle, row.Source, row.Index)
	}
	if err != nil {
		s.err = err
		s.result = ""
		return s, nil
	}
	if err := validatePolicyForTUI(next.Policy, s.inventory); err != nil {
		s.err = err
		s.result = ""
		return s, nil
	}
	if err := s.savePolicy(next.Policy); err != nil {
		s.err = err
		s.result = ""
		return s, nil
	}
	s.config = next.Policy
	s.clampRuleCursor(len(s.hostPolicyRows()))
	s.err = nil
	s.result = "host rule removed"
	return s, policyChangedCmd(next.Policy, s.result)
}

func (s policySection) removeSelectedHostGroup() (tea.Model, tea.Cmd) {
	row, ok := s.selectedHostPolicyRow()
	if !ok || row.Scope != "host" || strings.TrimSpace(row.Rule.Group) == "" {
		s.err = nil
		s.result = "select a stamped group row"
		return s, nil
	}
	bundle, err := s.reloadForWrite()
	if err != nil {
		s.err = err
		s.result = ""
		return s, nil
	}
	// Remove the group from the override that owns the selected row, not blindly
	// from this host's own rules; the row may be inherited from a group override.
	var next policy.Bundle
	if row.Source == policy.HostRulesKey(s.host) {
		next, err = policy.RemoveHostGroup(bundle, s.host, row.Rule.Group)
	} else {
		next, err = removeHostOverrideGroupForTUI(bundle, row.Source, row.Rule.Group)
	}
	if err != nil {
		s.err = err
		s.result = ""
		return s, nil
	}
	if err := validatePolicyForTUI(next.Policy, s.inventory); err != nil {
		s.err = err
		s.result = ""
		return s, nil
	}
	if err := s.savePolicy(next.Policy); err != nil {
		s.err = err
		s.result = ""
		return s, nil
	}
	s.config = next.Policy
	s.clampRuleCursor(len(s.hostPolicyRows()))
	s.err = nil
	s.result = "host group removed"
	return s, policyChangedCmd(next.Policy, s.result)
}

func (s policySection) removeHostRuleSet() (tea.Model, tea.Cmd) {
	bundle, err := s.reloadForWrite()
	if err != nil {
		s.err = err
		s.result = ""
		s.mode = policyModeBrowse
		return s, nil
	}
	next, err := policy.ClearHostRules(bundle, s.host)
	if err != nil {
		s.err = err
		s.result = ""
		s.mode = policyModeBrowse
		return s, nil
	}
	if err := s.savePolicy(next.Policy); err != nil {
		s.err = err
		s.result = ""
		s.mode = policyModeBrowse
		return s, nil
	}
	s.config = next.Policy
	s.mode = policyModeBrowse
	s.err = nil
	s.result = "host policy removed"
	s.ruleCursor = 0
	return s, policyChangedCmd(next.Policy, s.result)
}

func policyChangedCmd(cfg policy.Config, text string) tea.Cmd {
	return func() tea.Msg {
		return policyChangedMsg{config: cfg, text: text}
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

func parseRuleInput(value string) (policy.Rule, error) {
	fields := strings.Fields(strings.TrimSpace(value))
	if len(fields) < 2 {
		return policy.Rule{}, errors.New("enter: allow|deny [priority] <cmd regex>")
	}
	action := policy.Action(fields[0])
	if action != policy.ActionAllow && action != policy.ActionDeny {
		return policy.Rule{}, errors.New("rule action must be allow or deny")
	}
	priority := 0
	regexStart := 1
	if len(fields) >= 3 {
		if parsed, err := strconv.Atoi(fields[1]); err == nil {
			priority = parsed
			regexStart = 2
		}
	}
	cmdRegex := strings.TrimSpace(strings.Join(fields[regexStart:], " "))
	if cmdRegex == "" {
		return policy.Rule{}, errors.New("enter a command regex")
	}
	return policy.Rule{
		Priority: priority,
		Match:    policy.Match{CmdRegex: cmdRegex},
		Action:   action,
	}, nil
}

func formatRuleInput(rule policy.Rule) string {
	return strings.TrimSpace(fmt.Sprintf("%s %d %s", rule.Action, rule.Priority, rule.Match.CmdRegex))
}

func validateTUIRule(rule policy.Rule) error {
	_, err := policy.NewEngine(policy.Config{Rules: []policy.Rule{{
		Name:     "validate",
		Match:    rule.Match,
		Action:   rule.Action,
		Priority: rule.Priority,
	}}}, inventory.Inventory{})
	return err
}

func validatePolicyForTUI(cfg policy.Config, inv inventory.Inventory) error {
	_, err := policy.NewEngine(cfg, inv)
	return err
}

func (s policySection) View() string {
	if s.host != "" {
		return s.hostPolicyView()
	}
	if s.target.kind != policyTargetNone {
		return s.targetRuleListView()
	}
	return s.policyCardsView()
}

func (s policySection) hostPolicyView() string {
	inner := s.w - 2
	if inner < 8 {
		inner = 8
	}
	content := s.renderHostPolicyBody(inner)
	if extra := s.extraLines(inner); extra != "" {
		content += "\n\n" + extra
	}
	// Borderless, like the Sessions list: the rule rows read as one flat table
	// rather than a boxed card. The shell clamps width/height around it.
	return s.styles.background.MaxWidth(s.w).Render(content)
}

func (s policySection) targetRuleListView() string {
	inner := s.w - 2
	if inner < 8 {
		inner = 8
	}
	content := s.renderTargetRuleList(inner)
	if extra := s.extraLines(inner); extra != "" {
		content += "\n\n" + extra
	}
	return s.styles.background.MaxWidth(s.w).Render(content)
}

func (s policySection) extraLines(inner int) string {
	var extra []string
	if s.mode == policyModeGroupPicker {
		extra = append(extra, s.renderGroupPicker(inner))
	}
	if s.input.Focused() {
		extra = append(extra, s.input.View())
	}
	if s.err != nil {
		extra = append(extra, truncate(s.styles.err.Render(s.err.Error()), inner))
	} else if s.result != "" {
		style := s.styles.dim
		switch {
		case strings.HasPrefix(s.result, string(policy.ActionDeny)):
			style = s.styles.deny
		case strings.HasPrefix(s.result, string(policy.ActionAllow)):
			style = s.styles.ok
		case s.mode == policyModeConfirmHostDelete || s.mode == policyModeConfirmGroupDelete:
			style = s.styles.confirm
		}
		extra = append(extra, truncate(style.Render(s.result), inner))
	}
	return strings.Join(extra, "\n")
}

func (s policySection) renderHostPolicyBody(inner int) string {
	var b strings.Builder
	b.WriteString(s.styles.header.Render(truncate(s.styles.glyphs.Marker+" "+s.host, inner)))
	b.WriteString("\n")
	b.WriteString(s.styles.dim.Render("host tier evaluates before global · global rows are read-only here"))
	rows := s.hostPolicyRows()
	if len(rows) == 0 {
		b.WriteString("\n\n")
		b.WriteString(s.styles.dim.Render("No active rules. Default deny still applies."))
		b.WriteString("\n")
		b.WriteString(s.styles.dim.Render(outputSummary(s.config.Output)))
		return b.String()
	}
	start, end := scrollWindow(s.ruleCursor, len(rows), s.ruleVisibleHeight())
	tableRows := make([][]string, 0, end-start)
	for _, row := range rows[start:end] {
		group := ""
		if row.Scope == "host" {
			group = row.Rule.Group
		}
		action := string(row.Rule.Action)
		if row.Rule.Action == policy.ActionDeny {
			action = s.styles.deny.Render(action)
		} else {
			action = s.styles.ok.Render(action)
		}
		tableRows = append(tableRows, []string{
			row.Scope,
			strconv.Itoa(row.Rule.Priority),
			action,
			row.Rule.Match.CmdRegex,
			group,
		})
	}
	cursor := -1
	if s.ruleCursor >= start && s.ruleCursor < end {
		cursor = s.ruleCursor - start
	}
	b.WriteString("\n\n")
	b.WriteString(renderTable(s.styles, policyRuleColumns(), tableRows, cursor, inner, true))
	if end < len(rows) || start > 0 {
		b.WriteString("\n")
		b.WriteString(s.styles.dim.Render(fmt.Sprintf("rows %d-%d of %d", start+1, end, len(rows))))
	}
	b.WriteString("\n")
	b.WriteString(s.styles.dim.Render("output · " + outputSummary(s.config.Output)))
	return b.String()
}

func (s policySection) renderTargetRuleList(inner int) string {
	title := "Global"
	if s.target.kind == policyTargetGroup {
		title = "Group: " + s.target.group
	}
	rules := s.targetRules()
	var b strings.Builder
	b.WriteString(s.styles.header.Render(truncate(s.styles.glyphs.Marker+" "+title, inner)))
	b.WriteString("\n")
	b.WriteString(s.styles.dim.Render("rules use: allow|deny [priority] <cmd_regex>"))
	if len(rules) == 0 {
		b.WriteString("\n\n")
		b.WriteString(s.styles.dim.Render("No rules. Press a to add one."))
		return b.String()
	}
	start, end := scrollWindow(s.ruleCursor, len(rules), s.ruleVisibleHeight())
	tableRows := make([][]string, 0, end-start)
	for _, rule := range rules[start:end] {
		action := string(rule.Action)
		if rule.Action == policy.ActionDeny {
			action = s.styles.deny.Render(action)
		} else {
			action = s.styles.ok.Render(action)
		}
		tableRows = append(tableRows, []string{
			strconv.Itoa(rule.Priority),
			action,
			rule.Match.CmdRegex,
			rule.Group,
		})
	}
	cursor := -1
	if s.ruleCursor >= start && s.ruleCursor < end {
		cursor = s.ruleCursor - start
	}
	b.WriteString("\n\n")
	b.WriteString(renderTable(s.styles, targetRuleColumns(), tableRows, cursor, inner, true))
	return b.String()
}

func (s policySection) policyCardsView() string {
	var b strings.Builder
	if s.err != nil {
		b.WriteString(truncate(s.styles.err.Render(s.err.Error()), s.w))
		b.WriteString("\n")
	}
	targets := s.policyTargets()
	if len(targets) == 0 {
		b.WriteString(s.styles.dim.Render("No policy targets."))
		return b.String()
	}
	s.clampCardCursor()
	b.WriteString(s.policyCardGrid(targets))
	if extra := s.extraLines(maxInt(s.w, 8)); extra != "" {
		b.WriteString("\n")
		b.WriteString(extra)
	}
	return b.String()
}

func (s policySection) policyCardGrid(targets []policyTarget) string {
	cols := s.policyGridCols()
	cardW := s.policyCardOuterWidth(cols)
	totalRows := (len(targets) + cols - 1) / cols
	avail := s.h
	visRows := totalRows
	if s.h > 0 {
		fullGridH := totalRows*cardRowH - cardRowGap
		reserve := 0
		if fullGridH > avail {
			reserve = 1
		}
		visRows = (avail - reserve + cardRowGap) / cardRowH
		if visRows < 1 {
			visRows = 1
		}
	}
	cursorRow := 0
	if cols > 0 {
		cursorRow = s.cardCursor / cols
	}
	startRow, endRow := scrollWindow(cursorRow, totalRows, visRows)
	rows := make([]string, 0, endRow-startRow)
	for r := startRow; r < endRow; r++ {
		cards := make([]string, 0, cols*2)
		for c := 0; c < cols; c++ {
			idx := r*cols + c
			if idx >= len(targets) {
				break
			}
			if c > 0 {
				cards = append(cards, strings.Repeat(" ", cardGap))
			}
			cards = append(cards, s.renderPolicyCard(targets[idx], cardW, idx == s.cardCursor))
		}
		rows = append(rows, lipgloss.JoinHorizontal(lipgloss.Top, cards...))
	}
	grid := strings.Join(rows, strings.Repeat("\n", cardRowGap+1))
	if endRow < totalRows || startRow > 0 {
		grid += "\n" + s.styles.dim.Render(fmt.Sprintf("rows %d-%d of %d", startRow+1, endRow, totalRows))
	}
	return grid
}

func (s policySection) renderPolicyCard(target policyTarget, outerW int, selected bool) string {
	box := outerW - 2
	if box < 12 {
		box = 12
	}
	textW := box - 2
	if textW < 1 {
		textW = 1
	}
	name, rules := s.targetNameAndRules(target)
	allow, deny := countRuleActions(rules)
	labelStyle := s.styles.background
	if selected {
		labelStyle = s.styles.header
	}
	line1 := fitCell(labelStyle.Render(truncate(name, textW)), textW, false)
	line2 := fitCell(s.styles.dim.Render(truncate(fmt.Sprintf("%d rules · %d allow · %d deny", len(rules), allow, deny), textW)), textW, false)
	style := s.styles.card
	if selected {
		style = s.styles.cardSel
	}
	return style.Width(box).Render(lipgloss.JoinVertical(lipgloss.Left, line1, line2))
}

func (s policySection) renderGroupPicker(inner int) string {
	groups := s.sortedRuleGroupNames()
	if len(groups) == 0 {
		return s.styles.dim.Render("No rule groups")
	}
	start, end := scrollWindow(s.groupCursor, len(groups), 5)
	var lines []string
	lines = append(lines, s.styles.header.Render("Choose rule group"))
	for i := start; i < end; i++ {
		name := groups[i]
		group := s.config.RuleGroups[name]
		prefix := "  "
		if i == s.groupCursor {
			prefix = s.styles.cursor.Render("> ")
		}
		lines = append(lines, truncate(prefix+name+s.styles.dim.Render(fmt.Sprintf(" · %d rule(s)", len(group.Rules))), inner))
	}
	return strings.Join(lines, "\n")
}

func policyRuleColumns() []tableColumn {
	return []tableColumn{
		{header: "SCOPE", min: 6, max: 8},
		{header: "PRIORITY", right: true, min: 8, max: 8},
		{header: "ACTION", min: 5, max: 7},
		{header: "COMMAND", min: 12, weight: 2},
		{header: "GROUP", min: 5, max: 18, weight: 1},
	}
}

func targetRuleColumns() []tableColumn {
	return []tableColumn{
		{header: "PRIORITY", right: true, min: 8, max: 8},
		{header: "ACTION", min: 5, max: 7},
		{header: "COMMAND", min: 12, weight: 2},
		{header: "GROUP", min: 5, max: 18, weight: 1},
	}
}

func (s policySection) ruleVisibleHeight() int {
	if s.h <= 0 {
		return 0
	}
	visible := s.h - 9
	if visible < 1 {
		return 1
	}
	return visible
}

func (s policySection) policyTargets() []policyTarget {
	targets := []policyTarget{{kind: policyTargetGlobal}}
	for _, name := range s.sortedRuleGroupNames() {
		targets = append(targets, policyTarget{kind: policyTargetGroup, group: name})
	}
	return targets
}

func (s policySection) targetNameAndRules(target policyTarget) (string, []policy.Rule) {
	switch target.kind {
	case policyTargetGroup:
		return target.group, s.config.RuleGroups[target.group].Rules
	default:
		return "Global", s.config.Rules
	}
}

func (s policySection) targetRules() []policy.Rule {
	switch s.target.kind {
	case policyTargetGlobal:
		return s.config.Rules
	case policyTargetGroup:
		return s.config.RuleGroups[s.target.group].Rules
	default:
		return nil
	}
}

func (s policySection) selectedTargetRule() (policy.Rule, bool) {
	rules := s.targetRules()
	if s.ruleCursor < 0 || s.ruleCursor >= len(rules) {
		return policy.Rule{}, false
	}
	return rules[s.ruleCursor], true
}

func (s policySection) sortedRuleGroupNames() []string {
	names := make([]string, 0, len(s.config.RuleGroups))
	for name := range s.config.RuleGroups {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func (s policySection) hostPolicyRows() []policy.EffectiveRule {
	return policy.EffectiveRules(s.config, s.inventory, s.host)
}

func (s policySection) selectedHostPolicyRow() (policy.EffectiveRule, bool) {
	rows := s.hostPolicyRows()
	if s.ruleCursor < 0 || s.ruleCursor >= len(rows) {
		return policy.EffectiveRule{}, false
	}
	return rows[s.ruleCursor], true
}

func (s policySection) hostRuleSetRules() []policy.Rule {
	if ruleSet, ok := s.hostRuleSet(); ok {
		return ruleSet.Override.Rules
	}
	return nil
}

func (s *policySection) moveRuleCursor(delta int, n int) {
	if n <= 0 {
		s.ruleCursor = 0
		return
	}
	s.ruleCursor += delta
	if s.ruleCursor < 0 {
		s.ruleCursor = 0
	}
	if s.ruleCursor >= n {
		s.ruleCursor = n - 1
	}
}

func (s *policySection) clampRuleCursor(n int) {
	if n <= 0 {
		s.ruleCursor = 0
		return
	}
	if s.ruleCursor >= n {
		s.ruleCursor = n - 1
	}
	if s.ruleCursor < 0 {
		s.ruleCursor = 0
	}
}

func (s *policySection) clampCardCursor() {
	n := len(s.policyTargets())
	if n <= 0 {
		s.cardCursor = 0
		return
	}
	if s.cardCursor >= n {
		s.cardCursor = n - 1
	}
	if s.cardCursor < 0 {
		s.cardCursor = 0
	}
}

func (s policySection) policyGridCols() int {
	if s.w <= 0 {
		return 1
	}
	cols := (s.w + cardGap) / (cardMinOuter + cardGap)
	if cols < 1 {
		cols = 1
	}
	if n := len(s.policyTargets()); cols > n && n > 0 {
		cols = n
	}
	return cols
}

func (s policySection) policyCardOuterWidth(cols int) int {
	if cols < 1 {
		cols = 1
	}
	avail := s.w - cardGap*(cols-1)
	w := avail / cols
	if w < cardMinOuter {
		w = cardMinOuter
	}
	return w
}

func cloneBundleForTUI(bundle policy.Bundle) policy.Bundle {
	next := bundle
	next.Policy = clonePolicyConfigForTUI(bundle.Policy)
	return next
}

func clonePolicyConfigForTUI(cfg policy.Config) policy.Config {
	next := cfg
	next.Rules = append([]policy.Rule(nil), cfg.Rules...)
	if cfg.RuleGroups != nil {
		next.RuleGroups = make(map[string]policy.RuleGroup, len(cfg.RuleGroups))
		for name, group := range cfg.RuleGroups {
			group.Rules = append([]policy.Rule(nil), group.Rules...)
			next.RuleGroups[name] = group
		}
	}
	if cfg.HostOverrides != nil {
		next.HostOverrides = make(map[string]policy.HostOverride, len(cfg.HostOverrides))
		for name, override := range cfg.HostOverrides {
			override.Rules = append([]policy.Rule(nil), override.Rules...)
			next.HostOverrides[name] = override
		}
	}
	next.Output.Redact = append([]string(nil), cfg.Output.Redact...)
	return next
}

func removeHostOverrideRuleForTUI(bundle policy.Bundle, source string, index int) (policy.Bundle, error) {
	override, ok := bundle.Policy.HostOverrides[source]
	if !ok {
		return bundle, fmt.Errorf("host override %q not found", source)
	}
	if index < 0 || index >= len(override.Rules) {
		return bundle, fmt.Errorf("host override %q rule index %d out of range", source, index)
	}
	next := cloneBundleForTUI(bundle)
	override = next.Policy.HostOverrides[source]
	override.Rules = append(override.Rules[:index], override.Rules[index+1:]...)
	next.Policy.HostOverrides[source] = override
	return next, nil
}

// removeHostOverrideGroupForTUI bulk-removes the provenance-tagged rules of a
// stamped group from the override that actually owns the selected row, which may
// be a matched group override, not the host's own host:<name> rules.
func removeHostOverrideGroupForTUI(bundle policy.Bundle, source, group string) (policy.Bundle, error) {
	if strings.TrimSpace(group) == "" {
		return bundle, fmt.Errorf("policy group name is required")
	}
	override, ok := bundle.Policy.HostOverrides[source]
	if !ok {
		return bundle, fmt.Errorf("host override %q not found", source)
	}
	next := cloneBundleForTUI(bundle)
	override = next.Policy.HostOverrides[source]
	kept := make([]policy.Rule, 0, len(override.Rules))
	for _, rule := range override.Rules {
		if rule.Group == group {
			continue
		}
		kept = append(kept, rule)
	}
	override.Rules = kept
	next.Policy.HostOverrides[source] = override
	return next, nil
}

func hostRowIndexForSource(rows []policy.EffectiveRule, source string, index int) int {
	for i, row := range rows {
		if row.Source == source && row.Index == index {
			return i
		}
	}
	return maxInt(len(rows)-1, 0)
}

func firstHostGroupRow(rows []policy.EffectiveRule, group string) int {
	for i, row := range rows {
		if row.Scope == "host" && row.Rule.Group == group {
			return i
		}
	}
	return maxInt(len(rows)-1, 0)
}

func targetIndex(targets []policyTarget, target policyTarget) int {
	for i, candidate := range targets {
		if candidate.kind == target.kind && candidate.group == target.group {
			return i
		}
	}
	return 0
}

func countRuleActions(rules []policy.Rule) (allow, deny int) {
	for _, rule := range rules {
		switch rule.Action {
		case policy.ActionAllow:
			allow++
		case policy.ActionDeny:
			deny++
		}
	}
	return allow, deny
}

func outputSummary(out policy.Output) string {
	limit := "unlimited"
	if out.MaxBytes > 0 {
		limit = humanBytes(out.MaxBytes) + " cap"
	}
	switch n := len(out.Redact); n {
	case 0:
		return limit
	case 1:
		return limit + " · 1 redaction"
	default:
		return fmt.Sprintf("%s · %d redactions", limit, n)
	}
}

func humanBytes(n int) string {
	switch {
	case n >= 1<<20:
		if n%(1<<20) == 0 {
			return fmt.Sprintf("%d MiB", n/(1<<20))
		}
		return fmt.Sprintf("%.1f MiB", float64(n)/(1<<20))
	case n >= 1<<10:
		if n%(1<<10) == 0 {
			return fmt.Sprintf("%d KiB", n/(1<<10))
		}
		return fmt.Sprintf("%.1f KiB", float64(n)/(1<<10))
	default:
		return fmt.Sprintf("%d B", n)
	}
}
