package tui

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Praeviso/AgentSSH/internal/policy"
)

// Removing a stamped group from the host pane must mutate the override that owns
// the selected row — a matched group override, not blindly the host's own rules.
// Otherwise R on an inherited row deletes the wrong rules.
func TestRemoveSelectedHostGroupRespectsSource(t *testing.T) {
	inv := `version: 1
hosts:
  web-1: { addr: 10.0.0.11, user: deploy, tags: [prod] }
groups:
  prod: { tags: [prod] }
`
	pol := `version: 1
host_overrides:
  host:web-1:
    rules:
      - { match: { cmd_regex: '^a$' }, action: allow, group: shared }
  prod:
    rules:
      - { match: { cmd_regex: '^b$' }, action: deny, group: shared }
`
	m := sized(t, buildAppWith(t, inv, pol), 100, 24)
	m.detailHost = "web-1"
	m.screen = screenDetail
	m.pane = panePolicy
	m.policy = m.policy.withHost("web-1")

	// Select the row that belongs to the prod group override (not host:web-1).
	rows := m.policy.hostPolicyRows()
	idx := -1
	for i, r := range rows {
		if r.Source == "prod" {
			idx = i
		}
	}
	if idx < 0 {
		t.Fatalf("prod override row not found among %d rows", len(rows))
	}
	m.policy.ruleCursor = idx

	next, _ := m.policy.removeSelectedHostGroup()
	cfg := next.(policySection).config
	if got := len(cfg.HostOverrides["prod"].Rules); got != 0 {
		t.Fatalf("prod override rules = %d, want 0 (removed from the selected row's source)", got)
	}
	if got := len(cfg.HostOverrides[policy.HostRulesKey("web-1")].Rules); got != 1 {
		t.Fatalf("host:web-1 rules = %d, want 1 (untouched)", got)
	}
}

// The policy pane in a host's detail evaluates the command as that host, so the
// host's group overrides apply without the operator typing a host: prefix.
func TestPolicyPaneScopesEvaluationToHost(t *testing.T) {
	// prod-web-01 is tagged web; the sample policy allows ^ls through that group.
	m := buildApp(t)
	ps := m.policy.withHost("prod-web-01")

	ps.input.SetValue("ls -la")
	ps.evaluate()
	if !strings.HasPrefix(ps.result, "allow") {
		t.Fatalf("allowed cmd result = %q, want allow", ps.result)
	}
	if !strings.Contains(ps.result, "host=prod-web-01") {
		t.Fatalf("result missing host scope: %q", ps.result)
	}

	ps.input.SetValue("cat /etc/passwd")
	ps.evaluate()
	if !strings.HasPrefix(ps.result, "deny") {
		t.Fatalf("unmatched cmd result = %q, want deny", ps.result)
	}
}

// Drives evaluation through the real Update/key path (not a direct evaluate call)
// to prove the value-receiver Update persists the result back to the shell.
func TestPolicyEvaluateThroughKeyPathPersists(t *testing.T) {
	m := sized(t, buildApp(t), 100, 30)
	m = press(t, m, "enter") // open "bare"
	m = press(t, m, "3")     // policy pane
	m = press(t, m, "t")     // focus test input
	m.policy.input.SetValue("whoami")
	m = press(t, m, "enter") // evaluate
	if m.policy.result == "" {
		t.Fatal("policy result empty after evaluate via key path — Update lost the mutation")
	}
	if !strings.Contains(m.policy.result, "host=bare") {
		t.Fatalf("result = %q, want it scoped to host=bare", m.policy.result)
	}
}

func TestPolicyPaneAtRoot(t *testing.T) {
	m := buildApp(t)
	ps := m.policy.withHost("bare")
	if !ps.atRoot() {
		t.Fatal("policy pane with blurred input should be at root")
	}
	cmd := ps.input.Focus()
	_ = cmd
	if ps.atRoot() {
		t.Fatal("policy pane with focused input should not be at root")
	}
}

func TestPolicyPaneHostRuleSetCRUD(t *testing.T) {
	m := sized(t, buildApp(t), 100, 30)
	m.hosts.cursor = hostIndex(t, m.hosts.names, "bare")
	m = press(t, m, "enter")
	m = press(t, m, "3")

	m = press(t, m, "a")
	if !m.policy.capturing() {
		t.Fatal("rule input should capture after a")
	}
	m.policy.input.SetValue("allow 5 ^uptime$")
	m = press(t, m, "enter")
	ruleSet, ok := policy.LookupHostRules(policy.Bundle{Policy: m.policy.config, Inventory: m.policy.inventory}, "bare")
	if !ok || len(ruleSet.Override.Rules) != 1 || ruleSet.Override.Rules[0].Match.CmdRegex != "^uptime$" || ruleSet.Override.Rules[0].Action != policy.ActionAllow || ruleSet.Override.Rules[0].Priority != 5 {
		t.Fatalf("host rules after rule add = %#v ok=%v", ruleSet, ok)
	}
	if !strings.Contains(readFile(t, m.paths.PolicyFile), "host:bare") {
		t.Fatalf("policy file missing host rules:\n%s", readFile(t, m.paths.PolicyFile))
	}

	m = press(t, m, "r")
	ruleSet, ok = policy.LookupHostRules(policy.Bundle{Policy: m.policy.config, Inventory: m.policy.inventory}, "bare")
	if !ok || len(ruleSet.Override.Rules) != 0 {
		t.Fatalf("host rules after rule remove = %#v ok=%v", ruleSet, ok)
	}

	m = press(t, m, "x")
	if !m.policy.capturing() || !strings.Contains(m.policy.result, "delete host policy rules") {
		t.Fatalf("delete confirm state mode=%v result=%q", m.policy.mode, m.policy.result)
	}
	m = press(t, m, "y")
	if _, ok := policy.LookupHostRules(policy.Bundle{Policy: m.policy.config, Inventory: m.policy.inventory}, "bare"); ok {
		t.Fatalf("host rules still present after delete: %#v", m.policy.config.HostOverrides)
	}
	if strings.Contains(readFile(t, m.paths.PolicyFile), "host:bare") {
		t.Fatalf("policy file still has host rules:\n%s", readFile(t, m.paths.PolicyFile))
	}
}

func TestTopLevelPolicyTabCardsAndGroupCRUD(t *testing.T) {
	m := sized(t, buildApp(t), 100, 30)
	m = press(t, m, "2")
	if m.entryTab != entryPolicy {
		t.Fatalf("entryTab = %v, want policy", m.entryTab)
	}
	v := m.View()
	for _, want := range []string{"Global", "readonly", "rules"} {
		if !strings.Contains(v, want) {
			t.Fatalf("policy tab missing %q:\n%s", want, v)
		}
	}

	m = press(t, m, "n")
	if !m.policy.capturing() {
		t.Fatal("new group input should capture")
	}
	m.policy.input.SetValue("ops")
	m = press(t, m, "enter")
	if _, ok := m.policy.config.RuleGroups["ops"]; !ok {
		t.Fatalf("group not created: %#v", m.policy.config.RuleGroups)
	}

	m.policy.cardCursor = targetIndex(m.policy.policyTargets(), policyTarget{kind: policyTargetGroup, group: "ops"})
	m = press(t, m, "enter")
	if m.policy.target.kind != policyTargetGroup || m.policy.target.group != "ops" {
		t.Fatalf("target after open = %#v", m.policy.target)
	}
	m = press(t, m, "a")
	m.policy.input.SetValue("deny 7 ^reboot$")
	m = press(t, m, "enter")
	rules := m.policy.config.RuleGroups["ops"].Rules
	if len(rules) != 1 || rules[0].Action != policy.ActionDeny || rules[0].Priority != 7 || rules[0].Match.CmdRegex != "^reboot$" {
		t.Fatalf("group rule after add = %#v", rules)
	}
	m = press(t, m, "e")
	m.policy.input.SetValue("allow 3 ^uptime$")
	m = press(t, m, "enter")
	rules = m.policy.config.RuleGroups["ops"].Rules
	if len(rules) != 1 || rules[0].Action != policy.ActionAllow || rules[0].Priority != 3 || rules[0].Match.CmdRegex != "^uptime$" {
		t.Fatalf("group rule after edit = %#v", rules)
	}
	m = press(t, m, "r")
	if got := m.policy.config.RuleGroups["ops"].Rules; len(got) != 0 {
		t.Fatalf("group rule after remove = %#v", got)
	}
	m = press(t, m, "esc") // back to cards
	m = press(t, m, "d")
	if !m.policy.capturing() || !strings.Contains(m.policy.result, "delete rule group ops") {
		t.Fatalf("delete group confirm mode=%v result=%q", m.policy.mode, m.policy.result)
	}
	m = press(t, m, "y")
	if _, ok := m.policy.config.RuleGroups["ops"]; ok {
		t.Fatalf("group still present after delete: %#v", m.policy.config.RuleGroups)
	}
}

func TestTopLevelPolicyGlobalRuleCRUD(t *testing.T) {
	m := sized(t, buildApp(t), 100, 30)
	m = press(t, m, "2")
	m.policy.cardCursor = 0 // Global is always first.
	m = press(t, m, "enter")
	if m.policy.target.kind != policyTargetGlobal {
		t.Fatalf("target = %#v, want global", m.policy.target)
	}

	initial := len(m.policy.config.Rules)
	m = press(t, m, "a")
	m.policy.input.SetValue("allow 11 ^date$")
	m = press(t, m, "enter")
	if len(m.policy.config.Rules) != initial+1 || m.policy.config.Rules[len(m.policy.config.Rules)-1].Match.CmdRegex != "^date$" {
		t.Fatalf("global rules after add = %#v", m.policy.config.Rules)
	}
	m.policy.ruleCursor = len(m.policy.config.Rules) - 1
	m = press(t, m, "e")
	m.policy.input.SetValue("deny 12 ^date$")
	m = press(t, m, "enter")
	if got := m.policy.config.Rules[len(m.policy.config.Rules)-1]; got.Action != policy.ActionDeny || got.Priority != 12 {
		t.Fatalf("global rule after edit = %#v", got)
	}
	m = press(t, m, "r")
	if len(m.policy.config.Rules) != initial {
		t.Fatalf("global rules after remove = %#v", m.policy.config.Rules)
	}
}

func TestHostPolicyUnifiedListAndGroupActions(t *testing.T) {
	m := sized(t, buildApp(t), 110, 32)
	m.hosts.cursor = hostIndex(t, m.hosts.names, "bare")
	m = press(t, m, "enter")
	m = press(t, m, "3")

	m = press(t, m, "p")
	if m.policy.mode != policyModeGroupPicker {
		t.Fatalf("group picker mode = %v", m.policy.mode)
	}
	m = press(t, m, "enter")
	ruleSet, ok := m.policy.hostRuleSet()
	if !ok || len(ruleSet.Override.Rules) != 1 || ruleSet.Override.Rules[0].Group != "readonly" {
		t.Fatalf("host rules after stamp = %#v ok=%v", ruleSet, ok)
	}
	v := m.policy.View()
	for _, want := range []string{"SCOPE", "global", "host", "readonly", "^uptime$"} {
		if !strings.Contains(v, want) {
			t.Fatalf("host unified policy missing %q:\n%s", want, v)
		}
	}
	hostIdx := strings.Index(v, "host")
	globalIdx := strings.Index(v, "global")
	if hostIdx < 0 || globalIdx < 0 || hostIdx > globalIdx {
		t.Fatalf("host rows should render before global rows:\n%s", v)
	}

	rows := m.policy.hostPolicyRows()
	globalRow := -1
	for i, row := range rows {
		if row.Scope == "global" {
			globalRow = i
			break
		}
	}
	if globalRow < 0 {
		t.Fatalf("no global row in %#v", rows)
	}
	m.policy.ruleCursor = globalRow
	m = press(t, m, "r")
	if !strings.Contains(m.policy.result, "global rows are read-only") {
		t.Fatalf("global row remove result = %q", m.policy.result)
	}
	if b, _ := m.policy.hostRuleSet(); len(b.Override.Rules) != 1 {
		t.Fatalf("global-row remove changed host rules: %#v", b.Override.Rules)
	}

	m.policy.ruleCursor = firstHostGroupRow(m.policy.hostPolicyRows(), "readonly")
	m = press(t, m, "R")
	if b, _ := m.policy.hostRuleSet(); len(b.Override.Rules) != 0 {
		t.Fatalf("host group remove left rules: %#v", b.Override.Rules)
	}
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(raw)
}
