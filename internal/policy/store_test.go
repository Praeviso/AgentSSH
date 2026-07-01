package policy

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Praeviso/AgentSSH/internal/inventory"
)

func TestPolicyRuleCRUD(t *testing.T) {
	cfg := Config{Rules: []Rule{{Name: "old", Match: Match{CmdRegex: "^ls"}, Action: ActionAllow}}}
	next, err := AddRule(cfg, Rule{Name: "danger", Match: Match{CmdRegex: "rm -rf"}, Action: ActionDeny})
	if err != nil {
		t.Fatalf("AddRule: %v", err)
	}
	if len(next.Rules) != 2 || next.Rules[1].Name != "danger" {
		t.Fatalf("after add = %#v", next.Rules)
	}
	if len(cfg.Rules) != 1 {
		t.Fatalf("AddRule mutated original = %#v", cfg.Rules)
	}
	_, err = AddRule(next, Rule{Name: "danger", Match: Match{CmdRegex: "mkfs"}, Action: ActionDeny})
	if !errors.Is(err, ErrRuleExists) {
		t.Fatalf("duplicate add err = %v, want ErrRuleExists", err)
	}

	updated, err := UpdateRule(next, "danger", Rule{Name: "danger", Match: Match{CmdRegex: "mkfs"}, Action: ActionDeny})
	if err != nil {
		t.Fatalf("UpdateRule: %v", err)
	}
	if updated.Rules[1].Match.CmdRegex != "mkfs" || next.Rules[1].Match.CmdRegex != "rm -rf" {
		t.Fatalf("update copy semantics: updated=%#v original=%#v", updated.Rules, next.Rules)
	}

	removed, err := RemoveRule(updated, "old")
	if err != nil {
		t.Fatalf("RemoveRule: %v", err)
	}
	if len(removed.Rules) != 1 || removed.Rules[0].Name != "danger" {
		t.Fatalf("after remove = %#v", removed.Rules)
	}
	_, err = RemoveRule(removed, "missing")
	if !errors.Is(err, ErrRuleNotFound) {
		t.Fatalf("missing remove err = %v, want ErrRuleNotFound", err)
	}
}

func TestPolicySaveLoadRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.yaml")
	cfg := Config{
		Rules: []Rule{{
			Name:     "danger",
			Priority: 100,
			Match:    Match{CmdRegex: "rm -rf"},
			Action:   ActionDeny,
		}},
		HostOverrides: map[string]HostOverride{
			HostRulesKey("web-1"): {
				Rules: []Rule{{Priority: 10, Match: Match{CmdRegex: "^uptime$"}, Action: ActionAllow, Group: "readonly"}},
			},
		},
		RuleGroups: map[string]RuleGroup{
			"readonly": {
				Rules: []Rule{{Priority: 5, Match: Match{CmdRegex: "^whoami$"}, Action: ActionAllow}},
			},
		},
		Output: Output{MaxBytes: 1024, Redact: []string{"secret"}},
	}
	if err := Save(path, cfg); err != nil {
		t.Fatalf("Save: %v", err)
	}
	loaded, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if loaded.Version != 1 || len(loaded.Rules) != 1 || loaded.Rules[0].Name != "danger" || loaded.Rules[0].Priority != 100 || loaded.Output.Redact[0] != "secret" {
		t.Fatalf("loaded = %#v", loaded)
	}
	if group := loaded.RuleGroups["readonly"]; len(group.Rules) != 1 || group.Rules[0].Match.CmdRegex != "^whoami$" {
		t.Fatalf("loaded rule_groups = %#v", loaded.RuleGroups)
	}
	override := loaded.HostOverrides[HostRulesKey("web-1")]
	if len(override.Rules) != 1 || override.Rules[0].Priority != 10 || override.Rules[0].Action != ActionAllow || override.Rules[0].Group != "readonly" {
		t.Fatalf("loaded = %#v", loaded)
	}
	raw, err := Load(filepath.Join(t.TempDir(), "missing.yaml"))
	if err != nil {
		t.Fatalf("Load missing: %v", err)
	}
	if len(raw.Rules) != 0 {
		t.Fatalf("missing policy = %#v", raw)
	}
}

func TestPolicySavePreservesHostOverrideOrder(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.yaml")
	if err := os.WriteFile(path, []byte(`
version: 1
host_overrides:
  z:
    rules:
      - priority: 0
        match: { cmd_regex: '^uptime$' }
        action: deny
  a:
    rules:
      - priority: 0
        match: { cmd_regex: '^uptime$' }
        action: allow
`), 0o600); err != nil {
		t.Fatalf("write policy: %v", err)
	}
	loaded, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if err := Save(path, loaded); err != nil {
		t.Fatalf("Save: %v", err)
	}
	reloaded, err := Load(path)
	if err != nil {
		t.Fatalf("Load after save: %v", err)
	}
	engine, err := NewEngine(reloaded, inventory.Inventory{
		Hosts:  map[string]inventory.Host{"web-1": {Tags: []string{"both"}}},
		Groups: map[string]inventory.Group{"z": {Tags: []string{"both"}}, "a": {Tags: []string{"both"}}},
	})
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	decision, err := engine.Evaluate("web-1", "uptime")
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if decision.Action != ActionDeny || decision.Rule != "z/rules[0]" {
		t.Fatalf("decision = %#v, want z deny to remain first after save/load", decision)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read policy: %v", err)
	}
	zIndex := strings.Index(string(raw), "z:")
	aIndex := strings.Index(string(raw), "a:")
	if zIndex < 0 || aIndex < 0 || zIndex > aIndex {
		t.Fatalf("host override order not preserved:\n%s", raw)
	}
}

func TestRuleAmbiguous(t *testing.T) {
	cfg := Config{Rules: []Rule{
		{Name: "dup", Match: Match{CmdRegex: "a"}, Action: ActionDeny},
		{Name: "dup", Match: Match{CmdRegex: "b"}, Action: ActionDeny},
	}}
	_, err := RemoveRule(cfg, "dup")
	if !errors.Is(err, ErrRuleAmbiguous) {
		t.Fatalf("ambiguous err = %v", err)
	}
}

func TestHostRuleSetCRUD(t *testing.T) {
	bundle := Bundle{
		Policy: Config{},
		Inventory: inventory.Inventory{Hosts: map[string]inventory.Host{
			"web-1": {Addr: "10.0.0.11"},
		}},
	}

	next, err := SetHostRules(bundle, "web-1", HostOverride{
		Rules: []Rule{{Priority: 5, Match: Match{CmdRegex: "^ls"}, Action: ActionAllow}},
	})
	if err != nil {
		t.Fatalf("SetHostRules: %v", err)
	}
	if _, ok := bundle.Policy.HostOverrides[HostRulesKey("web-1")]; ok {
		t.Fatalf("SetHostRules mutated original policy = %#v", bundle.Policy.HostOverrides)
	}
	ruleSet, ok := LookupHostRules(next, "web-1")
	if !ok || ruleSet.Key != "host:web-1" || !ruleSet.Effective || len(ruleSet.Override.Rules) != 1 || ruleSet.Override.Rules[0].Priority != 5 {
		t.Fatalf("host rules = %#v ok=%v", ruleSet, ok)
	}
	if _, ok := next.Inventory.Groups["host:web-1"]; ok {
		t.Fatalf("host rules should not create inventory groups: %#v", next.Inventory.Groups)
	}

	next, err = AddHostRule(next, "web-1", Rule{Priority: 10, Match: Match{CmdRegex: "^uptime$"}, Action: ActionAllow})
	if err != nil {
		t.Fatalf("AddHostRule: %v", err)
	}
	ruleSet, _ = LookupHostRules(next, "web-1")
	if len(ruleSet.Override.Rules) != 2 || ruleSet.Override.Rules[1].Match.CmdRegex != "^uptime$" || ruleSet.Override.Rules[1].Priority != 10 {
		t.Fatalf("host rules after add = %#v", ruleSet.Override.Rules)
	}

	next, err = RemoveHostRule(next, "web-1", 0)
	if err != nil {
		t.Fatalf("RemoveHostRule: %v", err)
	}
	ruleSet, _ = LookupHostRules(next, "web-1")
	if len(ruleSet.Override.Rules) != 1 || ruleSet.Override.Rules[0].Match.CmdRegex != "^uptime$" {
		t.Fatalf("host rules after remove = %#v", ruleSet.Override.Rules)
	}

	next, err = ClearHostRules(next, "web-1")
	if err != nil {
		t.Fatalf("ClearHostRules: %v", err)
	}
	if _, ok := LookupHostRules(next, "web-1"); ok {
		t.Fatalf("host rules still present: %#v", next.Policy.HostOverrides)
	}
	_, err = SetHostRules(bundle, "missing", HostOverride{Rules: []Rule{{Match: Match{CmdRegex: "^ls"}, Action: ActionAllow}}})
	if !errors.Is(err, ErrHostNotFound) {
		t.Fatalf("missing host err = %v, want ErrHostNotFound", err)
	}
}

func TestRemoveHostRuleAndGroupWorkForOrphanedOverride(t *testing.T) {
	bundle := Bundle{
		Policy: Config{HostOverrides: map[string]HostOverride{
			HostRulesKey("old-web"): {Rules: []Rule{
				{Match: Match{CmdRegex: "^uptime$"}, Action: ActionAllow},
				{Match: Match{CmdRegex: "^id$"}, Action: ActionDeny, Group: "readonly"},
			}},
		}},
		Inventory: inventory.Inventory{Hosts: map[string]inventory.Host{}},
	}
	next, err := RemoveHostRule(bundle, "old-web", 0)
	if err != nil {
		t.Fatalf("RemoveHostRule: %v", err)
	}
	ruleSet, ok := LookupHostRules(next, "old-web")
	if !ok || len(ruleSet.Override.Rules) != 1 || ruleSet.Override.Rules[0].Match.CmdRegex != "^id$" {
		t.Fatalf("after RemoveHostRule = %#v ok=%v", ruleSet, ok)
	}
	next, err = RemoveHostGroup(next, "old-web", "readonly")
	if err != nil {
		t.Fatalf("RemoveHostGroup: %v", err)
	}
	ruleSet, ok = LookupHostRules(next, "old-web")
	if !ok || len(ruleSet.Override.Rules) != 0 {
		t.Fatalf("after RemoveHostGroup = %#v ok=%v", ruleSet, ok)
	}
}

func TestAddHostRuleCreatesHostRules(t *testing.T) {
	bundle := Bundle{
		Inventory: inventory.Inventory{Hosts: map[string]inventory.Host{
			"web-1": {Addr: "10.0.0.11"},
		}},
	}
	next, err := AddHostRule(bundle, "web-1", Rule{Match: Match{CmdRegex: "^whoami$"}, Action: ActionAllow})
	if err != nil {
		t.Fatalf("AddHostRule: %v", err)
	}
	ruleSet, ok := LookupHostRules(next, "web-1")
	if !ok || len(ruleSet.Override.Rules) != 1 || ruleSet.Override.Rules[0].Match.CmdRegex != "^whoami$" {
		t.Fatalf("host rules after create add = %#v ok=%v", ruleSet, ok)
	}
}

func TestRuleGroupCRUD(t *testing.T) {
	bundle := Bundle{}
	next, err := CreateGroup(bundle, "readonly")
	if err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}
	if _, ok := next.Policy.RuleGroups["readonly"]; !ok {
		t.Fatalf("group missing after create: %#v", next.Policy.RuleGroups)
	}
	if bundle.Policy.RuleGroups != nil {
		t.Fatalf("CreateGroup mutated original: %#v", bundle.Policy.RuleGroups)
	}
	if _, err := CreateGroup(next, "readonly"); !errors.Is(err, ErrGroupExists) {
		t.Fatalf("duplicate create err = %v, want ErrGroupExists", err)
	}

	next, err = AddGroupRule(next, "readonly", Rule{Priority: 5, Match: Match{CmdRegex: "^uptime$"}, Action: ActionAllow})
	if err != nil {
		t.Fatalf("AddGroupRule: %v", err)
	}
	if got := next.Policy.RuleGroups["readonly"].Rules; len(got) != 1 || got[0].Priority != 5 {
		t.Fatalf("rules after add = %#v", got)
	}

	next, err = UpdateGroupRule(next, "readonly", 0, Rule{Priority: 9, Match: Match{CmdRegex: "^whoami$"}, Action: ActionDeny})
	if err != nil {
		t.Fatalf("UpdateGroupRule: %v", err)
	}
	if got := next.Policy.RuleGroups["readonly"].Rules[0]; got.Priority != 9 || got.Action != ActionDeny || got.Match.CmdRegex != "^whoami$" {
		t.Fatalf("rule after update = %#v", got)
	}

	next, err = RemoveGroupRule(next, "readonly", 0)
	if err != nil {
		t.Fatalf("RemoveGroupRule: %v", err)
	}
	if got := next.Policy.RuleGroups["readonly"].Rules; len(got) != 0 {
		t.Fatalf("rules after remove = %#v", got)
	}

	next, err = DeleteGroup(next, "readonly")
	if err != nil {
		t.Fatalf("DeleteGroup: %v", err)
	}
	if _, ok := next.Policy.RuleGroups["readonly"]; ok {
		t.Fatalf("group still present: %#v", next.Policy.RuleGroups)
	}
	if _, err := DeleteGroup(next, "missing"); !errors.Is(err, ErrGroupNotFound) {
		t.Fatalf("missing delete err = %v, want ErrGroupNotFound", err)
	}
}

func TestRuleGroupRejectsReservedApprovalNames(t *testing.T) {
	for _, name := range []string{ApprovalGroup, "__agentssh_custom"} {
		t.Run(name, func(t *testing.T) {
			if _, err := CreateGroup(Bundle{}, name); !errors.Is(err, ErrReservedGroup) {
				t.Fatalf("CreateGroup err = %v, want ErrReservedGroup", err)
			}
			bundle := Bundle{
				Policy:    Config{RuleGroups: map[string]RuleGroup{name: {}}},
				Inventory: inventory.Inventory{Hosts: map[string]inventory.Host{"web-1": {}}},
			}
			if _, err := StampGroupOntoHost(bundle, "web-1", name); !errors.Is(err, ErrReservedGroup) {
				t.Fatalf("StampGroupOntoHost err = %v, want ErrReservedGroup", err)
			}
		})
	}
}

func TestStampGroupOntoHostCopiesWithProvenance(t *testing.T) {
	bundle := Bundle{
		Policy: Config{RuleGroups: map[string]RuleGroup{
			"readonly": {Rules: []Rule{
				{Priority: 5, Match: Match{CmdRegex: "^uptime$"}, Action: ActionAllow},
				{Priority: 9, Match: Match{CmdRegex: "^id$"}, Action: ActionDeny, Group: "old"},
			}},
		}},
		Inventory: inventory.Inventory{Hosts: map[string]inventory.Host{
			"web-1": {Addr: "10.0.0.11"},
		}},
	}
	next, err := StampGroupOntoHost(bundle, "web-1", "readonly")
	if err != nil {
		t.Fatalf("StampGroupOntoHost: %v", err)
	}
	ruleSet, ok := LookupHostRules(next, "web-1")
	if !ok || len(ruleSet.Override.Rules) != 2 {
		t.Fatalf("host rules = %#v ok=%v", ruleSet, ok)
	}
	for _, rule := range ruleSet.Override.Rules {
		if rule.Group != "readonly" {
			t.Fatalf("stamped rule missing provenance: %#v", rule)
		}
	}
	if _, ok := LookupHostRules(bundle, "web-1"); ok {
		t.Fatalf("StampGroupOntoHost mutated original: %#v", bundle.Policy.HostOverrides)
	}

	edited, err := UpdateGroupRule(next, "readonly", 0, Rule{Priority: 1, Match: Match{CmdRegex: "^changed$"}, Action: ActionDeny})
	if err != nil {
		t.Fatalf("UpdateGroupRule: %v", err)
	}
	ruleSet, _ = LookupHostRules(edited, "web-1")
	if got := ruleSet.Override.Rules[0].Match.CmdRegex; got != "^uptime$" {
		t.Fatalf("stamped snapshot changed after group edit: %q", got)
	}
}

func TestStampGroupOntoHostIsIdempotentForSameGroup(t *testing.T) {
	bundle := Bundle{
		Policy: Config{
			RuleGroups: map[string]RuleGroup{
				"readonly": {Rules: []Rule{{Priority: 5, Match: Match{CmdRegex: "^uptime$"}, Action: ActionAllow}}},
			},
		},
		Inventory: inventory.Inventory{Hosts: map[string]inventory.Host{"web-1": {}}},
	}
	next, err := StampGroupOntoHost(bundle, "web-1", "readonly")
	if err != nil {
		t.Fatalf("first StampGroupOntoHost: %v", err)
	}
	next, err = StampGroupOntoHost(next, "web-1", "readonly")
	if err != nil {
		t.Fatalf("second StampGroupOntoHost: %v", err)
	}
	ruleSet, ok := LookupHostRules(next, "web-1")
	if !ok || len(ruleSet.Override.Rules) != 1 || ruleSet.Override.Rules[0].Group != "readonly" {
		t.Fatalf("host rules = %#v ok=%v", ruleSet, ok)
	}
}

func TestRemoveHostGroupFiltersByProvenance(t *testing.T) {
	bundle := Bundle{
		Policy: Config{HostOverrides: map[string]HostOverride{
			HostRulesKey("web-1"): {Rules: []Rule{
				{Match: Match{CmdRegex: "^uptime$"}, Action: ActionAllow, Group: "readonly"},
				{Match: Match{CmdRegex: "^id$"}, Action: ActionDeny},
				{Match: Match{CmdRegex: "^whoami$"}, Action: ActionAllow, Group: "readonly"},
			}},
		}},
		Inventory: inventory.Inventory{Hosts: map[string]inventory.Host{"web-1": {}}},
	}
	next, err := RemoveHostGroup(bundle, "web-1", "readonly")
	if err != nil {
		t.Fatalf("RemoveHostGroup: %v", err)
	}
	ruleSet, ok := LookupHostRules(next, "web-1")
	if !ok || len(ruleSet.Override.Rules) != 1 || ruleSet.Override.Rules[0].Match.CmdRegex != "^id$" {
		t.Fatalf("host rules after remove group = %#v ok=%v", ruleSet, ok)
	}
}

// An empty group name must NOT match every ungrouped rule via rule.Group == "" —
// that would silently delete host-specific allow/deny rules. It is rejected.
func TestRemoveHostGroupRejectsEmptyName(t *testing.T) {
	bundle := Bundle{
		Policy: Config{HostOverrides: map[string]HostOverride{
			HostRulesKey("web-1"): {Rules: []Rule{
				{Match: Match{CmdRegex: "^id$"}, Action: ActionDeny},                         // ungrouped
				{Match: Match{CmdRegex: "^uptime$"}, Action: ActionAllow, Group: "readonly"}, // grouped
			}},
		}},
		Inventory: inventory.Inventory{Hosts: map[string]inventory.Host{"web-1": {}}},
	}
	if _, err := RemoveHostGroup(bundle, "web-1", "  "); err == nil {
		t.Fatal("RemoveHostGroup with a blank group name should error, not delete ungrouped rules")
	}
	// Original is untouched.
	if got := len(bundle.Policy.HostOverrides[HostRulesKey("web-1")].Rules); got != 2 {
		t.Fatalf("original rules mutated: have %d, want 2", got)
	}
}
