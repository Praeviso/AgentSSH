package policy

import (
	"strings"
	"testing"

	"github.com/Praeviso/AgentSSH/internal/inventory"
	"gopkg.in/yaml.v3"
)

func TestEvaluateHostTierBeforeGlobalPriority(t *testing.T) {
	engine := newTestEngine(t, Config{
		Rules: []Rule{
			{
				Name:     "global-deny-status",
				Priority: 100,
				Match:    Match{CmdRegex: `^systemctl status\b`},
				Action:   ActionDeny,
			},
		},
		HostOverrides: map[string]HostOverride{
			HostRulesKey("web-1"): {
				Rules: []Rule{{
					Priority: 0,
					Match:    Match{CmdRegex: `^systemctl status\b`},
					Action:   ActionAllow,
				}},
			},
		},
	}, inventory.Inventory{
		Hosts: map[string]inventory.Host{
			"web-1": {Tags: []string{"prod"}},
		},
	})

	decision, err := engine.Evaluate("web-1", "systemctl status nginx")
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if decision.Action != ActionAllow || decision.Rule != "host:web-1/rules[0]" {
		t.Fatalf("decision = %#v", decision)
	}
}

func TestEvaluatePriorityOrderingWithinTier(t *testing.T) {
	engine := newTestEngine(t, Config{
		Rules: []Rule{
			{
				Name:     "low-allow",
				Priority: 0,
				Match:    Match{CmdRegex: `^deploy\b`},
				Action:   ActionAllow,
			},
			{
				Name:     "high-deny",
				Priority: 50,
				Match:    Match{CmdRegex: `^deploy\b`},
				Action:   ActionDeny,
			},
		},
		HostOverrides: map[string]HostOverride{
			"prod": {
				Rules: []Rule{
					{
						Priority: 1,
						Match:    Match{CmdRegex: `^uptime$`},
						Action:   ActionAllow,
					},
					{
						Priority: 5,
						Match:    Match{CmdRegex: `^uptime$`},
						Action:   ActionDeny,
					},
				},
			},
		},
	}, inventory.Inventory{
		Hosts: map[string]inventory.Host{
			"web-1": {Tags: []string{"prod"}},
		},
		Groups: map[string]inventory.Group{
			"prod": {Tags: []string{"prod"}},
		},
	})

	decision, err := engine.Evaluate("web-1", "uptime")
	if err != nil {
		t.Fatalf("Evaluate host priority: %v", err)
	}
	if decision.Action != ActionDeny || decision.Rule != "prod/rules[1]" {
		t.Fatalf("host priority decision = %#v", decision)
	}

	decision, err = engine.Evaluate("web-2", "deploy now")
	if err != nil {
		t.Fatalf("Evaluate global priority: %v", err)
	}
	if decision.Action != ActionDeny || decision.Rule != "rules:high-deny" {
		t.Fatalf("global priority decision = %#v", decision)
	}
}

func TestEvaluateTieUsesFileOrder(t *testing.T) {
	engine := newTestEngine(t, Config{
		Rules: []Rule{
			{Name: "first", Priority: 10, Match: Match{CmdRegex: `^echo\b`}, Action: ActionAllow},
			{Name: "second", Priority: 10, Match: Match{CmdRegex: `^echo\b`}, Action: ActionDeny},
		},
		HostOverrides: map[string]HostOverride{
			HostRulesKey("web-1"): {
				Rules: []Rule{
					{Priority: 0, Match: Match{CmdRegex: `^id$`}, Action: ActionDeny},
					{Priority: 0, Match: Match{CmdRegex: `^id$`}, Action: ActionAllow},
				},
			},
		},
	}, inventory.Inventory{
		Hosts: map[string]inventory.Host{"web-1": {}},
	})

	decision, err := engine.Evaluate("web-1", "id")
	if err != nil {
		t.Fatalf("Evaluate host tie: %v", err)
	}
	if decision.Action != ActionDeny || decision.Rule != "host:web-1/rules[0]" {
		t.Fatalf("host tie decision = %#v", decision)
	}

	decision, err = engine.Evaluate("", "echo hi")
	if err != nil {
		t.Fatalf("Evaluate global tie: %v", err)
	}
	if decision.Action != ActionAllow || decision.Rule != "rules:first" {
		t.Fatalf("global tie decision = %#v", decision)
	}
}

func TestEvaluateAllowAndDenyActions(t *testing.T) {
	engine := newTestEngine(t, Config{
		Rules: []Rule{
			{Name: "allow-echo", Match: Match{CmdRegex: `^echo\b`}, Action: ActionAllow},
			{Name: "deny-rm", Match: Match{CmdRegex: `rm\s+-rf`}, Action: ActionDeny},
		},
	}, inventory.Inventory{})

	decision, err := engine.Evaluate("", "echo ok")
	if err != nil {
		t.Fatalf("Evaluate allow: %v", err)
	}
	if decision.Action != ActionAllow || decision.Rule != "rules:allow-echo" {
		t.Fatalf("allow decision = %#v", decision)
	}

	decision, err = engine.Evaluate("", "rm -rf /tmp/x")
	if err != nil {
		t.Fatalf("Evaluate deny: %v", err)
	}
	if decision.Action != ActionDeny || decision.Rule != "rules:deny-rm" {
		t.Fatalf("deny decision = %#v", decision)
	}
}

func TestEvaluateDefaultDenyWhenNothingMatches(t *testing.T) {
	engine := newTestEngine(t, Config{
		Rules: []Rule{{Name: "allow-echo", Match: Match{CmdRegex: `^echo\b`}, Action: ActionAllow}},
	}, inventory.Inventory{})

	decision, err := engine.Evaluate("", "uptime")
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if decision.Action != ActionDeny || decision.Rule != "default-deny" {
		t.Fatalf("default decision = %#v", decision)
	}
}

func TestEvaluateIgnoresRuleGroups(t *testing.T) {
	engine := newTestEngine(t, Config{
		RuleGroups: map[string]RuleGroup{
			"readonly": {
				Rules: []Rule{{Match: Match{CmdRegex: `^uptime$`}, Action: ActionAllow}},
			},
		},
	}, inventory.Inventory{})

	decision, err := engine.Evaluate("web-1", "uptime")
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if decision.Action != ActionDeny || decision.Rule != "default-deny" {
		t.Fatalf("rule group should be ignored, decision = %#v", decision)
	}
}

func TestEvaluateIgnoresRuleGroupProvenanceField(t *testing.T) {
	engine := newTestEngine(t, Config{
		Rules: []Rule{{
			Name:   "allow-uptime",
			Group:  "readonly",
			Match:  Match{CmdRegex: `^uptime$`},
			Action: ActionAllow,
		}},
		HostOverrides: map[string]HostOverride{
			HostRulesKey("web-1"): {
				Rules: []Rule{{
					Group:  "ops",
					Match:  Match{CmdRegex: `^id$`},
					Action: ActionDeny,
				}},
			},
		},
	}, inventory.Inventory{Hosts: map[string]inventory.Host{"web-1": {}}})

	decision, err := engine.Evaluate("", "uptime")
	if err != nil {
		t.Fatalf("Evaluate global: %v", err)
	}
	if decision.Action != ActionAllow || decision.Rule != "rules:allow-uptime" {
		t.Fatalf("global provenance decision = %#v", decision)
	}
	decision, err = engine.Evaluate("web-1", "id")
	if err != nil {
		t.Fatalf("Evaluate host: %v", err)
	}
	if decision.Action != ActionDeny || decision.Rule != "host:web-1/rules[0]" {
		t.Fatalf("host provenance decision = %#v", decision)
	}
}

func TestEvaluateMultiGroupHostRulePooling(t *testing.T) {
	engine := newTestEngine(t, Config{
		HostOverrides: map[string]HostOverride{
			"prod": {
				Rules: []Rule{{Priority: 1, Match: Match{CmdRegex: `^journalctl\b`}, Action: ActionDeny}},
			},
			"web": {
				Rules: []Rule{{Priority: 10, Match: Match{CmdRegex: `^journalctl\b`}, Action: ActionAllow}},
			},
		},
		Rules: []Rule{{Name: "global-deny", Priority: 100, Match: Match{CmdRegex: `^journalctl\b`}, Action: ActionDeny}},
	}, inventory.Inventory{
		Hosts: map[string]inventory.Host{
			"web-1": {Tags: []string{"prod", "web"}},
		},
		Groups: map[string]inventory.Group{
			"prod": {Tags: []string{"prod"}},
			"web":  {Tags: []string{"web"}},
		},
	})

	decision, err := engine.Evaluate("web-1", "journalctl -u nginx")
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if decision.Action != ActionAllow || decision.Rule != "web/rules[0]" {
		t.Fatalf("multi-group decision = %#v", decision)
	}
}

func TestEvaluateUnnamedGlobalRuleUsesIndex(t *testing.T) {
	engine := newTestEngine(t, Config{
		Rules: []Rule{{Match: Match{CmdRegex: `^true$`}, Action: ActionAllow}},
	}, inventory.Inventory{})

	decision, err := engine.Evaluate("", "true")
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if decision.Action != ActionAllow || decision.Rule != "rules[0]" {
		t.Fatalf("unnamed decision = %#v", decision)
	}
}

func TestInvalidPolicyRules(t *testing.T) {
	if _, err := NewEngine(Config{
		Rules: []Rule{{Name: "bad", Match: Match{CmdRegex: "["}, Action: ActionDeny}},
	}, inventory.Inventory{}); err == nil {
		t.Fatal("NewEngine invalid regex error = nil")
	}
	engine, err := NewEngine(Config{
		Rules: []Rule{{Name: "missing-action", Match: Match{CmdRegex: "^ls"}}},
	}, inventory.Inventory{})
	if err != nil {
		t.Fatalf("NewEngine missing action: %v", err)
	}
	decision, err := engine.Evaluate("", "ls")
	if err != nil {
		t.Fatalf("Evaluate missing action: %v", err)
	}
	if decision.Action != ActionAllow {
		t.Fatalf("missing action decision = %#v, want allow", decision)
	}
	if _, err := NewEngine(Config{
		Rules: []Rule{{Name: "bad-action", Match: Match{CmdRegex: "^ls"}, Action: Action("prompt")}},
	}, inventory.Inventory{}); err == nil {
		t.Fatal("NewEngine invalid action error = nil")
	}
}

func TestUnmarshalRejectsLegacySchemaKeys(t *testing.T) {
	tests := []struct {
		name string
		yml  string
		want string
	}{
		{
			name: "defaults",
			yml:  "version: 1\ndefaults:\n  policy: allow\n",
			want: `removed v0.5.1 key "defaults" at defaults`,
		},
		{
			name: "top level allow_rules",
			yml:  "version: 1\nallow_rules:\n  - '^ls$'\n",
			want: `removed v0.5.1 key "allow_rules" at allow_rules`,
		},
		{
			name: "host override policy",
			yml:  "version: 1\nhost_overrides:\n  web:\n    policy: deny\n",
			want: `removed v0.5.1 key "policy" at host_overrides.web.policy`,
		},
		{
			name: "host override allow_rules",
			yml:  "version: 1\nhost_overrides:\n  web:\n    allow_rules:\n      - '^ls$'\n",
			want: `removed v0.5.1 key "allow_rules" at host_overrides.web.allow_rules`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var cfg Config
			err := yaml.Unmarshal([]byte(tt.yml), &cfg)
			if err == nil || !strings.Contains(err.Error(), tt.want) || !strings.Contains(err.Error(), "migrate to schema version 1") {
				t.Fatalf("err = %v, want %q with migration hint", err, tt.want)
			}
		})
	}
}

func newTestEngine(t *testing.T, config Config, inv inventory.Inventory) Engine {
	t.Helper()
	engine, err := NewEngine(config, inv)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	return engine
}
