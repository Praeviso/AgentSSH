package policy

import (
	"testing"

	"github.com/Kritoooo/agentssh/internal/inventory"
)

func TestEvaluateRulesAndDefault(t *testing.T) {
	engine := newTestEngine(t, Config{
		Defaults: Defaults{Policy: ActionAllow},
		Rules: []Rule{
			{Name: "first", Match: Match{CmdRegex: "safe"}, Action: ActionAllow},
			{Name: "catastrophic", Match: Match{CmdRegex: `rm\s+-rf`}, Action: ActionDeny},
		},
	}, inventory.Inventory{})

	decision, err := engine.Evaluate("", "rm -rf /")
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if decision.Action != ActionDeny || decision.Rule != "rules:catastrophic" {
		t.Fatalf("decision = %#v", decision)
	}

	decision, err = engine.Evaluate("", "uptime")
	if err != nil {
		t.Fatalf("Evaluate default: %v", err)
	}
	if decision.Action != ActionAllow || decision.Rule != "default" {
		t.Fatalf("default decision = %#v", decision)
	}
}

func TestEvaluateOverrideAllowlist(t *testing.T) {
	engine := newTestEngine(t, Config{
		Defaults: Defaults{Policy: ActionAllow},
		HostOverrides: map[string]HostOverride{
			"prod": {
				Policy: ActionDeny,
				AllowRules: []Match{
					{CmdRegex: `^systemctl status\b`},
				},
			},
		},
	}, inventory.Inventory{
		Hosts: map[string]inventory.Host{
			"web-1": {Tags: []string{"web", "prod"}},
		},
		Groups: map[string]inventory.Group{
			"prod": {Tags: []string{"prod"}},
		},
	})

	decision, err := engine.Evaluate("web-1", "systemctl status nginx")
	if err != nil {
		t.Fatalf("Evaluate allowlist allow: %v", err)
	}
	if decision.Action != ActionAllow || decision.Rule != "prod/allow_rules[0]" {
		t.Fatalf("allowlist allow decision = %#v", decision)
	}

	decision, err = engine.Evaluate("web-1", "cat /etc/passwd")
	if err != nil {
		t.Fatalf("Evaluate allowlist deny: %v", err)
	}
	if decision.Action != ActionDeny || decision.Rule != "prod/default_deny" {
		t.Fatalf("allowlist deny decision = %#v", decision)
	}
}

func TestEvaluateMultiGroupDenyWins(t *testing.T) {
	engine := newTestEngine(t, Config{
		Defaults: Defaults{Policy: ActionAllow},
		HostOverrides: map[string]HostOverride{
			"prod": {
				Policy: ActionDeny,
				AllowRules: []Match{
					{CmdRegex: `^systemctl status\b`},
				},
			},
			"web": {Policy: ActionAllow},
		},
	}, inventory.Inventory{
		Hosts: map[string]inventory.Host{
			"web-1": {Tags: []string{"web", "prod"}},
		},
		Groups: map[string]inventory.Group{
			"prod": {Tags: []string{"prod"}},
			"web":  {Tags: []string{"web"}},
		},
	})

	decision, err := engine.Evaluate("web-1", "cat /var/log/nginx/error.log")
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if decision.Action != ActionDeny || decision.Rule != "prod/default_deny" {
		t.Fatalf("multi-group decision = %#v", decision)
	}
}

func TestEvaluateAllDenyOverridesMustAllow(t *testing.T) {
	engine := newTestEngine(t, Config{
		Defaults: Defaults{Policy: ActionAllow},
		HostOverrides: map[string]HostOverride{
			"prod": {
				Policy:     ActionDeny,
				AllowRules: []Match{{CmdRegex: `^echo\b`}},
			},
			"web": {
				Policy:     ActionDeny,
				AllowRules: []Match{{CmdRegex: `^systemctl status\b`}},
			},
		},
	}, inventory.Inventory{
		Hosts: map[string]inventory.Host{
			"web-1": {Tags: []string{"web", "prod"}},
		},
		Groups: map[string]inventory.Group{
			"prod": {Tags: []string{"prod"}},
			"web":  {Tags: []string{"web"}},
		},
	})

	decision, err := engine.Evaluate("web-1", "echo hi")
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if decision.Action != ActionDeny || decision.Rule != "web/default_deny" {
		t.Fatalf("all deny overrides decision = %#v", decision)
	}
}

func TestInvalidRegex(t *testing.T) {
	_, err := NewEngine(Config{
		Rules: []Rule{{Name: "bad", Match: Match{CmdRegex: "["}, Action: ActionDeny}},
	}, inventory.Inventory{})
	if err == nil {
		t.Fatal("NewEngine invalid regex error = nil")
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
