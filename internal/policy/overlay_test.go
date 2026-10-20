package policy

import (
	"strings"
	"testing"

	"github.com/Praeviso/AgentSSH/internal/inventory"
)

func TestOverlayDenyBeatsEveryRemoteRule(t *testing.T) {
	inv := inventory.Inventory{Hosts: map[string]inventory.Host{"web-1": {Tags: []string{"web"}}}}
	remote := Config{
		Rules: []Rule{{Name: "allow-all", Priority: 1000, Match: Match{CmdRegex: ".*"}, Action: ActionAllow}},
		HostOverrides: map[string]HostOverride{
			HostRulesKey("web-1"): {Rules: []Rule{{Name: "host-allow", Priority: 1000, Match: Match{CmdRegex: "^rm "}, Action: ActionAllow}}},
		},
		Overlay: &Config{
			Rules: []Rule{
				{Name: "no-rm", Priority: -5, Match: Match{CmdRegex: "^rm "}, Action: ActionDeny},
				{Name: "loosen", Match: Match{CmdRegex: "^reboot"}, Action: ActionAllow},
			},
		},
	}
	engine, err := NewEngine(remote, inv)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	decision, err := engine.Evaluate("web-1", "rm -rf /tmp/x")
	if err != nil {
		t.Fatal(err)
	}
	if decision.Action != ActionDeny || !strings.HasPrefix(decision.Rule, OverlayRulePrefix) {
		t.Fatalf("local deny should win over a remote host allow, got %+v", decision)
	}
	decision, _ = engine.Evaluate("web-1", "uptime")
	if decision.Action != ActionAllow || decision.Rule != "rules:allow-all" {
		t.Fatalf("commands the overlay does not deny fall through to remote policy, got %+v", decision)
	}
}

func TestOverlayCannotLoosenRemotePolicy(t *testing.T) {
	remote := Config{
		Rules:   []Rule{{Name: "deny-reboot", Match: Match{CmdRegex: "^reboot"}, Action: ActionDeny}},
		Overlay: &Config{Rules: []Rule{{Name: "allow-reboot", Priority: 999, Match: Match{CmdRegex: "^reboot"}, Action: ActionAllow}, {Name: "allow-ls", Match: Match{CmdRegex: "^ls"}, Action: ActionAllow}}},
	}
	engine, err := NewEngine(remote, inventory.Inventory{})
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	if decision, _ := engine.Evaluate("h", "reboot"); decision.Action != ActionDeny || decision.Rule != "rules:deny-reboot" {
		t.Fatalf("overlay allow must not override a remote deny, got %+v", decision)
	}
	if decision, _ := engine.Evaluate("h", "ls"); decision.Action != ActionDeny || decision.Rule != RuleDefaultDeny {
		t.Fatalf("overlay allow must not turn the gray zone into allow, got %+v", decision)
	}
	if got := IgnoredOverlayRules(*remote.Overlay); got != 2 {
		t.Fatalf("IgnoredOverlayRules = %d, want 2", got)
	}
}

func TestOverlayHostScopedDenyStaysScoped(t *testing.T) {
	inv := inventory.Inventory{Hosts: map[string]inventory.Host{"db-1": {}, "web-1": {}}}
	remote := Config{
		Rules: []Rule{{Name: "allow-all", Match: Match{CmdRegex: ".*"}, Action: ActionAllow}},
		Overlay: &Config{HostOverrides: map[string]HostOverride{
			HostRulesKey("db-1"): {Rules: []Rule{{Name: "no-psql", Match: Match{CmdRegex: "^psql"}, Action: ActionDeny}}},
		}},
	}
	engine, err := NewEngine(remote, inv)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	if decision, _ := engine.Evaluate("db-1", "psql"); decision.Action != ActionDeny {
		t.Fatalf("db-1 psql = %+v, want local deny", decision)
	}
	if decision, _ := engine.Evaluate("web-1", "psql"); decision.Action != ActionAllow {
		t.Fatalf("web-1 psql = %+v, want remote allow", decision)
	}
}
