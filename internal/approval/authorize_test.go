package approval

import (
	"testing"
	"time"

	"github.com/Praeviso/AgentSSH/internal/inventory"
	"github.com/Praeviso/AgentSSH/internal/policy"
)

func TestAuthorizeApprovalGrantCannotShadowExplicitDeny(t *testing.T) {
	cfg := policy.Config{
		Rules: []policy.Rule{{
			Name:     "deny-restart",
			Priority: 100,
			Match:    policy.Match{CmdRegex: `\Asystemctl[ \t]+restart[ \t]+prod-db\z`},
			Action:   policy.ActionDeny,
		}},
		HostOverrides: map[string]policy.HostOverride{
			policy.HostRulesKey("web-1"): {Rules: []policy.Rule{{
				Name:   "approval/abc",
				Match:  policy.Match{CmdRegex: `\Asystemctl[ \t]+restart(?:[ \t]+[A-Za-z0-9@%+=:,./_-]+)*[ \t]*\z`},
				Action: policy.ActionAllow,
				Group:  policy.ApprovalGroup,
			}}},
		},
	}
	auth, err := Authorize(cfg, inventory.Inventory{Hosts: map[string]inventory.Host{"web-1": {}}}, SessionStore{Dir: t.TempDir()}, RuntimeConfig{Enabled: true, HostGrantMode: HostGrantSafePrefix}, "s", "web-1", "systemctl restart prod-db", "", "req-test")
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	if auth.Status != AuthHardDeny {
		t.Fatalf("status = %#v, want hard deny", auth)
	}
}

func TestAuthorizeSessionAndHostGrantOnlyAfterDefaultDeny(t *testing.T) {
	inv := inventory.Inventory{Hosts: map[string]inventory.Host{"web-1": {}}}
	store := SessionStore{Dir: t.TempDir()}
	matcher, _ := Exact("systemctl restart nginx")
	if _, err := store.Grant("s", "web-1", ScopeSession, matcher, "", "ap_0123456789abcdef01234567", "r1", time.Hour, ChannelCLI); err != nil {
		t.Fatal(err)
	}
	auth, err := Authorize(policy.Config{}, inv, store, RuntimeConfig{Enabled: true, HostGrantMode: HostGrantSafePrefix}, "s", "web-1", "systemctl restart nginx", "", "req-test")
	if err != nil {
		t.Fatalf("Authorize session: %v", err)
	}
	if auth.Status != AuthAllowByGrant || auth.GrantScope != ScopeSession {
		t.Fatalf("session auth = %#v", auth)
	}

	cfg := policy.Config{HostOverrides: map[string]policy.HostOverride{
		policy.HostRulesKey("web-1"): {Rules: []policy.Rule{{
			Name:   "approval/host",
			Match:  policy.Match{CmdRegex: `\Als(?:[ \t]+[A-Za-z0-9@%+=:,./_-]+)*[ \t]*\z`},
			Action: policy.ActionAllow,
			Group:  policy.ApprovalGroup,
		}}},
	}}
	auth, err = Authorize(cfg, inv, SessionStore{Dir: t.TempDir()}, RuntimeConfig{Enabled: true, HostGrantMode: HostGrantSafePrefix}, "s2", "web-1", "ls /var", "", "req-test")
	if err != nil {
		t.Fatalf("Authorize host: %v", err)
	}
	if auth.Status != AuthAllowByGrant || auth.GrantScope != ScopeHost {
		t.Fatalf("host auth = %#v", auth)
	}
}

func TestAuthorizeNewDenyInvalidatesExistingGrant(t *testing.T) {
	inv := inventory.Inventory{Hosts: map[string]inventory.Host{"web-1": {}}}
	store := SessionStore{Dir: t.TempDir()}
	matcher, _ := Exact("id")
	if _, err := store.Grant("s", "web-1", ScopeSession, matcher, "", "ap_0123456789abcdef01234567", "r1", time.Hour, ChannelCLI); err != nil {
		t.Fatal(err)
	}
	cfg := policy.Config{Rules: []policy.Rule{{
		Name:   "deny-id",
		Match:  policy.Match{CmdRegex: `\Aid\z`},
		Action: policy.ActionDeny,
	}}}
	auth, err := Authorize(cfg, inv, store, RuntimeConfig{Enabled: true, HostGrantMode: HostGrantSafePrefix}, "s", "web-1", "id", "", "req-test")
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	if auth.Status != AuthHardDeny {
		t.Fatalf("auth = %#v, want hard deny", auth)
	}
}

func TestAuthorizeDisabledApprovalUsesPersistedHostRules(t *testing.T) {
	inv := inventory.Inventory{Hosts: map[string]inventory.Host{"web-1": {}}}
	cfg := policy.Config{HostOverrides: map[string]policy.HostOverride{
		policy.HostRulesKey("web-1"): {Rules: []policy.Rule{{
			Name:   "approval/host",
			Match:  policy.Match{CmdRegex: `\Als(?:[ \t]+[A-Za-z0-9@%+=:,./_-]+)*[ \t]*\z`},
			Action: policy.ActionAllow,
			Group:  policy.ApprovalGroup,
		}}},
	}}
	auth, err := Authorize(cfg, inv, SessionStore{Dir: t.TempDir()}, RuntimeConfig{Enabled: false, HostGrantMode: HostGrantSafePrefix}, "s", "web-1", "ls /var", "", "req-test")
	if err != nil {
		t.Fatalf("Authorize persisted host rule while disabled: %v", err)
	}
	if auth.Status != AuthAllow || auth.Decision.Action != policy.ActionAllow {
		t.Fatalf("auth = %#v, want raw allow while disabled", auth)
	}

	auth, err = Authorize(cfg, inv, SessionStore{Dir: t.TempDir()}, RuntimeConfig{Enabled: false, HostGrantMode: HostGrantSafePrefix}, "s", "web-1", "id", "", "req-test")
	if err != nil {
		t.Fatalf("Authorize gray while disabled: %v", err)
	}
	if auth.Status != AuthNeedsApproval || auth.Decision.Rule != policy.RuleDefaultDeny {
		t.Fatalf("gray auth = %#v, want default-deny needs approval sentinel", auth)
	}
}
