package approval

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Praeviso/AgentSSH/internal/audit"
	"github.com/Praeviso/AgentSSH/internal/inventory"
	"github.com/Praeviso/AgentSSH/internal/policy"
)

// A generated __agentssh_approval host rule matches command text only. It must
// never authorize a stdin run, even when the async approval channel is
// disabled: the operator never saw or hash-bound the payload.
func TestAuthorizeDisabledApprovalSkipsApprovalHostRulesForStdin(t *testing.T) {
	cfg := policy.Config{
		HostOverrides: map[string]policy.HostOverride{
			policy.HostRulesKey("web-1"): {Rules: []policy.Rule{{
				Name:   "approval/deadbeef",
				Match:  policy.Match{CmdRegex: `\Atee /etc/app.conf\z`},
				Action: policy.ActionAllow,
				Group:  policy.ApprovalGroup,
			}}},
		},
	}
	inv := inventory.Inventory{Hosts: map[string]inventory.Host{"web-1": {}}}
	runtime := RuntimeConfig{Enabled: false, HostGrantMode: HostGrantSafePrefix}
	store := SessionStore{Dir: t.TempDir()}

	// Without stdin, the operator-visible approval host rule still allows the
	// bare command (unchanged behavior).
	auth, err := PreflightAuthorize(cfg, inv, store, runtime, "s", "web-1", "tee /etc/app.conf", "")
	if err != nil {
		t.Fatalf("no-stdin authorize: %v", err)
	}
	if auth.Status != AuthAllow {
		t.Fatalf("no-stdin status = %q, want allow", auth.Status)
	}

	// With stdin, the approval host rule is stripped, so the command falls to
	// default-deny rather than riding a rule that never vouched for the payload.
	auth, err = PreflightAuthorize(cfg, inv, store, runtime, "s", "web-1", "tee /etc/app.conf", "deadbeefstdinhash")
	if err != nil {
		t.Fatalf("stdin authorize: %v", err)
	}
	if auth.Status == AuthAllow {
		t.Fatalf("stdin run was authorized by an approval host rule: %#v", auth)
	}
}

// An operator-authored (non-approval) allow rule keeps authorizing stdin runs:
// writing such a rule is a deliberate decision, so stdin must not disable it.
func TestAuthorizeDisabledApprovalKeepsOperatorAllowRuleForStdin(t *testing.T) {
	cfg := policy.Config{
		HostOverrides: map[string]policy.HostOverride{
			policy.HostRulesKey("web-1"): {Rules: []policy.Rule{{
				Name:   "operator-tee",
				Match:  policy.Match{CmdRegex: `\Atee /etc/app.conf\z`},
				Action: policy.ActionAllow,
			}}},
		},
	}
	inv := inventory.Inventory{Hosts: map[string]inventory.Host{"web-1": {}}}
	runtime := RuntimeConfig{Enabled: false, HostGrantMode: HostGrantSafePrefix}
	auth, err := PreflightAuthorize(cfg, inv, SessionStore{Dir: t.TempDir()}, runtime, "s", "web-1", "tee /etc/app.conf", "stdinhash")
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	if auth.Status != AuthAllow {
		t.Fatalf("operator allow rule did not authorize stdin run: %#v", auth)
	}
}

// blockedAuditStore returns an audit.Store whose Append fails: its parent path
// component is a regular file, so MkdirAll inside Append errors.
func blockedAuditStore(t *testing.T) audit.Store {
	t.Helper()
	root := t.TempDir()
	blocker := filepath.Join(root, "not-a-dir")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	return audit.NewStore(filepath.Join(blocker, "audit.log"))
}

// If the approval_granted audit append fails, no usable grant may exist:
// authorization is derived from the grant store, so a grant without its audit
// record would be a silent, untraceable authorization.
func TestApplyDecisionAuditFailureDoesNotCreateGrant(t *testing.T) {
	root := t.TempDir()
	pending := PendingStore{
		PendingDir:   filepath.Join(root, "pending"),
		ResponsesDir: filepath.Join(root, "responses"),
	}
	matcher, err := Exact("systemctl restart nginx")
	if err != nil {
		t.Fatal(err)
	}
	req, err := pending.Create(PendingRequest{
		ReqID:     "r1",
		SessionID: "s_fail",
		Host:      "web-1",
		Cmd:       "systemctl restart nginx",
		Candidate: matcher,
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	sessions := SessionStore{Dir: filepath.Join(root, "sessions")}
	opts := ApplyOptions{
		Pending:  pending,
		Sessions: sessions,
		Audit:    blockedAuditStore(t),
		Channel:  ChannelCLI,
	}
	if _, err := ApplyDecision(opts, req.ID, VerdictApproved, ScopeSession); err == nil {
		t.Fatalf("ApplyDecision succeeded despite audit failure")
	}
	// The grant store must hold nothing for this session.
	if _, ok, err := sessions.Peek("s_fail", "web-1", "systemctl restart nginx", ""); err != nil {
		t.Fatalf("Peek: %v", err)
	} else if ok {
		t.Fatalf("a grant was created despite the approval audit failing")
	}
}

// A mid-batch audit failure in a plan decision must leave no member grant
// without its audit record either.
func TestApplyPlanDecisionAuditFailureDoesNotCreateGrant(t *testing.T) {
	root := t.TempDir()
	pending := PendingStore{
		PendingDir:   filepath.Join(root, "pending"),
		ResponsesDir: filepath.Join(root, "responses"),
		PlansDir:     filepath.Join(root, "plans"),
	}
	var memberIDs []string
	for _, cmd := range []string{"systemctl restart nginx", "systemctl restart redis"} {
		matcher, err := Exact(cmd)
		if err != nil {
			t.Fatal(err)
		}
		req, err := pending.Create(PendingRequest{
			ReqID:     "r_" + cmd,
			SessionID: "s_planfail",
			Host:      "web-1",
			Cmd:       cmd,
			Candidate: matcher,
			PlanID:    "pl_000000000000000000000000",
		})
		if err != nil {
			t.Fatalf("Create %q: %v", cmd, err)
		}
		memberIDs = append(memberIDs, req.ID)
	}
	manifest, err := pending.CreatePlan(PlanManifest{
		ID:        "pl_000000000000000000000000",
		SessionID: "s_planfail",
		Host:      "web-1",
		MemberIDs: memberIDs,
	})
	if err != nil {
		t.Fatalf("CreatePlan: %v", err)
	}
	sessions := SessionStore{Dir: filepath.Join(root, "sessions")}
	opts := ApplyOptions{
		Pending:  pending,
		Sessions: sessions,
		Audit:    blockedAuditStore(t),
		Channel:  ChannelPlan,
	}
	if _, err := ApplyPlanDecision(opts, manifest.ID, VerdictApproved, ScopeSession); err == nil {
		t.Fatalf("ApplyPlanDecision succeeded despite audit failure")
	}
	for _, cmd := range []string{"systemctl restart nginx", "systemctl restart redis"} {
		if _, ok, err := sessions.Peek("s_planfail", "web-1", cmd, ""); err != nil {
			t.Fatalf("Peek %q: %v", cmd, err)
		} else if ok {
			t.Fatalf("plan member %q got a grant despite audit failure", cmd)
		}
	}
}
