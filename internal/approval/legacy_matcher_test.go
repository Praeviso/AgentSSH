package approval

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Praeviso/AgentSSH/internal/inventory"
	"github.com/Praeviso/AgentSSH/internal/policy"
)

// The '+' byte used to be emitted into the pattern verbatim, where it acts as
// a quantifier. Grants and host rules minted before the fix are still on disk:
// they fail to match the command the operator approved while matching commands
// the operator never saw. These tests cover the repair of that persisted state.

// legacyExactRegex reproduces what the pre-fix generator emitted for a command:
// every byte escaped except the old allowlist, which included '+'.
func legacyExactRegex(command string) string {
	matcher, err := Exact(command)
	if err != nil {
		panic(err)
	}
	return strings.ReplaceAll(matcher.Regex, `\x2B`, "+")
}

func writeLegacySessionFile(t *testing.T, dir string, sessionID string, grants []Grant) {
	t.Helper()
	doc := sessionFile{Version: 1, SessionID: sessionID, Updated: "2026-08-03T00:00:00Z", Grants: grants}
	data, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sessionPath(dir, sessionID), append(data, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestSessionStoreRepairsLegacyPlusGrantOnRead(t *testing.T) {
	const command = `docker exec c python -c "g=lambda p:u.urlopen(b+p,timeout=30)"`
	dir := t.TempDir()
	now := time.Date(2026, 8, 3, 0, 0, 0, 0, time.UTC)
	writeLegacySessionFile(t, dir, "s_legacy", []Grant{{
		Scope:      ScopeSession,
		Kind:       MatcherExact,
		Regex:      legacyExactRegex(command),
		SourceCmd:  command,
		Host:       "web-1",
		GrantedTS:  "2026-08-03T00:00:00Z",
		ExpiresTS:  now.Add(12 * time.Hour).UTC().Format(time.RFC3339),
		ApprovalID: "ap_0123456789abcdef01234567",
		ReqID:      "r1",
	}})
	store := SessionStore{Dir: dir, Now: func() time.Time { return now }}

	// The approved command is authorized again — this is the incident.
	if _, ok, err := store.Peek("s_legacy", "web-1", command, ""); err != nil || !ok {
		t.Fatalf("repaired grant should authorize the approved command: ok=%v err=%v", ok, err)
	}
	// And the plus-stripped variant, which the legacy pattern authorized, is not.
	widened := strings.ReplaceAll(command, "+", "")
	if _, ok, err := store.Peek("s_legacy", "web-1", widened, ""); err != nil || ok {
		t.Fatalf("repaired grant must not authorize unapproved command %q: ok=%v err=%v", widened, ok, err)
	}

	var doc sessionFile
	data, err := os.ReadFile(sessionPath(dir, "s_legacy"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Version != sessionFileVersion {
		t.Fatalf("version = %d, want %d", doc.Version, sessionFileVersion)
	}
	if len(doc.Grants) != 1 || strings.Contains(doc.Grants[0].Regex, "+") {
		t.Fatalf("repair was not persisted: %#v", doc.Grants)
	}
}

func TestSessionStoreDropsUnrepairableGrant(t *testing.T) {
	dir := t.TempDir()
	now := time.Date(2026, 8, 3, 0, 0, 0, 0, time.UTC)
	expires := now.Add(12 * time.Hour).UTC().Format(time.RFC3339)
	good, err := Exact("systemctl status nginx")
	if err != nil {
		t.Fatal(err)
	}
	writeLegacySessionFile(t, dir, "s_mixed", []Grant{
		{
			// No SourceCmd to re-derive from, and the pattern is legacy.
			Scope: ScopeSession, Kind: MatcherExact, Regex: `\Aecho\x20a+b\z`,
			Host: "web-1", ExpiresTS: expires, ApprovalID: "ap_bad", ReqID: "r1",
		},
		{
			Scope: ScopeSession, Kind: good.Kind, Regex: good.Regex, SourceCmd: good.SourceCmd,
			Host: "web-1", ExpiresTS: expires, ApprovalID: "ap_good", ReqID: "r2",
		},
	})
	store := SessionStore{Dir: dir, Now: func() time.Time { return now }}

	if _, ok, err := store.Peek("s_mixed", "web-1", "echo ab", ""); err != nil || ok {
		t.Fatalf("dropped grant must not authorize anything: ok=%v err=%v", ok, err)
	}
	// A poisoned neighbour must not take the healthy grant down with it.
	if _, ok, err := store.Peek("s_mixed", "web-1", "systemctl status nginx", ""); err != nil || !ok {
		t.Fatalf("healthy grant should still authorize: ok=%v err=%v", ok, err)
	}
}

// A grant whose stored pattern does not compile used to abort the whole locked
// session, failing every command in it rather than only its own.
func TestSessionStoreUncompilableGrantDoesNotBrickSession(t *testing.T) {
	dir := t.TempDir()
	now := time.Date(2026, 8, 3, 0, 0, 0, 0, time.UTC)
	expires := now.Add(12 * time.Hour).UTC().Format(time.RFC3339)
	good, err := Exact("systemctl status nginx")
	if err != nil {
		t.Fatal(err)
	}
	doc := sessionFile{Version: sessionFileVersion, SessionID: "s_poison", Grants: []Grant{
		{Scope: ScopeSession, Kind: MatcherExact, Regex: `\Ax++\z`, SourceCmd: "x++",
			Host: "web-1", ExpiresTS: expires, ApprovalID: "ap_bad", ReqID: "r1"},
		{Scope: ScopeSession, Kind: good.Kind, Regex: good.Regex, SourceCmd: good.SourceCmd,
			Host: "web-1", ExpiresTS: expires, ApprovalID: "ap_good", ReqID: "r2"},
	}}
	data, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sessionPath(dir, "s_poison"), append(data, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	store := SessionStore{Dir: dir, Now: func() time.Time { return now }}
	if _, ok, err := store.Peek("s_poison", "web-1", "systemctl status nginx", ""); err != nil || !ok {
		t.Fatalf("healthy grant should authorize despite a poisoned neighbour: ok=%v err=%v", ok, err)
	}
}

func TestLegacyHostRuleStopsAuthorizing(t *testing.T) {
	const command = "deploy --tag v1+build"
	cfg := policy.Config{
		Version: 1,
		HostOverrides: map[string]policy.HostOverride{
			policy.HostRulesKey("web-1"): {Rules: []policy.Rule{{
				Name:   "approval/legacy",
				Match:  policy.Match{CmdRegex: legacyExactRegex(command)},
				Action: policy.ActionAllow,
				Group:  policy.ApprovalGroup,
			}}},
		},
	}
	inv := inventory.Inventory{Hosts: map[string]inventory.Host{"web-1": {}}}
	store := SessionStore{Dir: t.TempDir()}
	runtime := RuntimeConfig{Enabled: true, HostGrantMode: HostGrantSafePrefix}

	// The rule authorized the plus-stripped command, which nobody approved.
	widened := strings.ReplaceAll(command, "+", "")
	auth, err := PreflightAuthorize(cfg, inv, store, runtime, "s_1", "web-1", widened, "")
	if err != nil {
		t.Fatal(err)
	}
	if auth.Status != AuthNeedsApproval {
		t.Fatalf("legacy rule still authorizes unapproved command %q: status=%s rule=%s", widened, auth.Status, auth.Decision.Rule)
	}
	// It never matched the approved command, so that falls back to approval too.
	auth, err = PreflightAuthorize(cfg, inv, store, runtime, "s_1", "web-1", command, "")
	if err != nil {
		t.Fatal(err)
	}
	if auth.Status != AuthNeedsApproval {
		t.Fatalf("status = %s, want needs_approval", auth.Status)
	}
	if err := CheckHostGrantRule(cfg.HostOverrides[policy.HostRulesKey("web-1")].Rules[0]); err == nil {
		t.Fatal("CheckHostGrantRule accepted a legacy pattern")
	}
}

// The exact commands from the production incident of 2026-08-03: the same
// command was re-approved three times inside one 12h session TTL because the
// grant's pattern, generated with an unescaped '+', could not match the
// command it was minted from. The load-bearing fragment is `u.urlopen(b+p,
// timeout=30)`.
const incidentCommand = `docker exec handrail-handrail-harness-1 python -c "import json,urllib.request as u; b='http://handrail-api:8080'; g=lambda p:json.load(u.urlopen(b+p,timeout=30)); ss=[s for s in g('/sessions') if s.get('template_id')=='lite-deployment-e2e']; assert ss,'e2e session missing'; s=max(ss,key=lambda x:x['created_at']); sid=s['id']; s=g('/sessions/'+sid); assert s['status']=='completed' and s['current_run_status']=='completed' and s['final_output'].strip()=='LITE_E2E_OK'; p=g('/admin/model-providers/cliproxy'); assert p['status']=='active' and p['default_model']=='deepseek-v4-flash' and p['protocol']=='openai_chat_completions'; v=g('/admin/agent-versions/'+s['agent_version_id']); assert v['model']=='deepseek-v4-flash' and v['model_provider_id']=='cliproxy'; es=g('/sessions/'+sid+'/events'); ts=[e['type'] for e in es]; assert 'run_completed' in ts and 'output_exported' in ts and 'tool_failed' not in ts; ars=g('/sessions/'+sid+'/artifacts'); a=[x for x in ars if x['kind']=='task_output' and x['name']=='lite-proof.txt']; assert len(a)==1; raw=u.urlopen(b+'/sessions/'+sid+'/artifacts/'+a[0]['id']+'/download?actor_type=user&actor_id=deployment-e2e',timeout=30).read(); assert raw.decode().strip()=='LITE_E2E_OK'; print(json.dumps({'status':'passed','session_id':sid,'run_id':s['current_run_id'],'model':v['model'],'artifact_id':a[0]['id'],'artifact_bytes':len(raw)},sort_keys=True))"`

const incidentHostCommand = `docker exec handrail-handrail-harness-1 python -c "from pathlib import Path; p=Path('/run/handrail/secrets/model-providers/cliproxy/api-key'); ok=p.is_file() and p.stat().st_size>0; print('cliproxy_secret=' + ('present bytes=' + str(p.stat().st_size) if ok else 'missing')); raise SystemExit(0 if ok else 1)"`

func TestAuthorizeGrantForPlusCommandFromProductionIncident(t *testing.T) {
	inv := inventory.Inventory{Hosts: map[string]inventory.Host{"greencloud-sg-1212": {}}}
	runtime := RuntimeConfig{Enabled: true, HostGrantMode: HostGrantSafePrefix}
	for _, command := range []string{incidentCommand, incidentHostCommand} {
		t.Run(fmt.Sprintf("%d bytes", len(command)), func(t *testing.T) {
			store := SessionStore{Dir: t.TempDir()}
			matcher, err := Exact(command)
			if err != nil {
				t.Fatalf("Exact: %v", err)
			}
			if _, err := store.Grant("s_71d8e139", "greencloud-sg-1212", ScopeSession, matcher, "", "ap_0123456789abcdef01234567", "r1", time.Hour, ChannelCLI); err != nil {
				t.Fatal(err)
			}

			// The incident: the approved command asked for approval again.
			auth, err := Authorize(policy.Config{}, inv, store, runtime, "s_71d8e139", "greencloud-sg-1212", command, "", "req-1")
			if err != nil {
				t.Fatalf("Authorize: %v", err)
			}
			if auth.Status != AuthAllowByGrant || auth.GrantScope != ScopeSession {
				t.Fatalf("approved command was not authorized by its own grant: status=%s scope=%s", auth.Status, auth.GrantScope)
			}

			// The other half, which the incident never surfaced: the grant also
			// authorized the command with every '+' removed.
			widened := strings.ReplaceAll(command, "+", "")
			auth, err = Authorize(policy.Config{}, inv, store, runtime, "s_71d8e139", "greencloud-sg-1212", widened, "", "req-2")
			if err != nil {
				t.Fatalf("Authorize widened: %v", err)
			}
			if auth.Status != AuthNeedsApproval {
				t.Fatalf("grant authorized a command the operator never approved: status=%s rule=%s", auth.Status, auth.Decision.Rule)
			}
		})
	}
}
