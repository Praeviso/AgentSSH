package approval

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Praeviso/AgentSSH/internal/audit"
	"github.com/Praeviso/AgentSSH/internal/inventory"
	"github.com/Praeviso/AgentSSH/internal/policy"
)

func TestTaskPermissionBoundaries(t *testing.T) {
	for _, tc := range []struct {
		source      string
		allow, deny []string
	}{
		{"systemctl status nginx", []string{"systemctl show nginx", "journalctl -u nginx -n 200 --since '1 hour ago' --no-pager"}, []string{"systemctl restart nginx", "systemctl show redis", "sudo systemctl status nginx", "systemctl show nginx; id", "systemctl show nginx --root /tmp", "journalctl -u nginx --vacuum-time 1s", "systemctl status nginx '* '"}},
		{"sudo -n systemctl restart nginx", []string{"sudo -n systemctl reload nginx", "sudo -n journalctl -u nginx -n 50 --no-pager"}, []string{"sudo systemctl restart nginx", "systemctl restart nginx", "sudo -u root systemctl restart nginx", "sudo -n systemctl stop nginx", "sudo -n systemctl restart redis"}},
		{"cd /opt/app && docker compose -f /opt/app/compose.yaml up -d app", []string{"cd '/opt/app' && docker compose -f /opt/app/compose.yaml build --no-cache app", "cd /opt/app && docker compose -f /opt/app/compose.yaml logs --tail 100 app", "cd /opt/app && docker compose -f /opt/app/compose.yaml restart app"}, []string{"docker compose -f /opt/app/compose.yaml up -d app", "cd /opt/other && docker compose -f /opt/app/compose.yaml up -d app", "cd /opt/app && docker compose -f /opt/app/other.yaml up -d app", "cd /opt/app && docker compose -f /opt/app/compose.yaml up -d db", "cd /opt/app && docker compose -f /opt/app/compose.yaml up -d", "cd /opt/app && docker compose -f /opt/app/compose.yaml down -v", "cd /opt/app && docker compose -f /opt/app/compose.yaml up --remove-orphans app", "cd /opt/app && docker compose -f /opt/app/compose.yaml build --build-arg CMD=bad app", "cd /opt/app && docker compose -f /opt/app/compose.yaml exec app sh"}},
		{"docker compose -f /opt/app/compose.yaml ps", []string{"docker compose -f /opt/app/compose.yaml logs --tail 100 app"}, []string{"docker compose -f /opt/app/compose.yaml up -d", "docker compose -f /opt/app/compose.yaml logs --tail 10000", "docker --context prod compose -f /opt/app/compose.yaml ps"}},
	} {
		t.Run(tc.source, func(t *testing.T) {
			p := TaskCandidate(tc.source, "")
			if p == nil {
				t.Fatal("no candidate")
			}
			if !p.Match(tc.source) {
				t.Fatal("candidate does not match source")
			}
			for _, command := range tc.allow {
				if !p.Match(command) {
					t.Errorf("did not allow %q", command)
				}
			}
			for _, command := range tc.deny {
				if p.Match(command) {
					t.Errorf("allowed %q", command)
				}
			}
		})
	}
	for _, command := range []string{"bash -c 'systemctl restart nginx'", "systemctl status nginx | cat", "docker compose up -d", "python3 -c print(1)", "/tmp/systemctl restart nginx", "systemctl restart nginx && id", "A=x systemctl restart nginx"} {
		if TaskCandidate(command, "") != nil {
			t.Errorf("unexpected profile %q", command)
		}
	}
	if TaskCandidate("systemctl restart nginx", "payload-hash") != nil {
		t.Fatal("stdin acquired task scope")
	}
}

func TestTaskGrantLifecycleAndExactCompatibility(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	root := t.TempDir()
	store := SessionStore{Dir: filepath.Join(root, "sessions"), Now: func() time.Time { return now }}
	pending := PendingStore{PendingDir: filepath.Join(root, "pending"), ResponsesDir: filepath.Join(root, "responses")}
	command := "systemctl restart nginx"
	matcher, _ := Exact(command)
	req, err := pending.Create(PendingRequest{ReqID: "req", SessionID: "s", Host: "web-1", Cmd: command, Candidate: matcher})
	if err != nil {
		t.Fatal(err)
	}
	opts := ApplyOptions{Pending: pending, Sessions: store, TaskTTL: time.Hour, Audit: audit.NewStore(filepath.Join(root, "audit.log"))}
	result, err := ApplyDecision(opts, req.ID, VerdictApproved, ScopeTask)
	if err != nil {
		t.Fatal(err)
	}
	if result.Grant.Task == nil || result.Grant.ExpiresTS != now.Add(time.Hour).Format(time.RFC3339) {
		t.Fatalf("grant %+v", result.Grant)
	}
	inv := inventory.Inventory{Hosts: map[string]inventory.Host{"web-1": {}, "web-2": {}}}
	runtime := RuntimeConfig{Enabled: true}
	for _, tc := range []struct {
		session, host, command, stdin string
		want                          AuthorizationStatus
	}{
		{"s", "web-1", "systemctl reload nginx", "", AuthAllowByGrant},
		{"s", "web-1", "journalctl -u nginx -n 100", "", AuthAllowByGrant},
		{"other", "web-1", command, "", AuthNeedsApproval},
		{"s", "web-2", command, "", AuthNeedsApproval},
		{"s", "web-1", command, "new-payload", AuthNeedsApproval},
	} {
		auth, err := PreflightAuthorize(policy.Config{}, inv, store, runtime, tc.session, tc.host, tc.command, tc.stdin)
		if err != nil || auth.Status != tc.want {
			t.Fatalf("%+v => %+v %v", tc, auth, err)
		}
	}
	deny := policy.Config{Rules: []policy.Rule{{Name: "no-reload", Match: policy.Match{CmdRegex: "systemctl reload"}, Action: policy.ActionDeny}}}
	for _, command := range []string{"systemctl reload nginx", "systemctl 'reload' nginx"} {
		auth, err := PreflightAuthorize(deny, inv, store, runtime, "s", "web-1", command, "")
		if err != nil || auth.Status != AuthHardDeny {
			t.Fatalf("deny bypass %q %+v %v", command, auth, err)
		}
	}
	now = now.Add(time.Hour)
	if _, ok, err := store.Peek("s", "web-1", command, ""); err != nil || ok {
		t.Fatal("grant survived expiry", err)
	}
	if _, err := store.Grant("exact", "web-1", ScopeSession, matcher, "", "old", "r", time.Hour, ChannelCLI); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := store.Peek("exact", "web-1", "systemctl reload nginx", ""); ok {
		t.Fatal("old exact scope widened")
	}
	task, _ := taskMatcher(command)
	if _, err := store.Grant("s", "web-1", ScopeTask, task, "", "new", "r2", time.Hour, ChannelCLI); err != nil {
		t.Fatal(err)
	}
	if err := store.End("s"); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := store.Peek("s", "web-1", command, ""); ok {
		t.Fatal("revocation did not clear grant")
	}
	verified, err := opts.Audit.Verify()
	if err != nil || !verified.OK {
		t.Fatal("audit", verified, err)
	}
}

func TestUnsupportedTaskApprovalLeavesRequestPending(t *testing.T) {
	root := t.TempDir()
	store := PendingStore{PendingDir: filepath.Join(root, "pending"), ResponsesDir: filepath.Join(root, "responses")}
	m, _ := Exact("bash -c 'echo hi'")
	req, err := store.Create(PendingRequest{SessionID: "s", Host: "h", Cmd: m.SourceCmd, Candidate: m})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ApplyDecision(ApplyOptions{Pending: store}, req.ID, VerdictApproved, ScopeTask); err == nil {
		t.Fatal("unsupported task approved")
	}
	status, err := store.Status(req.ID)
	if err != nil || status.Status != "pending" {
		t.Fatal(status, err)
	}
}

func TestPlanTaskGrantUsesExactFallbackAndTaskLifetime(t *testing.T) {
	root := t.TempDir()
	now := time.Now().UTC().Truncate(time.Second)
	store := PendingStore{PendingDir: filepath.Join(root, "pending"), ResponsesDir: filepath.Join(root, "responses"), PlansDir: filepath.Join(root, "plans")}
	sessions := SessionStore{Dir: filepath.Join(root, "sessions"), Now: func() time.Time { return now }}
	var ids []string
	for _, input := range []struct{ cmd, stdin string }{{"systemctl restart nginx", ""}, {"tee /opt/app/config", "hash"}} {
		m, _ := Exact(input.cmd)
		req, err := store.Create(PendingRequest{SessionID: "s", Host: "web", ReqID: input.cmd, Cmd: input.cmd, Candidate: m, StdinSHA256: input.stdin})
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, req.ID)
	}
	plan, err := store.CreatePlan(PlanManifest{SessionID: "s", Host: "web", MemberIDs: ids})
	if err != nil {
		t.Fatal(err)
	}
	results, err := ApplyPlanDecision(ApplyOptions{Pending: store, Sessions: sessions, TaskTTL: 30 * time.Minute}, plan.ID, VerdictApproved, ScopeTask)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 2 || results[0].Grant.Scope != ScopeTask || results[1].Grant.Scope != ScopeSession {
		t.Fatal(results)
	}
	for _, result := range results {
		if result.Grant.ExpiresTS != now.Add(30*time.Minute).Format(time.RFC3339) {
			t.Fatal(result.Grant)
		}
	}
	if _, ok, _ := sessions.Peek("s", "web", "tee /opt/app/config", "different"); ok {
		t.Fatal("stdin fallback widened")
	}
	if _, ok, _ := sessions.Peek("s", "web", "tee /opt/other/config", "hash"); ok {
		t.Fatal("command fallback widened")
	}
	if _, ok, _ := sessions.Peek("s", "web", "tee /opt/app/config", "hash"); !ok {
		t.Fatal("exact fallback lost")
	}
}

func TestTaskTTLValidationAndUnboundedLogs(t *testing.T) {
	for _, ttl := range []string{"0s", "-1m", "bad"} {
		if _, err := RuntimeConfigFromPolicy(policy.Approval{TaskTTL: ttl}, ""); err == nil {
			t.Errorf("accepted ttl %q", ttl)
		}
	}
	cfg, err := RuntimeConfigFromPolicy(policy.Approval{TaskTTL: "30m"}, "")
	if err != nil || cfg.TaskTTL != 30*time.Minute {
		t.Fatal(cfg, err)
	}
	for _, command := range []string{"journalctl -u nginx", "journalctl -u nginx -n 5000", "docker compose -f /opt/app/c.yaml logs", "docker compose -f /opt/app/c.yaml logs --tail all"} {
		if TaskCandidate(command, "") != nil {
			t.Errorf("unbounded logs %q", command)
		}
	}
}

func TestPreflightDoesNotCreateLocksOrRewriteExpiredGrants(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	store := SessionStore{Dir: filepath.Join(t.TempDir(), "sessions"), Now: func() time.Time { return now }}
	runtime := RuntimeConfig{Enabled: true}
	if _, err := PreflightAuthorize(policy.Config{}, inventory.Inventory{}, store, runtime, "s", "web", "id", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(store.Dir); !os.IsNotExist(err) {
		t.Fatal("preflight created a store", err)
	}
	m, _ := Exact("id")
	if _, err := store.Grant("s", "web", ScopeOnce, m, "", "ap", "req", time.Second, ChannelCLI); err != nil {
		t.Fatal(err)
	}
	file := sessionPath(store.Dir, "s")
	before, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	auth, err := PreflightAuthorize(policy.Config{}, inventory.Inventory{}, store, runtime, "s", "web", "id", "")
	if err != nil || auth.Status != AuthAllowByGrant {
		t.Fatal(auth, err)
	}
	now = now.Add(time.Second)
	auth, err = PreflightAuthorize(policy.Config{}, inventory.Inventory{}, store, runtime, "s", "web", "id", "")
	if err != nil || auth.Status != AuthNeedsApproval {
		t.Fatal(auth, err)
	}
	after, err := os.ReadFile(file)
	if err != nil || string(before) != string(after) {
		t.Fatal("preflight changed persistent grants", err)
	}
}
