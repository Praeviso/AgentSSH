package runner_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/Praeviso/AgentSSH/internal/approval"
	"github.com/Praeviso/AgentSSH/internal/audit"
	"github.com/Praeviso/AgentSSH/internal/executor"
	"github.com/Praeviso/AgentSSH/internal/inventory"
	"github.com/Praeviso/AgentSSH/internal/output"
	"github.com/Praeviso/AgentSSH/internal/policy"
	"github.com/Praeviso/AgentSSH/internal/runner"
	"github.com/Praeviso/AgentSSH/internal/session"
)

// fakeExecutor records which hosts ran and answers with a fixed result.
type fakeExecutor struct {
	mu     sync.Mutex
	hosts  []string
	result executor.Result
}

func (f *fakeExecutor) Run(_ context.Context, req executor.Request) executor.Result {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.hosts = append(f.hosts, req.Target.Name)
	return f.result
}

func (f *fakeExecutor) Close() error { return nil }

func (f *fakeExecutor) ran() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.hosts...)
}

// streamingExecutor writes its result's output to the supplied writers.
type streamingExecutor struct {
	fakeExecutor
}

func (f *streamingExecutor) RunStreaming(_ context.Context, req executor.Request, stdout io.Writer, stderr io.Writer) executor.Result {
	f.mu.Lock()
	f.hosts = append(f.hosts, req.Target.Name)
	result := f.result
	f.mu.Unlock()
	_, _ = io.WriteString(stdout, result.Stdout)
	_, _ = io.WriteString(stderr, result.Stderr)
	result.Stdout, result.Stderr = "", ""
	return result
}

type recordingObserver struct {
	mu       sync.Mutex
	denied   []string
	pending  []string
	notRun   []string
	finished []string
	streamed []bool
}

func (o *recordingObserver) Denied(host string, _ string, _ policy.Decision) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.denied = append(o.denied, host)
}

func (o *recordingObserver) ApprovalPending(host string, _ approval.PendingRequest) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.pending = append(o.pending, host)
}

func (o *recordingObserver) NotRun(host string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.notRun = append(o.notRun, host)
}

func (o *recordingObserver) Finished(host string, _ executor.Result, _ output.FilterResult, streamed bool) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.finished = append(o.finished, host)
	o.streamed = append(o.streamed, streamed)
}

func (o *recordingObserver) Warning(string) {}

type fixture struct {
	env  runner.Env
	exec *fakeExecutor
	dir  string
}

func newFixture(t *testing.T, cfg policy.Config, approvals bool, hosts ...string) fixture {
	t.Helper()
	dir := t.TempDir()
	inv := inventory.Inventory{Hosts: map[string]inventory.Host{}}
	for _, host := range hosts {
		inv.Hosts[host] = inventory.Host{}
	}
	filter, err := output.NewFilter(cfg.Output)
	if err != nil {
		t.Fatal(err)
	}
	exec := &fakeExecutor{result: executor.Result{Stdout: "up 3 days\n", Duration: 12 * time.Millisecond}}
	return fixture{
		dir:  dir,
		exec: exec,
		env: runner.Env{
			Policy:    cfg,
			Inventory: inv,
			Approval:  approval.RuntimeConfig{Enabled: approvals, HostGrantMode: approval.HostGrantSafePrefix, SessionTTL: time.Hour, WaitTimeout: time.Minute},
			Sessions:  approval.SessionStore{Dir: filepath.Join(dir, "sessions")},
			Pending: approval.PendingStore{
				PendingDir:   filepath.Join(dir, "pending"),
				ResponsesDir: filepath.Join(dir, "responses"),
				PlansDir:     filepath.Join(dir, "plans"),
			},
			Audit:    audit.NewStore(filepath.Join(dir, "audit.jsonl")),
			Executor: exec,
			Output:   filter,
		},
	}
}

func (f fixture) events(t *testing.T) []audit.Event {
	t.Helper()
	records, err := audit.NewStore(filepath.Join(f.dir, "audit.jsonl")).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	events := make([]audit.Event, 0, len(records))
	for _, record := range records {
		events = append(events, record.Event)
	}
	return events
}

func hostTarget(name string) inventory.ResolvedTarget {
	return inventory.ResolvedTarget{Kind: inventory.TargetKindHost, Targets: []inventory.Target{{Name: name}}}
}

func groupTarget(names ...string) inventory.ResolvedTarget {
	targets := make([]inventory.Target, 0, len(names))
	for _, name := range names {
		targets = append(targets, inventory.Target{Name: name})
	}
	return inventory.ResolvedTarget{Kind: inventory.TargetKindGroup, Targets: targets}
}

func allowUptime() policy.Config {
	return policy.Config{Rules: []policy.Rule{{
		Name:   "allow-uptime",
		Match:  policy.Match{CmdRegex: `\Auptime\z`},
		Action: policy.ActionAllow,
	}}}
}

func sessionContext(id, host string) session.Context {
	return session.Context{ID: id, Host: host}
}

func grant(t *testing.T, f fixture, sessionID, host, command string, scope approval.Scope) {
	t.Helper()
	matcher, err := approval.Exact(command)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.env.Sessions.Grant(sessionID, host, scope, matcher, "", "ap_0123456789abcdef01234567", "req-grant", time.Hour, approval.ChannelCLI); err != nil {
		t.Fatal(err)
	}
}

func TestRunAllowedCommandExecutesAndAudits(t *testing.T) {
	f := newFixture(t, allowUptime(), true, "web-1")
	obs := &recordingObserver{}

	outcome, err := runner.Run(context.Background(), f.env, runner.Request{Target: hostTarget("web-1"), Command: "uptime", Session: "s_1", Observer: obs})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if outcome.ExitCode != runner.ExitOK {
		t.Fatalf("exit = %d, want 0", outcome.ExitCode)
	}
	got := outcome.Responses[0]
	if got.Status != "completed" || got.ExecutionState != "finished" || got.Stdout != "up 3 days\n" || got.PolicyRule != "rules:allow-uptime" {
		t.Fatalf("response = %+v", got)
	}
	if got.CmdSHA256 == "" || got.SessionID != "s_1" {
		t.Fatalf("response not finalized: %+v", got)
	}
	if ran := f.exec.ran(); len(ran) != 1 || ran[0] != "web-1" {
		t.Fatalf("executed hosts = %v", ran)
	}
	if events := f.events(t); len(events) != 2 || events[0] != audit.EventStarted || events[1] != audit.EventCompleted {
		t.Fatalf("audit events = %v", events)
	}
	if len(obs.finished) != 1 || obs.streamed[0] {
		t.Fatalf("observer finished = %v streamed = %v", obs.finished, obs.streamed)
	}
}

func TestRunExplicitDenyIsTerminal(t *testing.T) {
	cfg := policy.Config{Rules: []policy.Rule{{
		Name:   "deny-reboot",
		Match:  policy.Match{CmdRegex: `\Areboot\z`},
		Action: policy.ActionDeny,
	}}}
	f := newFixture(t, cfg, true, "web-1")
	obs := &recordingObserver{}

	outcome, err := runner.Run(context.Background(), f.env, runner.Request{Target: hostTarget("web-1"), Command: "reboot", Session: "s_1", Observer: obs})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if outcome.ExitCode != runner.ExitPolicyDenied {
		t.Fatalf("exit = %d, want 6", outcome.ExitCode)
	}
	got := outcome.Responses[0]
	if got.Status != "denied" || got.NextAction != "stop" || got.ApprovalID != "" || got.PolicyRule != "rules:deny-reboot" {
		t.Fatalf("response = %+v", got)
	}
	if ran := f.exec.ran(); len(ran) != 0 {
		t.Fatalf("denied command executed on %v", ran)
	}
	if events := f.events(t); len(events) != 1 || events[0] != audit.EventDenied {
		t.Fatalf("audit events = %v", events)
	}
	if len(obs.denied) != 1 || len(obs.pending) != 0 {
		t.Fatalf("observer denied = %v pending = %v", obs.denied, obs.pending)
	}
}

func TestRunGrayZoneCreatesPendingApproval(t *testing.T) {
	f := newFixture(t, policy.Config{}, true, "web-1")

	outcome, err := runner.Run(context.Background(), f.env, runner.Request{Target: hostTarget("web-1"), Command: "systemctl restart nginx", Session: "s_1"})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if outcome.ExitCode != runner.ExitApprovalRequired {
		t.Fatalf("exit = %d, want 7", outcome.ExitCode)
	}
	got := outcome.Responses[0]
	if got.Status != "approval_pending" || got.NextAction != "wait_for_approval" || got.ApprovalID == "" {
		t.Fatalf("response = %+v", got)
	}
	status, err := f.env.Pending.Status(got.ApprovalID)
	if err != nil {
		t.Fatalf("pending status: %v", err)
	}
	if status.Status != "pending" || status.Request == nil || status.Request.Cmd != "systemctl restart nginx" {
		t.Fatalf("pending request = %+v", status)
	}
	if ran := f.exec.ran(); len(ran) != 0 {
		t.Fatalf("gray-zone command executed on %v", ran)
	}
	if events := f.events(t); len(events) != 1 || events[0] != audit.EventApprovalRequested {
		t.Fatalf("audit events = %v", events)
	}
}

func TestRunGrayZoneWithApprovalsDisabledIsDenied(t *testing.T) {
	f := newFixture(t, policy.Config{}, false, "web-1")

	outcome, err := runner.Run(context.Background(), f.env, runner.Request{Target: hostTarget("web-1"), Command: "systemctl restart nginx", Session: "s_1"})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if outcome.ExitCode != runner.ExitPolicyDenied || outcome.Responses[0].Status != "denied" || outcome.Responses[0].ApprovalID != "" {
		t.Fatalf("outcome = %+v", outcome)
	}
}

func TestRunExecutesAfterSessionGrantOnlyInThatSession(t *testing.T) {
	f := newFixture(t, policy.Config{}, true, "web-1")
	grant(t, f, "s_1", "web-1", "systemctl restart nginx", approval.ScopeSession)

	outcome, err := runner.Run(context.Background(), f.env, runner.Request{Target: hostTarget("web-1"), Command: "systemctl restart nginx", Session: "s_1"})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if outcome.ExitCode != runner.ExitOK || outcome.Responses[0].Status != "completed" || outcome.Responses[0].GrantScope != "session" {
		t.Fatalf("granted outcome = %+v", outcome)
	}

	other, err := runner.Run(context.Background(), f.env, runner.Request{Target: hostTarget("web-1"), Command: "systemctl restart nginx", Session: "s_2"})
	if err != nil {
		t.Fatalf("Run other session: %v", err)
	}
	if other.ExitCode != runner.ExitApprovalRequired {
		t.Fatalf("other session exit = %d, want 7", other.ExitCode)
	}
	if ran := f.exec.ran(); len(ran) != 1 {
		t.Fatalf("executed %d times, want 1", len(ran))
	}
}

func TestRunGroupNeedingApprovalExecutesNoMember(t *testing.T) {
	f := newFixture(t, policy.Config{}, true, "web-1", "web-2")
	// Group runs bind the session per host; only web-1 is authorized.
	grant(t, f, "s_1@web-1", "web-1", "systemctl restart nginx", approval.ScopeSession)
	obs := &recordingObserver{}

	outcome, err := runner.Run(context.Background(), f.env, runner.Request{Target: groupTarget("web-1", "web-2"), Command: "systemctl restart nginx", Session: "s_1", Observer: obs})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if outcome.ExitCode != runner.ExitApprovalRequired {
		t.Fatalf("exit = %d, want 7", outcome.ExitCode)
	}
	if got := outcome.Responses[0]; got.Host != "web-1" || got.Status != "not_run" || got.ExecutionState != "not_started" {
		t.Fatalf("web-1 response = %+v", got)
	}
	if got := outcome.Responses[1]; got.Host != "web-2" || got.Status != "approval_pending" || got.SessionID != "s_1@web-2" {
		t.Fatalf("web-2 response = %+v", got)
	}
	if ran := f.exec.ran(); len(ran) != 0 {
		t.Fatalf("group partially executed on %v", ran)
	}
	if len(obs.notRun) != 1 || len(obs.pending) != 1 || len(obs.finished) != 0 {
		t.Fatalf("observer notRun = %v pending = %v finished = %v", obs.notRun, obs.pending, obs.finished)
	}
}

func TestRunOnceGrantIsConsumedOnceUnderConcurrentReruns(t *testing.T) {
	f := newFixture(t, policy.Config{}, true, "web-1")
	grant(t, f, "s_1", "web-1", "systemctl restart nginx", approval.ScopeOnce)

	const reruns = 8
	exits := make([]int, reruns)
	errs := make([]error, reruns)
	var wg sync.WaitGroup
	for i := 0; i < reruns; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			outcome, err := runner.Run(context.Background(), f.env, runner.Request{Target: hostTarget("web-1"), Command: "systemctl restart nginx", Session: "s_1"})
			exits[i], errs[i] = outcome.ExitCode, err
		}(i)
	}
	wg.Wait()

	succeeded := 0
	for i := range exits {
		if errs[i] != nil {
			t.Fatalf("rerun %d: %v", i, errs[i])
		}
		switch exits[i] {
		case runner.ExitOK:
			succeeded++
		case runner.ExitApprovalRequired:
		default:
			t.Fatalf("rerun %d exit = %d", i, exits[i])
		}
	}
	if succeeded != 1 {
		t.Fatalf("%d reruns executed under one once grant, want 1", succeeded)
	}
	if ran := f.exec.ran(); len(ran) != 1 {
		t.Fatalf("executor ran %d times, want 1", len(ran))
	}
}

func TestRunMapsRemoteAndTransportFailures(t *testing.T) {
	f := newFixture(t, allowUptime(), true, "web-1")

	f.exec.result = executor.Result{ExitCode: 3}
	outcome, err := runner.Run(context.Background(), f.env, runner.Request{Target: hostTarget("web-1"), Command: "uptime", Session: "s_1"})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if outcome.ExitCode != runner.ExitRemoteFailed || outcome.Responses[0].Status != "failed" || outcome.Responses[0].ExitCode != 3 {
		t.Fatalf("remote failure outcome = %+v", outcome)
	}

	f.exec.result = executor.Result{ExitCode: -1, Err: errors.New("dial tcp: connection refused")}
	outcome, err = runner.Run(context.Background(), f.env, runner.Request{Target: hostTarget("web-1"), Command: "uptime", Session: "s_1"})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	got := outcome.Responses[0]
	if outcome.ExitCode != runner.ExitSSHError || got.Status != "ssh_error" || got.ExecutionState != "unknown" || got.NextAction != "inspect_before_retry" {
		t.Fatalf("transport failure outcome = %+v", outcome)
	}
}

func TestRunReleasesOnceGrantAfterTransportFailure(t *testing.T) {
	f := newFixture(t, policy.Config{}, true, "web-1")
	grant(t, f, "s_1", "web-1", "systemctl restart nginx", approval.ScopeOnce)
	req := runner.Request{Target: hostTarget("web-1"), Command: "systemctl restart nginx", Session: "s_1"}

	f.exec.result = executor.Result{ExitCode: -1, Err: errors.New("dial tcp: connection refused")}
	if outcome, err := runner.Run(context.Background(), f.env, req); err != nil || outcome.ExitCode != runner.ExitSSHError {
		t.Fatalf("first run = %+v, %v", outcome, err)
	}
	f.exec.result = executor.Result{}
	if outcome, err := runner.Run(context.Background(), f.env, req); err != nil || outcome.ExitCode != runner.ExitOK {
		t.Fatalf("rerun after transport failure = %+v, %v; want the once grant restored", outcome, err)
	}
	if outcome, err := runner.Run(context.Background(), f.env, req); err != nil || outcome.ExitCode != runner.ExitApprovalRequired {
		t.Fatalf("third run = %+v, %v; want the once grant consumed", outcome, err)
	}
}

func TestRunStreamsRedactedOutputForSingleHost(t *testing.T) {
	cfg := allowUptime()
	cfg.Output.Redact = []string{`token=\S+`}
	f := newFixture(t, cfg, true, "web-1")
	stream := &streamingExecutor{fakeExecutor: fakeExecutor{result: executor.Result{Stdout: "token=abc123 ok\n"}}}
	f.env.Executor = stream
	var stdout, stderr bytes.Buffer
	var streamedFor []string
	obs := &recordingObserver{}

	outcome, err := runner.Run(context.Background(), f.env, runner.Request{
		Target:   hostTarget("web-1"),
		Command:  "uptime",
		Session:  "s_1",
		Observer: obs,
		Stream: func(host string, reqID string) (io.Writer, io.Writer) {
			streamedFor = append(streamedFor, host+"/"+reqID)
			return &stdout, &stderr
		},
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if stdout.String() != "«REDACTED» ok\n" {
		t.Fatalf("streamed stdout = %q", stdout.String())
	}
	got := outcome.Responses[0]
	if got.Stdout != stdout.String() || got.Redactions != 1 || len(streamedFor) != 1 || streamedFor[0] != "web-1/"+got.ReqID {
		t.Fatalf("response = %+v streamedFor = %v", got, streamedFor)
	}
	if len(obs.streamed) != 1 || !obs.streamed[0] {
		t.Fatalf("observer streamed = %v", obs.streamed)
	}
}

func TestRunWithoutSessionIsUsageError(t *testing.T) {
	t.Setenv("AGENTSSH_SESSION", "")
	f := newFixture(t, allowUptime(), true, "web-1")

	_, err := runner.Run(context.Background(), f.env, runner.Request{Target: hostTarget("web-1"), Command: "uptime"})
	var usage runner.UsageError
	if !errors.As(err, &usage) {
		t.Fatalf("err = %T %[1]v, want UsageError", err)
	}
	if len(f.exec.ran()) != 0 || len(f.events(t)) != 0 {
		t.Fatal("a run without a session had side effects")
	}
}

func TestMergeExitCodeKeepsMostConservativeOutcome(t *testing.T) {
	order := []int{runner.ExitPolicyDenied, runner.ExitApprovalRequired, runner.ExitSSHError, runner.ExitRemoteFailed, runner.ExitOK}
	for i, stronger := range order {
		for _, weaker := range order[i:] {
			if got := runner.MergeExitCode(weaker, stronger); got != stronger {
				t.Fatalf("MergeExitCode(%d, %d) = %d, want %d", weaker, stronger, got, stronger)
			}
			if got := runner.MergeExitCode(stronger, weaker); got != stronger {
				t.Fatalf("MergeExitCode(%d, %d) = %d, want %d", stronger, weaker, got, stronger)
			}
		}
	}
}

func TestSubmitPlanClassifiesCommandsAndSharesDuplicatePending(t *testing.T) {
	cfg := allowUptime()
	cfg.Rules = append(cfg.Rules, policy.Rule{Name: "deny-reboot", Match: policy.Match{CmdRegex: `\Areboot\z`}, Action: policy.ActionDeny})
	f := newFixture(t, cfg, true, "web-1")
	planID, err := approval.NewPlanID()
	if err != nil {
		t.Fatal(err)
	}

	response, exitCode, err := runner.SubmitPlan(f.env, runner.PlanSubmitRequest{
		PlanID:  planID,
		Host:    "web-1",
		Session: sessionContext("s_1", "web-1"),
		Commands: []runner.PlanCommand{
			{Cmd: "uptime"},
			{Cmd: "reboot"},
			{Cmd: "systemctl restart nginx"},
			{Cmd: "systemctl restart nginx"},
		},
	})
	if err != nil {
		t.Fatalf("SubmitPlan: %v", err)
	}
	if exitCode != runner.ExitPolicyDenied {
		t.Fatalf("exit = %d, want 6 (deny outranks pending)", exitCode)
	}
	if response.Allowed != 1 || response.Denied != 1 || response.Pending != 1 || response.PlanID != planID {
		t.Fatalf("response = %+v", response)
	}
	statuses := []string{response.Commands[0].Status, response.Commands[1].Status, response.Commands[2].Status, response.Commands[3].Status}
	want := []string{"allowed", "denied", "approval_pending", "approval_pending"}
	for i := range want {
		if statuses[i] != want[i] {
			t.Fatalf("statuses = %v, want %v", statuses, want)
		}
	}
	if response.Commands[2].ApprovalID != response.Commands[3].ApprovalID {
		t.Fatalf("duplicate lines got distinct approvals: %+v", response.Commands)
	}
	plan, err := f.env.Pending.PlanStatus(planID)
	if err != nil {
		t.Fatalf("PlanStatus: %v", err)
	}
	if plan.Status != "pending" {
		t.Fatalf("plan status = %+v", plan)
	}
	if ran := f.exec.ran(); len(ran) != 0 {
		t.Fatalf("plan submit executed on %v", ran)
	}
}
