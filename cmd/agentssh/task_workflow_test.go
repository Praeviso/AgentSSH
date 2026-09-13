package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Praeviso/AgentSSH/internal/approval"
	"github.com/Praeviso/AgentSSH/internal/audit"
	"github.com/Praeviso/AgentSSH/internal/config"
	"github.com/Praeviso/AgentSSH/internal/executor"
	"github.com/Praeviso/AgentSSH/internal/policy"
)

type workflowExecutor struct {
	run func(context.Context, executor.Request) executor.Result
}

func (e workflowExecutor) Run(ctx context.Context, req executor.Request) executor.Result {
	return e.run(ctx, req)
}
func (e workflowExecutor) Close() error { return nil }
func useWorkflowExecutor(t *testing.T, run func(context.Context, executor.Request) executor.Result) {
	t.Helper()
	original := newExecutor
	newExecutor = func(*config.Config) executor.Executor { return workflowExecutor{run: run} }
	t.Cleanup(func() { newExecutor = original })
}

func approveNextRequest(t *testing.T, home string, scope approval.Scope, verdict approval.Verdict, before func() error) <-chan error {
	t.Helper()
	done := make(chan error, 1)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	go func() {
		paths := config.NewPaths(home)
		store := approvalStore(paths)
		for {
			requests, err := store.List()
			if err != nil {
				done <- err
				return
			}
			if len(requests) > 0 {
				if before != nil {
					if err := before(); err != nil {
						done <- err
						return
					}
				}
				_, err := approval.ApplyDecision(approval.ApplyOptions{Pending: store, Sessions: approval.SessionStore{Dir: paths.SessionsDir}, Audit: audit.NewStore(paths.AuditFile), TaskTTL: time.Hour}, requests[0].ID, verdict, scope)
				done <- err
				return
			}
			select {
			case <-ctx.Done():
				done <- ctx.Err()
				return
			case <-time.After(5 * time.Millisecond):
			}
		}
	}()
	return done
}

func TestRunWaitRetainsApprovedPayload(t *testing.T) {
	home := setupPlanHome(t)
	payload := writeStdinFile(t, "original bytes")
	var got []byte
	calls := 0
	useWorkflowExecutor(t, func(_ context.Context, req executor.Request) executor.Result {
		calls++
		got = append([]byte(nil), req.Stdin...)
		return executor.Result{Stdout: "done"}
	})
	done := approveNextRequest(t, home, approval.ScopeOnce, approval.VerdictApproved, func() error { return os.WriteFile(payload, []byte("changed while waiting"), 0600) })
	code, out, stderr := runExit(t, "run", "web-1", "--json", "--wait-approval", "2s", "--stdin-file", payload, "--", "tee /opt/app/config")
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if code != 0 || calls != 1 || string(got) != "original bytes" {
		t.Fatalf("code=%d calls=%d payload=%q out=%s stderr=%s", code, calls, got, out, stderr)
	}
	var result runResponse
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("not a single JSON document: %v %s", err, out)
	}
	if result.ExecutionState != "finished" || result.Status != "completed" {
		t.Fatalf("result %+v", result)
	}
	verified, err := audit.NewStore(config.NewPaths(home).AuditFile).Verify()
	if err != nil || !verified.OK {
		t.Fatal(verified, err)
	}
}

func TestRunWaitDeniedOrTimedOutDoesNotExecute(t *testing.T) {
	for _, denied := range []bool{true, false} {
		t.Run(fmt.Sprint(denied), func(t *testing.T) {
			home := setupPlanHome(t)
			calls := 0
			useWorkflowExecutor(t, func(context.Context, executor.Request) executor.Result { calls++; return executor.Result{} })
			var done <-chan error
			wait := "30ms"
			if denied {
				wait = "2s"
				done = approveNextRequest(t, home, "", approval.VerdictDenied, nil)
			}
			code, out, _ := runExit(t, "run", "web-1", "--json", "--wait-approval", wait, "--", "systemctl restart nginx")
			if done != nil {
				if err := <-done; err != nil {
					t.Fatal(err)
				}
			}
			want := exitApprovalRequired
			if denied {
				want = exitPolicyDenied
			}
			if code != want || calls != 0 {
				t.Fatalf("code=%d calls=%d out=%s", code, calls, out)
			}
			var result runResponse
			if err := json.Unmarshal([]byte(out), &result); err != nil {
				t.Fatal(err)
			}
			if result.ExecutionState != "not_started" {
				t.Fatal(result)
			}
		})
	}
}

func TestRunWaitRechecksPolicyAfterApproval(t *testing.T) {
	home := setupPlanHome(t)
	calls := 0
	useWorkflowExecutor(t, func(context.Context, executor.Request) executor.Result { calls++; return executor.Result{} })
	done := approveNextRequest(t, home, approval.ScopeSession, approval.VerdictApproved, func() error {
		cfg, err := policy.Load(config.NewPaths(home).PolicyFile)
		if err != nil {
			return err
		}
		cfg.Rules = append(cfg.Rules, policy.Rule{Name: "new-deny", Priority: 200, Match: policy.Match{CmdRegex: "systemctl restart"}, Action: policy.ActionDeny})
		return policy.Save(config.NewPaths(home).PolicyFile, cfg)
	})
	code, out, _ := runExit(t, "run", "web-1", "--json", "--wait-approval", "2s", "--", "systemctl restart nginx")
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if code != exitPolicyDenied || calls != 0 {
		t.Fatalf("code=%d calls=%d out=%s", code, calls, out)
	}
}

func TestRunWaitDoesNotReplayPartiallyExecutedGroup(t *testing.T) {
	home := setupPlanHome(t)
	store := approval.SessionStore{Dir: config.NewPaths(home).SessionsDir}
	matcher, err := approval.Exact("systemctl restart nginx")
	if err != nil {
		t.Fatal(err)
	}
	for _, host := range []string{"web-1", "web-2"} {
		if _, err := store.Grant("s_test@"+host, host, approval.ScopeSession, matcher, "", "initial-"+host, "r", time.Hour, approval.ChannelCLI); err != nil {
			t.Fatal(err)
		}
	}
	var hosts []string
	useWorkflowExecutor(t, func(_ context.Context, req executor.Request) executor.Result {
		hosts = append(hosts, req.Target.Name)
		if len(hosts) == 1 {
			if err := store.End("s_test@web-2"); err != nil {
				t.Error(err)
			}
		}
		return executor.Result{}
	})
	done := approveNextRequest(t, home, approval.ScopeSession, approval.VerdictApproved, nil)
	code, out, stderr := runExit(t, "run", "web", "--json", "--wait-approval", "2s", "--", "systemctl restart nginx")
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if code != exitApprovalRequired || len(hosts) != 1 || hosts[0] != "web-1" {
		t.Fatalf("group replayed: code=%d hosts=%v stdout=%s stderr=%s", code, hosts, out, stderr)
	}
	var rows []runResponse
	if err := json.Unmarshal([]byte(out), &rows); err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 || rows[0].Status != "completed" || rows[1].NextAction != "retry_unstarted_targets" {
		t.Fatalf("missing targeted continuation: %+v", rows)
	}
}

func TestTaskApprovalCLIAndPreflight(t *testing.T) {
	home := setupPlanHome(t)
	withFakeExecutor(t, fakeExecutor{})
	_, out, _ := runExit(t, "run", "web-1", "--json", "--", "systemctl restart nginx")
	var pending runResponse
	if err := json.Unmarshal([]byte(out), &pending); err != nil {
		t.Fatal(err)
	}
	if pending.Task == nil {
		t.Fatal("missing permission preview")
	}
	withOperatorAuth(t, home)
	if code, out, errOut := runExit(t, "approval", "grant", pending.ApprovalID, "--task"); code != 0 {
		t.Fatalf("grant %d %s %s", code, out, errOut)
	}
	_, out, _ = runExit(t, "policy", "test", "--host", "web-1", "--session", "s_test", "--json", "--", "systemctl status nginx", "systemctl reload redis")
	var preflight policyTestResponse
	if err := json.Unmarshal([]byte(out), &preflight); err != nil {
		t.Fatal(err)
	}
	if preflight.Allow != 1 || preflight.NeedsApproval != 1 || preflight.Commands[0].GrantScope != "task" || preflight.Commands[0].GrantExpiresTS == "" {
		t.Fatalf("preflight %+v", preflight)
	}
	if preflight.Commands[0].Task == nil || preflight.Commands[0].Task.Profile != "service-maintenance" {
		t.Fatalf("preflight did not report the existing grant's full scope: %+v", preflight)
	}
	if code, out, errOut := runExit(t, "run", "web-1", "--json", "--", "systemctl reload nginx"); code != 0 {
		t.Fatalf("run %d %s %s", code, out, errOut)
	}
	if code, out, _ := runExit(t, "session", "grants", "s_test"); code != 0 || !strings.Contains(out, "service-maintenance") {
		t.Fatal(code, out)
	}
}

func TestPreflightStdinMatchesRuntimeWithoutConsumingOnce(t *testing.T) {
	home := setupPlanHome(t)
	payload := writeStdinFile(t, "original")
	_, out, _ := runExit(t, "run", "web-1", "--json", "--stdin-file", payload, "--", "tee /opt/app/config")
	var pending runResponse
	if err := json.Unmarshal([]byte(out), &pending); err != nil {
		t.Fatal(err)
	}
	paths := config.NewPaths(home)
	if _, err := approval.ApplyDecision(approval.ApplyOptions{Pending: approvalStore(paths), Sessions: approval.SessionStore{Dir: paths.SessionsDir}, Audit: audit.NewStore(paths.AuditFile)}, pending.ApprovalID, approval.VerdictApproved, approval.ScopeOnce); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		code, out, stderr := runExit(t, "policy", "test", "--host", "web-1", "--stdin-file", payload, "--json", "--", "tee /opt/app/config")
		var preflight policyTestResponse
		if err := json.Unmarshal([]byte(out), &preflight); err != nil {
			t.Fatalf("%v %s %s", err, out, stderr)
		}
		if code != 0 || preflight.Allow != 1 {
			t.Fatal(code, out, stderr)
		}
	}
	var captured [][]byte
	withCaptureExecutor(t, &captured)
	if code, out, _ := runExit(t, "run", "web-1", "--json", "--stdin-file", payload, "--", "tee /opt/app/config"); code != 0 || len(captured) != 1 {
		t.Fatal(code, out, captured)
	}
	if err := os.WriteFile(payload, []byte("changed"), 0600); err != nil {
		t.Fatal(err)
	}
	_, out, _ = runExit(t, "policy", "test", "--host", "web-1", "--stdin-file", payload, "--json", "--", "tee /opt/app/config")
	var preflight policyTestResponse
	_ = json.Unmarshal([]byte(out), &preflight)
	if preflight.NeedsApproval != 1 {
		t.Fatal(out)
	}
}

func writeWorkflowPlan(t *testing.T, content string) string {
	t.Helper()
	file := filepath.Join(t.TempDir(), "plan.yaml")
	if err := os.WriteFile(file, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	return file
}

func TestPlanRunApprovalResumeAndCompletedSteps(t *testing.T) {
	home := setupPlanHome(t)
	var commands []string
	useWorkflowExecutor(t, func(_ context.Context, req executor.Request) executor.Result {
		commands = append(commands, req.Command)
		return executor.Result{Stdout: "ok"}
	})
	file := writeWorkflowPlan(t, "echo first\nsystemctl restart nginx\necho last\n")
	code, out, stderr := runExit(t, "plan", "run", "web-1", "--file", file, "--json")
	var run planExecution
	if err := json.Unmarshal([]byte(out), &run); err != nil {
		t.Fatalf("%v %s %s", err, out, stderr)
	}
	if code != exitApprovalRequired || len(commands) != 0 || run.Status != "pending" {
		t.Fatal(code, commands, out)
	}
	// The source plan is no longer consulted when resuming.
	if err := os.WriteFile(file, []byte("echo changed\n"), 0600); err != nil {
		t.Fatal(err)
	}
	withOperatorAuth(t, home)
	if code, out, _ := runExit(t, "plan", "grant", run.ApprovalPlanID, "--task"); code != 0 {
		t.Fatal(code, out)
	}
	code, out, stderr = runExit(t, "plan", "resume", run.ID, "--json")
	if code != 0 || len(commands) != 3 || commands[0] != "echo first" || commands[2] != "echo last" {
		t.Fatal(code, commands, out, stderr)
	}
	if code, out, _ := runExit(t, "plan", "resume", run.ID, "--json"); code != 0 || len(commands) != 3 {
		t.Fatal("completed plan repeated", code, commands, out)
	}
	verified, err := audit.NewStore(config.NewPaths(home).AuditFile).Verify()
	if err != nil || !verified.OK {
		t.Fatal(verified, err)
	}
}

func TestPlanRunStopsAndRefusesUnknownOrFailedReplay(t *testing.T) {
	for _, unknown := range []bool{true, false} {
		t.Run(fmt.Sprint(unknown), func(t *testing.T) {
			setupPlanHome(t)
			calls := 0
			useWorkflowExecutor(t, func(context.Context, executor.Request) executor.Result {
				calls++
				if unknown {
					return executor.Result{Err: errors.New("connection lost")}
				}
				return executor.Result{ExitCode: 5}
			})
			file := writeWorkflowPlan(t, "echo first\necho should-not-run\n")
			code, out, stderr := runExit(t, "plan", "run", "web-1", "--file", file, "--json")
			var run planExecution
			if err := json.Unmarshal([]byte(out), &run); err != nil {
				t.Fatalf("%v %s %s", err, out, stderr)
			}
			want := "failed"
			if unknown {
				want = "unknown"
			}
			if code == 0 || calls != 1 || run.Status != want {
				t.Fatal(code, calls, out, stderr)
			}
			if code, out, _ := runExit(t, "plan", "resume", run.ID, "--json"); code != exitUsage || calls != 1 {
				t.Fatal("unsafe replay", code, calls, out)
			}
		})
	}
}

func TestPlanResumeAfterRevocationDoesNotRepeatCompletedStep(t *testing.T) {
	home := setupPlanHome(t)
	paths := config.NewPaths(home)
	var commands []string
	useWorkflowExecutor(t, func(_ context.Context, req executor.Request) executor.Result {
		commands = append(commands, req.Command)
		if len(commands) == 1 {
			if err := (approval.SessionStore{Dir: paths.SessionsDir}).End("s_test"); err != nil {
				t.Error(err)
			}
		}
		return executor.Result{}
	})
	file := writeWorkflowPlan(t, "echo first\nsystemctl restart nginx\necho last\n")
	_, out, _ := runExit(t, "plan", "run", "web-1", "--file", file, "--json")
	var run planExecution
	_ = json.Unmarshal([]byte(out), &run)
	withOperatorAuth(t, home)
	if code, out, _ := runExit(t, "plan", "grant", run.ApprovalPlanID, "--session"); code != 0 {
		t.Fatal(code, out)
	}
	code, out, stderr := runExit(t, "plan", "resume", run.ID, "--json")
	if code != exitApprovalRequired || len(commands) != 1 {
		t.Fatal(code, commands, out, stderr)
	}
	// Resubmission groups the remaining request; no remote operation repeats.
	code, out, _ = runExit(t, "plan", "resume", run.ID, "--json")
	_ = json.Unmarshal([]byte(out), &run)
	if code != exitApprovalRequired || len(commands) != 1 {
		t.Fatal(code, commands, out)
	}
	if code, out, _ := runExit(t, "plan", "grant", run.ApprovalPlanID, "--session"); code != 0 {
		t.Fatal(code, out)
	}
	if code, out, _ := runExit(t, "plan", "resume", run.ID, "--json"); code != 0 || len(commands) != 3 {
		t.Fatal(code, commands, out)
	}
}

func TestPlanResumeRejectsChangedStdin(t *testing.T) {
	home := setupPlanHome(t)
	payload := writeStdinFile(t, "original")
	calls := 0
	useWorkflowExecutor(t, func(context.Context, executor.Request) executor.Result { calls++; return executor.Result{} })
	file := writeWorkflowPlan(t, fmt.Sprintf("version: 1\ncommands:\n  - cmd: tee /opt/app/config\n    stdin_file: %s\n", payload))
	_, out, _ := runExit(t, "plan", "run", "web-1", "--file", file, "--json")
	var run planExecution
	_ = json.Unmarshal([]byte(out), &run)
	withOperatorAuth(t, home)
	if code, out, _ := runExit(t, "plan", "grant", run.ApprovalPlanID, "--once"); code != 0 {
		t.Fatal(code, out)
	}
	if err := os.WriteFile(payload, []byte("changed"), 0600); err != nil {
		t.Fatal(err)
	}
	if code, out, _ := runExit(t, "plan", "resume", run.ID, "--json"); code != exitUsage || calls != 0 {
		t.Fatal(code, calls, out)
	}
}

func TestRunArgvAndPlanCWDShareExactCommand(t *testing.T) {
	home := setupPlanHome(t)
	var commands []string
	useWorkflowExecutor(t, func(_ context.Context, req executor.Request) executor.Result {
		commands = append(commands, req.Command)
		return executor.Result{}
	})
	file := writeWorkflowPlan(t, "version: 1\ncommands:\n  - argv: [printf, '%s', 'hello world']\n    cwd: /opt/my app\n")
	_, out, _ := runExit(t, "plan", "submit", "web-1", "--file", file, "--json")
	var plan planSubmitResponse
	if err := json.Unmarshal([]byte(out), &plan); err != nil {
		t.Fatal(err, out)
	}
	withOperatorAuth(t, home)
	if code, out, _ := runExit(t, "plan", "grant", plan.PlanID, "--once"); code != 0 {
		t.Fatal(code, out)
	}
	if code, out, stderr := runExit(t, "run", "web-1", "--argv", "--cwd", "/opt/my app", "--json", "--", "printf", "%s", "hello world"); code != 0 || len(commands) != 1 || commands[0] != plan.Commands[0].Cmd {
		t.Fatal(code, commands, out, stderr)
	}
}

func TestPlanRunWaitsAndExecutesAfterApproval(t *testing.T) {
	home := setupPlanHome(t)
	calls := 0
	useWorkflowExecutor(t, func(context.Context, executor.Request) executor.Result { calls++; return executor.Result{} })
	done := approveNextRequest(t, home, approval.ScopeTask, approval.VerdictApproved, nil)
	file := writeWorkflowPlan(t, "systemctl restart nginx\n")
	code, out, stderr := runExit(t, "plan", "run", "web-1", "--file", file, "--wait-approval", "2s", "--json")
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	var run planExecution
	if err := json.Unmarshal([]byte(out), &run); err != nil {
		t.Fatal(err, out)
	}
	if code != 0 || calls != 1 || run.Status != "completed" {
		t.Fatal(code, calls, out, stderr)
	}
}

func TestPlanRunAllowedCommandsWithoutApprovalChannel(t *testing.T) {
	home := setupPlanHome(t)
	cfg := readPolicyFile(t, home)
	cfg.Approval.Enabled = false
	if err := policy.Save(config.NewPaths(home).PolicyFile, cfg); err != nil {
		t.Fatal(err)
	}
	calls := 0
	useWorkflowExecutor(t, func(context.Context, executor.Request) executor.Result { calls++; return executor.Result{} })
	file := writeWorkflowPlan(t, "echo first\necho second\n")
	if code, out, stderr := runExit(t, "plan", "run", "web-1", "--file", file, "--json"); code != 0 || calls != 2 {
		t.Fatal(code, calls, out, stderr)
	}
	file = writeWorkflowPlan(t, "echo should-not-run\nsystemctl restart nginx\n")
	if code, out, stderr := runExit(t, "plan", "run", "web-1", "--file", file, "--json"); code != exitPolicyDenied || calls != 2 {
		t.Fatal(code, calls, out, stderr)
	}
}

func TestPlanResumeConcurrentExecutionIsRejected(t *testing.T) {
	home := setupPlanHome(t)
	started := make(chan struct{})
	release := make(chan struct{})
	var calls atomic.Int32
	useWorkflowExecutor(t, func(context.Context, executor.Request) executor.Result {
		calls.Add(1)
		close(started)
		<-release
		return executor.Result{}
	})
	file := writeWorkflowPlan(t, "systemctl restart nginx\n")
	_, out, _ := runExit(t, "plan", "run", "web-1", "--file", file, "--json")
	var run planExecution
	if err := json.Unmarshal([]byte(out), &run); err != nil {
		t.Fatal(err, out)
	}
	paths := config.NewPaths(home)
	if _, err := approval.ApplyPlanDecision(approval.ApplyOptions{Pending: approvalStore(paths), Sessions: approval.SessionStore{Dir: paths.SessionsDir}, Audit: audit.NewStore(paths.AuditFile)}, run.ApprovalPlanID, approval.VerdictApproved, approval.ScopeSession); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { _, _, err := runCommandForTest(t, "plan", "resume", run.ID, "--json"); done <- err }()
	select {
	case <-started:
	case <-time.After(3 * time.Second):
		close(release)
		t.Fatal("execution did not start")
	}
	_, _, concurrentErr := runCommandForTest(t, "plan", "resume", run.ID, "--json")
	code := exitCodeForError(concurrentErr)
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if code != exitUsage || calls.Load() != 1 || (concurrentErr == nil || !strings.Contains(concurrentErr.Error(), "already running")) {
		t.Fatal(code, calls.Load(), concurrentErr)
	}
}

func TestStructuredPlanRejectsMisspelledExecutionContext(t *testing.T) {
	home := setupPlanHome(t)
	file := writeWorkflowPlan(t, "version: 1\ncommands:\n  - cmd: systemctl restart nginx\n    cwdd: /opt/app\n")
	_, _, err := runCommandForTest(t, "plan", "submit", "web-1", "--file", file, "--json")
	if exitCodeForError(err) != exitUsage || !strings.Contains(err.Error(), "cwdd") {
		t.Fatal(err)
	}
	requests, err := approvalStore(config.NewPaths(home)).List()
	if err != nil || len(requests) != 0 {
		t.Fatal(requests, err)
	}
}
