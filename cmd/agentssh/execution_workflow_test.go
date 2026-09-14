package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/Praeviso/AgentSSH/internal/approval"
	"github.com/Praeviso/AgentSSH/internal/config"
	"github.com/Praeviso/AgentSSH/internal/executor"
	"github.com/Praeviso/AgentSSH/internal/payload"
)

func TestPlanResumeReusesPendingApprovalBatch(t *testing.T) {
	home := setupPlanHome(t)
	useWorkflowExecutor(t, func(context.Context, executor.Request) executor.Result {
		t.Fatal("pending plan executed without approval")
		return executor.Result{}
	})
	file := writeWorkflowPlan(t, "systemctl restart nginx\n")
	code, out, stderr := runExit(t, "plan", "run", "web-1", "--file", file, "--json")
	if code != exitApprovalRequired {
		t.Fatalf("run code=%d stdout=%s stderr=%s", code, out, stderr)
	}
	var first planExecution
	if err := json.Unmarshal([]byte(out), &first); err != nil {
		t.Fatal(err)
	}
	code, out, stderr = runExit(t, "plan", "resume", first.ID, "--json")
	if code != exitApprovalRequired {
		t.Fatalf("resume code=%d stdout=%s stderr=%s", code, out, stderr)
	}
	var second planExecution
	if err := json.Unmarshal([]byte(out), &second); err != nil {
		t.Fatal(err)
	}
	if second.ApprovalPlanID != first.ApprovalPlanID {
		t.Fatalf("resume created a duplicate plan: first=%s second=%s", first.ApprovalPlanID, second.ApprovalPlanID)
	}
	entries, err := os.ReadDir(config.NewPaths(home).PlansDir)
	if err != nil {
		t.Fatal(err)
	}
	plans := 0
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasPrefix(entry.Name(), "pl_") {
			plans++
		}
	}
	if plans != 1 {
		t.Fatalf("plan manifest count=%d want 1", plans)
	}
}

func TestPlanRunEventsJSONLMode(t *testing.T) {
	setupPlanHome(t)
	useWorkflowExecutor(t, func(context.Context, executor.Request) executor.Result {
		return executor.Result{Stdout: "ok\n"}
	})
	file := writeWorkflowPlan(t, "echo events\n")
	code, out, stderr := runExit(t, "plan", "run", "web-1", "--file", file, "--events")
	if code != 0 {
		t.Fatalf("code=%d stdout=%s stderr=%s", code, out, stderr)
	}
	var eventTypes []string
	scanner := bufio.NewScanner(strings.NewReader(out))
	for scanner.Scan() {
		var event executionEvent
		if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
			t.Fatalf("non-jsonl event %q: %v", scanner.Text(), err)
		}
		eventTypes = append(eventTypes, event.Type)
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(eventTypes, ",")
	for _, want := range []string{"step_started", "step_completed", "execution_completed"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("events %v missing %s", eventTypes, want)
		}
	}
	if strings.Contains(out, `"steps"`) {
		t.Fatalf("--events mixed final execution JSON into JSONL stream: %s", out)
	}
}

func TestPlanRunVerifyContinueCollectsFailures(t *testing.T) {
	setupPlanHome(t)
	var commands []string
	useWorkflowExecutor(t, func(_ context.Context, req executor.Request) executor.Result {
		commands = append(commands, req.Command)
		if strings.Contains(req.Command, "verify-fail") {
			return executor.Result{ExitCode: 3, Stderr: "bad\n"}
		}
		return executor.Result{Stdout: "ok\n"}
	})
	file := writeWorkflowPlan(t, `version: 1
commands:
  - id: apply
    cmd: echo apply
  - id: verify-a
    phase: verify
    on_failure: continue
    cmd: echo verify-fail
  - id: verify-b
    phase: verify
    cmd: echo verify-pass
`)
	code, out, stderr := runExit(t, "plan", "run", "web-1", "--file", file, "--json")
	if code != exitRemoteFailed {
		t.Fatalf("code=%d stdout=%s stderr=%s", code, out, stderr)
	}
	var run planExecution
	if err := json.Unmarshal([]byte(out), &run); err != nil {
		t.Fatal(err)
	}
	if len(commands) != 3 || run.Status != "failed" || run.Steps[1].Status != "failed_continued" || run.Steps[2].Status != "completed" {
		t.Fatalf("commands=%v run=%+v", commands, run)
	}
	if got := run.PhaseSummary["verify"].Failed; got != 1 {
		t.Fatalf("verify failures=%d want 1", got)
	}
}

func TestPlanRunSavedPayloadResumeWithoutOriginalPath(t *testing.T) {
	home := setupPlanHome(t)
	payloadPath := filepath.Join(t.TempDir(), "payload.txt")
	if err := os.WriteFile(payloadPath, []byte("original payload"), 0o600); err != nil {
		t.Fatal(err)
	}
	var got []byte
	useWorkflowExecutor(t, func(_ context.Context, req executor.Request) executor.Result {
		got = append([]byte(nil), req.Stdin...)
		return executor.Result{Stdout: "ok\n"}
	})
	file := writeWorkflowPlan(t, fmt.Sprintf(`version: 1
commands:
  - cmd: tee /opt/app/config
    stdin_file: %s
`, payloadPath))
	code, out, stderr := runExit(t, "plan", "run", "web-1", "--file", file, "--save-payloads", "--payload-ttl", "1h", "--json")
	if code != exitApprovalRequired {
		t.Fatalf("run code=%d stdout=%s stderr=%s", code, out, stderr)
	}
	var run planExecution
	if err := json.Unmarshal([]byte(out), &run); err != nil {
		t.Fatal(err)
	}
	if run.Steps[0].PayloadRef == "" || len(run.ActivePayloadRefs) != 1 {
		t.Fatalf("payload was not retained: %+v", run)
	}
	if err := os.Remove(payloadPath); err != nil {
		t.Fatal(err)
	}
	withOperatorAuth(t, home)
	if code, out, _ := runExit(t, "plan", "grant", run.ApprovalPlanID, "--session"); code != 0 {
		t.Fatalf("grant code=%d stdout=%s", code, out)
	}
	code, out, stderr = runExit(t, "plan", "resume", run.ID, "--json")
	if code != 0 || string(got) != "original payload" {
		t.Fatalf("resume code=%d stdin=%q stdout=%s stderr=%s", code, got, out, stderr)
	}
	var completed planExecution
	if err := json.Unmarshal([]byte(out), &completed); err != nil {
		t.Fatal(err)
	}
	if len(completed.ActivePayloadRefs) != 0 {
		t.Fatalf("terminal execution kept active payload pins: %+v", completed.ActivePayloadRefs)
	}
	if _, err := planPayloadStore(config.NewPaths(home)).List(); err != nil {
		t.Fatal(err)
	}
}

func TestPlanResumeApprovedButGrantRevokedBeforeFirstStepCreatesNewBatch(t *testing.T) {
	home := setupPlanHome(t)
	paths := config.NewPaths(home)
	calls := 0
	useWorkflowExecutor(t, func(context.Context, executor.Request) executor.Result {
		calls++
		return executor.Result{Stdout: "should not run"}
	})
	file := writeWorkflowPlan(t, "systemctl restart nginx\n")
	code, out, stderr := runExit(t, "plan", "run", "web-1", "--file", file, "--json")
	if code != exitApprovalRequired {
		t.Fatalf("initial run code=%d stdout=%s stderr=%s", code, out, stderr)
	}
	var first planExecution
	if err := json.Unmarshal([]byte(out), &first); err != nil {
		t.Fatal(err)
	}
	withOperatorAuth(t, home)
	if code, out, _ := runExit(t, "plan", "grant", first.ApprovalPlanID, "--session"); code != 0 {
		t.Fatalf("grant code=%d stdout=%s", code, out)
	}
	if err := (approval.SessionStore{Dir: paths.SessionsDir}).End(first.SessionID); err != nil {
		t.Fatal(err)
	}
	code, out, stderr = runExit(t, "plan", "resume", first.ID, "--json")
	if code != exitApprovalRequired {
		t.Fatalf("resume code=%d stdout=%s stderr=%s", code, out, stderr)
	}
	var second planExecution
	if err := json.Unmarshal([]byte(out), &second); err != nil {
		t.Fatal(err)
	}
	if calls != 0 {
		t.Fatalf("executed with revoked grant: calls=%d", calls)
	}
	if second.Status != "pending" || second.ApprovalPlanID == "" || second.ApprovalPlanID == first.ApprovalPlanID {
		t.Fatalf("expected fresh pending approval batch, first=%s second=%+v", first.ApprovalPlanID, second)
	}
	if second.NextAction == nil || !strings.Contains(second.NextAction.Reason, "pending") {
		t.Fatalf("next_action does not describe pending approval: %+v", second.NextAction)
	}
	wantArgv := []string{"agentssh", "plan", "wait", second.ApprovalPlanID, "--timeout", "30s", "--json"}
	if fmt.Sprint(second.NextAction.Argv) != fmt.Sprint(wantArgv) {
		t.Fatalf("next_action argv=%v want %v", second.NextAction.Argv, wantArgv)
	}
}

func TestPlanRunPrepareInputFailureUnpinsPayloadRefs(t *testing.T) {
	home := setupPlanHome(t)
	store := planPayloadStore(config.NewPaths(home))
	ref, err := store.Put([]byte("retained"), payload.PutOptions{RetainFor: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	missing := filepath.Join(t.TempDir(), "missing.txt")
	file := writeWorkflowPlan(t, fmt.Sprintf(`version: 1
commands:
  - id: retained
    cmd: tee /tmp/retained
    payload_ref: %s
  - id: missing
    cmd: tee /tmp/missing
    stdin_file: %s
`, ref.String(), missing))
	code, out, stderr := runExit(t, "plan", "run", "web-1", "--file", file, "--json")
	if code != exitUsage {
		t.Fatalf("run code=%d stdout=%s stderr=%s", code, out, stderr)
	}
	items, err := store.List()
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range items {
		if item.Ref.SHA256 == ref.SHA256 && len(item.Pins) != 0 {
			t.Fatalf("prepare failure leaked payload pins: %+v", item.Pins)
		}
	}
}

func TestExecutionHasLiveOwnerMissingLockDoesNotCreateFile(t *testing.T) {
	lockPath := filepath.Join(t.TempDir(), "missing.lock")
	if executionHasLiveOwner(lockPath) {
		t.Fatal("missing lock reported live owner")
	}
	if _, err := os.Stat(lockPath); !os.IsNotExist(err) {
		t.Fatalf("read-only liveness probe created lock file: %v", err)
	}
}

func TestExecutionFollowRefreshesStaleRunningAndExpiredSnapshots(t *testing.T) {
	t.Run("owner disappears", func(t *testing.T) {
		setupPlanHome(t)
		cfg, err := config.Load()
		if err != nil {
			t.Fatal(err)
		}
		id := "px_111111111111111111111111"
		path, err := executionPath(cfg, id)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		run := planExecution{Version: 1, ID: id, Host: "web-1", SessionID: "s_test", Status: "running", Steps: []planExecutionStep{{ID: "step-001", Cmd: "echo waiting", Status: "running"}}}
		if err := saveExecution(path, &run); err != nil {
			t.Fatal(err)
		}
		lockPath, err := executionLockPath(cfg, id)
		if err != nil {
			t.Fatal(err)
		}
		lock, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX); err != nil {
			t.Fatal(err)
		}
		done := make(chan struct{})
		go func() {
			time.Sleep(100 * time.Millisecond)
			_ = syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
			_ = lock.Close()
			close(done)
		}()
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		var out bytes.Buffer
		started := time.Now()
		if err := followExecutionEvents(ctx, &out, cfg, id, strings.TrimSuffix(path, ".json")+".events.jsonl", path, lockPath, 0); err != nil {
			t.Fatal(err)
		}
		<-done
		if time.Since(started) > 900*time.Millisecond {
			t.Fatalf("follow waited for timeout instead of owner disappearance; output=%s", out.String())
		}
		if !strings.Contains(out.String(), `"status":"unknown"`) || !strings.Contains(out.String(), "no active owner") {
			t.Fatalf("follow did not emit stale-owner snapshot: %s", out.String())
		}
		persisted, err := readExecution(path, id)
		if err != nil {
			t.Fatal(err)
		}
		if persisted.Status != "running" {
			t.Fatalf("follow mutated snapshot status to %q", persisted.Status)
		}
	})

	t.Run("pending denial terminates", func(t *testing.T) {
		home := setupPlanHome(t)
		useWorkflowExecutor(t, func(context.Context, executor.Request) executor.Result {
			t.Fatal("pending execution should not run")
			return executor.Result{}
		})
		file := writeWorkflowPlan(t, "systemctl restart nginx\n")
		code, stdout, stderr := runExit(t, "plan", "run", "web-1", "--file", file, "--json")
		if code != exitApprovalRequired {
			t.Fatalf("run code=%d stdout=%s stderr=%s", code, stdout, stderr)
		}
		var run planExecution
		if err := json.Unmarshal([]byte(stdout), &run); err != nil {
			t.Fatal(err)
		}
		withOperatorAuth(t, home)
		if code, stdout, stderr := runExit(t, "plan", "deny", run.ApprovalPlanID); code != 0 {
			t.Fatalf("deny code=%d stdout=%s stderr=%s", code, stdout, stderr)
		}
		cfg, err := config.Load()
		if err != nil {
			t.Fatal(err)
		}
		path, err := executionPath(cfg, run.ID)
		if err != nil {
			t.Fatal(err)
		}
		lockPath, err := executionLockPath(cfg, run.ID)
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		var out bytes.Buffer
		started := time.Now()
		if err := followExecutionEvents(ctx, &out, cfg, run.ID, strings.TrimSuffix(path, ".json")+".events.jsonl", path, lockPath, 0); err != nil {
			t.Fatal(err)
		}
		if time.Since(started) > 500*time.Millisecond {
			t.Fatalf("denied follow waited for timeout; output=%s", out.String())
		}
		if !strings.Contains(out.String(), `"status":"denied"`) {
			t.Fatalf("follow did not emit denied snapshot: %s", out.String())
		}
	})

	t.Run("expired terminates", func(t *testing.T) {
		setupPlanHome(t)
		cfg, err := config.Load()
		if err != nil {
			t.Fatal(err)
		}
		id := "px_222222222222222222222222"
		path, err := executionPath(cfg, id)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		run := planExecution{Version: 1, ID: id, Host: "web-1", SessionID: "s_test", Status: "expired", Steps: []planExecutionStep{{ID: "step-001", Cmd: "systemctl restart nginx", Status: "not_started"}}}
		if err := saveExecution(path, &run); err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		var out bytes.Buffer
		started := time.Now()
		if err := followExecutionEvents(ctx, &out, cfg, id, strings.TrimSuffix(path, ".json")+".events.jsonl", path, path+".lock", 0); err != nil {
			t.Fatal(err)
		}
		if time.Since(started) > 500*time.Millisecond {
			t.Fatalf("expired follow waited for timeout; output=%s", out.String())
		}
		if !strings.Contains(out.String(), `"status":"expired"`) {
			t.Fatalf("follow did not emit expired snapshot: %s", out.String())
		}
	})
}

func TestPlanExecutionStatusJSONFlagCompatibility(t *testing.T) {
	setupPlanHome(t)
	cfg, err := config.Load()
	if err != nil {
		t.Fatal(err)
	}
	id := "px_333333333333333333333333"
	path, err := executionPath(cfg, id)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	run := planExecution{Version: 1, ID: id, Host: "web-1", SessionID: "s_test", Status: "completed", Steps: []planExecutionStep{{ID: "step-001", Cmd: "echo ok", Status: "completed"}}}
	if err := saveExecution(path, &run); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"plan", "execution", id}, {"plan", "execution", id, "--json"}} {
		code, stdout, stderr := runExit(t, args...)
		if code != exitOK {
			t.Fatalf("%v code=%d stdout=%s stderr=%s", args, code, stdout, stderr)
		}
		var got planExecution
		if err := json.Unmarshal([]byte(stdout), &got); err != nil {
			t.Fatalf("%v did not emit JSON: %v stdout=%s", args, err, stdout)
		}
		if got.ID != id || got.Status != "completed" {
			t.Fatalf("%v got execution=%+v", args, got)
		}
	}
	code, stdout, stderr := runExit(t, "plan", "execution", id, "--follow", "--json", "--timeout", "30ms")
	if code != exitUsage {
		t.Fatalf("follow+json code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
}
