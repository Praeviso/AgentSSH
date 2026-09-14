package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/Praeviso/AgentSSH/internal/approval"
	"github.com/Praeviso/AgentSSH/internal/config"
	"github.com/Praeviso/AgentSSH/internal/fileutil"
	"github.com/Praeviso/AgentSSH/internal/inventory"
	"github.com/Praeviso/AgentSSH/internal/session"
	"github.com/spf13/cobra"
)

type planExecution struct {
	Version           int                              `json:"version"`
	ID                string                           `json:"execution_id"`
	Host              string                           `json:"host"`
	SessionID         string                           `json:"session_id"`
	Label             string                           `json:"label,omitempty"`
	Metadata          approval.PlanMetadata            `json:"metadata,omitempty"`
	ReviewSHA256      string                           `json:"review_sha256,omitempty"`
	ApprovalPlanID    string                           `json:"approval_plan_id,omitempty"`
	ApprovalRounds    []executionApprovalRound         `json:"approval_rounds,omitempty"`
	Status            string                           `json:"status"`
	NextAction        *executionNextAction             `json:"next_action,omitempty"`
	PhaseSummary      map[string]executionPhaseSummary `json:"phase_summary,omitempty"`
	ActivePayloadRefs []payloadRefJSON                 `json:"active_payload_refs,omitempty"`
	Steps             []planExecutionStep              `json:"steps"`
}

type planExecutionStep struct {
	ID          string       `json:"id,omitempty"`
	Name        string       `json:"name,omitempty"`
	Phase       string       `json:"phase,omitempty"`
	OnFailure   string       `json:"on_failure,omitempty"`
	Cmd         string       `json:"cmd"`
	StdinFile   string       `json:"stdin_file,omitempty"`
	PayloadRef  string       `json:"payload_ref,omitempty"`
	StdinSHA256 string       `json:"stdin_sha256,omitempty"`
	StdinBytes  int64        `json:"stdin_bytes,omitempty"`
	Status      string       `json:"status"`
	Result      *runResponse `json:"result,omitempty"`
}

func newPlanRunCommand() *cobra.Command {
	var file, sessionID, label, wait string
	var jsonOutput, events, savePayloads bool
	var payloadTTL string
	cmd := &cobra.Command{Use: "run <host> --file <path> [--session <id>] [--wait-approval 30s] [--json]", Short: "Submit and execute a saved plan sequentially, stopping on failure.", Args: exactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		if file == "" {
			return newUsageError("plan run requires --file")
		}
		if err := validateApprovalWait(wait); err != nil {
			return err
		}
		if jsonOutput && events {
			return newUsageError("--events cannot be combined with --json")
		}
		ttl, err := validatePayloadTTL(payloadTTL)
		if err != nil {
			return err
		}
		cfg, err := config.Load()
		if err != nil {
			return classifyConfigError(err)
		}
		resolved, err := inventory.NewResolver(cfg.Inventory).Resolve(args[0])
		if err != nil {
			return newUsageError("%v", err)
		}
		if resolved.Kind != inventory.TargetKindHost {
			return newUsageError("plan run requires a single host")
		}
		host := resolved.Targets[0].Name
		sessionCtx, err := (session.Resolver{}).Resolve(host, sessionID, label)
		if err != nil {
			return newUsageError("%v", err)
		}
		spec, err := readPlanDocument(file)
		if err != nil {
			return err
		}
		commands := spec.Commands
		if len(commands) == 0 {
			return newUsageError("plan is empty")
		}
		id, err := approval.NewPlanID()
		if err != nil {
			return err
		}
		id = "px_" + strings.TrimPrefix(id, "pl_")
		activeRefs, err := prepareExecutionPlanInputs(cfg, commands, savePayloads, ttl, id)
		if err != nil {
			return err
		}
		inputsHandedOff := false
		defer func() {
			if inputsHandedOff || len(activeRefs) == 0 {
				return
			}
			_ = releaseExecutionPayloadPins(cfg, &planExecution{ID: id, ActivePayloadRefs: activeRefs})
		}()
		run := planExecution{Version: 1, ID: id, Host: host, SessionID: sessionCtx.ID, Label: label, Metadata: spec.Metadata, Status: "ready"}
		run.ActivePayloadRefs = activeRefs
		for _, command := range commands {
			stdinFile := command.StdinFile
			if stdinFile != "" {
				stdinFile, err = filepath.Abs(stdinFile)
				if err != nil {
					return err
				}
			}
			run.Steps = append(run.Steps, planExecutionStep{
				ID: command.ID, Name: command.Name, Phase: command.Phase, OnFailure: command.OnFailure,
				Cmd: command.Cmd, StdinFile: stdinFile, PayloadRef: command.PayloadRef, StdinSHA256: command.stdin.sha256, StdinBytes: command.stdin.bytes, Status: "not_started",
			})
		}
		run.ReviewSHA256 = approval.PlanReviewDigest(executionPlanReview(&run))
		inputsHandedOff = true
		return executeSavedPlan(cmd, cfg, &run, executionRunOptions{wait: wait, jsonOutput: jsonOutput, events: events}, true)
	}}
	cmd.Flags().StringVar(&file, "file", "", "legacy or structured plan file")
	cmd.Flags().StringVar(&sessionID, "session", "", "one session for this task")
	cmd.Flags().StringVar(&label, "session-label", "", "human-readable task label")
	cmd.Flags().StringVar(&wait, "wait-approval", "", "maximum approval wait, e.g. 30s; otherwise return pending")
	cmd.Flags().BoolVar(&jsonOutput, "json", false, "emit one structured execution result")
	cmd.Flags().BoolVar(&events, "events", false, "emit durable execution events as JSONL on stdout")
	cmd.Flags().BoolVar(&savePayloads, "save-payloads", false, "snapshot stdin_file payloads so resume does not require the original path")
	cmd.Flags().StringVar(&payloadTTL, "payload-ttl", "", "payload retention hint for saved stdin snapshots, e.g. 24h")
	return cmd
}

func newPlanResumeCommand() *cobra.Command {
	var wait string
	var jsonOutput, events bool
	cmd := &cobra.Command{Use: "resume <execution_id> [--wait-approval 30s] [--json]", Short: "Continue only steps that have not started, using the original snapshot.", Args: exactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		if err := validateApprovalWait(wait); err != nil {
			return err
		}
		if jsonOutput && events {
			return newUsageError("--events cannot be combined with --json")
		}
		cfg, err := config.Load()
		if err != nil {
			return classifyConfigError(err)
		}
		run := planExecution{ID: args[0]}
		return executeSavedPlan(cmd, cfg, &run, executionRunOptions{wait: wait, jsonOutput: jsonOutput, events: events}, false)
	}}
	cmd.Flags().StringVar(&wait, "wait-approval", "", "maximum approval wait, e.g. 30s")
	cmd.Flags().BoolVar(&jsonOutput, "json", false, "emit one structured execution result")
	cmd.Flags().BoolVar(&events, "events", false, "emit durable execution events as JSONL on stdout")
	return cmd
}

func newPlanExecutionStatusCommand() *cobra.Command {
	var follow bool
	var jsonOutput bool
	var timeoutValue string
	var afterSeq uint64
	statusCmd := &cobra.Command{Use: "execution <execution_id>", Short: "Read a saved execution's progress as JSON.", Args: exactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		if follow && jsonOutput {
			return newUsageError("--json cannot be combined with --follow")
		}
		cfg, err := config.Load()
		if err != nil {
			return classifyConfigError(err)
		}
		if follow {
			timeout := 0 * time.Second
			if timeoutValue != "" {
				var err error
				timeout, err = time.ParseDuration(timeoutValue)
				if err != nil || timeout <= 0 {
					return newUsageError("--timeout requires a positive duration")
				}
			}
			eventsPath, err := executionEventsPath(cfg, args[0])
			if err != nil {
				return err
			}
			path, err := executionPath(cfg, args[0])
			if err != nil {
				return err
			}
			if _, err := readExecution(path, args[0]); err != nil {
				return err
			}
			ctx := cmd.Context()
			if ctx == nil {
				ctx = context.Background()
			}
			var cancel context.CancelFunc
			if timeout > 0 {
				ctx, cancel = context.WithTimeout(ctx, timeout)
			} else {
				ctx, cancel = context.WithCancel(ctx)
			}
			defer cancel()
			lockPath, err := executionLockPath(cfg, args[0])
			if err != nil {
				return err
			}
			return followExecutionEvents(ctx, cmd.OutOrStdout(), cfg, args[0], eventsPath, path, lockPath, afterSeq)
		}
		path, err := executionPath(cfg, args[0])
		if err != nil {
			return err
		}
		run, err := readExecution(path, args[0])
		if err != nil {
			return err
		}
		lockPath, err := executionLockPath(cfg, args[0])
		if err != nil {
			return err
		}
		refreshExecutionDerivedStatus(cfg, &run, executionHasLiveOwner(lockPath))
		return writeJSON(cmd, run)
	}}
	statusCmd.Flags().BoolVar(&follow, "follow", false, "stream durable execution events as JSONL without executing")
	statusCmd.Flags().BoolVar(&jsonOutput, "json", false, "emit machine-readable JSON (default; incompatible with --follow)")
	statusCmd.Flags().StringVar(&timeoutValue, "timeout", "", "maximum follow duration, e.g. 30s")
	statusCmd.Flags().Uint64Var(&afterSeq, "after-seq", 0, "only emit events after this sequence")
	return statusCmd
}

type executionRunOptions struct {
	wait       string
	jsonOutput bool
	events     bool
}

func executionPath(cfg *config.Config, id string) (string, error) {
	if len(id) != 27 || !strings.HasPrefix(id, "px_") {
		return "", newUsageError("invalid execution id")
	}
	for _, r := range id[3:] {
		valid := r >= '0' && r <= '9' || r >= 'a' && r <= 'f'
		if !valid {
			return "", newUsageError("invalid execution id")
		}
	}
	return filepath.Join(cfg.Paths.PlansDir, "executions", id+".json"), nil
}

func readExecution(path, id string) (planExecution, error) {
	var run planExecution
	data, err := os.ReadFile(path)
	if err != nil {
		return run, newUsageError("cannot read execution: %v", err)
	}
	if err := json.Unmarshal(data, &run); err != nil {
		return run, err
	}
	if run.ID != id || run.Version != 1 || run.Host == "" || run.SessionID == "" || len(run.Steps) == 0 {
		return run, newUsageError("invalid execution snapshot")
	}
	return run, nil
}

func saveExecution(path string, run *planExecution) error {
	data, err := json.MarshalIndent(run, "", "  ")
	if err != nil {
		return err
	}
	if err := fileutil.WriteFileAtomic(path, append(data, '\n'), 0600, "execution-*.json"); err != nil {
		return err
	}
	// The running checkpoint must reach disk before starting a remote step.
	// Atomic rename alone protects readers but can lose that checkpoint after
	// a machine crash, allowing a later resume to repeat the operation.
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer func() { _ = file.Close() }()
	if err := file.Sync(); err != nil {
		return err
	}
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer func() { _ = dir.Close() }()
	return dir.Sync()
}

func emitExecution(cmd *cobra.Command, cfg *config.Config, run *planExecution, jsonOutput bool) error {
	lockPath, err := executionLockPath(cfg, run.ID)
	if err == nil {
		refreshExecutionDerivedStatus(cfg, run, executionHasLiveOwner(lockPath))
	}
	if jsonOutput {
		return writeJSON(cmd, run)
	}
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "execution %s · %s · session %s\n", run.ID, run.Status, run.SessionID)
	if run.ApprovalPlanID != "" {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "approval plan %s\n", run.ApprovalPlanID)
	}
	for i, step := range run.Steps {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "%d. %s · %s\n", i+1, step.Status, step.Cmd)
		if step.Result != nil {
			_, _ = fmt.Fprint(cmd.OutOrStdout(), step.Result.Stdout)
			_, _ = fmt.Fprint(cmd.ErrOrStderr(), step.Result.Stderr)
		}
	}
	if run.Status == "pending" || run.Status == "ready" {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "continue: agentssh plan resume %s --json\n", run.ID)
	}
	return nil
}

func executeSavedPlan(cmd *cobra.Command, cfg *config.Config, run *planExecution, options executionRunOptions, create bool) (resultErr error) {
	snapshotSaved := false
	defer func() {
		if !create || snapshotSaved || resultErr == nil || len(run.ActivePayloadRefs) == 0 {
			return
		}
		_ = releaseExecutionPayloadPins(cfg, run)
	}()
	path, err := executionPath(cfg, run.ID)
	if err != nil {
		return err
	}
	eventsPath, err := executionEventsPath(cfg, run.ID)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	lock, err := os.OpenFile(path+".lock", os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return err
	}
	defer func() { _ = lock.Close() }()
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return newUsageError("execution is already running")
	}
	defer func() { _ = syscall.Flock(int(lock.Fd()), syscall.LOCK_UN) }()
	if create {
		if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("execution id already exists")
		}
		if err := saveExecution(path, run); err != nil {
			return err
		}
		snapshotSaved = true
		run.PhaseSummary = summarizeExecutionPhases(run.Steps)
	} else {
		loaded, err := readExecution(path, run.ID)
		if err != nil {
			return err
		}
		*run = loaded
	}
	events := &executionEventWriter{path: eventsPath, executionID: run.ID}
	if options.events {
		events.stream = cmd.OutOrStdout()
	}
	defer func() {
		if options.events {
			return
		}
		if err := emitExecution(cmd, cfg, run, options.jsonOutput); err != nil && resultErr == nil {
			resultErr = err
		}
	}()
	for i := range run.Steps {
		if run.Steps[i].Status == "running" {
			run.Steps[i].Status = "unknown"
			run.Status = "unknown"
			if err := saveExecution(path, run); err != nil {
				return err
			}
			if err := events.append(executionEvent{Type: "step_unknown", StepID: run.Steps[i].ID, Status: "unknown", Reason: "previous running checkpoint had no completed result"}); err != nil {
				return err
			}
		}
	}
	switch run.Status {
	case "completed":
		return nil
	case "failed", "unknown":
		return newUsageError("execution %s is %s; inspect its results before explicitly creating a new plan", run.ID, run.Status)
	case "denied":
		return commandExitError{Code: exitPolicyDenied}
	}
	var remaining []planCommand
	if remaining, err = approvalCommandsFromExecution(run.Steps); err != nil {
		return err
	}
	if len(remaining) == 0 {
		if hasVerificationFailure(run.Steps) {
			run.Status = "failed"
			if err := releaseExecutionPayloadPins(cfg, run); err != nil {
				return err
			}
			if err := saveExecution(path, run); err != nil {
				return err
			}
			if err := events.append(executionEvent{Type: "execution_failed", Status: run.Status, Reason: "verification failed"}); err != nil {
				return err
			}
			return commandExitError{Code: exitRemoteFailed}
		}
		run.Status = "completed"
		if err := releaseExecutionPayloadPins(cfg, run); err != nil {
			return err
		}
		if err := saveExecution(path, run); err != nil {
			return err
		}
		if err := events.append(executionEvent{Type: "execution_completed", Status: run.Status}); err != nil {
			return err
		}
		return nil
	}
	if run.ApprovalPlanID != "" {
		status, err := approvalStore(cfg.Paths).PlanStatus(run.ApprovalPlanID)
		if err != nil {
			return err
		}
		if run.ReviewSHA256 == "" && status.ReviewSHA256 != "" {
			run.ReviewSHA256 = status.ReviewSHA256
		}
		appendApprovalRound(run, run.ApprovalPlanID, status.Status, "existing approval plan status", status.Pending, status.Denied, status.Expired)
		switch status.Status {
		case "denied":
			run.Status = "denied"
			if err := releaseExecutionPayloadPins(cfg, run); err != nil {
				return err
			}
			if err := saveExecution(path, run); err != nil {
				return err
			}
			if err := events.append(executionEvent{Type: "execution_denied", PlanID: run.ApprovalPlanID, Status: run.Status}); err != nil {
				return err
			}
			return commandExitError{Code: exitPolicyDenied}
		case "expired":
			run.Status = "expired"
			run.ApprovalPlanID = ""
			if err := saveExecution(path, run); err != nil {
				return err
			}
		case "pending":
			run.Status = "pending"
			if err := saveExecution(path, run); err != nil {
				return err
			}
			if options.wait == "" {
				return commandExitError{Code: exitApprovalRequired}
			}
		case "approved":
			ready, err := executionAuthorizationReady(cfg, run, remaining)
			if err != nil {
				return err
			}
			if !ready {
				oldPlanID := run.ApprovalPlanID
				waitCtx, cancel := context.WithTimeout(cmd.Context(), 250*time.Millisecond)
				waitStatus, waitErr := waitPlanReady(waitCtx, cfg, run, remaining)
				cancel()
				if waitErr != nil {
					return waitErr
				}
				switch waitStatus {
				case "approved":
					run.Status = "ready"
				case "denied":
					run.Status = "denied"
					if err := releaseExecutionPayloadPins(cfg, run); err != nil {
						return err
					}
					if err := saveExecution(path, run); err != nil {
						return err
					}
					if err := events.append(executionEvent{Type: "execution_denied", PlanID: oldPlanID, Status: run.Status}); err != nil {
						return err
					}
					return commandExitError{Code: exitPolicyDenied}
				default:
					run.ApprovalPlanID = ""
					run.Status = "ready"
					appendApprovalRound(run, oldPlanID, status.Status, "approved grant was no longer usable; requesting a new approval round for remaining steps", status.Pending, status.Denied, status.Expired)
					if err := saveExecution(path, run); err != nil {
						return err
					}
				}
			}
		}
	}
	runtime, err := approvalRuntime(cfg)
	if err != nil {
		return err
	}
	if run.ApprovalPlanID == "" || run.Status == "expired" {
		response, err := submitPlanInputs(cmd, cfg, runtime, run.Host, remaining, run.SessionID, run.Label, executionPlanReview(run))
		if response.PlanID != "" {
			run.ApprovalPlanID = response.PlanID
			if response.ReviewSHA256 != "" {
				run.ReviewSHA256 = response.ReviewSHA256
			}
			appendApprovalRound(run, response.PlanID, "pending", "authorization required for remaining steps", response.Pending, response.Denied, 0)
			if err := events.append(executionEvent{Type: "approval_submitted", PlanID: response.PlanID, Status: "pending"}); err != nil {
				return err
			}
		}
		if err != nil {
			switch exitCodeForError(err) {
			case exitPolicyDenied:
				run.Status = "denied"
			case exitApprovalRequired:
				run.Status = "pending"
			default:
				return err
			}
			if saveErr := saveExecution(path, run); saveErr != nil {
				return saveErr
			}
			if exitCodeForError(err) == exitPolicyDenied {
				if releaseErr := releaseExecutionPayloadPins(cfg, run); releaseErr != nil {
					return releaseErr
				}
				if saveErr := saveExecution(path, run); saveErr != nil {
					return saveErr
				}
				if eventErr := events.append(executionEvent{Type: "execution_denied", PlanID: run.ApprovalPlanID, Status: run.Status}); eventErr != nil {
					return eventErr
				}
			}
			if exitCodeForError(err) == exitPolicyDenied || options.wait == "" {
				return err
			}
		}
	}
	ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if run.Status == "pending" && run.ApprovalPlanID != "" && options.wait != "" {
		_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "waiting for plan %s · execution %s\n", run.ApprovalPlanID, run.ID)
		timeout, _ := time.ParseDuration(options.wait)
		waitCtx, cancel := context.WithTimeout(ctx, timeout)
		status, err := waitPlanReady(waitCtx, cfg, run, remaining)
		cancel()
		if err != nil {
			return err
		}
		if status != "approved" {
			if status == "denied" {
				run.Status = "denied"
				if err := releaseExecutionPayloadPins(cfg, run); err != nil {
					return err
				}
				if err := saveExecution(path, run); err != nil {
					return err
				}
				if err := events.append(executionEvent{Type: "execution_denied", PlanID: run.ApprovalPlanID, Status: run.Status}); err != nil {
					return err
				}
				return commandExitError{Code: exitPolicyDenied}
			}
			if status == "expired" {
				run.Status = "expired"
				if err := saveExecution(path, run); err != nil {
					return err
				}
				return newUsageError("plan %s records have expired; resume will submit a fresh approval round", run.ApprovalPlanID)
			}
			return commandExitError{Code: exitApprovalRequired}
		}
	}
	child := &cobra.Command{}
	child.SetContext(ctx)
	child.SetErr(cmd.ErrOrStderr())
	for i := range run.Steps {
		step := &run.Steps[i]
		if step.Status == "completed" || step.Status == "failed_continued" {
			continue
		}
		if ctx.Err() != nil {
			run.Status = "ready"
			if err := saveExecution(path, run); err != nil {
				return err
			}
			return ctx.Err()
		}
		stdin, err := stepStdinSpec(*step)
		if err != nil {
			return err
		}
		step.Status = "running"
		run.Status = "running"
		if err := saveExecution(path, run); err != nil {
			return err
		}
		if err := events.append(executionEvent{Type: "step_started", StepID: step.ID, Status: "running"}); err != nil {
			return err
		}
		runFlags := runFlags{
			session:       run.SessionID,
			sessionLabel:  run.Label,
			stdinSnapshot: &stdin,
			executionID:   run.ID,
			stepID:        step.ID,
			reviewSHA256:  run.ReviewSHA256,
			onOutput: func(outputEvent runOutputEvent) error {
				return events.append(executionEvent{
					Type:      "step_output",
					StepID:    outputEvent.StepID,
					RequestID: outputEvent.ReqID,
					Output:    eventOutputFromStream(outputEvent),
				})
			},
		}
		rows, _, runErr := captureRun(child, run.Host, step.Cmd, runFlags)
		if len(rows) == 1 {
			step.Result = &rows[0]
			switch rows[0].Status {
			case "completed":
				step.Status = "completed"
			case "failed":
				run.Status = "failed"
				if step.Phase == executionStepVerify && step.OnFailure == executionOnFailureContinue {
					step.Status = "failed_continued"
				} else {
					step.Status = "failed"
				}
			case "approval_pending", "not_run":
				step.Status = "not_started"
				run.Status = "pending"
			case "denied":
				step.Status = "not_started"
				run.Status = "denied"
			default:
				step.Status = "unknown"
				run.Status = "unknown"
			}
		} else {
			step.Status = "unknown"
			run.Status = "unknown"
		}
		if err := saveExecution(path, run); err != nil {
			return err
		}
		if len(rows) == 1 {
			if err := events.append(executionEvent{Type: "step_completed", StepID: step.ID, RequestID: rows[0].ReqID, Status: step.Status, Output: eventOutputFromRun(rows[0])}); err != nil {
				return err
			}
		} else {
			if err := events.append(executionEvent{Type: "step_unknown", StepID: step.ID, Status: step.Status, Reason: "unexpected run response shape"}); err != nil {
				return err
			}
		}
		if step.Status == "failed_continued" {
			continue
		}
		if runErr != nil {
			if run.Status == "failed" || run.Status == "denied" {
				if err := releaseExecutionPayloadPins(cfg, run); err != nil {
					return err
				}
				if err := saveExecution(path, run); err != nil {
					return err
				}
				if err := events.append(executionEvent{Type: "execution_failed", Status: run.Status, Reason: "step failed"}); err != nil {
					return err
				}
			}
			return runErr
		}
		if step.Status != "completed" {
			return fmt.Errorf("step outcome is %s", step.Status)
		}
	}
	if hasVerificationFailure(run.Steps) {
		run.Status = "failed"
		if err := releaseExecutionPayloadPins(cfg, run); err != nil {
			return err
		}
		if err := saveExecution(path, run); err != nil {
			return err
		}
		if err := events.append(executionEvent{Type: "execution_failed", Status: run.Status, Reason: "verification failed"}); err != nil {
			return err
		}
		return commandExitError{Code: exitRemoteFailed}
	}
	run.Status = "completed"
	if err := releaseExecutionPayloadPins(cfg, run); err != nil {
		return err
	}
	if err := saveExecution(path, run); err != nil {
		return err
	}
	return events.append(executionEvent{Type: "execution_completed", Status: run.Status})
}

func waitPlanReady(ctx context.Context, cfg *config.Config, run *planExecution, commands []planCommand) (string, error) {
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for {
		if ctx.Err() != nil {
			return "pending", nil
		}
		status, err := approvalStore(cfg.Paths).PlanStatus(run.ApprovalPlanID)
		if err != nil {
			return "", err
		}
		if status.Status == "denied" || status.Status == "expired" {
			return status.Status, nil
		}
		if status.Status == "approved" {
			current, err := config.Load()
			if err != nil {
				return "", err
			}
			runtime, err := approvalRuntime(current)
			if err != nil {
				return "", err
			}
			ready := true
			for _, command := range commands {
				auth, err := approval.PreflightAuthorize(current.Policy, current.Inventory, approval.SessionStore{Dir: current.Paths.SessionsDir}, runtime, run.SessionID, run.Host, command.Cmd, command.stdin.sha256)
				if err != nil {
					return "", err
				}
				if auth.Status == approval.AuthHardDeny || !runtime.Enabled && auth.Status == approval.AuthNeedsApproval {
					return "denied", nil
				}
				if auth.Status != approval.AuthAllow && auth.Status != approval.AuthAllowByGrant {
					ready = false
				}
			}
			if ready {
				return "approved", nil
			}
		}
		select {
		case <-ctx.Done():
			return "pending", nil
		case <-ticker.C:
		}
	}
}

func executionAuthorizationReady(cfg *config.Config, run *planExecution, commands []planCommand) (bool, error) {
	runtime, err := approvalRuntime(cfg)
	if err != nil {
		return false, err
	}
	for _, command := range commands {
		auth, err := approval.PreflightAuthorize(cfg.Policy, cfg.Inventory, approval.SessionStore{Dir: cfg.Paths.SessionsDir}, runtime, run.SessionID, run.Host, command.Cmd, command.stdin.sha256)
		if err != nil {
			return false, err
		}
		if auth.Status == approval.AuthHardDeny || !runtime.Enabled && auth.Status == approval.AuthNeedsApproval {
			return false, commandExitError{Code: exitPolicyDenied}
		}
		if auth.Status != approval.AuthAllow && auth.Status != approval.AuthAllowByGrant {
			return false, nil
		}
	}
	return true, nil
}

func hasVerificationFailure(steps []planExecutionStep) bool {
	for _, step := range steps {
		if step.Status == "failed_continued" {
			return true
		}
	}
	return false
}

func validateApprovalWait(value string) error {
	if value == "" {
		return nil
	}
	duration, err := time.ParseDuration(value)
	if err != nil || duration <= 0 {
		return newUsageError("--wait-approval requires a positive duration")
	}
	return nil
}

func validatePayloadTTL(value string) (time.Duration, error) {
	if value == "" {
		return 0, nil
	}
	duration, err := time.ParseDuration(value)
	if err != nil || duration <= 0 {
		return 0, newUsageError("--payload-ttl requires a positive duration")
	}
	return duration, nil
}
