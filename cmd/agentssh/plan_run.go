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
	Version        int                 `json:"version"`
	ID             string              `json:"execution_id"`
	Host           string              `json:"host"`
	SessionID      string              `json:"session_id"`
	Label          string              `json:"label,omitempty"`
	ApprovalPlanID string              `json:"approval_plan_id,omitempty"`
	Status         string              `json:"status"`
	Steps          []planExecutionStep `json:"steps"`
}

type planExecutionStep struct {
	Cmd         string       `json:"cmd"`
	StdinFile   string       `json:"stdin_file,omitempty"`
	StdinSHA256 string       `json:"stdin_sha256,omitempty"`
	StdinBytes  int64        `json:"stdin_bytes,omitempty"`
	Status      string       `json:"status"`
	Result      *runResponse `json:"result,omitempty"`
}

func newPlanRunCommand() *cobra.Command {
	var file, sessionID, label, wait string
	var jsonOutput bool
	cmd := &cobra.Command{Use: "run <host> --file <path> [--session <id>] [--wait-approval 30s] [--json]", Short: "Submit and execute a saved plan sequentially, stopping on failure.", Args: exactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		if file == "" {
			return newUsageError("plan run requires --file")
		}
		if err := validateApprovalWait(wait); err != nil {
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
		commands, err := readPlanCommands(file)
		if err != nil {
			return err
		}
		if len(commands) == 0 {
			return newUsageError("plan is empty")
		}
		if err := resolveStdin(commands); err != nil {
			return err
		}
		id, err := approval.NewPlanID()
		if err != nil {
			return err
		}
		id = "px_" + strings.TrimPrefix(id, "pl_")
		run := planExecution{Version: 1, ID: id, Host: host, SessionID: sessionCtx.ID, Label: label, Status: "ready"}
		for _, command := range commands {
			stdinFile := command.StdinFile
			if stdinFile != "" {
				stdinFile, err = filepath.Abs(stdinFile)
				if err != nil {
					return err
				}
			}
			run.Steps = append(run.Steps, planExecutionStep{Cmd: command.Cmd, StdinFile: stdinFile, StdinSHA256: command.stdin.sha256, StdinBytes: command.stdin.bytes, Status: "not_started"})
		}
		return executeSavedPlan(cmd, cfg, &run, wait, jsonOutput, true)
	}}
	cmd.Flags().StringVar(&file, "file", "", "legacy or structured plan file")
	cmd.Flags().StringVar(&sessionID, "session", "", "one session for this task")
	cmd.Flags().StringVar(&label, "session-label", "", "human-readable task label")
	cmd.Flags().StringVar(&wait, "wait-approval", "", "maximum approval wait, e.g. 30s; otherwise return pending")
	cmd.Flags().BoolVar(&jsonOutput, "json", false, "emit one structured execution result")
	return cmd
}

func newPlanResumeCommand() *cobra.Command {
	var wait string
	var jsonOutput bool
	cmd := &cobra.Command{Use: "resume <execution_id> [--wait-approval 30s] [--json]", Short: "Continue only steps that have not started, using the original snapshot.", Args: exactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		if err := validateApprovalWait(wait); err != nil {
			return err
		}
		cfg, err := config.Load()
		if err != nil {
			return classifyConfigError(err)
		}
		run := planExecution{ID: args[0]}
		return executeSavedPlan(cmd, cfg, &run, wait, jsonOutput, false)
	}}
	cmd.Flags().StringVar(&wait, "wait-approval", "", "maximum approval wait, e.g. 30s")
	cmd.Flags().BoolVar(&jsonOutput, "json", false, "emit one structured execution result")
	return cmd
}

func newPlanExecutionStatusCommand() *cobra.Command {
	return &cobra.Command{Use: "execution <execution_id>", Short: "Read a saved execution's progress as JSON.", Args: exactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := config.Load()
		if err != nil {
			return classifyConfigError(err)
		}
		path, err := executionPath(cfg, args[0])
		if err != nil {
			return err
		}
		run, err := readExecution(path, args[0])
		if err != nil {
			return err
		}
		return writeJSON(cmd, run)
	}}
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

func emitExecution(cmd *cobra.Command, run *planExecution, jsonOutput bool) error {
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

func executeSavedPlan(cmd *cobra.Command, cfg *config.Config, run *planExecution, wait string, jsonOutput, create bool) (resultErr error) {
	path, err := executionPath(cfg, run.ID)
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
	} else {
		loaded, err := readExecution(path, run.ID)
		if err != nil {
			return err
		}
		*run = loaded
	}
	defer func() {
		if err := emitExecution(cmd, run, jsonOutput); err != nil && resultErr == nil {
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
	if run.ApprovalPlanID != "" {
		status, err := approvalStore(cfg.Paths).PlanStatus(run.ApprovalPlanID)
		if err != nil {
			return err
		}
		if status.Status == "denied" {
			run.Status = "denied"
			if err := saveExecution(path, run); err != nil {
				return err
			}
			return commandExitError{Code: exitPolicyDenied}
		}
	}
	var remaining []planCommand
	for _, step := range run.Steps {
		if step.Status == "completed" {
			continue
		}
		if step.Status != "not_started" {
			return newUsageError("execution has a non-resumable step")
		}
		stdin, err := loadStdinSpec("saved stdin_file", step.StdinFile)
		if err != nil {
			return err
		}
		if stdin.sha256 != step.StdinSHA256 || stdin.bytes != step.StdinBytes {
			return newUsageError("saved stdin changed; submit a new plan with the new content")
		}
		stdin.data = nil
		remaining = append(remaining, planCommand{Cmd: step.Cmd, StdinFile: step.StdinFile, stdin: stdin})
	}
	runtime, err := approvalRuntime(cfg)
	if err != nil {
		return err
	}
	response, err := submitPlanInputs(cmd, cfg, runtime, run.Host, remaining, run.SessionID, run.Label)
	if response.PlanID != "" {
		run.ApprovalPlanID = response.PlanID
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
		if exitCodeForError(err) == exitPolicyDenied || wait == "" {
			return err
		}
	}
	ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if response.Pending > 0 {
		_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "waiting for plan %s · execution %s\n", run.ApprovalPlanID, run.ID)
		timeout, _ := time.ParseDuration(wait)
		waitCtx, cancel := context.WithTimeout(ctx, timeout)
		status, err := waitPlanReady(waitCtx, cfg, run, remaining)
		cancel()
		if err != nil {
			return err
		}
		if status != "approved" {
			if status == "denied" {
				run.Status = "denied"
				if err := saveExecution(path, run); err != nil {
					return err
				}
				return commandExitError{Code: exitPolicyDenied}
			}
			return commandExitError{Code: exitApprovalRequired}
		}
	}
	child := &cobra.Command{}
	child.SetContext(ctx)
	child.SetErr(cmd.ErrOrStderr())
	for i := range run.Steps {
		step := &run.Steps[i]
		if step.Status == "completed" {
			continue
		}
		if ctx.Err() != nil {
			run.Status = "ready"
			if err := saveExecution(path, run); err != nil {
				return err
			}
			return ctx.Err()
		}
		stdin, err := loadStdinSpec("saved stdin_file", step.StdinFile)
		if err != nil {
			return err
		}
		if stdin.sha256 != step.StdinSHA256 || stdin.bytes != step.StdinBytes {
			return newUsageError("saved stdin changed; submit a new plan")
		}
		step.Status = "running"
		run.Status = "running"
		if err := saveExecution(path, run); err != nil {
			return err
		}
		rows, _, runErr := captureRun(child, run.Host, step.Cmd, runFlags{session: run.SessionID, sessionLabel: run.Label, stdinSnapshot: &stdin})
		if len(rows) == 1 {
			step.Result = &rows[0]
			switch rows[0].Status {
			case "completed":
				step.Status = "completed"
			case "failed":
				step.Status = "failed"
				run.Status = "failed"
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
		if runErr != nil {
			return runErr
		}
		if step.Status != "completed" {
			return fmt.Errorf("step outcome is %s", step.Status)
		}
	}
	run.Status = "completed"
	return saveExecution(path, run)
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
			return "denied", nil
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
