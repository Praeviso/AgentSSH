package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Praeviso/AgentSSH/internal/approval"
	"github.com/Praeviso/AgentSSH/internal/config"
	"github.com/spf13/cobra"
)

// captureRun calls the same execution path as the CLI and preserves its single
// JSON result. Progress goes to stderr; callers can decide when to emit stdout.
func captureRun(cmd *cobra.Command, host, command string, flags runFlags) ([]runResponse, bool, error) {
	var out bytes.Buffer
	child := &cobra.Command{}
	child.SetContext(cmd.Context())
	child.SetOut(&out)
	child.SetErr(cmd.ErrOrStderr())
	flags.jsonOutput = true
	flags.fields = ""
	err := runDirect(child, host, command, flags)
	if out.Len() == 0 {
		return nil, false, err
	}
	group := out.Bytes()[0] == '['
	var rows []runResponse
	if group {
		if decodeErr := json.Unmarshal(out.Bytes(), &rows); decodeErr != nil {
			return nil, group, decodeErr
		}
	} else {
		var row runResponse
		if decodeErr := json.Unmarshal(out.Bytes(), &row); decodeErr != nil {
			return nil, group, decodeErr
		}
		rows = []runResponse{row}
	}
	return rows, group, err
}

func emitCapturedRun(cmd *cobra.Command, rows []runResponse, group bool, flags runFlags) error {
	if len(rows) == 0 {
		return nil
	}
	if flags.jsonOutput {
		fields, err := parseRunFields(flags.fields)
		if err != nil {
			return err
		}
		if len(fields) > 0 {
			selected := make([]map[string]any, 0, len(rows))
			for _, row := range rows {
				value, err := selectRunFields(row, fields)
				if err != nil {
					return err
				}
				selected = append(selected, value)
			}
			if group {
				return writeJSON(cmd, selected)
			}
			return writeJSON(cmd, selected[0])
		}
		if group {
			return writeJSON(cmd, rows)
		}
		return writeJSON(cmd, rows[0])
	}
	for _, row := range rows {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "%s · %s · exit %d · request %s\n", row.Host, row.Status, row.ExitCode, row.ReqID)
		_, _ = fmt.Fprint(cmd.OutOrStdout(), row.Stdout)
		_, _ = fmt.Fprint(cmd.ErrOrStderr(), row.Stderr)
	}
	return nil
}

func runAwaited(cmd *cobra.Command, host, command string, flags runFlags) error {
	timeout, err := time.ParseDuration(flags.waitApproval)
	if err != nil || timeout <= 0 {
		return newUsageError("--wait-approval requires a positive duration")
	}
	stdin, err := loadStdinSpec("--stdin-file", flags.stdinFile)
	if err != nil {
		return err
	}
	if flags.stdinSnapshot != nil {
		stdin = *flags.stdinSnapshot
	}
	flags.stdinSnapshot = &stdin
	flags.waitApproval = ""
	ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	child := &cobra.Command{}
	child.SetContext(ctx)
	child.SetErr(cmd.ErrOrStderr())
	rows, group, runErr := captureRun(child, host, command, flags)
	canWait := true
	for _, row := range rows {
		if row.ExecutionState != "not_started" {
			canWait = false
		}
	}
	if !canWait && exitCodeForError(runErr) == exitApprovalRequired {
		// A grant may expire or be revoked between group members. Repeating
		// the original group would also repeat its completed remote operations.
		for i := range rows {
			if rows[i].Status == "approval_pending" {
				rows[i].NextAction = "retry_unstarted_targets"
			}
		}
	}
	if canWait && exitCodeForError(runErr) == exitApprovalRequired {
		cfg, err := config.Load()
		if err != nil {
			return classifyConfigError(err)
		}
		var ids []string
		for _, row := range rows {
			if row.ApprovalID != "" {
				ids = append(ids, row.ApprovalID)
				_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "waiting for approval %s · %s\n", row.ApprovalID, row.Host)
			}
		}
		waitCtx, cancel := context.WithTimeout(ctx, timeout)
		status, err := waitForRunApproval(waitCtx, approvalStore(cfg.Paths), ids, rows, command, stdin.sha256)
		cancel()
		if err != nil {
			return err
		}
		switch status {
		case "approved":
			rows, group, runErr = captureRun(child, host, command, flags)
		case "denied", "policy_denied":
			for i := range rows {
				if rows[i].Status == "approval_pending" {
					rows[i].Status = "approval_denied"
					if status == "policy_denied" {
						rows[i].Status = "denied"
					}
					rows[i].ExitCode = exitPolicyDenied
					rows[i].NextAction = "stop"
				}
			}
			runErr = commandExitError{Code: exitPolicyDenied}
		default:
			for i := range rows {
				rows[i].NextAction = "wait_for_approval"
			}
		}
	}
	if err := emitCapturedRun(cmd, rows, group, flags); err != nil {
		return err
	}
	return runErr
}

// A resolution is written before its grant. Wait for usable authorization too,
// avoiding the approved-not-yet-granted race and duplicate pending requests.
func waitForRunApproval(ctx context.Context, store approval.PendingStore, ids []string, rows []runResponse, command, stdinHash string) (string, error) {
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for {
		if ctx.Err() != nil {
			return "pending", nil
		}
		allApproved := len(ids) > 0
		for _, id := range ids {
			status, err := store.Status(id)
			if err != nil {
				return "", err
			}
			if status.Status == "denied" {
				return "denied", nil
			}
			if status.Status != "approved" {
				allApproved = false
			}
		}
		if allApproved {
			cfg, err := config.Load()
			if err != nil {
				return "", classifyConfigError(err)
			}
			runtime, err := approvalRuntime(cfg)
			if err != nil {
				return "", err
			}
			ready := true
			for _, row := range rows {
				auth, err := approval.PreflightAuthorize(cfg.Policy, cfg.Inventory, approval.SessionStore{Dir: cfg.Paths.SessionsDir}, runtime, row.SessionID, row.Host, command, stdinHash)
				if err != nil {
					return "", err
				}
				if auth.Status == approval.AuthHardDeny || !runtime.Enabled && auth.Status == approval.AuthNeedsApproval {
					return "policy_denied", nil
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
