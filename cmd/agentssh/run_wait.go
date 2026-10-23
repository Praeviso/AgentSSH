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
	"github.com/Praeviso/AgentSSH/internal/remote"
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
		status, err := waitForRunApproval(waitCtx, cfg, ids, rows, command, stdin)
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
func waitForRunApproval(ctx context.Context, cfg *config.Config, ids []string, rows []runResponse, command string, stdin stdinSpec) (string, error) {
	ticker := time.NewTicker(pollInterval(cfg))
	defer ticker.Stop()
	for {
		if ctx.Err() != nil {
			return "pending", nil
		}
		allApproved := len(ids) > 0
		for _, id := range ids {
			status, _, err := approvalStatus(ctx, cfg, id)
			if ctx.Err() != nil {
				return "pending", nil
			}
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
			checks := make([]remote.AuthorizeCheck, 0, len(rows))
			for _, row := range rows {
				checks = append(checks, remote.AuthorizeCheck{Host: row.Host, Session: row.SessionID, Cmd: command, StdinSHA256: stdin.sha256, StdinBytes: stdin.bytes})
			}
			statuses, enabled, err := preflight(ctx, cfg, checks)
			if ctx.Err() != nil {
				return "pending", nil
			}
			if err != nil {
				return "", err
			}
			ready := true
			for _, status := range statuses {
				if status == approval.AuthHardDeny || !enabled && status == approval.AuthNeedsApproval {
					return "policy_denied", nil
				}
				if status != approval.AuthAllow && status != approval.AuthAllowByGrant {
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
