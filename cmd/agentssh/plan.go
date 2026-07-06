package main

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/Praeviso/AgentSSH/internal/approval"
	"github.com/Praeviso/AgentSSH/internal/audit"
	"github.com/Praeviso/AgentSSH/internal/config"
	"github.com/Praeviso/AgentSSH/internal/inventory"
	"github.com/Praeviso/AgentSSH/internal/policy"
	"github.com/Praeviso/AgentSSH/internal/session"
	"github.com/spf13/cobra"
)

// A plan bundles one task's commands into a single approval round-trip: the
// agent submits N commands, the operator reviews the batch once, and every
// gray-zone line becomes an ordinary once/session grant. Execution still goes
// through `run` per command, so audit granularity and explicit-deny precedence
// are unchanged.

func newPlanCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "plan",
		Short: "Submit and track multi-command approval plans.",
	}

	var submitFlags struct {
		session      string
		sessionLabel string
		file         string
		jsonOutput   bool
	}
	submitCmd := &cobra.Command{
		Use:   "submit <host> [--session <id>] [--file <path>] [--json] [-- <cmd> <cmd>...]",
		Short: "Submit a batch of commands for one approval review.",
		Long: "Each argument after -- is one complete remote command (quote each one).\n" +
			"--file adds one command per line (blank lines and # comments are skipped).\n" +
			"Allowed commands are reported as such; gray-zone commands become one\n" +
			"pending approval each, bundled under a single plan id.",
		Args: func(cmd *cobra.Command, args []string) error {
			if cmd.ArgsLenAtDash() > 1 || (cmd.ArgsLenAtDash() < 0 && len(args) != 1) {
				return newUsageError("requires <host> and commands after -- (or --file)")
			}
			if len(args) < 1 {
				return newUsageError("requires <host>")
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			commands := append([]string(nil), args[1:]...)
			return runPlanSubmit(cmd, args[0], commands, submitFlags.session, submitFlags.sessionLabel, submitFlags.file, submitFlags.jsonOutput)
		},
	}
	submitCmd.Flags().StringVar(&submitFlags.session, "session", "", "associate the plan with a session id")
	submitCmd.Flags().StringVar(&submitFlags.sessionLabel, "session-label", "", "attach a human-readable label to the session")
	submitCmd.Flags().StringVar(&submitFlags.file, "file", "", "read additional commands from a file, one per line")
	submitCmd.Flags().BoolVar(&submitFlags.jsonOutput, "json", false, "emit machine-readable JSON")

	var statusJSON bool
	statusCmd := &cobra.Command{
		Use:   "status <plan_id> [--json]",
		Short: "Read a plan's aggregate approval state.",
		Args:  exactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runPlanStatus(cmd, args[0], statusJSON)
		},
	}
	statusCmd.Flags().BoolVar(&statusJSON, "json", false, "emit machine-readable JSON")

	var waitTimeout string
	var waitJSON bool
	waitCmd := &cobra.Command{
		Use:   "wait <plan_id> [--timeout <duration>] [--json]",
		Short: "Wait until every command in a plan is adjudicated.",
		Args:  exactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runPlanWait(cmd, args[0], waitTimeout, waitJSON)
		},
	}
	waitCmd.Flags().StringVar(&waitTimeout, "timeout", "", "maximum wait duration, e.g. 10m")
	waitCmd.Flags().BoolVar(&waitJSON, "json", false, "emit machine-readable JSON")

	var grantOnce, grantSession bool
	grantCmd := &cobra.Command{
		Use:               "grant <plan_id> --once|--session",
		Short:             "Approve every pending command in a plan.",
		Args:              exactArgs(1),
		PersistentPreRunE: requireOperator,
		RunE: func(cmd *cobra.Command, args []string) error {
			var scope approval.Scope
			switch {
			case grantOnce && !grantSession:
				scope = approval.ScopeOnce
			case grantSession && !grantOnce:
				scope = approval.ScopeSession
			default:
				return newUsageError("choose exactly one of --once or --session (plans never grant host scope; use approval grant <id> --host per command)")
			}
			return runPlanDecision(cmd, args[0], approval.VerdictApproved, scope)
		},
	}
	grantCmd.Flags().BoolVar(&grantOnce, "once", false, "approve one run per command")
	grantCmd.Flags().BoolVar(&grantSession, "session", false, "approve each command for this session")

	denyCmd := &cobra.Command{
		Use:               "deny <plan_id>",
		Short:             "Deny every pending command in a plan.",
		Args:              exactArgs(1),
		PersistentPreRunE: requireOperator,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runPlanDecision(cmd, args[0], approval.VerdictDenied, "")
		},
	}

	cmd.AddCommand(submitCmd, statusCmd, waitCmd, grantCmd, denyCmd)
	return cmd
}

type planSubmitLine struct {
	Seq        int    `json:"seq"`
	Cmd        string `json:"cmd"`
	Status     string `json:"status"` // allowed | denied | approval_pending
	PolicyRule string `json:"policy_rule,omitempty"`
	ApprovalID string `json:"approval_id,omitempty"`
}

type planSubmitResponse struct {
	PlanID    string           `json:"plan_id,omitempty"`
	SessionID string           `json:"session_id"`
	Host      string           `json:"host"`
	Commands  []planSubmitLine `json:"commands"`
	Allowed   int              `json:"allowed"`
	Denied    int              `json:"denied"`
	Pending   int              `json:"pending"`
}

func readPlanFile(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, newUsageError("cannot read --file: %v", err)
	}
	var commands []string
	for _, line := range strings.Split(string(data), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		commands = append(commands, trimmed)
	}
	return commands, nil
}

func runPlanSubmit(cmd *cobra.Command, targetName string, commands []string, sessionFlag string, sessionLabel string, file string, jsonOutput bool) error {
	cfg, err := config.Load()
	if err != nil {
		return classifyConfigError(err)
	}
	runtime := approvalRuntimeWithWarning(cmd, cfg)
	if !runtime.Enabled {
		return newUsageError("plan submit requires the async approval channel\n" +
			"  enable it in ~/.agentssh/policy.yaml (approval.enabled: true) or via AGENTSSH_APPROVAL\n" +
			"  without approval, pre-check commands with: agentssh policy test --host <host> '<cmd>'")
	}
	if file != "" {
		fromFile, err := readPlanFile(file)
		if err != nil {
			return err
		}
		commands = append(commands, fromFile...)
	}
	cleaned := make([]string, 0, len(commands))
	for _, command := range commands {
		if strings.TrimSpace(command) == "" {
			continue
		}
		cleaned = append(cleaned, command)
	}
	if len(cleaned) == 0 {
		return newUsageError("plan submit requires at least one command (after -- or via --file)")
	}

	resolved, err := inventory.NewResolver(cfg.Inventory).Resolve(targetName)
	if err != nil {
		return newUsageError("%v\n  list all hosts: agentssh hosts", err)
	}
	if resolved.Kind != inventory.TargetKindHost || len(resolved.Targets) != 1 {
		return newUsageError("plan submit targets a single host; submit one plan per host")
	}
	target := resolved.Targets[0]

	sessionCtx, err := (session.Resolver{}).Resolve(target.Name, sessionFlag, sessionLabel)
	if err != nil {
		if errors.Is(err, session.ErrNoSession) {
			return newUsageError("a session must be declared for plan submit\n" +
				"  mint one id per task: agentssh session new\n" +
				"  then pass --session <id> here and on every run in the task")
		}
		return fmt.Errorf("resolve session: %w", err)
	}

	pendingStore := approvalStore(cfg.Paths)
	sessionStore := approval.SessionStore{Dir: cfg.Paths.SessionsDir}
	store := audit.NewStore(cfg.Paths.AuditFile)
	planID, err := approval.NewPlanID()
	if err != nil {
		return err
	}

	response := planSubmitResponse{SessionID: sessionCtx.ID, Host: target.Name}
	var memberIDs []string
	exitCode := exitOK
	for i, command := range cleaned {
		line := planSubmitLine{Seq: i + 1, Cmd: command}
		auth, err := approval.PreflightAuthorize(cfg.Policy, cfg.Inventory, sessionStore, runtime, sessionCtx.ID, target.Name, command, "")
		if err != nil {
			return newUsageError("policy.yaml is invalid: %v\n  fix the rule in ~/.agentssh/policy.yaml (check: agentssh policy show)", err)
		}
		line.PolicyRule = auth.Decision.Rule
		switch auth.Status {
		case approval.AuthAllow, approval.AuthAllowByGrant:
			line.Status = "allowed"
			response.Allowed++
		case approval.AuthHardDeny:
			line.Status = "denied"
			response.Denied++
			exitCode = mergeExitCode(exitCode, exitPolicyDenied)
		case approval.AuthNeedsApproval:
			reqID, err := newReqID()
			if err != nil {
				return err
			}
			req, err := pendingStore.Create(approval.PendingRequest{
				ReqID:     reqID,
				SessionID: sessionCtx.ID,
				Host:      target.Name,
				Cmd:       command,
				Candidate: auth.ApprovalMatcher,
				PlanID:    planID,
				PlanSeq:   i + 1,
				PlanTotal: len(cleaned),
			})
			if err != nil {
				return err
			}
			line.Status = "approval_pending"
			line.ApprovalID = req.ID
			memberIDs = append(memberIDs, req.ID)
			exit := exitApprovalRequired
			record := baseAuditRecord(reqID, sessionCtx, audit.EventApprovalRequested, target.Name, command, auth.Decision, &exit, "", 0)
			record.ApprovalID = req.ID
			record.ApprovalMatcher = req.Candidate.Regex
			record.ApprovalChannel = approval.ChannelPlan
			record.PlanID = planID
			if _, err := store.Append(record); err != nil {
				return err
			}
			response.Pending++
			exitCode = mergeExitCode(exitCode, exitApprovalRequired)
		default:
			return fmt.Errorf("unknown approval authorization status %q", auth.Status)
		}
		response.Commands = append(response.Commands, line)
	}

	if len(memberIDs) > 0 {
		manifest, err := pendingStore.CreatePlan(approval.PlanManifest{
			ID:        planID,
			SessionID: sessionCtx.ID,
			Host:      target.Name,
			MemberIDs: memberIDs,
		})
		if err != nil {
			return err
		}
		response.PlanID = manifest.ID
	}

	if jsonOutput {
		if err := writeJSON(cmd, response); err != nil {
			return err
		}
	} else {
		printPlanSubmitHuman(cmd, response)
	}
	if exitCode != exitOK {
		return commandExitError{Code: exitCode}
	}
	return nil
}

func printPlanSubmitHuman(cmd *cobra.Command, response planSubmitResponse) {
	out := cmd.ErrOrStderr()
	for _, line := range response.Commands {
		marker := "✓"
		note := "allowed"
		switch line.Status {
		case "denied":
			marker = "✗"
			note = "denied by policy (" + line.PolicyRule + ")"
		case "approval_pending":
			marker = "!"
			note = "approval pending " + line.ApprovalID
		}
		_, _ = fmt.Fprintf(out, "%s %d/%d %s · %s\n", marker, line.Seq, len(response.Commands), line.Cmd, note)
	}
	if response.PlanID != "" {
		_, _ = fmt.Fprintf(out, "! plan %s · %d command(s) awaiting one operator review\n", response.PlanID, response.Pending)
		_, _ = fmt.Fprintf(out, "  wait for the decision: agentssh plan wait %s\n", response.PlanID)
	} else if response.Denied == 0 {
		_, _ = fmt.Fprintln(out, "✓ all commands already allowed — run them directly")
	}
}

func runPlanStatus(cmd *cobra.Command, id string, jsonOutput bool) error {
	cfg, err := config.Load()
	if err != nil {
		return classifyConfigError(err)
	}
	status, err := approvalStore(cfg.Paths).PlanStatus(id)
	if err != nil {
		return mapPlanError(err)
	}
	return emitPlanStatus(cmd, status, jsonOutput)
}

func runPlanWait(cmd *cobra.Command, id string, timeoutValue string, jsonOutput bool) error {
	cfg, err := config.Load()
	if err != nil {
		return classifyConfigError(err)
	}
	runtime := approvalRuntimeWithWarning(cmd, cfg)
	timeout, err := resolveWaitTimeout(runtime.WaitTimeout, timeoutValue)
	if err != nil {
		return err
	}
	status, err := approvalStore(cfg.Paths).WaitPlan(id, timeout)
	if err != nil {
		return mapPlanError(err)
	}
	return emitPlanStatus(cmd, status, jsonOutput)
}

// emitPlanStatus prints the aggregate state and maps it to the approval exit
// contract: approved 0, denied 6, still pending 7, expired 2 (stale records —
// re-submit rather than assume a verdict).
func emitPlanStatus(cmd *cobra.Command, status approval.PlanStatus, jsonOutput bool) error {
	if jsonOutput {
		if err := writeJSON(cmd, status); err != nil {
			return err
		}
	} else {
		out := cmd.OutOrStdout()
		_, _ = fmt.Fprintf(out, "plan %s · %s · approved %d · denied %d · pending %d",
			status.ID, status.Status, status.Approved, status.Denied, status.Pending)
		if status.Expired > 0 {
			_, _ = fmt.Fprintf(out, " · expired %d", status.Expired)
		}
		_, _ = fmt.Fprintln(out)
		for _, member := range status.Members {
			cmdText := ""
			if member.Request != nil {
				cmdText = " · " + member.Request.Cmd
			}
			_, _ = fmt.Fprintf(out, "  %s %s%s\n", member.ApprovalID, member.Status, cmdText)
		}
	}
	switch status.Status {
	case "approved":
		return nil
	case "denied":
		return commandExitError{Code: exitPolicyDenied}
	case "expired":
		return newUsageError("plan %s records have expired; re-submit the plan", status.ID)
	default:
		return commandExitError{Code: exitApprovalRequired}
	}
}

func runPlanDecision(cmd *cobra.Command, id string, verdict approval.Verdict, scope approval.Scope) error {
	cfg, err := config.Load()
	if err != nil {
		return classifyConfigError(err)
	}
	runtime, err := approvalRuntime(cfg)
	if err != nil {
		return newUsageError("%v", err)
	}
	results, err := approval.ApplyPlanDecision(approval.ApplyOptions{
		Pending:    approvalStore(cfg.Paths),
		Sessions:   approval.SessionStore{Dir: cfg.Paths.SessionsDir},
		Audit:      audit.NewStore(cfg.Paths.AuditFile),
		Bundle:     policy.Bundle{Policy: cfg.Policy, Inventory: cfg.Inventory},
		PolicyPath: cfg.Paths.PolicyFile,
		SessionTTL: runtime.SessionTTL,
		Channel:    approval.ChannelCLI,
		SavePolicy: func(next policy.Config) error {
			return saveValidatedPolicy(cfg.Paths, next)
		},
	}, id, verdict, scope)
	if err != nil {
		return mapPlanError(err)
	}
	action := "denied"
	if verdict == approval.VerdictApproved {
		action = fmt.Sprintf("approved scope=%s", scope)
	}
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "plan %s: %s %d command(s)\n", id, action, len(results))
	return nil
}

func mapPlanError(err error) error {
	switch {
	case errors.Is(err, approval.ErrInvalidPlanID),
		errors.Is(err, approval.ErrPlanNotFound),
		errors.Is(err, approval.ErrPlanScope),
		errors.Is(err, approval.ErrPlanNoPending):
		return newUsageError("%v", err)
	default:
		return err
	}
}
