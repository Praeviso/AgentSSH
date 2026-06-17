package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/Kritoooo/agentssh/internal/audit"
	"github.com/Kritoooo/agentssh/internal/config"
	"github.com/Kritoooo/agentssh/internal/executor"
	"github.com/Kritoooo/agentssh/internal/inventory"
	"github.com/Kritoooo/agentssh/internal/output"
	"github.com/Kritoooo/agentssh/internal/policy"
	"github.com/Kritoooo/agentssh/internal/session"
	"github.com/Kritoooo/agentssh/internal/tui"
	"github.com/spf13/cobra"
)

const (
	exitOK           = 0
	exitRemoteFailed = 1
	exitUsage        = 2
	exitPolicyDenied = 6
	exitSSHError     = 9
)

var newExecutor = func() executor.Executor {
	return executor.NewSSHExecutor(nil)
}

func main() {
	os.Exit(execute())
}

func execute() int {
	root := newRootCommand()
	if err := root.Execute(); err != nil {
		if isUsageError(err) {
			_, _ = fmt.Fprintln(root.ErrOrStderr(), err)
			return exitUsage
		}
		var exitErr commandExitError
		if errors.As(err, &exitErr) {
			return exitErr.Code
		}
		_, _ = fmt.Fprintln(root.ErrOrStderr(), err)
		return exitRemoteFailed
	}
	return exitOK
}

func newRootCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:               "agentssh",
		Short:             "AgentSSH is a local least-privilege SSH gateway for AI agents.",
		Long:              "AgentSSH exposes policy-checked SSH operations to agents while keeping credentials and audit control local.",
		SilenceErrors:     true,
		SilenceUsage:      true,
		CompletionOptions: cobra.CompletionOptions{DisableDefaultCmd: true},
	}

	cmd.AddCommand(
		newHostsCommand(),
		newRunCommand(),
		newStatusCommand(),
		newTUICommand(),
		newInventoryCommand(),
		newPolicyCommand(),
		newAuditCommand(),
		newSessionCommand(),
	)

	return cmd
}

func newHostsCommand() *cobra.Command {
	var jsonOutput bool
	cmd := &cobra.Command{
		Use:   "hosts [--json]",
		Short: "List configured hosts and groups.",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := config.Load()
			if err != nil {
				return classifyConfigError(err)
			}
			return printHosts(cmd, inventory.NewResolver(cfg.Inventory).Public(), jsonOutput)
		},
	}
	cmd.Flags().BoolVar(&jsonOutput, "json", false, "emit machine-readable JSON")
	return cmd
}

func newRunCommand() *cobra.Command {
	var flags runFlags
	cmd := &cobra.Command{
		Use:   "run <host|group> [--skill <name>] [--session <id>] [--session-label <text>] [--json] -- <cmd...>",
		Short: "Run a policy-checked command on a configured host or group.",
		Args: func(cmd *cobra.Command, args []string) error {
			if cmd.ArgsLenAtDash() != 1 {
				return newUsageError("requires <host|group> followed by -- <cmd...>")
			}
			if len(args) < 2 {
				return newUsageError("requires command after --")
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			target := args[0]
			remoteCommand := strings.Join(args[1:], " ")
			return runDirect(cmd, target, remoteCommand, flags)
		},
	}
	cmd.Flags().StringVar(&flags.skill, "skill", "", "associate the run with an agent skill name")
	cmd.Flags().StringVar(&flags.session, "session", "", "associate the run with a session id")
	cmd.Flags().StringVar(&flags.sessionLabel, "session-label", "", "attach a human-readable label to the session")
	cmd.Flags().BoolVar(&flags.jsonOutput, "json", false, "emit machine-readable JSON")
	return cmd
}

func newStatusCommand() *cobra.Command {
	var jsonOutput bool
	cmd := &cobra.Command{
		Use:   "status <req> [--json]",
		Short: "Show the audit status for a request.",
		Args:  exactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runStatus(cmd, args[0], jsonOutput)
		},
	}
	cmd.Flags().BoolVar(&jsonOutput, "json", false, "emit machine-readable JSON")
	return cmd
}

func newTUICommand() *cobra.Command {
	return &cobra.Command{
		Use:   "tui",
		Short: "Open the terminal audit viewer.",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runTUI(cmd)
		},
	}
}

func runTUI(cmd *cobra.Command) error {
	cfg, err := config.Load()
	if err != nil {
		return classifyConfigError(err)
	}
	opts := tui.Options{
		AuditFile: cfg.Paths.AuditFile,
		Hosts:     hostMetaFromInventory(cfg.Inventory),
	}
	err = tui.NewRunner().Run(opts)
	if tui.IsNotInteractive(err) {
		// Non-TTY (piped/CI): fall back to the line-oriented commands.
		_, _ = fmt.Fprintln(cmd.ErrOrStderr(), "tui requires an interactive terminal; showing plain session summary.")
		_, _ = fmt.Fprintln(cmd.ErrOrStderr(), "use 'agentssh audit ls|show <req>|verify' or 'agentssh session ls' for details.")
		return runSessionLS(cmd)
	}
	return err
}

func hostMetaFromInventory(inv inventory.Inventory) map[string]tui.HostMeta {
	hosts := make(map[string]tui.HostMeta, len(inv.Hosts))
	for name, host := range inv.Hosts {
		hosts[name] = tui.HostMeta{User: host.User, Addr: host.Addr, Tags: host.Tags}
	}
	return hosts
}

func newInventoryCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "inventory",
		Short: "Manage host inventory.",
	}
	cmd.AddCommand(
		leafNoArgs("ls", "List inventory entries.", "inventory ls"),
		leafNoArgs("edit", "Edit inventory.yaml.", "inventory edit"),
	)
	return cmd
}

func newPolicyCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "policy",
		Short: "Manage command policy.",
	}
	var testHost string
	testCmd := &cobra.Command{
		Use:   "test <cmd>",
		Short: "Evaluate a command against policy.",
		Args:  minArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runPolicyTest(cmd, testHost, strings.Join(args, " "))
		},
	}
	testCmd.Flags().StringVar(&testHost, "host", "", "include host/group override context")
	cmd.AddCommand(
		&cobra.Command{
			Use:   "show",
			Short: "Show policy.yaml.",
			Args:  cobra.NoArgs,
			RunE: func(cmd *cobra.Command, _ []string) error {
				return runPolicyShow(cmd)
			},
		},
		leafNoArgs("edit", "Edit policy.yaml.", "policy edit"),
		testCmd,
	)
	return cmd
}

func newAuditCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "audit",
		Short: "Browse and verify the audit log.",
	}
	var filters audit.Filters
	lsCmd := &cobra.Command{
		Use:   "ls",
		Short: "List audit records.",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runAuditLS(cmd, filters)
		},
	}
	lsCmd.Flags().StringVar(&filters.Host, "host", "", "filter by host")
	lsCmd.Flags().StringVar(&filters.SessionID, "session", "", "filter by session id")
	lsCmd.Flags().Var((*eventValue)(&filters.Event), "status", "filter by event/status")
	cmd.AddCommand(
		lsCmd,
		&cobra.Command{
			Use:   "show <req>",
			Short: "Show one audit request.",
			Args:  exactArgs(1),
			RunE: func(cmd *cobra.Command, args []string) error {
				return runAuditShow(cmd, args[0])
			},
		},
		&cobra.Command{
			Use:   "verify",
			Short: "Verify the audit hash chain.",
			Args:  cobra.NoArgs,
			RunE: func(cmd *cobra.Command, _ []string) error {
				return runAuditVerify(cmd)
			},
		},
	)
	return cmd
}

func newSessionCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "session",
		Short: "Browse audit sessions.",
	}
	cmd.AddCommand(&cobra.Command{
		Use:   "ls",
		Short: "List recent sessions.",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runSessionLS(cmd)
		},
	})
	return cmd
}

func leafNoArgs(use string, short string, name string) *cobra.Command {
	return &cobra.Command{
		Use:   use,
		Short: short,
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return printNotImplemented(cmd, name)
		},
	}
}

func exactArgs(count int) cobra.PositionalArgs {
	return func(_ *cobra.Command, args []string) error {
		if len(args) != count {
			return newUsageError("accepts %d arg(s), received %d", count, len(args))
		}
		return nil
	}
}

func minArgs(count int) cobra.PositionalArgs {
	return func(_ *cobra.Command, args []string) error {
		if len(args) < count {
			return newUsageError("requires at least %d arg(s), received %d", count, len(args))
		}
		return nil
	}
}

func printNotImplemented(cmd *cobra.Command, format string, args ...any) error {
	if len(args) == 0 {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "not implemented: %s\n", format)
		return nil
	}
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "not implemented: "+format+"\n", args...)
	return nil
}

type runFlags struct {
	skill        string
	session      string
	sessionLabel string
	jsonOutput   bool
}

type runResponse struct {
	ReqID           string `json:"req_id"`
	SessionID       string `json:"session_id"`
	Host            string `json:"host"`
	Status          string `json:"status"`
	ExitCode        int    `json:"exit_code"`
	DurationMS      int64  `json:"duration_ms"`
	Stdout          string `json:"stdout"`
	Stderr          string `json:"stderr"`
	OutputTruncated bool   `json:"output_truncated"`
	Redactions      int    `json:"redactions"`
	Skill           string `json:"skill,omitempty"`
	PolicyAction    string `json:"policy_action,omitempty"`
	PolicyRule      string `json:"policy_rule,omitempty"`
}

type usageError string

func (e usageError) Error() string {
	return string(e)
}

func newUsageError(format string, args ...any) usageError {
	return usageError(fmt.Sprintf(format, args...))
}

func isUsageError(err error) bool {
	var target usageError
	return errors.As(err, &target)
}

type commandExitError struct {
	Code int
}

func (e commandExitError) Error() string {
	return fmt.Sprintf("exit %d", e.Code)
}

var _ = []int{
	exitOK,
	exitRemoteFailed,
	exitUsage,
	exitPolicyDenied,
	exitSSHError,
}

func classifyConfigError(err error) error {
	if err == nil {
		return nil
	}
	if errors.As(err, &config.MissingHomeError{}) {
		return newUsageError("%v", err)
	}
	return fmt.Errorf("%w", err)
}

func printHosts(cmd *cobra.Command, public inventory.PublicInventory, jsonOutput bool) error {
	if jsonOutput {
		return writeJSON(cmd, public)
	}

	out := cmd.OutOrStdout()
	_, _ = fmt.Fprintln(out, "Hosts:")
	if len(public.Hosts) == 0 {
		_, _ = fmt.Fprintln(out, "  (none)")
	}
	for _, host := range public.Hosts {
		_, _ = fmt.Fprintf(out, "  %s", host.Name)
		if len(host.Tags) > 0 {
			_, _ = fmt.Fprintf(out, " tags=%s", strings.Join(host.Tags, ","))
		}
		_, _ = fmt.Fprintln(out)
	}

	_, _ = fmt.Fprintln(out, "Groups:")
	if len(public.Groups) == 0 {
		_, _ = fmt.Fprintln(out, "  (none)")
	}
	for _, group := range public.Groups {
		_, _ = fmt.Fprintf(out, "  %s", group.Name)
		if len(group.Tags) > 0 {
			_, _ = fmt.Fprintf(out, " tags=%s", strings.Join(group.Tags, ","))
		}
		_, _ = fmt.Fprintln(out)
	}

	return nil
}

func runDirect(cmd *cobra.Command, targetName string, remoteCommand string, flags runFlags) error {
	cfg, err := config.Load()
	if err != nil {
		return classifyConfigError(err)
	}

	resolved, err := inventory.NewResolver(cfg.Inventory).Resolve(targetName)
	if err != nil {
		if inventory.IsUnknown(err) {
			return newUsageError("%v\n  查看全部: agentssh hosts", err)
		}
		return newUsageError("%v", err)
	}

	engine, err := policy.NewEngine(cfg.Policy, cfg.Inventory)
	if err != nil {
		return fmt.Errorf("load policy: %w", err)
	}
	outputFilter, err := output.NewFilter(cfg.Policy.Output)
	if err != nil {
		return fmt.Errorf("load output filter: %w", err)
	}
	sessionCtx, err := session.Resolver{Path: cfg.Paths.SessionFile}.Resolve(flags.session, flags.sessionLabel)
	if err != nil {
		return fmt.Errorf("resolve session: %w", err)
	}
	store := audit.NewStore(cfg.Paths.AuditFile)
	ssh := newExecutor()
	exitCode := exitOK
	responses := make([]runResponse, 0, len(resolved.Targets))
	for _, target := range resolved.Targets {
		reqID, err := newReqID()
		if err != nil {
			return err
		}
		decision, err := engine.Evaluate(target.Name, remoteCommand)
		if err != nil {
			return fmt.Errorf("evaluate policy for %s: %w", target.Name, err)
		}
		if decision.Action == policy.ActionDeny {
			if _, err := store.Append(baseAuditRecord(reqID, sessionCtx, audit.EventDenied, target.Name, remoteCommand, flags.skill, decision, nil, "", 0)); err != nil {
				return err
			}
			response := runResponse{
				ReqID:        reqID,
				SessionID:    sessionCtx.ID,
				Host:         target.Name,
				Status:       "denied",
				ExitCode:     exitPolicyDenied,
				PolicyAction: string(decision.Action),
				PolicyRule:   decision.Rule,
				Skill:        flags.skill,
			}
			if flags.jsonOutput {
				responses = append(responses, response)
			} else {
				printDenyHuman(cmd, target.Name, remoteCommand, decision)
			}
			exitCode = mergeExitCode(exitCode, exitPolicyDenied)
			continue
		}

		if _, err := store.Append(baseAuditRecord(reqID, sessionCtx, audit.EventStarted, target.Name, remoteCommand, flags.skill, decision, nil, "", 0)); err != nil {
			return err
		}
		result := ssh.Run(context.Background(), executor.Request{
			Target:  target,
			Command: remoteCommand,
		})
		status := statusForResult(result)
		event := audit.EventCompleted
		if status != "completed" {
			event = audit.EventFailed
		}
		filtered := outputFilter.Apply(result.Stdout, result.Stderr)
		// The audit hash records the bytes that crossed the trust boundary and
		// were returned to the agent after output filtering.
		outputHash := audit.ComputeOutputSHA256(filtered.Stdout, filtered.Stderr)
		if _, err := store.Append(baseAuditRecord(reqID, sessionCtx, event, target.Name, remoteCommand, flags.skill, decision, &result.ExitCode, outputHash, result.Duration.Milliseconds(), filtered)); err != nil {
			return err
		}
		if flags.jsonOutput {
			responses = append(responses, runResponse{
				ReqID:           reqID,
				SessionID:       sessionCtx.ID,
				Host:            target.Name,
				Status:          status,
				ExitCode:        result.ExitCode,
				DurationMS:      result.Duration.Milliseconds(),
				Stdout:          filtered.Stdout,
				Stderr:          filtered.Stderr,
				OutputTruncated: filtered.OutputTruncated,
				Redactions:      filtered.Redactions,
				Skill:           flags.skill,
				PolicyAction:    string(decision.Action),
				PolicyRule:      decision.Rule,
			})
		} else {
			printRunHuman(cmd, target.Name, result, filtered, flags.skill)
		}

		exitCode = mergeExitCode(exitCode, exitCodeForResult(result))
	}

	if flags.jsonOutput {
		if resolved.Kind == inventory.TargetKindHost {
			if err := writeJSON(cmd, responses[0]); err != nil {
				return err
			}
		} else if err := writeJSON(cmd, responses); err != nil {
			return err
		}
	}

	if err := (session.Resolver{Path: cfg.Paths.SessionFile}).Update(sessionCtx.ID, time.Now().UTC()); err != nil {
		return err
	}
	if exitCode != exitOK {
		return commandExitError{Code: exitCode}
	}
	return nil
}

func printRunHuman(cmd *cobra.Command, host string, result executor.Result, filtered output.FilterResult, skill string) {
	out := cmd.OutOrStdout()
	marker := "✓"
	if isSSHErrorResult(result) {
		marker = "!"
	} else if result.ExitCode != 0 {
		marker = "✗"
	}

	_, _ = fmt.Fprintf(out, "%s %s · exit %d · %s", marker, host, result.ExitCode, formatDuration(result.Duration))
	if skill != "" {
		_, _ = fmt.Fprintf(out, " · skill=%s", skill)
	}
	_, _ = fmt.Fprintln(out)
	if filtered.Stdout != "" {
		_, _ = fmt.Fprint(out, filtered.Stdout)
		if !strings.HasSuffix(filtered.Stdout, "\n") {
			_, _ = fmt.Fprintln(out)
		}
	}
	if filtered.Stderr != "" {
		_, _ = fmt.Fprint(cmd.ErrOrStderr(), filtered.Stderr)
		if !strings.HasSuffix(filtered.Stderr, "\n") {
			_, _ = fmt.Fprintln(cmd.ErrOrStderr())
		}
	}
	if isSSHErrorResult(result) && result.Err != nil {
		_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "ssh error: %v\n", result.Err)
	}
}

func printDenyHuman(cmd *cobra.Command, host string, command string, decision policy.Decision) {
	_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "✗ denied by policy · %s · 命中规则 %q\n", host, decision.Rule)
	_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "  %s 属于不可执行的危险命令或未被 allowlist 放行;此拦截无法临场放行。\n", command)
	_, _ = fmt.Fprintln(cmd.ErrOrStderr(), "  如确需放宽,请人类修改 ~/.agentssh/policy.yaml。")
}

func statusForResult(result executor.Result) string {
	if isSSHErrorResult(result) {
		return "ssh_error"
	}
	if result.ExitCode != 0 {
		return "failed"
	}
	return "completed"
}

func exitCodeForResult(result executor.Result) int {
	if isSSHErrorResult(result) {
		return exitSSHError
	}
	if result.ExitCode != 0 {
		return exitRemoteFailed
	}
	return exitOK
}

func isSSHErrorResult(result executor.Result) bool {
	if result.Err != nil && !executor.IsProcessExit(result) {
		return true
	}
	// OpenSSH reserves exit code 255 for client/connection errors. A remote
	// command can theoretically also exit 255; AgentSSH treats 255 from ssh as
	// a connection/SSH failure to match the CLI contract.
	return len(result.Argv) > 0 && result.Argv[0] == "ssh" && result.ExitCode == 255
}

func mergeExitCode(current int, next int) int {
	// Multi-target runs report the most conservative outcome:
	// deny(6) > ssh_error(9) > remote_failed(1) > success(0).
	if current == exitPolicyDenied || next == exitPolicyDenied {
		return exitPolicyDenied
	}
	if current == exitSSHError || next == exitSSHError {
		return exitSSHError
	}
	if current == exitRemoteFailed || next == exitRemoteFailed {
		return exitRemoteFailed
	}
	return exitOK
}

func writeJSON(cmd *cobra.Command, value any) error {
	encoder := json.NewEncoder(cmd.OutOrStdout())
	encoder.SetIndent("", "  ")
	return encoder.Encode(value)
}

func formatDuration(duration time.Duration) string {
	if duration < time.Second {
		return fmt.Sprintf("%dms", duration.Milliseconds())
	}
	return fmt.Sprintf("%.1fs", duration.Seconds())
}

func runPolicyShow(cmd *cobra.Command) error {
	cfg, err := config.Load()
	if err != nil {
		return classifyConfigError(err)
	}
	return writeJSON(cmd, cfg.Policy)
}

func runPolicyTest(cmd *cobra.Command, host string, command string) error {
	cfg, err := config.Load()
	if err != nil {
		return classifyConfigError(err)
	}
	engine, err := policy.NewEngine(cfg.Policy, cfg.Inventory)
	if err != nil {
		return fmt.Errorf("load policy: %w", err)
	}
	decision, err := engine.Evaluate(host, command)
	if err != nil {
		return err
	}
	if host != "" {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "%s · rule=%s · host=%s\n", decision.Action, decision.Rule, host)
		return nil
	}
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "%s · rule=%s\n", decision.Action, decision.Rule)
	return nil
}

func runAuditLS(cmd *cobra.Command, filters audit.Filters) error {
	cfg, err := config.Load()
	if err != nil {
		return classifyConfigError(err)
	}
	records, err := audit.NewStore(cfg.Paths.AuditFile).ReadAll()
	if err != nil {
		return err
	}
	records = audit.FilterRecords(records, filters)
	for _, record := range records {
		exit := "-"
		if record.ExitCode != nil {
			exit = fmt.Sprintf("%d", *record.ExitCode)
		}
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "%d %s %s %s host=%s session=%s policy=%s/%s exit=%s\n", record.Seq, record.TS, record.ReqID, record.Event, record.Host, record.SessionID, record.PolicyAction, record.PolicyRule, exit)
	}
	return nil
}

func runAuditShow(cmd *cobra.Command, reqID string) error {
	cfg, err := config.Load()
	if err != nil {
		return classifyConfigError(err)
	}
	records, err := audit.NewStore(cfg.Paths.AuditFile).ReadAll()
	if err != nil {
		return err
	}
	var matched []audit.Record
	for _, record := range records {
		if record.ReqID == reqID {
			matched = append(matched, record)
		}
	}
	if len(matched) == 0 {
		return newUsageError("audit request %q not found", reqID)
	}
	return writeJSON(cmd, matched)
}

func runStatus(cmd *cobra.Command, reqID string, jsonOutput bool) error {
	cfg, err := config.Load()
	if err != nil {
		return classifyConfigError(err)
	}
	records, err := audit.NewStore(cfg.Paths.AuditFile).ReadAll()
	if err != nil {
		return err
	}
	var latest *audit.Record
	for i := range records {
		if records[i].ReqID == reqID {
			latest = &records[i]
		}
	}
	if latest == nil {
		return newUsageError("audit request %q not found", reqID)
	}
	status := string(latest.Event)
	exitCode := 0
	if latest.ExitCode != nil {
		exitCode = *latest.ExitCode
	} else if latest.Event == audit.EventDenied {
		exitCode = exitPolicyDenied
	}
	response := runResponse{
		ReqID:           latest.ReqID,
		SessionID:       latest.SessionID,
		Host:            latest.Host,
		Status:          status,
		ExitCode:        exitCode,
		DurationMS:      latest.DurationMS,
		OutputTruncated: latest.OutputTruncated,
		Redactions:      latest.Redactions,
		Skill:           latest.Skill,
		PolicyAction:    latest.PolicyAction,
		PolicyRule:      latest.PolicyRule,
	}
	if jsonOutput {
		return writeJSON(cmd, response)
	}
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "%s · host=%s · status=%s · exit=%d · policy=%s/%s\n", latest.ReqID, latest.Host, status, exitCode, latest.PolicyAction, latest.PolicyRule)
	return nil
}

func runAuditVerify(cmd *cobra.Command) error {
	cfg, err := config.Load()
	if err != nil {
		return classifyConfigError(err)
	}
	result, err := audit.NewStore(cfg.Paths.AuditFile).Verify()
	if err != nil {
		return err
	}
	if result.OK {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "audit chain ok · records=%d\n", result.Count)
		return nil
	}
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "audit chain broken · seq=%d · reason=%s\n", result.BrokenSeq, result.Reason)
	return commandExitError{Code: exitRemoteFailed}
}

func runSessionLS(cmd *cobra.Command) error {
	cfg, err := config.Load()
	if err != nil {
		return classifyConfigError(err)
	}
	records, err := audit.NewStore(cfg.Paths.AuditFile).ReadAll()
	if err != nil {
		return err
	}
	for _, summary := range session.Summaries(records) {
		label := summary.Label
		if label == "" {
			label = "(none)"
		}
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "%s label=%q start=%s end=%s commands=%d\n", summary.ID, label, summary.Start, summary.End, summary.CommandCount)
	}
	return nil
}

func baseAuditRecord(reqID string, sessionCtx session.Context, event audit.Event, host string, command string, skill string, decision policy.Decision, exitCode *int, outputHash string, durationMS int64, filtered ...output.FilterResult) audit.Record {
	filterResult := output.FilterResult{}
	if len(filtered) > 0 {
		filterResult = filtered[0]
	}
	return audit.Record{
		ReqID:           reqID,
		SessionID:       sessionCtx.ID,
		SessionLabel:    sessionCtx.Label,
		Event:           event,
		Agent:           os.Getenv("AGENTSSH_AGENT"),
		Skill:           skill,
		Host:            host,
		Cmd:             command,
		PolicyAction:    string(decision.Action),
		PolicyRule:      decision.Rule,
		ExitCode:        exitCode,
		OutputSHA256:    outputHash,
		OutputTruncated: filterResult.OutputTruncated,
		Redactions:      filterResult.Redactions,
		DurationMS:      durationMS,
	}
}

func newReqID() (string, error) {
	var bytes [3]byte
	if _, err := rand.Read(bytes[:]); err != nil {
		return "", fmt.Errorf("generate request id: %w", err)
	}
	return hex.EncodeToString(bytes[:]), nil
}

type eventValue audit.Event

func (v *eventValue) Set(value string) error {
	switch audit.Event(value) {
	case "", audit.EventStarted, audit.EventCompleted, audit.EventFailed, audit.EventDenied:
		*v = eventValue(value)
		return nil
	default:
		return fmt.Errorf("invalid status %q", value)
	}
}

func (v *eventValue) String() string {
	return string(*v)
}

func (v *eventValue) Type() string {
	return "status"
}
