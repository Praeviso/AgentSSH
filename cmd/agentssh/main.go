package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/Kritoooo/agentssh/internal/config"
	"github.com/Kritoooo/agentssh/internal/executor"
	"github.com/Kritoooo/agentssh/internal/inventory"
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
			return printNotImplemented(cmd, "status req=%q json=%t", args[0], jsonOutput)
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
			return printNotImplemented(cmd, "tui")
		},
	}
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
	cmd.AddCommand(
		leafNoArgs("show", "Show policy.yaml.", "policy show"),
		leafNoArgs("edit", "Edit policy.yaml.", "policy edit"),
		&cobra.Command{
			Use:   "test <cmd>",
			Short: "Evaluate a command against policy.",
			Args:  minArgs(1),
			RunE: func(cmd *cobra.Command, args []string) error {
				return printNotImplemented(cmd, "policy test command=%q", strings.Join(args, " "))
			},
		},
	)
	return cmd
}

func newAuditCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "audit",
		Short: "Browse and verify the audit log.",
	}
	cmd.AddCommand(
		leafNoArgs("ls", "List audit records.", "audit ls"),
		&cobra.Command{
			Use:   "show <req>",
			Short: "Show one audit request.",
			Args:  exactArgs(1),
			RunE: func(cmd *cobra.Command, args []string) error {
				return printNotImplemented(cmd, "audit show req=%q", args[0])
			},
		},
		leafNoArgs("verify", "Verify the audit hash chain.", "audit verify"),
	)
	return cmd
}

func newSessionCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "session",
		Short: "Browse audit sessions.",
	}
	cmd.AddCommand(leafNoArgs("ls", "List recent sessions.", "session ls"))
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

	ssh := newExecutor()
	exitCode := exitOK
	responses := make([]runResponse, 0, len(resolved.Targets))
	for _, target := range resolved.Targets {
		result := ssh.Run(context.Background(), executor.Request{
			Target:  target,
			Command: remoteCommand,
		})
		status := statusForResult(result)
		if flags.jsonOutput {
			responses = append(responses, runResponse{
				ReqID:           "",
				SessionID:       "",
				Host:            target.Name,
				Status:          status,
				ExitCode:        result.ExitCode,
				DurationMS:      result.Duration.Milliseconds(),
				Stdout:          result.Stdout,
				Stderr:          result.Stderr,
				OutputTruncated: false,
				Redactions:      0,
				Skill:           flags.skill,
			})
		} else {
			printRunHuman(cmd, target.Name, result, flags.skill)
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

	if exitCode != exitOK {
		return commandExitError{Code: exitCode}
	}
	return nil
}

func printRunHuman(cmd *cobra.Command, host string, result executor.Result, skill string) {
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
	if result.Stdout != "" {
		_, _ = fmt.Fprint(out, result.Stdout)
		if !strings.HasSuffix(result.Stdout, "\n") {
			_, _ = fmt.Fprintln(out)
		}
	}
	if result.Stderr != "" {
		_, _ = fmt.Fprint(cmd.ErrOrStderr(), result.Stderr)
		if !strings.HasSuffix(result.Stderr, "\n") {
			_, _ = fmt.Fprintln(cmd.ErrOrStderr())
		}
	}
	if isSSHErrorResult(result) && result.Err != nil {
		_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "ssh error: %v\n", result.Err)
	}
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
