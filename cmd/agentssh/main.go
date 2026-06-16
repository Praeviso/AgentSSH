package main

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

const (
	exitOK           = 0
	exitRemoteFailed = 1
	exitUsage        = 2
	exitPolicyDenied = 6
	exitSSHError     = 9
)

func main() {
	os.Exit(execute())
}

func execute() int {
	root := newRootCommand()
	if err := root.Execute(); err != nil {
		if isUsageError(err) {
			return exitUsage
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
			return printNotImplemented(cmd, "hosts", jsonOutput)
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
			return printNotImplemented(cmd, "run target=%q command=%q skill=%q session=%q session_label=%q json=%t", target, remoteCommand, flags.skill, flags.session, flags.sessionLabel, flags.jsonOutput)
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

var _ = []int{
	exitOK,
	exitRemoteFailed,
	exitUsage,
	exitPolicyDenied,
	exitSSHError,
}
