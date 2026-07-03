package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"filippo.io/age"
	"github.com/Praeviso/AgentSSH/internal/approval"
	"github.com/Praeviso/AgentSSH/internal/audit"
	"github.com/Praeviso/AgentSSH/internal/config"
	"github.com/Praeviso/AgentSSH/internal/discovery"
	"github.com/Praeviso/AgentSSH/internal/executor"
	"github.com/Praeviso/AgentSSH/internal/fileutil"
	"github.com/Praeviso/AgentSSH/internal/hostform"
	"github.com/Praeviso/AgentSSH/internal/inventory"
	"github.com/Praeviso/AgentSSH/internal/output"
	"github.com/Praeviso/AgentSSH/internal/policy"
	"github.com/Praeviso/AgentSSH/internal/secrets"
	"github.com/Praeviso/AgentSSH/internal/session"
	"github.com/Praeviso/AgentSSH/internal/tui"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

const (
	exitOK               = 0
	exitRemoteFailed     = 1
	exitUsage            = 2
	exitPolicyDenied     = 6
	exitApprovalRequired = 7
	exitSSHError         = 9
)

const envMasterPassword = "AGENTSSH_MASTER_PASSWORD"

const (
	operatorVerifierFile    = "operator.verifier"
	operatorVerifierVersion = 1
	operatorVerifierPurpose = "agentssh operator verifier"
)

// version is overridden at build time via -ldflags "-X main.version=<tag>".
var version = "dev"

var newExecutor = func(cfg *config.Config) executor.Executor {
	switch selectedTransport(cfg) {
	case executor.TransportNative:
		options := executor.NativeOptions{}
		if cfg != nil {
			options.HostKeyPolicy = cfg.Inventory.HostKeyPolicy
			options.PasswordSource = passwordSourceForRun(cfg.Paths)
			options.DisableConnectionReuse = !sshMultiplexingEnabled(cfg)
			options.KeepAliveInterval = sshKeepAliveInterval(cfg)
		}
		return executor.NewNativeExecutor(options)
	default:
		return executor.NewSSHExecutorWithOptions(nil, executor.SSHOptions{
			DisableMultiplexing: !sshMultiplexingEnabled(cfg),
			ControlPersist:      sshControlPersist(cfg),
			KeepAliveInterval:   sshKeepAliveInterval(cfg),
		})
	}
}

var readSecretNoEcho = readSecretFromTTY
var stdinIsTerminal = func() bool {
	return term.IsTerminal(int(os.Stdin.Fd()))
}

func main() {
	os.Exit(execute())
}

func execute() int {
	root := newRootCommand()
	err := root.Execute()
	code := exitCodeForError(err)
	if err != nil {
		var exitErr commandExitError
		if !errors.As(err, &exitErr) {
			// Surface usage/generic errors. A commandExitError's human-facing
			// message was already printed by the command itself.
			_, _ = fmt.Fprintln(root.ErrOrStderr(), err)
		}
	}
	return code
}

// exitCodeForError maps a top-level command error to a process exit code per
// docs/DESIGN.md §A.5. It is the single source of truth shared by execute()
// and the exit-code tests.
func exitCodeForError(err error) int {
	if err == nil {
		return exitOK
	}
	if isUsageError(err) || isCobraUsageError(err) {
		return exitUsage
	}
	var exitErr commandExitError
	if errors.As(err, &exitErr) {
		return exitErr.Code
	}
	return exitRemoteFailed
}

// isCobraUsageError catches cobra/pflag's own validation errors (unknown
// command/flag) which are not our usageError type, so they still map to exit 2.
func isCobraUsageError(err error) bool {
	if err == nil {
		return false
	}
	// Flag-parse errors are already converted to usageError by the root's
	// FlagErrorFunc; only "unknown command" reaches here un-typed. Matching just
	// that one phrase keeps the string-match false-positive window minimal.
	return strings.HasPrefix(err.Error(), "unknown command")
}

func newRootCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:               "agentssh",
		Short:             "AgentSSH is a local least-privilege SSH gateway for AI agents.",
		Long:              "AgentSSH exposes policy-checked SSH operations to agents while keeping credentials and audit control local.",
		Version:           version,
		SilenceErrors:     true,
		SilenceUsage:      true,
		CompletionOptions: cobra.CompletionOptions{DisableDefaultCmd: true},
	}
	// Map cobra/pflag flag-parse errors (unknown/invalid flag) to our usageError
	// so they exit 2 instead of falling through to the generic exit 1.
	cmd.SetFlagErrorFunc(func(_ *cobra.Command, err error) error {
		return usageError(err.Error())
	})

	cmd.AddCommand(
		newHostsCommand(),
		newRunCommand(),
		newStatusCommand(),
		newTUICommand(),
		newOperatorCommand(),
		newInventoryCommand(),
		newSecretCommand(),
		newPolicyCommand(),
		newApprovalCommand(),
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
		Args:  noArgs,
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
		Use:   "run <host|group> [--session <id>] [--session-label <text>] [--json] -- <cmd...>",
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
		Short: "Open the terminal control console.",
		Args:  noArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runTUI(cmd)
		},
	}
}

func runTUI(cmd *cobra.Command) error {
	home, err := config.ResolveHome()
	if err != nil {
		return err
	}
	created, err := config.EnsureHome(home)
	if err != nil {
		return classifyConfigError(err)
	}
	if created {
		_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "initialized %s with starter inventory.yaml and policy.yaml\n", home)
	}
	cfg, err := config.Load()
	paths := config.NewPaths(home)
	if err != nil {
		// A malformed inventory.yaml/policy.yaml must not lock the operator out of
		// the console — launch so the Hosts/Policy tabs can show a fixable error
		// card. (The agent-facing commands still treat this as a setup error.)
		var parseErr config.ParseError
		if !errors.As(err, &parseErr) {
			return classifyConfigError(err)
		}
	} else {
		paths = cfg.Paths
	}
	opts := tui.Options{
		Paths:    paths,
		FirstRun: created,
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

func newOperatorCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "operator",
		Short: "Manage local operator authentication.",
	}
	cmd.AddCommand(&cobra.Command{
		Use:   "init",
		Short: "Initialize the local operator password verifier.",
		Args:  noArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runOperatorInit(cmd)
		},
	})
	return cmd
}

func newInventoryCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "inventory",
		Short: "Manage host inventory.",
	}
	var lsJSON bool
	lsCmd := &cobra.Command{
		Use:   "ls [--json]",
		Short: "List configured inventory entries.",
		Args:  noArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runInventoryLS(cmd, lsJSON)
		},
	}
	lsCmd.Flags().BoolVar(&lsJSON, "json", false, "emit machine-readable JSON")

	var add inventoryAddOptions
	addCmd := &cobra.Command{
		Use:               "add [name] [--addr <addr>] [--user <user>] [--port <port>] [--alias <ssh_config_alias>] [--identity-file <path>] [--tags <a,b>]",
		Short:             "Add a host to inventory.yaml.",
		Args:              cobra.MaximumNArgs(1),
		PersistentPreRunE: requireOperator,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) > 0 {
				add.Name = args[0]
			}
			return runInventoryAdd(cmd, add)
		},
	}
	addCmd.Flags().StringVar(&add.Addr, "addr", "", "host address")
	addCmd.Flags().StringVar(&add.User, "user", "", "SSH user")
	addCmd.Flags().IntVar(&add.Port, "port", 0, "SSH port")
	addCmd.Flags().StringVar(&add.Alias, "alias", "", "ssh_config host alias")
	addCmd.Flags().StringVar(&add.IdentityFile, "identity-file", "", "identity file path")
	addCmd.Flags().BoolVar(&add.Password, "password", false, "prompt for and store an encrypted SSH password")
	addCmd.Flags().StringVar(&add.Tags, "tags", "", "comma-separated tags")

	var update inventoryUpdateOptions
	updateCmd := &cobra.Command{
		Use:               "update <name> [--addr <addr>] [--user <user>] [--port <port>] [--alias <ssh_config_alias>] [--identity-file <path>] [--tags <a,b>]",
		Short:             "Update an existing host in inventory.yaml.",
		Args:              exactArgs(1),
		PersistentPreRunE: requireOperator,
		RunE: func(cmd *cobra.Command, args []string) error {
			update.Name = args[0]
			flags := cmd.Flags()
			update.AddrSet = flags.Changed("addr")
			update.UserSet = flags.Changed("user")
			update.PortSet = flags.Changed("port")
			update.AliasSet = flags.Changed("alias")
			update.IdentityFileSet = flags.Changed("identity-file")
			update.TagsSet = flags.Changed("tags")
			return runInventoryUpdate(cmd, update)
		},
	}
	updateCmd.Flags().StringVar(&update.Addr, "addr", "", "host address")
	updateCmd.Flags().StringVar(&update.User, "user", "", "SSH user")
	updateCmd.Flags().IntVar(&update.Port, "port", 0, "SSH port")
	updateCmd.Flags().StringVar(&update.Alias, "alias", "", "ssh_config host alias")
	updateCmd.Flags().StringVar(&update.IdentityFile, "identity-file", "", "identity file path")
	updateCmd.Flags().StringVar(&update.Tags, "tags", "", "comma-separated tags; empty clears tags")

	rmCmd := &cobra.Command{
		Use:               "rm <name>",
		Aliases:           []string{"remove", "delete"},
		Short:             "Remove a host from inventory.yaml.",
		Args:              exactArgs(1),
		PersistentPreRunE: requireOperator,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runInventoryRM(cmd, args[0])
		},
	}

	var discover inventoryDiscoverOptions
	discoverCmd := &cobra.Command{
		Use:               "discover [--probe] [--json] [--import]",
		Short:             "Discover SSH hosts from local SSH config and known_hosts.",
		Args:              noArgs,
		PersistentPreRunE: requireOperator,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runInventoryDiscover(cmd, discover)
		},
	}
	discoverCmd.Flags().BoolVar(&discover.Probe, "probe", false, "dial and authenticate discovered hosts")
	discoverCmd.Flags().BoolVar(&discover.JSON, "json", false, "emit machine-readable JSON")
	discoverCmd.Flags().BoolVar(&discover.Import, "import", false, "import connectable hosts not already in inventory")

	testCmd := &cobra.Command{
		Use:               "test <name>",
		Short:             "Test native SSH connectivity for an inventory host.",
		Args:              exactArgs(1),
		PersistentPreRunE: requireOperator,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runInventoryTest(cmd, args[0])
		},
	}

	cmd.AddCommand(
		lsCmd,
		addCmd,
		updateCmd,
		rmCmd,
		discoverCmd,
		testCmd,
		leafNoArgs("edit", "Edit inventory.yaml.", "edit ~/.agentssh/inventory.yaml directly"),
	)
	return cmd
}

func newSecretCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "secret",
		Short: "Manage encrypted SSH passwords.",
	}
	cmd.AddCommand(
		&cobra.Command{
			Use:               "set <host>",
			Short:             "Prompt for and store an encrypted SSH password.",
			Args:              exactArgs(1),
			PersistentPreRunE: requireOperator,
			RunE: func(cmd *cobra.Command, args []string) error {
				return runSecretSet(cmd, args[0])
			},
		},
		newSecretLSCommand(),
		&cobra.Command{
			Use:               "rm <host>",
			Short:             "Remove a stored SSH password.",
			Args:              exactArgs(1),
			PersistentPreRunE: requireOperator,
			RunE: func(cmd *cobra.Command, args []string) error {
				return runSecretRM(cmd, args[0])
			},
		},
	)
	return cmd
}

func newSecretLSCommand() *cobra.Command {
	var jsonOutput bool
	cmd := &cobra.Command{
		Use:               "ls [--json]",
		Short:             "List hosts with stored SSH passwords.",
		Args:              noArgs,
		PersistentPreRunE: requireOperator,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runSecretLS(cmd, jsonOutput)
		},
	}
	cmd.Flags().BoolVar(&jsonOutput, "json", false, "emit machine-readable JSON")
	return cmd
}

func newPolicyCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "policy",
		Short: "Manage command policy.",
	}
	cmd.AddCommand(newPolicyRuleCommand(), newPolicyGroupCommand(), newPolicyHostCommand())
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
			Args:  noArgs,
			RunE: func(cmd *cobra.Command, _ []string) error {
				return runPolicyShow(cmd)
			},
		},
		leafNoArgs("edit", "Edit policy.yaml.", "edit ~/.agentssh/policy.yaml directly (validate with: agentssh policy show)"),
		testCmd,
	)
	return cmd
}

func newPolicyHostCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "host",
		Short: "Manage per-host policy rules.",
	}
	lsCmd := &cobra.Command{
		Use:   "ls",
		Short: "List per-host policy rules.",
		Args:  noArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runPolicyHostLS(cmd)
		},
	}

	ruleCmd := newPolicyHostRuleCommand()
	groupCmd := newPolicyHostGroupCommand()

	rmCmd := &cobra.Command{
		Use:               "rm <host>",
		Aliases:           []string{"remove", "delete"},
		Short:             "Clear per-host policy rules.",
		Args:              exactArgs(1),
		PersistentPreRunE: requireOperator,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runPolicyHostRM(cmd, args[0])
		},
	}
	cmd.AddCommand(lsCmd, ruleCmd, groupCmd, rmCmd)
	return cmd
}

func newPolicyHostRuleCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "rule",
		Short: "Manage per-host policy rules.",
	}
	var add policyHostRuleOptions
	addCmd := &cobra.Command{
		Use:               "add <host> (--cmd-regex <regex> --action allow|deny [--priority <int>] | --from-group <name>)",
		Short:             "Append a manual rule or stamp a rule group onto host rules.",
		Args:              exactArgs(1),
		PersistentPreRunE: requireOperator,
		RunE: func(cmd *cobra.Command, args []string) error {
			add.Host = args[0]
			cmdRegexSet := cmd.Flags().Changed("cmd-regex")
			fromGroupSet := cmd.Flags().Changed("from-group")
			if cmdRegexSet && fromGroupSet {
				return newUsageError("policy host rule add accepts either --cmd-regex or --from-group, not both")
			}
			if !cmdRegexSet && !fromGroupSet {
				return newUsageError("policy host rule add requires --cmd-regex or --from-group")
			}
			if fromGroupSet && (cmd.Flags().Changed("action") || cmd.Flags().Changed("priority")) {
				return newUsageError("policy host rule add --from-group does not accept --action or --priority")
			}
			if cmdRegexSet && !cmd.Flags().Changed("action") {
				return newUsageError("policy host rule add requires --action allow|deny")
			}
			return runPolicyHostRuleAdd(cmd, add)
		},
	}
	addCmd.Flags().StringVar(&add.CmdRegex, "cmd-regex", "", "command regex to match")
	addCmd.Flags().StringVar(&add.Action, "action", "", "policy action: allow or deny")
	addCmd.Flags().IntVar(&add.Priority, "priority", 0, "rule priority; higher values evaluate first")
	addCmd.Flags().StringVar(&add.FromGroup, "from-group", "", "stamp all rules from a reusable rule group")

	lsCmd := &cobra.Command{
		Use:   "ls <host>",
		Short: "List host-specific policy rules.",
		Args:  exactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runPolicyHostRuleLS(cmd, args[0])
		},
	}

	rmCmd := &cobra.Command{
		Use:               "rm <host> <index>",
		Aliases:           []string{"remove", "delete"},
		Short:             "Remove a host-specific policy rule by index.",
		Args:              exactArgs(2),
		PersistentPreRunE: requireOperator,
		RunE: func(cmd *cobra.Command, args []string) error {
			index, err := strconv.Atoi(args[1])
			if err != nil {
				return newUsageError("host rule index must be a number")
			}
			return runPolicyHostRuleRM(cmd, args[0], index)
		},
	}

	cmd.AddCommand(addCmd, lsCmd, rmCmd)
	return cmd
}

func newPolicyHostGroupCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "group",
		Short: "Manage rule-group snapshots stamped onto hosts.",
	}
	rmCmd := &cobra.Command{
		Use:               "rm <host> <name>",
		Aliases:           []string{"remove", "delete"},
		Short:             "Remove all host rules stamped from a group.",
		Args:              exactArgs(2),
		PersistentPreRunE: requireOperator,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runPolicyHostGroupRM(cmd, args[0], args[1])
		},
	}
	cmd.AddCommand(rmCmd)
	return cmd
}

func newPolicyGroupCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "group",
		Short: "Manage reusable policy rule groups.",
	}
	lsCmd := &cobra.Command{
		Use:   "ls",
		Short: "List policy rule groups.",
		Args:  noArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runPolicyGroupLS(cmd)
		},
	}
	addCmd := &cobra.Command{
		Use:               "add <name>",
		Short:             "Create a reusable policy rule group.",
		Args:              exactArgs(1),
		PersistentPreRunE: requireOperator,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runPolicyGroupAdd(cmd, args[0])
		},
	}
	rmCmd := &cobra.Command{
		Use:               "rm <name>",
		Aliases:           []string{"remove", "delete"},
		Short:             "Delete a reusable policy rule group.",
		Args:              exactArgs(1),
		PersistentPreRunE: requireOperator,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runPolicyGroupRM(cmd, args[0])
		},
	}
	ruleCmd := newPolicyGroupRuleCommand()
	cmd.AddCommand(lsCmd, addCmd, rmCmd, ruleCmd)
	return cmd
}

func newPolicyGroupRuleCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "rule",
		Short: "Manage rules inside reusable policy groups.",
	}
	var add policyGroupRuleOptions
	addCmd := &cobra.Command{
		Use:               "add <group> --cmd-regex <regex> --action allow|deny [--priority <int>]",
		Short:             "Append a rule to a policy rule group.",
		Args:              exactArgs(1),
		PersistentPreRunE: requireOperator,
		RunE: func(cmd *cobra.Command, args []string) error {
			add.Group = args[0]
			if !cmd.Flags().Changed("action") {
				return newUsageError("policy group rule add requires --action allow|deny")
			}
			return runPolicyGroupRuleAdd(cmd, add)
		},
	}
	addCmd.Flags().StringVar(&add.CmdRegex, "cmd-regex", "", "command regex to match")
	addCmd.Flags().StringVar(&add.Action, "action", "", "policy action: allow or deny")
	addCmd.Flags().IntVar(&add.Priority, "priority", 0, "rule priority; higher values evaluate first")

	lsCmd := &cobra.Command{
		Use:   "ls <group>",
		Short: "List rules inside a policy rule group.",
		Args:  exactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runPolicyGroupRuleLS(cmd, args[0])
		},
	}
	rmCmd := &cobra.Command{
		Use:               "rm <group> <index>",
		Aliases:           []string{"remove", "delete"},
		Short:             "Remove a rule from a policy rule group by index.",
		Args:              exactArgs(2),
		PersistentPreRunE: requireOperator,
		RunE: func(cmd *cobra.Command, args []string) error {
			index, err := strconv.Atoi(args[1])
			if err != nil {
				return newUsageError("group rule index must be a number")
			}
			return runPolicyGroupRuleRM(cmd, args[0], index)
		},
	}
	cmd.AddCommand(addCmd, lsCmd, rmCmd)
	return cmd
}

func newPolicyRuleCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "rule",
		Short: "Manage global policy rules.",
	}
	lsCmd := &cobra.Command{
		Use:   "ls",
		Short: "List global policy rules.",
		Args:  noArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runPolicyRuleLS(cmd)
		},
	}
	var add policyRuleOptions
	addCmd := &cobra.Command{
		Use:               "add <name> --cmd-regex <regex> --action allow|deny [--priority <int>]",
		Short:             "Add a global policy rule.",
		Args:              exactArgs(1),
		PersistentPreRunE: requireOperator,
		RunE: func(cmd *cobra.Command, args []string) error {
			add.Name = args[0]
			if !cmd.Flags().Changed("action") {
				return newUsageError("policy rule add requires --action allow|deny")
			}
			return runPolicyRuleAdd(cmd, add)
		},
	}
	addCmd.Flags().StringVar(&add.CmdRegex, "cmd-regex", "", "command regex to match")
	addCmd.Flags().StringVar(&add.Action, "action", "", "policy action: allow or deny")
	addCmd.Flags().IntVar(&add.Priority, "priority", 0, "rule priority; higher values evaluate first")

	var update policyRuleOptions
	updateCmd := &cobra.Command{
		Use:               "update <name> [--name <new-name>] [--cmd-regex <regex>] [--action allow|deny] [--priority <int>]",
		Short:             "Update a global policy rule.",
		Args:              exactArgs(1),
		PersistentPreRunE: requireOperator,
		RunE: func(cmd *cobra.Command, args []string) error {
			update.Name = args[0]
			flags := cmd.Flags()
			update.NewNameSet = flags.Changed("name")
			update.CmdRegexSet = flags.Changed("cmd-regex")
			update.ActionSet = flags.Changed("action")
			update.PrioritySet = flags.Changed("priority")
			return runPolicyRuleUpdate(cmd, update)
		},
	}
	updateCmd.Flags().StringVar(&update.NewName, "name", "", "new rule name")
	updateCmd.Flags().StringVar(&update.CmdRegex, "cmd-regex", "", "command regex to match")
	updateCmd.Flags().StringVar(&update.Action, "action", "", "policy action: allow or deny")
	updateCmd.Flags().IntVar(&update.Priority, "priority", 0, "rule priority; higher values evaluate first")

	rmCmd := &cobra.Command{
		Use:               "rm <name>",
		Aliases:           []string{"remove", "delete"},
		Short:             "Remove a global policy rule.",
		Args:              exactArgs(1),
		PersistentPreRunE: requireOperator,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runPolicyRuleRM(cmd, args[0])
		},
	}
	cmd.AddCommand(lsCmd, addCmd, updateCmd, rmCmd)
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
		Args:  noArgs,
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
			Args:  noArgs,
			RunE: func(cmd *cobra.Command, _ []string) error {
				return runAuditVerify(cmd)
			},
		},
		newAuditRepairCommand(),
	)
	return cmd
}

func newAuditRepairCommand() *cobra.Command {
	var truncateBroken bool
	cmd := &cobra.Command{
		Use:               "repair --truncate-broken",
		Short:             "Repair a broken audit log by truncating the unverifiable tail.",
		Args:              noArgs,
		PersistentPreRunE: requireOperator,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if !truncateBroken {
				return newUsageError("audit repair requires --truncate-broken")
			}
			return runAuditRepair(cmd)
		},
	}
	cmd.Flags().BoolVar(&truncateBroken, "truncate-broken", false, "remove the first broken audit record and every later record")
	return cmd
}

func newApprovalCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "approval",
		Short: "Inspect and adjudicate async approvals.",
	}
	var lsJSON bool
	lsCmd := &cobra.Command{
		Use:               "ls [--json]",
		Short:             "List pending approval requests.",
		Args:              noArgs,
		PersistentPreRunE: requireOperator,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runApprovalLS(cmd, lsJSON)
		},
	}
	lsCmd.Flags().BoolVar(&lsJSON, "json", false, "emit machine-readable JSON")

	var grantOnce, grantSession, grantHost bool
	grantCmd := &cobra.Command{
		Use:               "grant <id> --once|--session|--host",
		Short:             "Approve a pending request.",
		Args:              exactArgs(1),
		PersistentPreRunE: requireOperator,
		RunE: func(cmd *cobra.Command, args []string) error {
			scope, err := approvalScopeFromFlags(grantOnce, grantSession, grantHost)
			if err != nil {
				return err
			}
			return runApprovalGrant(cmd, args[0], scope)
		},
	}
	grantCmd.Flags().BoolVar(&grantOnce, "once", false, "approve one rerun")
	grantCmd.Flags().BoolVar(&grantSession, "session", false, "approve this session")
	grantCmd.Flags().BoolVar(&grantHost, "host", false, "persist an approval host rule")

	denyCmd := &cobra.Command{
		Use:               "deny <id>",
		Short:             "Deny a pending request.",
		Args:              exactArgs(1),
		PersistentPreRunE: requireOperator,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runApprovalDeny(cmd, args[0])
		},
	}
	statusCmd := &cobra.Command{
		Use:   "status <id>",
		Short: "Read one approval result.",
		Args:  exactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runApprovalStatus(cmd, args[0])
		},
	}
	var waitTimeout string
	waitCmd := &cobra.Command{
		Use:   "wait <id> [--timeout <duration>]",
		Short: "Wait for an approval result.",
		Args:  exactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runApprovalWait(cmd, args[0], waitTimeout)
		},
	}
	waitCmd.Flags().StringVar(&waitTimeout, "timeout", "", "maximum wait duration, e.g. 10m")

	cmd.AddCommand(lsCmd, grantCmd, denyCmd, statusCmd, waitCmd)
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
		Args:  noArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runSessionLS(cmd)
		},
	})
	cmd.AddCommand(&cobra.Command{
		Use:   "new",
		Short: "Mint a fresh session id for a task.",
		Long: "Print a fresh session id. Bind a task's runs to it so audit groups them:\n" +
			"  AGENTSSH_SESSION=$(agentssh session new)",
		Args: noArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			id, err := session.NewID()
			if err != nil {
				return err
			}
			_, _ = fmt.Fprintln(cmd.OutOrStdout(), id)
			return nil
		},
	})
	cmd.AddCommand(&cobra.Command{
		Use:               "end <id>",
		Short:             "Clear approval grants for a session.",
		Args:              exactArgs(1),
		PersistentPreRunE: requireOperator,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runSessionEnd(cmd, args[0])
		},
	})
	return cmd
}

func leafNoArgs(use string, short string, hint string) *cobra.Command {
	return &cobra.Command{
		Use:   use,
		Short: short,
		Args:  noArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "not implemented yet — %s\n", hint)
			return nil
		},
	}
}

// noArgs is cobra.NoArgs but returns our usageError so extra args exit 2.
func noArgs(cmd *cobra.Command, args []string) error {
	if err := cobra.NoArgs(cmd, args); err != nil {
		return usageError(err.Error())
	}
	return nil
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

type runFlags struct {
	session      string
	sessionLabel string
	jsonOutput   bool
}

type runResponse struct {
	ReqID           string   `json:"req_id"`
	SessionID       string   `json:"session_id"`
	Host            string   `json:"host"`
	Cmd             string   `json:"cmd,omitempty"`
	Status          string   `json:"status"`
	ExitCode        int      `json:"exit_code"`
	DurationMS      int64    `json:"duration_ms"`
	Stdout          string   `json:"stdout"`
	Stderr          string   `json:"stderr"`
	OutputTruncated bool     `json:"output_truncated"`
	Redactions      int      `json:"redactions"`
	PolicyAction    string   `json:"policy_action,omitempty"`
	PolicyRule      string   `json:"policy_rule,omitempty"`
	ApprovalID      string   `json:"approval_id,omitempty"`
	ApprovalMatcher string   `json:"approval_matcher,omitempty"`
	ProposedScopes  []string `json:"proposed_scope,omitempty"`
}

type runPlan struct {
	Target     inventory.Target
	ReqID      string
	SessionCtx session.Context
	Auth       approval.Authorization
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
	exitApprovalRequired,
	exitSSHError,
}

func classifyConfigError(err error) error {
	if err == nil {
		return nil
	}
	if errors.As(err, &config.MissingHomeError{}) {
		return newUsageError("%v", err)
	}
	var parseErr config.ParseError
	if errors.As(err, &parseErr) {
		return newUsageError("%v\n  fix the YAML in ~/.agentssh and re-run; validate with: agentssh hosts / agentssh policy show", err)
	}
	var setupErr config.SetupError
	if errors.As(err, &setupErr) {
		return newUsageError("%v\n  fix AGENTSSH_HOME or your ~/.agentssh setup, then re-run", err)
	}
	return fmt.Errorf("%w", err)
}

func selectedTransport(cfg *config.Config) string {
	transport := ""
	if env := os.Getenv("AGENTSSH_TRANSPORT"); env != "" {
		transport = env
	} else if cfg != nil {
		transport = cfg.Inventory.Transport
	}
	switch transport {
	case "", executor.TransportNative:
		return executor.TransportNative
	case executor.TransportShell:
		return executor.TransportShell
	default:
		return executor.TransportNative
	}
}

func sshMultiplexingEnabled(cfg *config.Config) bool {
	if cfg == nil {
		return true
	}
	switch strings.ToLower(strings.TrimSpace(cfg.Inventory.SSH.Multiplexing)) {
	case "", "on", "true", "yes", "1", "auto":
		return true
	case "off", "false", "no", "0", "disabled":
		return false
	default:
		return true
	}
}

func sshControlPersist(cfg *config.Config) time.Duration {
	if cfg == nil {
		return 0
	}
	return sshDuration(cfg.Inventory.SSH.ControlPersist)
}

func sshKeepAliveInterval(cfg *config.Config) time.Duration {
	if cfg == nil {
		return 0
	}
	return sshDuration(cfg.Inventory.SSH.KeepAliveInterval)
}

func sshDuration(value string) time.Duration {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0
	}
	duration, err := time.ParseDuration(value)
	if err != nil {
		return 0
	}
	return duration
}

type inventoryAddOptions struct {
	Name         string
	Addr         string
	User         string
	Port         int
	Alias        string
	IdentityFile string
	Password     bool
	Tags         string
}

type inventoryUpdateOptions struct {
	Name            string
	Addr            string
	User            string
	Port            int
	Alias           string
	IdentityFile    string
	Tags            string
	AddrSet         bool
	UserSet         bool
	PortSet         bool
	AliasSet        bool
	IdentityFileSet bool
	TagsSet         bool
}

type inventoryDiscoverOptions struct {
	Probe  bool
	JSON   bool
	Import bool
}

type policyRuleOptions struct {
	Name        string
	NewName     string
	CmdRegex    string
	Action      string
	Priority    int
	NewNameSet  bool
	CmdRegexSet bool
	ActionSet   bool
	PrioritySet bool
}

type policyHostRuleOptions struct {
	Host      string
	CmdRegex  string
	Action    string
	Priority  int
	FromGroup string
}

type policyGroupRuleOptions struct {
	Group    string
	CmdRegex string
	Action   string
	Priority int
}

func runInventoryAdd(cmd *cobra.Command, opts inventoryAddOptions) error {
	home, err := config.ResolveHome()
	if err != nil {
		return err
	}
	paths := config.NewPaths(home)
	inv, err := loadInventoryForWrite(paths.InventoryFile)
	if err != nil {
		return err
	}

	formOptions := hostform.Options{
		Name:          opts.Name,
		Addr:          opts.Addr,
		User:          opts.User,
		Port:          opts.Port,
		Tags:          hostform.SplitTags(opts.Tags),
		Alias:         opts.Alias,
		IdentityFile:  strings.TrimSpace(opts.IdentityFile),
		ExistingNames: existingHostNames(inv),
	}
	result, err := hostform.Run(formOptions)
	if hostform.IsNotInteractive(err) {
		result, err = resultFromFlags(formOptions)
	}
	if err != nil {
		return err
	}
	if !result.Submitted {
		return nil
	}
	if !opts.Password {
		return addInventoryHost(paths, inv, result)
	}

	// --password: collect and validate the credential BEFORE mutating inventory,
	// so a failed prompt / missing-or-wrong master / corrupt store never leaves a
	// half-added host. Then add the host and persist the secret, rolling back the
	// inventory entry if the secret write fails, so the two stores stay consistent.
	store, master, err := openSecretsForOperator(cmd, paths.SecretsFile)
	if err != nil {
		return err
	}
	password, err := readSecretNoEcho(fmt.Sprintf("Enter SSH password for %s: ", result.Name))
	if err != nil {
		return err
	}
	if err := addInventoryHost(paths, inv, result); err != nil {
		return err
	}
	store.Set(result.Name, password)
	if err := store.Save(master); err != nil {
		if rbErr := removeInventoryHostByName(paths, result.Name); rbErr != nil {
			return fmt.Errorf("failed to store password (%v) and to roll back inventory add: %w", err, rbErr)
		}
		return fmt.Errorf("failed to store password; rolled back inventory add: %w", err)
	}
	return nil
}

func removeInventoryHostByName(paths config.Paths, name string) error {
	inv, err := loadInventoryForWrite(paths.InventoryFile)
	if err != nil {
		return err
	}
	next, err := inventory.RemoveHost(inv, name)
	if err != nil {
		return err
	}
	if err := writeInventoryAtomic(paths.Home, paths.InventoryFile, next); err != nil {
		return err
	}
	return clearHostRulesForDeletedHost(paths, name)
}

func resultFromFlags(opts hostform.Options) (hostform.Result, error) {
	result, errs := hostform.Validate(opts)
	if len(errs) == 0 {
		result.Submitted = true
		return result, nil
	}
	if opts.Name == "" {
		return result, newUsageError("inventory add requires [name] in non-interactive mode; example: agentssh inventory add web-1 --addr 10.0.0.11")
	}
	if opts.Addr == "" && opts.Alias == "" {
		return result, newUsageError("inventory add requires --addr or --alias in non-interactive mode")
	}
	return result, newUsageError("invalid inventory host: %s", firstValidationError(errs))
}

func firstValidationError(errs map[string]string) string {
	keys := []string{"name", "addr", "user", "port", "tags", "alias"}
	for _, key := range keys {
		if errs[key] != "" {
			return errs[key]
		}
	}
	return "unknown validation error"
}

func loadInventoryForWrite(path string) (inventory.Inventory, error) {
	inv, err := inventory.Load(path)
	if err != nil {
		return inv, config.ParseError{File: path, Err: err}
	}
	return inv, nil
}

func addInventoryHost(paths config.Paths, inv inventory.Inventory, result hostform.Result) error {
	next, err := inventory.AddHost(inv, result.Name, inventory.Host{
		Addr:           result.Addr,
		User:           result.User,
		Port:           result.Port,
		SSHConfigAlias: result.Alias,
		IdentityFile:   result.Identity,
		Tags:           result.Tags,
	})
	if errors.Is(err, inventory.ErrHostExists) {
		return newUsageError("inventory host %q already exists", result.Name)
	}
	if err != nil {
		return err
	}
	return writeInventoryAtomic(paths.Home, paths.InventoryFile, next)
}

func runInventoryUpdate(cmd *cobra.Command, opts inventoryUpdateOptions) error {
	if !opts.AddrSet && !opts.UserSet && !opts.PortSet && !opts.AliasSet && !opts.IdentityFileSet && !opts.TagsSet {
		return newUsageError("inventory update requires at least one field flag")
	}
	paths, err := resolvePathsForWrite()
	if err != nil {
		return err
	}
	base, err := loadInventoryForWrite(paths.InventoryFile)
	if err != nil {
		return err
	}
	existing, ok := base.Hosts[opts.Name]
	if !ok {
		return newUsageError("inventory host %q not found", opts.Name)
	}
	nextHost := existing
	if opts.AddrSet {
		nextHost.Addr = strings.TrimSpace(opts.Addr)
	}
	if opts.UserSet {
		nextHost.User = strings.TrimSpace(opts.User)
	}
	if opts.PortSet {
		nextHost.Port = opts.Port
	}
	if opts.AliasSet {
		nextHost.SSHConfigAlias = strings.TrimSpace(opts.Alias)
	}
	if opts.IdentityFileSet {
		nextHost.IdentityFile = strings.TrimSpace(opts.IdentityFile)
	}
	if opts.TagsSet {
		nextHost.Tags = hostform.SplitTags(opts.Tags)
	}
	if nextHost.Addr == "" && nextHost.SSHConfigAlias == "" {
		return newUsageError("inventory host requires --addr or --alias")
	}
	if opts.PortSet && (nextHost.Port < 1 || nextHost.Port > 65535) {
		return newUsageError("port must be a number from 1 to 65535")
	}
	next, err := inventory.UpdateHost(base, opts.Name, nextHost)
	if err != nil {
		return err
	}
	if err := writeInventoryAtomic(paths.Home, paths.InventoryFile, next); err != nil {
		return err
	}
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "updated host %s\n", opts.Name)
	return nil
}

func runInventoryRM(cmd *cobra.Command, name string) error {
	paths, err := resolvePathsForWrite()
	if err != nil {
		return err
	}
	base, err := loadInventoryForWrite(paths.InventoryFile)
	if err != nil {
		if auditErr := appendInventoryAudit(paths, audit.EventFailed, name, "inventory rm "+name, err.Error(), exitRemoteFailed); auditErr != nil {
			return auditErr
		}
		return err
	}
	next, err := inventory.RemoveHost(base, name)
	if err != nil {
		if errors.Is(err, inventory.ErrHostNotFound) {
			if auditErr := appendInventoryAudit(paths, audit.EventFailed, name, "inventory rm "+name, err.Error(), exitUsage); auditErr != nil {
				return auditErr
			}
			return newUsageError("inventory host %q not found", name)
		}
		if auditErr := appendInventoryAudit(paths, audit.EventFailed, name, "inventory rm "+name, err.Error(), exitRemoteFailed); auditErr != nil {
			return auditErr
		}
		return err
	}
	if err := clearHostRulesForDeletedHost(paths, name); err != nil {
		if auditErr := appendInventoryAudit(paths, audit.EventFailed, name, "inventory rm "+name, err.Error(), exitRemoteFailed); auditErr != nil {
			return auditErr
		}
		return err
	}
	if err := writeInventoryAtomic(paths.Home, paths.InventoryFile, next); err != nil {
		if auditErr := appendInventoryAudit(paths, audit.EventFailed, name, "inventory rm "+name, err.Error(), exitRemoteFailed); auditErr != nil {
			return auditErr
		}
		return err
	}
	if err := appendInventoryAudit(paths, audit.EventCompleted, name, "inventory rm "+name, "", exitOK); err != nil {
		return err
	}
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "removed host %s\n", name)
	return nil
}

func clearHostRulesForDeletedHost(paths config.Paths, name string) error {
	cfg, err := policy.Load(paths.PolicyFile)
	if err != nil {
		return config.ParseError{File: paths.PolicyFile, Err: err}
	}
	next, err := policy.ClearHostRules(policy.Bundle{Policy: cfg}, name)
	if errors.Is(err, policy.ErrNoHostRules) {
		return nil
	}
	if err != nil {
		return err
	}
	return saveValidatedPolicy(paths, next.Policy)
}

func writeInventoryAtomic(home string, path string, inv inventory.Inventory) error {
	_ = home
	return inventory.Save(path, inv)
}

func appendInventoryAudit(paths config.Paths, event audit.Event, host string, command string, errText string, exitCode int) error {
	reqID, err := audit.NewReqID()
	if err != nil {
		return err
	}
	exit := exitCode
	record := audit.Record{
		ReqID:        reqID,
		Event:        event,
		Host:         host,
		Cmd:          command,
		Error:        errText,
		ExitCode:     &exit,
		SessionID:    "",
		SessionLabel: "",
	}
	_, err = audit.NewStore(paths.AuditFile).Append(record)
	return err
}

func refreshInventoryHostOS(paths config.Paths, hostName string, osName string) {
	_ = updateInventoryHostOS(paths, hostName, osName)
}

func updateInventoryHostOS(paths config.Paths, hostName string, osName string) error {
	osName = strings.TrimSpace(osName)
	if hostName == "" || osName == "" || paths.InventoryFile == "" {
		return nil
	}
	inv, err := inventory.Load(paths.InventoryFile)
	if err != nil {
		return err
	}
	if host, ok := inv.Hosts[hostName]; !ok || host.OS == osName {
		return nil
	}
	next, err := inventory.SetHostOS(inv, hostName, osName)
	if err != nil {
		return err
	}
	return inventory.Save(paths.InventoryFile, next)
}

func runSecretSet(cmd *cobra.Command, host string) error {
	paths, err := resolvePathsForWrite()
	if err != nil {
		return err
	}
	if err := setHostPassword(cmd, paths.SecretsFile, host); err != nil {
		return err
	}
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "stored password for %s\n", host)
	return nil
}

func runSecretLS(cmd *cobra.Command, jsonOutput bool) error {
	paths, err := resolvePathsForWrite()
	if err != nil {
		return err
	}
	store, _, err := openSecretsForOperator(cmd, paths.SecretsFile)
	if err != nil {
		return err
	}
	names := store.Names()
	if jsonOutput {
		return writeJSON(cmd, names)
	}
	out := cmd.OutOrStdout()
	for _, name := range names {
		_, _ = fmt.Fprintln(out, name)
	}
	return nil
}

func runSecretRM(cmd *cobra.Command, host string) error {
	paths, err := resolvePathsForWrite()
	if err != nil {
		return err
	}
	store, master, err := openSecretsForOperator(cmd, paths.SecretsFile)
	if err != nil {
		return err
	}
	store.Delete(host)
	if err := store.Save(master); err != nil {
		return err
	}
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "removed password for %s\n", host)
	return nil
}

func setHostPassword(cmd *cobra.Command, path string, host string) error {
	store, master, err := openSecretsForOperator(cmd, path)
	if err != nil {
		return err
	}
	password, err := readSecretNoEcho(fmt.Sprintf("Enter SSH password for %s: ", host))
	if err != nil {
		return err
	}
	store.Set(host, password)
	return store.Save(master)
}

func runOperatorInit(cmd *cobra.Command) error {
	if !stdinIsTerminal() {
		return newUsageError("operator init requires an interactive TTY")
	}
	home, err := config.ResolveHome()
	if err != nil {
		return err
	}
	created, err := config.EnsureHome(home)
	if err != nil {
		return classifyConfigError(err)
	}
	paths := config.NewPaths(home)
	if os.Getenv(config.EnvHome) != "" {
		_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "WARNING: %s is set; operator verifier will be initialized under %s.\n", config.EnvHome, paths.Home)
	}
	exists, err := fileExists(operatorVerifierPath(paths))
	if err != nil {
		return err
	}
	if exists {
		return newUsageError("operator password verifier already exists at %s", operatorVerifierPath(paths))
	}
	master, err := promptOperatorMaster()
	if err != nil {
		return err
	}
	secretsExist, err := fileExists(paths.SecretsFile)
	if err != nil {
		return err
	}
	if secretsExist {
		if _, err := openSecretsWithMaster(paths.SecretsFile, master); err != nil {
			return err
		}
	} else {
		confirm, err := readSecretNoEcho("Confirm AgentSSH master password: ")
		if err != nil {
			return err
		}
		if confirm != master {
			return newUsageError("operator master password confirmation did not match")
		}
	}
	if err := saveOperatorVerifier(operatorVerifierPath(paths), master); err != nil {
		return err
	}
	if created {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "initialized %s with starter inventory.yaml and policy.yaml\n", home)
	}
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "initialized operator password verifier at %s\n", operatorVerifierPath(paths))
	return nil
}

type operatorMasterContextKey struct{}

// openSecretsForOperator opens the encrypted secrets store using the master
// password that requireOperator verified and cached on the command context.
// Every caller is behind the operator gate, so a missing cached master is an
// internal wiring bug rather than a runtime condition: fail closed.
func openSecretsForOperator(cmd *cobra.Command, path string) (*secrets.Store, string, error) {
	master, ok := operatorMasterFromCommand(cmd)
	if !ok {
		return nil, "", fmt.Errorf("operator master password was not verified by the command gate")
	}
	store, err := openSecretsWithMaster(path, master)
	if err != nil {
		return nil, "", err
	}
	return store, master, nil
}

func openSecretsWithMaster(path string, master string) (*secrets.Store, error) {
	store, err := secrets.Open(path, master)
	if errors.Is(err, secrets.ErrWrongMaster) {
		return nil, newUsageError("cannot open secrets: wrong master password or corrupt secrets file")
	}
	if err != nil {
		return nil, err
	}
	return store, nil
}

func resolvePathsForWrite() (config.Paths, error) {
	home, err := config.ResolveHome()
	if err != nil {
		return config.Paths{}, err
	}
	return config.NewPaths(home), nil
}

func requireOperator(cmd *cobra.Command, _ []string) error {
	if !stdinIsTerminal() {
		return newUsageError("operator commands require an interactive TTY")
	}
	home, err := config.ResolveHome()
	if err != nil {
		return err
	}
	paths := config.NewPaths(home)
	warnEnvHomeForOperatorCommand(cmd, paths.Home)
	master, err := promptOperatorMaster()
	if err != nil {
		return err
	}
	if err := verifyOperatorMaster(paths, master); err != nil {
		return err
	}
	cmd.SetContext(context.WithValue(cmd.Context(), operatorMasterContextKey{}, master))
	return nil
}

func warnEnvHomeForOperatorCommand(cmd *cobra.Command, home string) {
	if os.Getenv(config.EnvHome) == "" {
		return
	}
	_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "WARNING: %s is set; operator-gated command will use config directory %s. Ensure this was selected by the human operator.\n", config.EnvHome, home)
}

func verifyOperatorMaster(paths config.Paths, master string) error {
	if master == "" {
		return newUsageError("operator master password is required")
	}
	exists, err := fileExists(paths.SecretsFile)
	if err != nil {
		return err
	}
	if exists {
		_, err := openSecretsWithMaster(paths.SecretsFile, master)
		return err
	}
	if err := verifyOperatorVerifier(operatorVerifierPath(paths), master); err != nil {
		return operatorVerifierUsageError(err)
	}
	return nil
}

func operatorVerifierUsageError(err error) error {
	switch {
	case errors.Is(err, os.ErrNotExist):
		return newUsageError("operator password verifier is not initialized; run 'agentssh operator init' from an interactive terminal")
	case errors.Is(err, secrets.ErrWrongMaster):
		return newUsageError("cannot verify operator master password: wrong password or corrupt operator verifier")
	default:
		return err
	}
}

func promptOperatorMaster() (string, error) {
	master, err := readSecretNoEcho("Enter AgentSSH master password: ")
	if err != nil {
		return "", err
	}
	if master == "" {
		return "", newUsageError("operator master password is required")
	}
	return master, nil
}

func operatorMasterFromCommand(cmd *cobra.Command) (string, bool) {
	if cmd == nil {
		return "", false
	}
	master, ok := cmd.Context().Value(operatorMasterContextKey{}).(string)
	if !ok || master == "" {
		return "", false
	}
	return master, true
}

func operatorVerifierPath(paths config.Paths) string {
	return operatorVerifierPathForHome(paths.Home)
}

func operatorVerifierPathForHome(home string) string {
	return filepath.Join(home, operatorVerifierFile)
}

type operatorVerifierPayload struct {
	Version int    `json:"version"`
	Purpose string `json:"purpose"`
}

func saveOperatorVerifier(path string, master string) error {
	recipient, err := age.NewScryptRecipient(master)
	if err != nil {
		return secrets.ErrWrongMaster
	}
	payload := operatorVerifierPayload{
		Version: operatorVerifierVersion,
		Purpose: operatorVerifierPurpose,
	}
	plaintext, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal operator verifier: %w", err)
	}
	var ciphertext bytes.Buffer
	writer, err := age.Encrypt(&ciphertext, recipient)
	if err != nil {
		return fmt.Errorf("create operator verifier encryptor: %w", err)
	}
	if _, err := writer.Write(plaintext); err != nil {
		_ = writer.Close()
		return fmt.Errorf("encrypt operator verifier: %w", err)
	}
	if err := writer.Close(); err != nil {
		return fmt.Errorf("finalize operator verifier: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create operator verifier directory: %w", err)
	}
	if err := fileutil.WriteFileAtomic(path, ciphertext.Bytes(), 0o600, "operator-verifier-*.age"); err != nil {
		return fileutil.LabelAtomicError(err, "operator verifier")
	}
	return nil
}

func verifyOperatorVerifier(path string, master string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	identity, err := age.NewScryptIdentity(master)
	if err != nil {
		return secrets.ErrWrongMaster
	}
	reader, err := age.Decrypt(bytes.NewReader(data), identity)
	if err != nil {
		return secrets.ErrWrongMaster
	}
	plaintext, err := io.ReadAll(reader)
	if err != nil {
		return secrets.ErrWrongMaster
	}
	var payload operatorVerifierPayload
	if err := json.Unmarshal(plaintext, &payload); err != nil {
		return secrets.ErrWrongMaster
	}
	if payload.Version != operatorVerifierVersion || payload.Purpose != operatorVerifierPurpose {
		return secrets.ErrWrongMaster
	}
	return nil
}

func fileExists(path string) (bool, error) {
	_, err := os.Stat(path)
	if err == nil {
		return true, nil
	}
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	return false, err
}

func passwordSourceForRun(paths config.Paths) func(string) (string, bool) {
	return secrets.EnvPasswordSource(paths.SecretsFile)
}

func readSecretFromTTY(prompt string) (string, error) {
	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		return "", newUsageError("interactive TTY is required to read secrets without echo")
	}
	_, _ = fmt.Fprint(os.Stderr, prompt)
	value, err := term.ReadPassword(fd)
	_, _ = fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", fmt.Errorf("read secret: %w", err)
	}
	return string(value), nil
}

func existingHostNames(inv inventory.Inventory) map[string]struct{} {
	return inventory.HostNames(inv)
}

func runInventoryLS(cmd *cobra.Command, jsonOutput bool) error {
	cfg, err := config.Load()
	if err != nil {
		return classifyConfigError(err)
	}
	if jsonOutput {
		return writeJSON(cmd, cfg.Inventory)
	}
	printInventory(cmd, cfg.Inventory)
	return nil
}

func printInventory(cmd *cobra.Command, inv inventory.Inventory) {
	out := cmd.OutOrStdout()
	if inv.Transport != "" || inv.HostKeyPolicy != "" {
		parts := []string{}
		if inv.Transport != "" {
			parts = append(parts, "transport="+inv.Transport)
		}
		if inv.HostKeyPolicy != "" {
			parts = append(parts, "host_key_policy="+inv.HostKeyPolicy)
		}
		_, _ = fmt.Fprintln(out, strings.Join(parts, " "))
	}

	_, _ = fmt.Fprintln(out, "Hosts:")
	hostNames := sortedHostNamesLocal(inv.Hosts)
	if len(hostNames) == 0 {
		_, _ = fmt.Fprintln(out, "  (none)")
	}
	for _, name := range hostNames {
		host := inv.Hosts[name]
		_, _ = fmt.Fprintf(out, "  %s", name)
		for _, part := range hostParts(host) {
			_, _ = fmt.Fprintf(out, " %s", part)
		}
		_, _ = fmt.Fprintln(out)
	}

	_, _ = fmt.Fprintln(out, "Groups:")
	groupNames := sortedGroupNamesLocal(inv.Groups)
	if len(groupNames) == 0 {
		_, _ = fmt.Fprintln(out, "  (none)")
	}
	for _, name := range groupNames {
		group := inv.Groups[name]
		_, _ = fmt.Fprintf(out, "  %s", name)
		if len(group.Tags) > 0 {
			_, _ = fmt.Fprintf(out, " tags=%s", strings.Join(group.Tags, ","))
		}
		_, _ = fmt.Fprintln(out)
	}
}

func hostParts(host inventory.Host) []string {
	var parts []string
	if host.Addr != "" {
		parts = append(parts, "addr="+host.Addr)
	}
	if host.User != "" {
		parts = append(parts, "user="+host.User)
	}
	if host.Port != 0 {
		parts = append(parts, "port="+strconv.Itoa(host.Port))
	}
	if host.SSHConfigAlias != "" {
		parts = append(parts, "alias="+host.SSHConfigAlias)
	}
	if host.OS != "" {
		parts = append(parts, "os="+host.OS)
	}
	if host.IdentityFile != "" {
		parts = append(parts, "identity_file="+host.IdentityFile)
	}
	if len(host.Tags) > 0 {
		parts = append(parts, "tags="+strings.Join(host.Tags, ","))
	}
	return parts
}

func runInventoryDiscover(cmd *cobra.Command, opts inventoryDiscoverOptions) error {
	cfg, err := config.Load()
	if err != nil {
		return classifyConfigError(err)
	}
	result, err := discovery.Static(discovery.Options{
		ConfigPath:     filepath.Join(os.Getenv("HOME"), ".ssh", "config"),
		KnownHostsPath: filepath.Join(os.Getenv("HOME"), ".ssh", "known_hosts"),
		Home:           os.Getenv("HOME"),
		Inventory:      cfg.Inventory,
	})
	if err != nil {
		return err
	}
	if opts.Probe {
		exec := executor.NewNativeExecutor(executor.NativeOptions{
			ConfigPath:     filepath.Join(os.Getenv("HOME"), ".ssh", "config"),
			KnownHostsPath: filepath.Join(os.Getenv("HOME"), ".ssh", "known_hosts"),
			ConnectTimeout: executor.ProbeTimeout,
			HostKeyPolicy:  cfg.Inventory.HostKeyPolicy,
			// Use stored passwords so a password-only host probes the same way it
			// will run (env-only master; no prompting across many candidates).
			PasswordSource: passwordSourceForRun(cfg.Paths),
		})
		defer func() { _ = exec.Close() }()
		result.Candidates = discovery.Probe(context.Background(), result.Candidates, discovery.ProbeOptions{
			Executor:    exec,
			Timeout:     executor.ProbeTimeout,
			Concurrency: 4,
		})
	}
	imported := 0
	if opts.Import {
		next := cfg.Inventory
		seen := discovery.EndpointKeys(cfg.Inventory)
		for _, candidate := range result.Candidates {
			if candidate.InInventory || candidate.ProbeStatus != executor.ProbeConnectable {
				continue
			}
			// Endpoint (not just name) de-dup: a discovered alias that resolves to
			// a machine already in inventory must not be added again, or group/tag
			// runs would execute the same host twice.
			key := discovery.EndpointKey(candidate.Addr, candidate.Port)
			if key != "" && seen[key] {
				continue
			}
			var addErr error
			next, addErr = inventory.AddHost(next, candidate.Name, discovery.ImportHost(candidate))
			if errors.Is(addErr, inventory.ErrHostExists) {
				continue
			}
			if addErr != nil {
				return addErr
			}
			if key != "" {
				seen[key] = true
			}
			imported++
		}
		if imported > 0 {
			if err := inventory.Save(cfg.Paths.InventoryFile, next); err != nil {
				return err
			}
		}
	}
	if opts.JSON {
		return writeJSON(cmd, result)
	}
	printDiscovery(cmd, result, imported)
	return nil
}

func printDiscovery(cmd *cobra.Command, result discovery.Result, imported int) {
	out := cmd.OutOrStdout()
	_, _ = fmt.Fprintln(out, "NAME\tSOURCE\tADDR\tKEY\tKNOWN_HOSTS\tINVENTORY\tSTATUS")
	for _, candidate := range result.Candidates {
		key := "-"
		if candidate.HasKey {
			key = "yes"
		}
		known := "no"
		if candidate.InKnownHosts {
			known = "yes"
		}
		inv := "no"
		if candidate.InInventory {
			inv = "yes"
		}
		_, _ = fmt.Fprintf(out, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n", candidate.Name, candidate.Source, formatCandidateAddr(candidate), key, known, inv, candidateStatus(candidate))
		if candidate.Hint != "" {
			_, _ = fmt.Fprintf(out, "  %s\n", candidate.Hint)
		}
	}
	for _, note := range result.Notes {
		_, _ = fmt.Fprintf(out, "note: %s\n", note)
	}
	if imported > 0 {
		_, _ = fmt.Fprintf(out, "imported=%d\n", imported)
	}
}

func candidateStatus(candidate discovery.Candidate) string {
	if candidate.ProbeStatus != "" {
		return string(candidate.ProbeStatus)
	}
	if candidate.InInventory {
		return "imported"
	}
	if candidate.HasKey {
		return "looks-connectable"
	}
	return "needs-auth"
}

func formatCandidateAddr(candidate discovery.Candidate) string {
	if candidate.Port == 0 || candidate.Port == 22 {
		return candidate.Addr
	}
	return fmt.Sprintf("%s:%d", candidate.Addr, candidate.Port)
}

func runInventoryTest(cmd *cobra.Command, name string) error {
	cfg, err := config.Load()
	if err != nil {
		return classifyConfigError(err)
	}
	resolved, err := inventory.NewResolver(cfg.Inventory).Resolve(name)
	if err != nil {
		if inventory.IsUnknown(err) {
			return newUsageError("%v\n  list all hosts: agentssh hosts", err)
		}
		return newUsageError("%v\n  choose a concrete host, not an empty group", err)
	}
	if resolved.Kind != inventory.TargetKindHost || len(resolved.Targets) != 1 {
		return newUsageError("inventory test requires a host name, got group %q", name)
	}
	exec := executor.NewNativeExecutor(executor.NativeOptions{
		ConnectTimeout: executor.ProbeTimeout,
		HostKeyPolicy:  cfg.Inventory.HostKeyPolicy,
		// Test the same credentials `run` will use, including a stored password
		// (env-only master).
		PasswordSource: passwordSourceForRun(cfg.Paths),
	})
	defer func() { _ = exec.Close() }()
	result := exec.Probe(context.Background(), resolved.Targets[0])
	if result.Err == nil && result.ExitCode == 0 {
		refreshInventoryHostOS(cfg.Paths, name, result.OS)
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "OK %s\n", name)
		return nil
	}
	if result.Err != nil {
		_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "FAILED %s: %v\n%s\n", name, result.Err, executor.ConnectHint(result.Err))
	} else {
		_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "FAILED %s: probe command exited %d\n", name, result.ExitCode)
	}
	return commandExitError{Code: exitSSHError}
}

func sortedHostNamesLocal(hosts map[string]inventory.Host) []string {
	names := make([]string, 0, len(hosts))
	for name := range hosts {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func sortedGroupNamesLocal(groups map[string]inventory.Group) []string {
	names := make([]string, 0, len(groups))
	for name := range groups {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
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
	runtime := approvalRuntimeWithWarning(cmd, cfg)

	resolved, err := inventory.NewResolver(cfg.Inventory).Resolve(targetName)
	if err != nil {
		if inventory.IsUnknown(err) {
			return newUsageError("%v\n  list all hosts: agentssh hosts", err)
		}
		// e.g. a group whose tags match no hosts.
		return newUsageError("%v\n  list hosts and tags with: agentssh hosts", err)
	}

	outputFilter, err := output.NewFilter(cfg.Policy.Output)
	if err != nil {
		return newUsageError("invalid output filter in policy.yaml: %v\n  fix the regex under output.redact in ~/.agentssh/policy.yaml", err)
	}
	store := audit.NewStore(cfg.Paths.AuditFile)
	sessionStore := approval.SessionStore{Dir: cfg.Paths.SessionsDir}
	pendingStore := approval.PendingStore{PendingDir: cfg.Paths.PendingDir, ResponsesDir: cfg.Paths.ResponsesDir}
	ssh := newExecutor(cfg)
	defer func() { _ = ssh.Close() }()
	plans, err := buildRunPlans(cfg, resolved, remoteCommand, flags, runtime, sessionStore, runtime.Enabled)
	if err != nil {
		return err
	}
	if runtime.Enabled && anyPlanNeedsApproval(plans) {
		return handleApprovalPreflightBlock(cmd, pendingStore, store, plans, remoteCommand, flags, resolved)
	}

	exitCode := exitOK
	responses := make([]runResponse, 0, len(resolved.Targets))
	for _, plan := range plans {
		target := plan.Target
		sessionCtx := plan.SessionCtx
		reqID := plan.ReqID
		auth, err := approval.Authorize(cfg.Policy, cfg.Inventory, sessionStore, runtime, sessionCtx.ID, target.Name, remoteCommand)
		if err != nil {
			return newUsageError("policy.yaml is invalid: %v\n  fix the rule in ~/.agentssh/policy.yaml, then re-run (check: agentssh policy show)", err)
		}
		plan.Auth = auth
		switch auth.Status {
		case approval.AuthHardDeny:
			response, err := appendDeniedRun(cmd, store, plan, remoteCommand, flags, exitPolicyDenied)
			if err != nil {
				return err
			}
			if flags.jsonOutput {
				responses = append(responses, response)
			}
			exitCode = mergeExitCode(exitCode, exitPolicyDenied)
			continue
		case approval.AuthNeedsApproval:
			if !runtime.Enabled {
				response, err := appendDeniedRun(cmd, store, plan, remoteCommand, flags, exitPolicyDenied)
				if err != nil {
					return err
				}
				if flags.jsonOutput {
					responses = append(responses, response)
				}
				exitCode = mergeExitCode(exitCode, exitPolicyDenied)
				continue
			}
			response, err := appendApprovalPending(cmd, pendingStore, store, plan, remoteCommand, flags)
			if err != nil {
				return err
			}
			if flags.jsonOutput {
				responses = append(responses, response)
			}
			exitCode = mergeExitCode(exitCode, exitApprovalRequired)
			continue
		case approval.AuthAllow, approval.AuthAllowByGrant:
		default:
			return fmt.Errorf("unknown approval authorization status %q", auth.Status)
		}

		decision := auth.Decision
		if _, err := store.Append(baseAuditRecord(reqID, sessionCtx, audit.EventStarted, target.Name, remoteCommand, decision, nil, "", 0)); err != nil {
			return err
		}
		streamExec, canStream := ssh.(executor.StreamingExecutor)
		streamFilter, canStreamFilter := outputFilter.(output.StreamFilter)
		if canStream && canStreamFilter && shouldStreamRun(flags, resolved) {
			streamed := runStreaming(cmd, streamExec, target, remoteCommand, streamFilter)
			result := streamed.Result
			status := statusForResult(result)
			event := audit.EventCompleted
			if status != "completed" {
				event = audit.EventFailed
			}
			outputHash := audit.ComputeOutputSHA256(string(streamed.Stdout), string(streamed.Stderr))
			filtered := output.FilterResult{
				OutputTruncated: streamed.OutputTruncated,
				Redactions:      streamed.Redactions,
			}
			if _, err := store.Append(baseAuditRecord(reqID, sessionCtx, event, target.Name, remoteCommand, decision, &result.ExitCode, outputHash, result.Duration.Milliseconds(), filtered)); err != nil {
				return err
			}
			if !isSSHErrorResult(result) {
				refreshInventoryHostOS(cfg.Paths, target.Name, result.OS)
			}
			printRunStreamFooter(cmd, target.Name, result, streamed.Stdout)
			exitCode = mergeExitCode(exitCode, exitCodeForResult(result))
			continue
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
		if _, err := store.Append(baseAuditRecord(reqID, sessionCtx, event, target.Name, remoteCommand, decision, &result.ExitCode, outputHash, result.Duration.Milliseconds(), filtered)); err != nil {
			return err
		}
		if !isSSHErrorResult(result) {
			refreshInventoryHostOS(cfg.Paths, target.Name, result.OS)
		}
		if flags.jsonOutput {
			responses = append(responses, runResponse{
				ReqID:           reqID,
				SessionID:       sessionCtx.ID,
				Host:            target.Name,
				Cmd:             remoteCommand,
				Status:          status,
				ExitCode:        result.ExitCode,
				DurationMS:      result.Duration.Milliseconds(),
				Stdout:          filtered.Stdout,
				Stderr:          filtered.Stderr,
				OutputTruncated: filtered.OutputTruncated,
				Redactions:      filtered.Redactions,
				PolicyAction:    string(decision.Action),
				PolicyRule:      decision.Rule,
			})
			if isSSHErrorResult(result) {
				printSSHErrorHint(cmd, result)
			}
		} else {
			printRunHuman(cmd, target.Name, result, filtered)
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

func approvalRuntime(cfg *config.Config) (approval.RuntimeConfig, error) {
	if cfg == nil {
		return approval.RuntimeConfigFromPolicy(policy.Approval{}, os.Getenv(config.EnvApproval))
	}
	return approval.RuntimeConfigFromPolicy(cfg.Policy.Approval, os.Getenv(config.EnvApproval))
}

func approvalRuntimeWithWarning(cmd *cobra.Command, cfg *config.Config) approval.RuntimeConfig {
	runtime, err := approvalRuntime(cfg)
	if err == nil {
		return runtime
	}
	_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "WARNING: invalid approval configuration: %v; treating approval as disabled for this run.\n", err)
	return approval.RuntimeConfig{
		Enabled:       false,
		HostGrantMode: approval.HostGrantSafePrefix,
		SessionTTL:    approval.DefaultSessionTTL,
		WaitTimeout:   approval.DefaultWaitTimeout,
	}
}

func buildRunPlans(cfg *config.Config, resolved inventory.ResolvedTarget, remoteCommand string, flags runFlags, runtime approval.RuntimeConfig, sessionStore approval.SessionStore, preflight bool) ([]runPlan, error) {
	sessionResolver := session.Resolver{}
	plans := make([]runPlan, 0, len(resolved.Targets))
	for _, target := range resolved.Targets {
		reqID, err := newReqID()
		if err != nil {
			return nil, err
		}
		sessionCtx, err := sessionResolver.Resolve(target.Name, flags.session, flags.sessionLabel)
		if err != nil {
			if errors.Is(err, session.ErrNoSession) {
				return nil, newUsageError("a session must be declared for run\n" +
					"  pass --session <id> or set AGENTSSH_SESSION (e.g. AGENTSSH_SESSION=$(agentssh session new))\n" +
					"  one session per task keeps the audit trail grouped by task")
			}
			return nil, fmt.Errorf("resolve session: %w", err)
		}
		sessionCtx.ID = sessionIDForTarget(sessionCtx.ID, target.Name, len(resolved.Targets) > 1)
		var auth approval.Authorization
		if preflight {
			auth, err = approval.PreflightAuthorize(cfg.Policy, cfg.Inventory, sessionStore, runtime, sessionCtx.ID, target.Name, remoteCommand)
		} else {
			auth, err = approval.Authorize(cfg.Policy, cfg.Inventory, sessionStore, runtime, sessionCtx.ID, target.Name, remoteCommand)
		}
		if err != nil {
			return nil, newUsageError("policy.yaml is invalid: %v\n  fix the rule in ~/.agentssh/policy.yaml, then re-run (check: agentssh policy show)", err)
		}
		plans = append(plans, runPlan{Target: target, ReqID: reqID, SessionCtx: sessionCtx, Auth: auth})
	}
	return plans, nil
}

func anyPlanNeedsApproval(plans []runPlan) bool {
	for _, plan := range plans {
		if plan.Auth.Status == approval.AuthNeedsApproval {
			return true
		}
	}
	return false
}

func handleApprovalPreflightBlock(cmd *cobra.Command, pending approval.PendingStore, store audit.Store, plans []runPlan, remoteCommand string, flags runFlags, resolved inventory.ResolvedTarget) error {
	exitCode := exitOK
	responses := make([]runResponse, 0, len(plans))
	for _, plan := range plans {
		switch plan.Auth.Status {
		case approval.AuthHardDeny:
			response, err := appendDeniedRun(cmd, store, plan, remoteCommand, flags, exitPolicyDenied)
			if err != nil {
				return err
			}
			responses = append(responses, response)
			exitCode = mergeExitCode(exitCode, exitPolicyDenied)
		case approval.AuthNeedsApproval:
			response, err := appendApprovalPending(cmd, pending, store, plan, remoteCommand, flags)
			if err != nil {
				return err
			}
			responses = append(responses, response)
			exitCode = mergeExitCode(exitCode, exitApprovalRequired)
		default:
			exit := exitApprovalRequired
			if _, err := store.Append(baseAuditRecord(plan.ReqID, plan.SessionCtx, audit.EventDenied, plan.Target.Name, remoteCommand, plan.Auth.Decision, &exit, "", 0)); err != nil {
				return err
			}
			response := runResponse{
				ReqID:        plan.ReqID,
				SessionID:    plan.SessionCtx.ID,
				Host:         plan.Target.Name,
				Cmd:          remoteCommand,
				Status:       "not_run",
				ExitCode:     exitApprovalRequired,
				PolicyAction: string(plan.Auth.Decision.Action),
				PolicyRule:   plan.Auth.Decision.Rule,
			}
			responses = append(responses, response)
			if !flags.jsonOutput {
				printNotRunHuman(cmd, plan.Target.Name)
			}
			exitCode = mergeExitCode(exitCode, exitApprovalRequired)
		}
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

func appendDeniedRun(cmd *cobra.Command, store audit.Store, plan runPlan, remoteCommand string, flags runFlags, exitCode int) (runResponse, error) {
	if _, err := store.Append(baseAuditRecord(plan.ReqID, plan.SessionCtx, audit.EventDenied, plan.Target.Name, remoteCommand, plan.Auth.Decision, nil, "", 0)); err != nil {
		return runResponse{}, err
	}
	response := runResponse{
		ReqID:        plan.ReqID,
		SessionID:    plan.SessionCtx.ID,
		Host:         plan.Target.Name,
		Cmd:          remoteCommand,
		Status:       "denied",
		ExitCode:     exitCode,
		PolicyAction: string(plan.Auth.Decision.Action),
		PolicyRule:   plan.Auth.Decision.Rule,
	}
	if !flags.jsonOutput {
		printDenyHuman(cmd, plan.Target.Name, remoteCommand, plan.Auth.Decision)
	}
	return response, nil
}

func appendApprovalPending(cmd *cobra.Command, pending approval.PendingStore, store audit.Store, plan runPlan, remoteCommand string, flags runFlags) (runResponse, error) {
	req, err := pending.Create(approval.PendingRequest{
		ReqID:     plan.ReqID,
		SessionID: plan.SessionCtx.ID,
		Host:      plan.Target.Name,
		Cmd:       remoteCommand,
		Candidate: plan.Auth.ApprovalMatcher,
	})
	if err != nil {
		return runResponse{}, err
	}
	exit := exitApprovalRequired
	record := baseAuditRecord(plan.ReqID, plan.SessionCtx, audit.EventApprovalRequested, plan.Target.Name, remoteCommand, plan.Auth.Decision, &exit, "", 0)
	record.ApprovalID = req.ID
	record.ApprovalMatcher = req.Candidate.Regex
	record.ApprovalChannel = approval.ChannelExit
	if _, err := store.Append(record); err != nil {
		return runResponse{}, err
	}
	response := runResponse{
		ReqID:           plan.ReqID,
		SessionID:       plan.SessionCtx.ID,
		Host:            plan.Target.Name,
		Cmd:             remoteCommand,
		Status:          "approval_pending",
		ExitCode:        exitApprovalRequired,
		PolicyAction:    string(plan.Auth.Decision.Action),
		PolicyRule:      plan.Auth.Decision.Rule,
		ApprovalID:      req.ID,
		ApprovalMatcher: req.Candidate.Regex,
		ProposedScopes:  scopeStrings(req.ProposedScopes),
	}
	if !flags.jsonOutput {
		printApprovalPendingHuman(cmd, plan.Target.Name, req)
	}
	return response, nil
}

func scopeStrings(scopes []approval.Scope) []string {
	out := make([]string, 0, len(scopes))
	for _, scope := range scopes {
		out = append(out, string(scope))
	}
	return out
}

func sessionIDForTarget(baseID string, host string, multiTarget bool) string {
	if !multiTarget || strings.TrimSpace(host) == "" {
		return baseID
	}
	return baseID + "@" + strings.TrimSpace(host)
}

func printRunHuman(cmd *cobra.Command, host string, result executor.Result, filtered output.FilterResult) {
	out := cmd.OutOrStdout()
	marker := "✓"
	if isSSHErrorResult(result) {
		marker = "!"
	} else if result.ExitCode != 0 {
		marker = "✗"
	}

	_, _ = fmt.Fprintf(out, "%s %s · exit %d · %s", marker, host, result.ExitCode, formatDuration(result.Duration))
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
	if isSSHErrorResult(result) {
		printSSHErrorHint(cmd, result)
	}
}

type streamingRunResult struct {
	Result          executor.Result
	Stdout          []byte
	Stderr          []byte
	OutputTruncated bool
	Redactions      int
}

func shouldStreamRun(flags runFlags, resolved inventory.ResolvedTarget) bool {
	return !flags.jsonOutput && len(resolved.Targets) == 1
}

func runStreaming(cmd *cobra.Command, streamExec executor.StreamingExecutor, target inventory.Target, remoteCommand string, streamFilter output.StreamFilter) streamingRunResult {
	stdout := streamFilter.NewStreamWriter(cmd.OutOrStdout())
	stderr := streamFilter.NewStreamWriter(cmd.ErrOrStderr())
	result := streamExec.RunStreaming(context.Background(), executor.Request{
		Target:  target,
		Command: remoteCommand,
	}, stdout, stderr)
	stdout.Flush()
	stderr.Flush()
	return streamingRunResult{
		Result:          result,
		Stdout:          stdout.Emitted(),
		Stderr:          stderr.Emitted(),
		OutputTruncated: stdout.Truncated() || stderr.Truncated(),
		Redactions:      stdout.Redactions() + stderr.Redactions(),
	}
}

func printRunStreamFooter(cmd *cobra.Command, host string, result executor.Result, stdout []byte) {
	out := cmd.OutOrStdout()
	marker := "✓"
	if isSSHErrorResult(result) {
		marker = "!"
	} else if result.ExitCode != 0 {
		marker = "✗"
	}

	if len(stdout) > 0 && stdout[len(stdout)-1] != '\n' {
		_, _ = fmt.Fprintln(out)
	}
	_, _ = fmt.Fprintf(out, "%s %s · exit %d · %s", marker, host, result.ExitCode, formatDuration(result.Duration))
	_, _ = fmt.Fprintln(out)
	if isSSHErrorResult(result) {
		printSSHErrorHint(cmd, result)
	}
}

func printSSHErrorHint(cmd *cobra.Command, result executor.Result) {
	// `run` is agent-facing: its stderr must not leak operator-only details
	// (identity-file paths, resolved addresses) that the dehydrated hosts/Public()
	// boundary withholds. Print only the credential-free hint. Operators who need
	// the verbatim transport error should use `agentssh inventory test <host>`,
	// which is operator-facing and prints it in full.
	_, _ = fmt.Fprintln(cmd.ErrOrStderr(), "ssh connection failed (exit 9)")
	hint := executor.ConnectHint(result.Err)
	if hint == "" {
		hint = "hint: SSH connection failed; check addr, port, network, host key trust, and available SSH keys."
	}
	_, _ = fmt.Fprintln(cmd.ErrOrStderr(), hint)
}

func printDenyHuman(cmd *cobra.Command, host string, command string, decision policy.Decision) {
	_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "✗ denied by policy · %s · matched rule %q\n", host, decision.Rule)
	_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "  %s matched a deny rule or no allow rule; this block cannot be approved inline.\n", command)
	_, _ = fmt.Fprintln(cmd.ErrOrStderr(), "  If the policy should change, ask an operator to edit ~/.agentssh/policy.yaml.")
}

func printApprovalPendingHuman(cmd *cobra.Command, host string, req approval.PendingRequest) {
	_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "! approval required · %s · %s\n", host, req.ID)
	_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "  submitted for approval — wait for the operator's decision, then re-run the original command. candidate matcher: %s\n", req.Candidate.Regex)
}

func printNotRunHuman(cmd *cobra.Command, host string) {
	_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "! not run · %s · waiting for approval on another target\n", host)
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
	// deny(6) > approval_required(7) > ssh_error(9) > remote_failed(1) > success(0).
	if current == exitPolicyDenied || next == exitPolicyDenied {
		return exitPolicyDenied
	}
	if current == exitApprovalRequired || next == exitApprovalRequired {
		return exitApprovalRequired
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

func runPolicyRuleLS(cmd *cobra.Command) error {
	cfg, err := config.Load()
	if err != nil {
		return classifyConfigError(err)
	}
	out := cmd.OutOrStdout()
	if len(cfg.Policy.Rules) == 0 {
		_, _ = fmt.Fprintln(out, "(none)")
		return nil
	}
	for i, rule := range cfg.Policy.Rules {
		_, _ = fmt.Fprintf(out, "%d name=%s priority=%d action=%s cmd_regex=%s\n", i, rule.Name, rule.Priority, rule.Action, strconv.Quote(rule.Match.CmdRegex))
	}
	return nil
}

func runPolicyRuleAdd(cmd *cobra.Command, opts policyRuleOptions) error {
	paths, cfg, err := loadPolicyForWrite()
	if err != nil {
		return err
	}
	rule, err := policyRuleFromOptions(opts.Name, opts.CmdRegex, opts.Action, opts.Priority)
	if err != nil {
		return err
	}
	next, err := policy.AddRule(cfg, rule)
	if errors.Is(err, policy.ErrRuleExists) {
		return newUsageError("policy rule %q already exists", opts.Name)
	}
	if err != nil {
		return err
	}
	if err := saveValidatedPolicy(paths, next); err != nil {
		return err
	}
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "added policy rule %s\n", rule.Name)
	return nil
}

func runPolicyRuleUpdate(cmd *cobra.Command, opts policyRuleOptions) error {
	if !opts.NewNameSet && !opts.CmdRegexSet && !opts.ActionSet && !opts.PrioritySet {
		return newUsageError("policy rule update requires at least one field flag")
	}
	paths, cfg, err := loadPolicyForWrite()
	if err != nil {
		return err
	}
	current, err := policyRuleByName(cfg, opts.Name)
	if err != nil {
		return policyRuleUsageError(opts.Name, err)
	}
	nextRule := current
	if opts.NewNameSet {
		nextRule.Name = strings.TrimSpace(opts.NewName)
	}
	if opts.CmdRegexSet {
		nextRule.Match.CmdRegex = strings.TrimSpace(opts.CmdRegex)
	}
	if opts.ActionSet {
		action, err := parsePolicyAction(opts.Action)
		if err != nil {
			return err
		}
		nextRule.Action = action
	}
	if opts.PrioritySet {
		nextRule.Priority = opts.Priority
	}
	if err := validatePolicyRule(nextRule); err != nil {
		return err
	}
	next, err := policy.UpdateRule(cfg, opts.Name, nextRule)
	if errors.Is(err, policy.ErrRuleExists) {
		return newUsageError("policy rule %q already exists", nextRule.Name)
	}
	if err != nil {
		return policyRuleUsageError(opts.Name, err)
	}
	if err := saveValidatedPolicy(paths, next); err != nil {
		return err
	}
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "updated policy rule %s\n", nextRule.Name)
	return nil
}

func runPolicyRuleRM(cmd *cobra.Command, name string) error {
	paths, cfg, err := loadPolicyForWrite()
	if err != nil {
		return err
	}
	next, err := policy.RemoveRule(cfg, name)
	if err != nil {
		return policyRuleUsageError(name, err)
	}
	if err := saveValidatedPolicy(paths, next); err != nil {
		return err
	}
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "removed policy rule %s\n", name)
	return nil
}

func runPolicyGroupLS(cmd *cobra.Command) error {
	cfg, err := config.Load()
	if err != nil {
		return classifyConfigError(err)
	}
	names := sortedPolicyGroupNames(cfg.Policy.RuleGroups)
	out := cmd.OutOrStdout()
	if len(names) == 0 {
		_, _ = fmt.Fprintln(out, "(none)")
		return nil
	}
	for _, name := range names {
		group := cfg.Policy.RuleGroups[name]
		allow, deny := ruleActionCounts(group.Rules)
		_, _ = fmt.Fprintf(out, "%s rules=%d allow=%d deny=%d\n", name, len(group.Rules), allow, deny)
	}
	return nil
}

func runPolicyGroupAdd(cmd *cobra.Command, name string) error {
	paths, bundle, err := loadPolicyBundleForWrite()
	if err != nil {
		return err
	}
	next, err := policy.CreateGroup(bundle, name)
	if errors.Is(err, policy.ErrGroupExists) {
		return newUsageError("policy group %q already exists", strings.TrimSpace(name))
	}
	if err != nil {
		return policyGroupUsageError(name, err)
	}
	if err := saveValidatedPolicy(paths, next.Policy); err != nil {
		return err
	}
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "added policy group %s\n", strings.TrimSpace(name))
	return nil
}

func runPolicyGroupRM(cmd *cobra.Command, name string) error {
	paths, bundle, err := loadPolicyBundleForWrite()
	if err != nil {
		return err
	}
	next, err := policy.DeleteGroup(bundle, name)
	if err != nil {
		return policyGroupUsageError(name, err)
	}
	if err := saveValidatedPolicy(paths, next.Policy); err != nil {
		return err
	}
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "removed policy group %s\n", strings.TrimSpace(name))
	return nil
}

func runPolicyGroupRuleAdd(cmd *cobra.Command, opts policyGroupRuleOptions) error {
	paths, bundle, err := loadPolicyBundleForWrite()
	if err != nil {
		return err
	}
	rule, err := policyGroupRuleFromOptions(opts)
	if err != nil {
		return err
	}
	next, err := policy.AddGroupRule(bundle, opts.Group, rule)
	if err != nil {
		return policyGroupUsageError(opts.Group, err)
	}
	if err := saveValidatedPolicy(paths, next.Policy); err != nil {
		return err
	}
	group := next.Policy.RuleGroups[strings.TrimSpace(opts.Group)]
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "added policy group rule %s[%d]\n", strings.TrimSpace(opts.Group), len(group.Rules)-1)
	return nil
}

func runPolicyGroupRuleLS(cmd *cobra.Command, groupName string) error {
	cfg, err := config.Load()
	if err != nil {
		return classifyConfigError(err)
	}
	group, ok := cfg.Policy.RuleGroups[strings.TrimSpace(groupName)]
	if !ok {
		return policyGroupUsageError(groupName, policy.ErrGroupNotFound)
	}
	out := cmd.OutOrStdout()
	if len(group.Rules) == 0 {
		_, _ = fmt.Fprintln(out, "(none)")
		return nil
	}
	for i, rule := range group.Rules {
		_, _ = fmt.Fprintln(out, formatIndexedRule(i, rule, false))
	}
	return nil
}

func runPolicyGroupRuleRM(cmd *cobra.Command, groupName string, index int) error {
	paths, bundle, err := loadPolicyBundleForWrite()
	if err != nil {
		return err
	}
	next, err := policy.RemoveGroupRule(bundle, groupName, index)
	if err != nil {
		return policyGroupUsageError(groupName, err)
	}
	if err := saveValidatedPolicy(paths, next.Policy); err != nil {
		return err
	}
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "removed policy group rule %s[%d]\n", strings.TrimSpace(groupName), index)
	return nil
}

func runPolicyHostLS(cmd *cobra.Command) error {
	cfg, err := config.Load()
	if err != nil {
		return classifyConfigError(err)
	}
	ruleSets := policy.HostRuleSets(policy.Bundle{Policy: cfg.Policy, Inventory: cfg.Inventory})
	out := cmd.OutOrStdout()
	if len(ruleSets) == 0 {
		_, _ = fmt.Fprintln(out, "(none)")
		return nil
	}
	for _, ruleSet := range ruleSets {
		status := "effective"
		if !ruleSet.Effective {
			status = "missing-host"
		}
		_, _ = fmt.Fprintf(out, "host=%s rules=%d status=%s key=%s\n", ruleSet.Host, len(ruleSet.Override.Rules), status, ruleSet.Key)
		for i, rule := range ruleSet.Override.Rules {
			_, _ = fmt.Fprintf(out, "  rule[%d] %s\n", i, formatRuleFields(rule, true))
		}
	}
	return nil
}

func runPolicyHostRuleAdd(cmd *cobra.Command, opts policyHostRuleOptions) error {
	paths, bundle, err := loadPolicyBundleForWrite()
	if err != nil {
		return err
	}
	if strings.TrimSpace(opts.FromGroup) != "" {
		next, err := policy.StampGroupOntoHost(bundle, opts.Host, opts.FromGroup)
		if err != nil {
			return policyGroupOrHostUsageError(opts.Host, opts.FromGroup, err)
		}
		if err := saveValidatedPolicy(paths, next.Policy); err != nil {
			return err
		}
		group := next.Policy.RuleGroups[strings.TrimSpace(opts.FromGroup)]
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "stamped policy group %s onto host %s (%d rule(s))\n", strings.TrimSpace(opts.FromGroup), strings.TrimSpace(opts.Host), len(group.Rules))
		return nil
	}
	rule, err := policyHostRuleFromOptions(opts)
	if err != nil {
		return err
	}
	next, err := policy.AddHostRule(bundle, opts.Host, rule)
	if errors.Is(err, policy.ErrHostNotFound) {
		return newUsageError("inventory host %q not found", opts.Host)
	}
	if err != nil {
		return policyHostUsageError(opts.Host, err)
	}
	if err := saveValidatedPolicy(paths, next.Policy); err != nil {
		return err
	}
	ruleSet, _ := policy.LookupHostRules(next, opts.Host)
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "added policy host rule %s[%d]\n", strings.TrimSpace(opts.Host), len(ruleSet.Override.Rules)-1)
	return nil
}

func runPolicyHostRuleLS(cmd *cobra.Command, host string) error {
	cfg, err := config.Load()
	if err != nil {
		return classifyConfigError(err)
	}
	ruleSet, ok := policy.LookupHostRules(policy.Bundle{Policy: cfg.Policy, Inventory: cfg.Inventory}, host)
	if !ok {
		return policyHostUsageError(host, policy.ErrNoHostRules)
	}
	out := cmd.OutOrStdout()
	if len(ruleSet.Override.Rules) == 0 {
		_, _ = fmt.Fprintln(out, "(none)")
		return nil
	}
	for i, rule := range ruleSet.Override.Rules {
		_, _ = fmt.Fprintln(out, formatIndexedRule(i, rule, true))
	}
	return nil
}

func runPolicyHostRuleRM(cmd *cobra.Command, host string, index int) error {
	paths, bundle, err := loadPolicyBundleForWrite()
	if err != nil {
		return err
	}
	next, err := policy.RemoveHostRule(bundle, host, index)
	if err != nil {
		return policyHostUsageError(host, err)
	}
	if err := saveValidatedPolicy(paths, next.Policy); err != nil {
		return err
	}
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "removed policy host rule %s[%d]\n", strings.TrimSpace(host), index)
	return nil
}

func runPolicyHostGroupRM(cmd *cobra.Command, host string, groupName string) error {
	paths, bundle, err := loadPolicyBundleForWrite()
	if err != nil {
		return err
	}
	next, err := policy.RemoveHostGroup(bundle, host, groupName)
	if err != nil {
		return policyGroupOrHostUsageError(host, groupName, err)
	}
	if err := saveValidatedPolicy(paths, next.Policy); err != nil {
		return err
	}
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "removed policy host group %s[%s]\n", strings.TrimSpace(host), strings.TrimSpace(groupName))
	return nil
}

func runPolicyHostRM(cmd *cobra.Command, host string) error {
	paths, bundle, err := loadPolicyBundleForWrite()
	if err != nil {
		return err
	}
	next, err := policy.ClearHostRules(bundle, host)
	if err != nil {
		return policyHostUsageError(host, err)
	}
	if err := saveValidatedPolicy(paths, next.Policy); err != nil {
		return err
	}
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "removed policy host %s\n", strings.TrimSpace(host))
	return nil
}

func loadPolicyForWrite() (config.Paths, policy.Config, error) {
	home, err := config.ResolveHome()
	if err != nil {
		return config.Paths{}, policy.Config{}, err
	}
	paths := config.NewPaths(home)
	cfg, err := policy.Load(paths.PolicyFile)
	if err != nil {
		return paths, cfg, config.ParseError{File: paths.PolicyFile, Err: err}
	}
	return paths, cfg, nil
}

func loadPolicyBundleForWrite() (config.Paths, policy.Bundle, error) {
	paths, cfg, err := loadPolicyForWrite()
	if err != nil {
		return paths, policy.Bundle{}, err
	}
	inv, err := loadInventoryForWrite(paths.InventoryFile)
	if err != nil {
		return paths, policy.Bundle{}, err
	}
	return paths, policy.Bundle{Policy: cfg, Inventory: inv}, nil
}

func policyRuleFromOptions(name string, cmdRegex string, actionValue string, priority int) (policy.Rule, error) {
	action, err := parsePolicyAction(actionValue)
	if err != nil {
		return policy.Rule{}, err
	}
	rule := policy.Rule{
		Name:     strings.TrimSpace(name),
		Priority: priority,
		Match: policy.Match{
			CmdRegex: strings.TrimSpace(cmdRegex),
		},
		Action: action,
	}
	if err := validatePolicyRule(rule); err != nil {
		return policy.Rule{}, err
	}
	return rule, nil
}

func policyHostRuleFromOptions(opts policyHostRuleOptions) (policy.Rule, error) {
	action, err := parsePolicyAction(opts.Action)
	if err != nil {
		return policy.Rule{}, err
	}
	rule := policy.Rule{
		Priority: opts.Priority,
		Match: policy.Match{
			CmdRegex: strings.TrimSpace(opts.CmdRegex),
		},
		Action: action,
	}
	if err := validatePolicyRuleShape(rule, "policy host rule --cmd-regex"); err != nil {
		return policy.Rule{}, err
	}
	return rule, nil
}

func policyGroupRuleFromOptions(opts policyGroupRuleOptions) (policy.Rule, error) {
	action, err := parsePolicyAction(opts.Action)
	if err != nil {
		return policy.Rule{}, err
	}
	rule := policy.Rule{
		Priority: opts.Priority,
		Match: policy.Match{
			CmdRegex: strings.TrimSpace(opts.CmdRegex),
		},
		Action: action,
	}
	if err := validatePolicyRuleShape(rule, "policy group rule --cmd-regex"); err != nil {
		return policy.Rule{}, err
	}
	return rule, nil
}

func parsePolicyAction(value string) (policy.Action, error) {
	switch policy.Action(strings.TrimSpace(value)) {
	case policy.ActionAllow:
		return policy.ActionAllow, nil
	case policy.ActionDeny:
		return policy.ActionDeny, nil
	default:
		return "", newUsageError("invalid policy action %q; expected allow or deny", value)
	}
}

func validatePolicyRule(rule policy.Rule) error {
	if strings.TrimSpace(rule.Name) == "" {
		return newUsageError("policy rule name is required")
	}
	if strings.IndexFunc(rule.Name, func(r rune) bool { return r == '\t' || r == '\n' || r == '\r' }) >= 0 {
		return newUsageError("policy rule name must not contain control whitespace")
	}
	return validatePolicyRuleShape(rule, "policy rule --cmd-regex")
}

func validatePolicyRuleShape(rule policy.Rule, source string) error {
	if strings.TrimSpace(rule.Match.CmdRegex) == "" {
		return newUsageError("%s is required", source)
	}
	if _, err := parsePolicyAction(string(rule.Action)); err != nil {
		return err
	}
	_, err := policy.NewEngine(policy.Config{Rules: []policy.Rule{{
		Name:     "validate",
		Match:    rule.Match,
		Action:   rule.Action,
		Priority: rule.Priority,
	}}}, inventory.Inventory{})
	if err != nil {
		return newUsageError("%v", err)
	}
	return nil
}

func validatePolicyConfig(cfg policy.Config) error {
	if _, err := policy.NewEngine(cfg, inventory.Inventory{}); err != nil {
		return newUsageError("policy.yaml would be invalid: %v", err)
	}
	return nil
}

func saveValidatedPolicy(paths config.Paths, cfg policy.Config) error {
	if err := validatePolicyConfig(cfg); err != nil {
		return err
	}
	return policy.Save(paths.PolicyFile, cfg)
}

func policyRuleByName(cfg policy.Config, name string) (policy.Rule, error) {
	found := -1
	for i, rule := range cfg.Rules {
		if rule.Name != name {
			continue
		}
		if found >= 0 {
			return policy.Rule{}, policy.ErrRuleAmbiguous
		}
		found = i
	}
	if found < 0 {
		return policy.Rule{}, policy.ErrRuleNotFound
	}
	return cfg.Rules[found], nil
}

func policyRuleUsageError(name string, err error) error {
	switch {
	case errors.Is(err, policy.ErrRuleNotFound):
		return newUsageError("policy rule %q not found", name)
	case errors.Is(err, policy.ErrRuleAmbiguous):
		return newUsageError("policy rule %q is ambiguous; edit policy.yaml directly", name)
	default:
		return err
	}
}

func policyHostUsageError(host string, err error) error {
	switch {
	case errors.Is(err, policy.ErrHostNotFound):
		return newUsageError("inventory host %q not found", host)
	case errors.Is(err, policy.ErrNoHostRules):
		return newUsageError("host %q has no policy rules", host)
	default:
		return err
	}
}

func policyGroupUsageError(group string, err error) error {
	switch {
	case errors.Is(err, policy.ErrGroupNotFound):
		return newUsageError("policy group %q not found", strings.TrimSpace(group))
	case errors.Is(err, policy.ErrGroupExists):
		return newUsageError("policy group %q already exists", strings.TrimSpace(group))
	case errors.Is(err, policy.ErrReservedGroup):
		return newUsageError("policy group %q is reserved for AgentSSH internals", strings.TrimSpace(group))
	default:
		return err
	}
}

func policyGroupOrHostUsageError(host string, group string, err error) error {
	if errors.Is(err, policy.ErrGroupNotFound) {
		return policyGroupUsageError(group, err)
	}
	return policyHostUsageError(host, err)
}

func sortedPolicyGroupNames(groups map[string]policy.RuleGroup) []string {
	names := make([]string, 0, len(groups))
	for name := range groups {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func ruleActionCounts(rules []policy.Rule) (allow, deny int) {
	for _, rule := range rules {
		switch rule.Action {
		case policy.ActionAllow:
			allow++
		case policy.ActionDeny:
			deny++
		}
	}
	return allow, deny
}

func formatIndexedRule(index int, rule policy.Rule, includeGroup bool) string {
	return strconv.Itoa(index) + " " + formatRuleFields(rule, includeGroup)
}

func formatRuleFields(rule policy.Rule, includeGroup bool) string {
	parts := []string{
		fmt.Sprintf("priority=%d", rule.Priority),
		fmt.Sprintf("action=%s", rule.Action),
		fmt.Sprintf("cmd_regex=%s", strconv.Quote(rule.Match.CmdRegex)),
	}
	if includeGroup && strings.TrimSpace(rule.Group) != "" {
		parts = append(parts, "group="+strconv.Quote(rule.Group))
	}
	return strings.Join(parts, " ")
}

func runPolicyTest(cmd *cobra.Command, host string, command string) error {
	cfg, err := config.Load()
	if err != nil {
		return classifyConfigError(err)
	}
	runtime, err := approvalRuntime(cfg)
	if err != nil {
		return newUsageError("%v", err)
	}
	engine, err := policy.NewEngine(cfg.Policy, cfg.Inventory)
	if err != nil {
		return newUsageError("policy.yaml is invalid: %v\n  fix the rule in ~/.agentssh/policy.yaml, then re-run (check: agentssh policy show)", err)
	}
	decision, err := engine.Evaluate(host, command)
	if err != nil {
		return err
	}
	if decision.Rule == policy.RuleDefaultDeny && runtime.Enabled {
		decision = policy.Decision{Action: policy.Action("needs-approval"), Rule: policy.RuleDefaultDeny}
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
		_, _ = fmt.Fprintln(cmd.OutOrStdout(), formatAuditListRecord(record))
	}
	return nil
}

func formatAuditListRecord(record audit.Record) string {
	parts := []string{
		fmt.Sprintf("%d", record.Seq),
		record.TS,
		record.ReqID,
		string(record.Event),
		"host=" + dashIfEmpty(record.Host),
		"session=" + dashIfEmpty(record.SessionID),
		"policy=" + formatPolicy(record),
		"exit=" + auditListExit(record),
	}
	if record.DurationMS > 0 {
		parts = append(parts, "dur="+formatDuration(time.Duration(record.DurationMS)*time.Millisecond))
	}
	if output := auditListOutput(record); output != "" {
		parts = append(parts, "out="+output)
	}
	if record.Error != "" {
		parts = append(parts, "err="+strconv.Quote(truncateRunes(record.Error, 96)))
	}
	if record.Cmd != "" {
		parts = append(parts, "cmd="+strconv.Quote(truncateRunes(record.Cmd, 96)))
	}
	return strings.Join(parts, " ")
}

func formatPolicy(record audit.Record) string {
	action := dashIfEmpty(record.PolicyAction)
	rule := dashIfEmpty(record.PolicyRule)
	return action + "/" + rule
}

func auditListExit(record audit.Record) string {
	if record.ExitCode != nil {
		return fmt.Sprintf("%d", *record.ExitCode)
	}
	if record.Event == audit.EventDenied {
		return fmt.Sprintf("%d", exitPolicyDenied)
	}
	return "-"
}

func auditListOutput(record audit.Record) string {
	var parts []string
	if record.OutputTruncated {
		parts = append(parts, "truncated")
	}
	if record.Redactions > 0 {
		parts = append(parts, fmt.Sprintf("redacted:%d", record.Redactions))
	}
	return strings.Join(parts, ",")
}

func dashIfEmpty(value string) string {
	if value == "" {
		return "-"
	}
	return value
}

func truncateRunes(value string, limit int) string {
	runes := []rune(value)
	if len(runes) <= limit {
		return value
	}
	if limit <= 1 {
		return "…"
	}
	return string(runes[:limit-1]) + "…"
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
		Cmd:             latest.Cmd,
		Status:          status,
		ExitCode:        exitCode,
		DurationMS:      latest.DurationMS,
		OutputTruncated: latest.OutputTruncated,
		Redactions:      latest.Redactions,
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

func runAuditRepair(cmd *cobra.Command) error {
	cfg, err := config.Load()
	if err != nil {
		return classifyConfigError(err)
	}
	result, err := audit.NewStore(cfg.Paths.AuditFile).TruncateBroken()
	if err != nil {
		return err
	}
	if !result.Changed {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "audit chain already ok · records=%d\n", result.Kept)
		return nil
	}
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "audit repaired · broken_seq=%d · reason=%s · kept=%d · removed=%d · backup=%s\n", result.BrokenSeq, result.Reason, result.Kept, result.Removed, result.BackupPath)
	return nil
}

func runApprovalLS(cmd *cobra.Command, jsonOutput bool) error {
	cfg, err := config.Load()
	if err != nil {
		return classifyConfigError(err)
	}
	requests, err := approvalStore(cfg.Paths).List()
	if err != nil {
		return err
	}
	if jsonOutput {
		return writeJSON(cmd, requests)
	}
	out := cmd.OutOrStdout()
	if len(requests) == 0 {
		_, _ = fmt.Fprintln(out, "(none)")
		return nil
	}
	for _, req := range requests {
		_, _ = fmt.Fprintf(out, "%s host=%s session=%s scope=%s cmd=%s matcher=%s\n", req.ID, req.Host, req.SessionID, strings.Join(scopeStrings(req.ProposedScopes), ","), strconv.Quote(req.Cmd), strconv.Quote(req.Candidate.Regex))
	}
	return nil
}

func runApprovalGrant(cmd *cobra.Command, id string, scope approval.Scope) error {
	cfg, err := config.Load()
	if err != nil {
		return classifyConfigError(err)
	}
	runtime, err := approvalRuntime(cfg)
	if err != nil {
		return newUsageError("%v", err)
	}
	_, err = approval.ApplyDecision(approval.ApplyOptions{
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
	}, id, approval.VerdictApproved, scope)
	if errors.Is(err, approval.ErrPendingNotFound) || errors.Is(err, approval.ErrInvalidID) {
		return newUsageError("%v", err)
	}
	if errors.Is(err, approval.ErrAlreadyResolved) {
		return newUsageError("approval %s is already resolved", id)
	}
	if err != nil {
		return err
	}
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "approved %s scope=%s\n", id, scope)
	return nil
}

func runApprovalDeny(cmd *cobra.Command, id string) error {
	cfg, err := config.Load()
	if err != nil {
		return classifyConfigError(err)
	}
	_, err = approval.ApplyDecision(approval.ApplyOptions{
		Pending: approvalStore(cfg.Paths),
		Audit:   audit.NewStore(cfg.Paths.AuditFile),
		Channel: approval.ChannelCLI,
	}, id, approval.VerdictDenied, "")
	if errors.Is(err, approval.ErrPendingNotFound) || errors.Is(err, approval.ErrInvalidID) {
		return newUsageError("%v", err)
	}
	if errors.Is(err, approval.ErrAlreadyResolved) {
		return newUsageError("approval %s is already resolved", id)
	}
	if err != nil {
		return err
	}
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "denied %s\n", id)
	return nil
}

func runApprovalStatus(cmd *cobra.Command, id string) error {
	cfg, err := config.Load()
	if err != nil {
		return classifyConfigError(err)
	}
	status, err := approvalStore(cfg.Paths).Status(id)
	if errors.Is(err, approval.ErrPendingNotFound) || errors.Is(err, approval.ErrInvalidID) {
		return newUsageError("%v", err)
	}
	if err != nil {
		return err
	}
	if err := writeJSON(cmd, status); err != nil {
		return err
	}
	return approvalStatusExit(status)
}

func runApprovalWait(cmd *cobra.Command, id string, timeoutValue string) error {
	cfg, err := config.Load()
	if err != nil {
		return classifyConfigError(err)
	}
	runtime, err := approvalRuntime(cfg)
	if err != nil {
		return newUsageError("%v", err)
	}
	timeout := runtime.WaitTimeout
	if timeoutValue != "" {
		timeout, err = time.ParseDuration(timeoutValue)
		if err != nil || timeout < 0 {
			return newUsageError("invalid --timeout %q", timeoutValue)
		}
	}
	status, err := approvalStore(cfg.Paths).Wait(id, timeout)
	if errors.Is(err, approval.ErrPendingNotFound) || errors.Is(err, approval.ErrInvalidID) {
		return newUsageError("%v", err)
	}
	if err != nil {
		return err
	}
	if err := writeJSON(cmd, status); err != nil {
		return err
	}
	return approvalStatusExit(status)
}

func runSessionEnd(cmd *cobra.Command, id string) error {
	cfg, err := config.Load()
	if err != nil {
		return classifyConfigError(err)
	}
	if err := (approval.SessionStore{Dir: cfg.Paths.SessionsDir}).End(id); err != nil {
		return err
	}
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "ended session %s\n", id)
	return nil
}

func approvalStatusExit(status approval.StatusResult) error {
	switch status.Status {
	case "approved":
		return nil
	case "denied":
		return commandExitError{Code: exitPolicyDenied}
	default:
		return commandExitError{Code: exitApprovalRequired}
	}
}

func approvalScopeFromFlags(once, sessionScope, host bool) (approval.Scope, error) {
	count := 0
	var scope approval.Scope
	if once {
		count++
		scope = approval.ScopeOnce
	}
	if sessionScope {
		count++
		scope = approval.ScopeSession
	}
	if host {
		count++
		scope = approval.ScopeHost
	}
	if count != 1 {
		return "", newUsageError("approval grant requires exactly one of --once, --session, or --host")
	}
	return scope, nil
}

func approvalStore(paths config.Paths) approval.PendingStore {
	return approval.PendingStore{PendingDir: paths.PendingDir, ResponsesDir: paths.ResponsesDir}
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

func baseAuditRecord(reqID string, sessionCtx session.Context, event audit.Event, host string, command string, decision policy.Decision, exitCode *int, outputHash string, durationMS int64, filtered ...output.FilterResult) audit.Record {
	filterResult := output.FilterResult{}
	if len(filtered) > 0 {
		filterResult = filtered[0]
	}
	return audit.Record{
		ReqID:           reqID,
		SessionID:       sessionCtx.ID,
		SessionLabel:    sessionCtx.Label,
		Event:           event,
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
	return audit.NewReqID()
}

type eventValue audit.Event

func (v *eventValue) Set(value string) error {
	switch audit.Event(value) {
	case "", audit.EventStarted, audit.EventCompleted, audit.EventFailed, audit.EventDenied, audit.EventApprovalRequested, audit.EventApprovalGranted, audit.EventApprovalDenied:
		*v = eventValue(value)
		return nil
	default:
		return newUsageError("invalid --status %q; expected one of: started, completed, failed, denied, approval_requested, approval_granted, approval_denied", value)
	}
}

func (v *eventValue) String() string {
	return string(*v)
}

func (v *eventValue) Type() string {
	return "status"
}
