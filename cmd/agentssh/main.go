package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Praeviso/AgentSSH/internal/audit"
	"github.com/Praeviso/AgentSSH/internal/config"
	"github.com/Praeviso/AgentSSH/internal/executor"
	"github.com/Praeviso/AgentSSH/internal/hostform"
	"github.com/Praeviso/AgentSSH/internal/inventory"
	"github.com/Praeviso/AgentSSH/internal/output"
	"github.com/Praeviso/AgentSSH/internal/policy"
	"github.com/Praeviso/AgentSSH/internal/session"
	"github.com/Praeviso/AgentSSH/internal/tui"
	"github.com/spf13/cobra"
)

const (
	exitOK           = 0
	exitRemoteFailed = 1
	exitUsage        = 2
	exitPolicyDenied = 6
	exitSSHError     = 9
)

// version is overridden at build time via -ldflags "-X main.version=<tag>".
var version = "dev"

var newExecutor = func(cfg *config.Config) executor.Executor {
	switch selectedTransport(cfg) {
	case executor.TransportNative:
		options := executor.NativeOptions{}
		if cfg != nil {
			options.HostKeyPolicy = cfg.Inventory.HostKeyPolicy
		}
		return executor.NewNativeExecutor(options)
	default:
		return executor.NewSSHExecutor(nil)
	}
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
		Short: "Open the terminal control console.",
		Args:  noArgs,
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
		Paths: cfg.Paths,
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
		Use:   "add [name] [--addr <addr>] [--user <user>] [--port <port>] [--alias <ssh_config_alias>] [--tags <a,b>]",
		Short: "Add a host to inventory.yaml.",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) > 0 {
				add.Name = args[0]
			}
			return runInventoryAdd(add)
		},
	}
	addCmd.Flags().StringVar(&add.Addr, "addr", "", "host address")
	addCmd.Flags().StringVar(&add.User, "user", "", "SSH user")
	addCmd.Flags().IntVar(&add.Port, "port", 0, "SSH port")
	addCmd.Flags().StringVar(&add.Alias, "alias", "", "ssh_config host alias")
	addCmd.Flags().StringVar(&add.Tags, "tags", "", "comma-separated tags")

	cmd.AddCommand(
		lsCmd,
		addCmd,
		leafNoArgs("edit", "Edit inventory.yaml.", "edit ~/.agentssh/inventory.yaml directly"),
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
		Args:  noArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runSessionLS(cmd)
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

type inventoryAddOptions struct {
	Name  string
	Addr  string
	User  string
	Port  int
	Alias string
	Tags  string
}

func runInventoryAdd(opts inventoryAddOptions) error {
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
	return addInventoryHost(paths, inv, result)
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

func writeInventoryAtomic(home string, path string, inv inventory.Inventory) error {
	_ = home
	return inventory.Save(path, inv)
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
	if len(host.Tags) > 0 {
		parts = append(parts, "tags="+strings.Join(host.Tags, ","))
	}
	return parts
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

	resolved, err := inventory.NewResolver(cfg.Inventory).Resolve(targetName)
	if err != nil {
		if inventory.IsUnknown(err) {
			return newUsageError("%v\n  查看全部: agentssh hosts", err)
		}
		// e.g. a group whose tags match no hosts.
		return newUsageError("%v\n  list hosts and tags with: agentssh hosts", err)
	}

	engine, err := policy.NewEngine(cfg.Policy, cfg.Inventory)
	if err != nil {
		return newUsageError("policy.yaml is invalid: %v\n  fix the rule in ~/.agentssh/policy.yaml, then re-run (check: agentssh policy show)", err)
	}
	outputFilter, err := output.NewFilter(cfg.Policy.Output)
	if err != nil {
		return newUsageError("invalid output filter in policy.yaml: %v\n  fix the regex under output.redact in ~/.agentssh/policy.yaml", err)
	}
	sessionCtx, err := session.Resolver{Path: cfg.Paths.SessionFile}.Resolve(flags.session, flags.sessionLabel)
	if err != nil {
		return fmt.Errorf("resolve session: %w", err)
	}
	store := audit.NewStore(cfg.Paths.AuditFile)
	ssh := newExecutor(cfg)
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
			if _, err := store.Append(baseAuditRecord(reqID, sessionCtx, event, target.Name, remoteCommand, flags.skill, decision, &result.ExitCode, outputHash, result.Duration.Milliseconds(), filtered)); err != nil {
				return err
			}
			printRunStreamFooter(cmd, target.Name, result, streamed.Stdout, flags.skill)
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
	if isSSHErrorResult(result) {
		hint := "  check host reachability and your SSH key/agent; verify the host with: agentssh hosts"
		if result.Err != nil {
			_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "ssh connection failed (exit 9): %v\n%s\n", result.Err, hint)
		} else {
			// exit-255 with no exec error (ssh's own connection-error code).
			_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "ssh connection failed (exit 9)\n%s\n", hint)
		}
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

func printRunStreamFooter(cmd *cobra.Command, host string, result executor.Result, stdout []byte, skill string) {
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
	if skill != "" {
		_, _ = fmt.Fprintf(out, " · skill=%s", skill)
	}
	_, _ = fmt.Fprintln(out)
	if isSSHErrorResult(result) {
		hint := "  check host reachability and your SSH key/agent; verify the host with: agentssh hosts"
		if result.Err != nil {
			_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "ssh connection failed (exit 9): %v\n%s\n", result.Err, hint)
		} else {
			_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "ssh connection failed (exit 9)\n%s\n", hint)
		}
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
		return newUsageError("policy.yaml is invalid: %v\n  fix the rule in ~/.agentssh/policy.yaml, then re-run (check: agentssh policy show)", err)
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
		return newUsageError("invalid --status %q; expected one of: started, completed, failed, denied", value)
	}
}

func (v *eventValue) String() string {
	return string(*v)
}

func (v *eventValue) Type() string {
	return "status"
}
