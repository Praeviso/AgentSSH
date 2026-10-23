package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/Praeviso/AgentSSH/internal/approval"
	"github.com/Praeviso/AgentSSH/internal/audit"
	"github.com/Praeviso/AgentSSH/internal/commandline"
	"github.com/Praeviso/AgentSSH/internal/config"
	"github.com/Praeviso/AgentSSH/internal/inventory"
	"github.com/Praeviso/AgentSSH/internal/payload"
	"github.com/Praeviso/AgentSSH/internal/policy"
	"github.com/Praeviso/AgentSSH/internal/runner"
	"github.com/Praeviso/AgentSSH/internal/session"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
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
		savePayloads bool
		payloadTTL   string
	}
	submitCmd := &cobra.Command{
		Use:   "submit <host> [--session <id>] [--file <path>] [--json] [-- <cmd> <cmd>...]",
		Short: "Submit a batch of commands for one approval review.",
		Long: "Each argument after -- is one complete remote command (quote each one).\n" +
			"--file adds one command per line (blank lines and # comments are skipped),\n" +
			"or a structured version: 1 file with commands[].cmd and optional stdin_file.\n" +
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
			return runPlanSubmit(cmd, args[0], commands, submitFlags.session, submitFlags.sessionLabel, submitFlags.file, submitFlags.jsonOutput, submitFlags.savePayloads, submitFlags.payloadTTL)
		},
	}
	submitCmd.Flags().StringVar(&submitFlags.session, "session", "", "associate the plan with a session id")
	submitCmd.Flags().StringVar(&submitFlags.sessionLabel, "session-label", "", "attach a human-readable label to the session")
	submitCmd.Flags().StringVar(&submitFlags.file, "file", "", "read commands from a legacy line file or a structured version: 1 plan")
	submitCmd.Flags().BoolVar(&submitFlags.jsonOutput, "json", false, "emit machine-readable JSON")
	submitCmd.Flags().BoolVar(&submitFlags.savePayloads, "save-payloads", false, "retain stdin payload bytes in the local content-addressed payload store")
	submitCmd.Flags().StringVar(&submitFlags.payloadTTL, "payload-ttl", "24h", "retention for --save-payloads payloads, e.g. 24h")

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

	var grantOnce, grantSession, grantTask bool
	grantCmd := &cobra.Command{
		Use:               "grant <plan_id> --once|--session|--task",
		Short:             "Approve every pending command in a plan.",
		Args:              exactArgs(1),
		PersistentPreRunE: requireOperator,
		RunE: func(cmd *cobra.Command, args []string) error {
			scope, err := approvalScopeFromFlags(grantOnce, grantSession, false, grantTask)
			if err != nil {
				return newUsageError("choose exactly one of --once, --session or --task (plans never grant host scope)")
			}
			return runPlanDecision(cmd, args[0], approval.VerdictApproved, scope)
		},
	}
	grantCmd.Flags().BoolVar(&grantOnce, "once", false, "approve one run per command")
	grantCmd.Flags().BoolVar(&grantSession, "session", false, "approve each command for this session")
	grantCmd.Flags().BoolVar(&grantTask, "task", false, "approve bounded task profiles; unsupported commands stay exact for the same task lifetime")

	denyCmd := &cobra.Command{
		Use:               "deny <plan_id>",
		Short:             "Deny every pending command in a plan.",
		Args:              exactArgs(1),
		PersistentPreRunE: requireOperator,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runPlanDecision(cmd, args[0], approval.VerdictDenied, "")
		},
	}

	cmd.AddCommand(submitCmd, statusCmd, waitCmd, grantCmd, denyCmd, newPlanInspectCommand(), newPlanRunCommand(), newPlanResumeCommand(), newPlanExecutionStatusCommand(), newPlanPayloadCommand(), newPlanTemplateCommand())
	return cmd
}

type planSubmitResponse = runner.PlanSubmitResponse

type planSubmitOptions struct {
	Review           approval.PlanReview
	SavePayloads     bool
	PayloadRetainFor time.Duration
}

type planSpec struct {
	Version  int                   `yaml:"version"`
	Metadata approval.PlanMetadata `yaml:"metadata,omitempty"`
	Commands []planCommand         `yaml:"commands"`
}

type planCommand struct {
	ID        string   `yaml:"id,omitempty"`
	Name      string   `yaml:"name,omitempty"`
	Phase     string   `yaml:"phase,omitempty"`
	OnFailure string   `yaml:"on_failure,omitempty"`
	Cmd       string   `yaml:"cmd"`
	Argv      []string `yaml:"argv,omitempty"`
	CWD       string   `yaml:"cwd,omitempty"`
	// StdinFile is resolved relative to the current working directory, the same
	// frame of reference as run --stdin-file -- not relative to the plan file.
	StdinFile  string `yaml:"stdin_file"`
	PayloadRef string `yaml:"payload_ref,omitempty"`
	// stdin holds the payload identity once resolveStdin has run. Unexported, so
	// the YAML decoder leaves it alone.
	stdin stdinSpec
}

// planFileLines splits a legacy plan file: one command per line, blank lines
// and # comments skipped.
func planFileLines(data []byte) []string {
	var commands []string
	for _, line := range strings.Split(string(data), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		commands = append(commands, trimmed)
	}
	return commands
}

// declaresStructuredPlan dispatches on the first meaningful line alone, so a
// structured file that fails to parse is a usage error rather than a pile of
// YAML fragments silently read as commands. A legacy plan file holds shell
// commands, and none of those open with a YAML document marker or with one of
// the plan schema's own top-level keys.
func declaresStructuredPlan(data []byte) bool {
	lines := planFileLines(data)
	if len(lines) == 0 {
		return false
	}
	return lines[0] == "---" ||
		strings.HasPrefix(lines[0], "version:") ||
		strings.HasPrefix(lines[0], "commands:")
}

func parseStructuredPlanDocument(data []byte) (planSpec, error) {
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	var spec planSpec
	if err := decoder.Decode(&spec); err != nil {
		return planSpec{}, newUsageError("cannot parse structured --file: %v", err)
	}
	// A trailing '---' or a comment-only document decodes as nil; only a second
	// document carrying real content means the file holds more than one plan.
	var extra any
	switch err := decoder.Decode(&extra); {
	case errors.Is(err, io.EOF):
	case err != nil:
		return planSpec{}, newUsageError("cannot parse structured --file: %v", err)
	case extra != nil:
		return planSpec{}, newUsageError("structured --file must contain exactly one YAML document")
	}
	if spec.Version != 1 {
		return planSpec{}, newUsageError("unsupported structured plan version %d; supported version is 1", spec.Version)
	}
	if spec.Commands == nil {
		return planSpec{}, newUsageError("structured plan commands is required")
	}
	seen := map[string]bool{}
	for i := range spec.Commands {
		spec.Commands[i].ID = stableStepID(i, spec.Commands[i].ID)
		if seen[spec.Commands[i].ID] {
			return planSpec{}, newUsageError("structured plan commands[%d].id duplicates %q", i, spec.Commands[i].ID)
		}
		seen[spec.Commands[i].ID] = true
		spec.Commands[i].Phase = strings.TrimSpace(spec.Commands[i].Phase)
		if spec.Commands[i].Phase == "" {
			spec.Commands[i].Phase = "apply"
		}
		spec.Commands[i].OnFailure = strings.TrimSpace(spec.Commands[i].OnFailure)
		if spec.Commands[i].OnFailure == "" {
			spec.Commands[i].OnFailure = "stop"
		}
		if err := validatePlanCommand(spec.Commands[i], i); err != nil {
			return planSpec{}, err
		}
		// Trim the way line mode does. A YAML block scalar carries a trailing
		// newline, and a command whose text differs by so much as that newline
		// mints a grant no later run can ever match.
		spec.Commands[i].Cmd = strings.TrimSpace(spec.Commands[i].Cmd)
		c := &spec.Commands[i]
		if strings.ContainsAny(c.Cmd, "\n\r") {
			return planSpec{}, newUsageError("structured plan commands[%d].cmd must be a single line", i)
		}
		if c.Cmd == "" && len(c.Argv) == 0 {
			return planSpec{}, newUsageError("structured plan commands[%d].cmd or argv is required", i)
		}
		if c.Cmd != "" && c.Argv != nil {
			return planSpec{}, newUsageError("structured plan commands[%d] must choose cmd or argv", i)
		}
		var err error
		if c.Argv != nil {
			c.Cmd, err = commandline.Render(c.Argv, c.CWD)
		} else {
			c.Cmd, err = commandline.Shell(c.Cmd, c.CWD)
		}
		if err != nil {
			return planSpec{}, newUsageError("commands[%d]: %v", i, err)
		}
		c.Argv = nil
		c.CWD = ""
	}
	return spec, nil
}

func validatePlanCommand(command planCommand, index int) error {
	phase := strings.TrimSpace(command.Phase)
	if phase == "" {
		phase = "apply"
	}
	if phase != "apply" && phase != "verify" {
		return newUsageError("structured plan commands[%d].phase must be apply or verify", index)
	}
	onFailure := strings.TrimSpace(command.OnFailure)
	if onFailure == "" {
		onFailure = "stop"
	}
	if onFailure != "stop" && onFailure != "continue" {
		return newUsageError("structured plan commands[%d].on_failure must be stop or continue", index)
	}
	if onFailure == "continue" && phase != "verify" {
		return newUsageError("structured plan commands[%d].on_failure: continue is only valid for verify phase", index)
	}
	if command.StdinFile != "" && command.PayloadRef != "" {
		return newUsageError("structured plan commands[%d] must choose stdin_file or payload_ref", index)
	}
	return nil
}

func validatePlanCommands(commands []planCommand) error {
	seen := map[string]bool{}
	for i, command := range commands {
		if command.ID == "" {
			commands[i].ID = stableStepID(i, "")
			command.ID = commands[i].ID
		}
		if seen[command.ID] {
			return newUsageError("structured plan commands[%d].id duplicates %q", i, command.ID)
		}
		seen[command.ID] = true
		if err := validatePlanCommand(command, i); err != nil {
			return err
		}
	}
	return nil
}

func resolveStdin(commands []planCommand, keepDataOpt ...bool) error {
	keepData := len(keepDataOpt) > 0 && keepDataOpt[0]
	for i := range commands {
		if commands[i].PayloadRef != "" {
			continue
		}
		stdin, err := loadStdinSpec(fmt.Sprintf("commands[%d].stdin_file", i), commands[i].StdinFile)
		if err != nil {
			return err
		}
		// Submit stores only identity metadata; release the payload immediately
		// so peak memory is bounded by one file.
		if !keepData {
			stdin.data = nil
		}
		commands[i].stdin = stdin
	}
	return nil
}

func readPlanDocument(file string) (planSpec, error) {
	data, err := os.ReadFile(file)
	if err != nil {
		return planSpec{}, newUsageError("cannot read --file: %v", err)
	}
	if declaresStructuredPlan(data) {
		return parseStructuredPlanDocument(data)
	}
	var commands []planCommand
	for i, line := range planFileLines(data) {
		commands = append(commands, planCommand{ID: stableStepID(i, ""), Phase: "apply", OnFailure: "stop", Cmd: line})
	}
	return planSpec{Version: 1, Commands: commands}, nil
}

func readPlanCommands(file string) ([]planCommand, error) {
	spec, err := readPlanDocument(file)
	if err != nil {
		return nil, err
	}
	return spec.Commands, nil
}

func runPlanSubmit(cmd *cobra.Command, targetName string, commands []string, sessionFlag string, sessionLabel string, file string, jsonOutput bool, savePayloads bool, payloadTTLValue string) error {
	cfg, err := config.Load()
	if err != nil {
		return classifyConfigError(err)
	}
	runtime := approvalRuntimeWithWarning(cmd, cfg)
	// A gateway checks its own policy for the device.
	if !runtime.Enabled && cfg.Gateway == nil {
		return newUsageError("plan submit requires the async approval channel\n" +
			"  enable it in ~/.agentssh/policy.yaml (approval.enabled: true) or via AGENTSSH_APPROVAL\n" +
			"  without approval, pre-check commands with: agentssh policy test --host <host> -- '<cmd>' '<cmd>'...")
	}
	planCommands := make([]planCommand, 0, len(commands))
	for i, command := range commands {
		if strings.TrimSpace(command) == "" {
			continue
		}
		planCommands = append(planCommands, planCommand{ID: stableStepID(i, ""), Phase: "apply", OnFailure: "stop", Cmd: command})
	}
	var metadata approval.PlanMetadata
	if file != "" {
		spec, err := readPlanDocument(file)
		if err != nil {
			return err
		}
		metadata = spec.Metadata
		planCommands = append(planCommands, spec.Commands...)
	}
	if len(planCommands) == 0 {
		return newUsageError("plan submit requires at least one command (after -- or via --file)")
	}
	if err := validatePlanCommands(planCommands); err != nil {
		return err
	}
	// Resolve every stdin_file before the first pending request is written. A
	// missing, non-regular, or oversized payload therefore has zero side effects.
	if err := resolvePayloadRefs(cfg, planCommands); err != nil {
		return err
	}
	if err := resolveStdin(planCommands, savePayloads); err != nil {
		return err
	}
	var retainFor time.Duration
	if savePayloads {
		retainFor, err = time.ParseDuration(payloadTTLValue)
		if err != nil || retainFor <= 0 {
			return newUsageError("--payload-ttl requires a positive duration")
		}
	}

	response, err := submitPlanInputsWithOptions(cmd, cfg, runtime, targetName, planCommands, sessionFlag, sessionLabel, planSubmitOptions{Review: approval.PlanReview{Metadata: metadata}, SavePayloads: savePayloads, PayloadRetainFor: retainFor})
	if response.SessionID == "" {
		return err
	}
	if jsonOutput {
		if emitErr := writeJSON(cmd, response); emitErr != nil {
			return emitErr
		}
	} else {
		printPlanSubmitHuman(cmd, response)
	}
	return err
}

func submitPlanInputs(cmd *cobra.Command, cfg *config.Config, runtime approval.RuntimeConfig, targetName string, planCommands []planCommand, sessionFlag, sessionLabel string, reviews ...approval.PlanReview) (response planSubmitResponse, resultErr error) {
	var opts planSubmitOptions
	if len(reviews) > 0 {
		opts.Review = reviews[0]
	}
	return submitPlanInputsWithOptions(cmd, cfg, runtime, targetName, planCommands, sessionFlag, sessionLabel, opts)
}

func submitPlanInputsWithOptions(cmd *cobra.Command, cfg *config.Config, runtime approval.RuntimeConfig, targetName string, planCommands []planCommand, sessionFlag, sessionLabel string, opts planSubmitOptions) (response planSubmitResponse, resultErr error) {
	reviewTemplate := opts.Review

	inv := cfg.Inventory
	if cfg.Gateway != nil {
		public, err := gatewayHosts(cmd, cfg)
		if err != nil {
			return response, err
		}
		inv = inventory.FromPublic(public)
	}
	resolved, err := inventory.NewResolver(inv).Resolve(targetName)
	if err != nil {
		return response, newUsageError("%v\n  list all hosts: agentssh hosts", err)
	}
	if resolved.Kind != inventory.TargetKindHost || len(resolved.Targets) != 1 {
		return response, newUsageError("plan submit targets a single host; submit one plan per host")
	}
	target := resolved.Targets[0]

	sessionCtx, err := (session.Resolver{}).Resolve(target.Name, sessionFlag, sessionLabel)
	if err != nil {
		if errors.Is(err, session.ErrNoSession) {
			return response, newUsageError("a session must be declared for plan submit\n" +
				"  mint one id per task: agentssh session new\n" +
				"  then pass --session <id> here and on every run in the task")
		}
		return response, fmt.Errorf("resolve session: %w", err)
	}

	planID, err := approval.NewPlanID()
	if err != nil {
		return response, err
	}
	var pinnedRefs []payload.Ref
	defer func() {
		if response.PlanID == "" || resultErr != nil && exitCodeForError(resultErr) != exitApprovalRequired && exitCodeForError(resultErr) != exitPolicyDenied {
			releasePayloadPins(cfg.Paths, planID, pinnedRefs)
		}
	}()
	if opts.SavePayloads {
		refs, err := saveCommandPayloads(cfg, planCommands, opts.PayloadRetainFor, planID)
		pinnedRefs = append(pinnedRefs, refs...)
		if err != nil {
			return response, err
		}
	}
	refs, err := pinCommandPayloadRefs(cfg, planCommands, planID)
	pinnedRefs = append(pinnedRefs, refs...)
	if err != nil {
		return response, err
	}

	commands := make([]runner.PlanCommand, 0, len(planCommands))
	for _, command := range planCommands {
		commands = append(commands, runner.PlanCommand{
			ID:         command.ID,
			Name:       command.Name,
			Phase:      command.Phase,
			OnFailure:  command.OnFailure,
			Cmd:        command.Cmd,
			Stdin:      command.stdin.runnerStdin(),
			PayloadRef: command.PayloadRef,
		})
	}
	var exitCode int
	if cfg.Gateway != nil {
		response, exitCode, err = gatewaySubmitPlan(cmd, cfg, planID, target.Name, sessionCtx, commands, reviewTemplate)
	} else {
		env := runner.Env{
			Policy:    cfg.Policy,
			Inventory: cfg.Inventory,
			Approval:  runtime,
			Sessions:  approval.SessionStore{Dir: cfg.Paths.SessionsDir},
			Pending:   approvalStore(cfg.Paths),
			Audit:     audit.NewStore(cfg.Paths.AuditFile),
		}
		response, exitCode, err = runner.SubmitPlan(env, runner.PlanSubmitRequest{
			PlanID:   planID,
			Host:     target.Name,
			Session:  sessionCtx,
			Commands: commands,
			Review:   reviewTemplate,
		})
	}
	if err != nil {
		return response, err
	}
	if exitCode != exitOK {
		return response, commandExitError{Code: exitCode}
	}
	return response, nil
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
		if line.StdinSHA256 != "" {
			note += fmt.Sprintf(" · stdin %d B", line.StdinBytes)
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
	cfg, err := config.LoadPaths()
	if err != nil {
		return classifyConfigError(err)
	}
	status, _, err := planStatus(cmd.Context(), cfg, id)
	if err != nil {
		return err
	}
	if status.Status != "pending" {
		releasePlanStatusPayloadPins(cfg.Paths, status)
	}
	return emitPlanStatus(cmd, status, jsonOutput)
}

func runPlanWait(cmd *cobra.Command, id string, timeoutValue string, jsonOutput bool) error {
	cfg, err := config.Load()
	if err != nil {
		return classifyConfigError(err)
	}
	var status approval.PlanStatus
	if cfg.Gateway != nil {
		first, defaultTimeout, err := planStatus(cmd.Context(), cfg, id)
		if err != nil {
			return err
		}
		timeout, err := resolveWaitTimeout(defaultTimeout, timeoutValue)
		if err != nil {
			return err
		}
		status, err = waitFor(cmd.Context(), timeout, first, func(s approval.PlanStatus) bool { return s.Pending == 0 },
			func(ctx context.Context) (approval.PlanStatus, error) {
				status, _, err := planStatus(ctx, cfg, id)
				return status, err
			})
		if err != nil {
			return err
		}
	} else {
		runtime := approvalRuntimeWithWarning(cmd, cfg)
		timeout, err := resolveWaitTimeout(runtime.WaitTimeout, timeoutValue)
		if err != nil {
			return err
		}
		status, err = approvalStore(cfg.Paths).WaitPlan(id, timeout)
		if err != nil {
			return mapPlanError(err)
		}
	}
	if status.Status != "pending" {
		releasePlanStatusPayloadPins(cfg.Paths, status)
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
		TaskTTL:    runtime.TaskTTL,
		Channel:    approval.ChannelCLI,
		SavePolicy: func(next policy.Config) error {
			return saveValidatedPolicy(cfg.Paths, next)
		},
	}, id, verdict, scope)
	if err != nil {
		return mapPlanError(err)
	}
	if manifest, manifestErr := approvalStore(cfg.Paths).GetPlan(id); manifestErr == nil {
		releasePlanPayloadPins(cfg.Paths, manifest)
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
		errors.Is(err, approval.ErrPlanNoPending),
		errors.Is(err, approval.ErrPlanDigest):
		return newUsageError("%v", err)
	default:
		return err
	}
}
