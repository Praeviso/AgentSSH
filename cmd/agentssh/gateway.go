package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/Praeviso/AgentSSH/internal/approval"
	"github.com/Praeviso/AgentSSH/internal/config"
	"github.com/Praeviso/AgentSSH/internal/executor"
	"github.com/Praeviso/AgentSSH/internal/inventory"
	"github.com/Praeviso/AgentSSH/internal/output"
	"github.com/Praeviso/AgentSSH/internal/policy"
	"github.com/Praeviso/AgentSSH/internal/remote"
	"github.com/Praeviso/AgentSSH/internal/remoteclient"
	"github.com/Praeviso/AgentSSH/internal/runner"
	"github.com/Praeviso/AgentSSH/internal/session"
	"github.com/spf13/cobra"
)

// gatewayCommands are what a gateway device runs: the agent's commands, which
// the gateway answers, and the commands that touch only this machine's own
// state (plan snapshots, stdin payloads, enrollment). Every other command
// reads or changes inventory, policy, audit or approval decisions, which for
// a gateway device live on the gateway.
var gatewayCommands = []string{
	"agentssh hosts",
	"agentssh run",
	"agentssh status",
	"agentssh plan run",
	"agentssh plan resume",
	"agentssh plan execution",
	"agentssh plan payload",
	"agentssh plan template",
	"agentssh session new",
	"agentssh approval status",
	"agentssh approval wait",
	"agentssh plan submit",
	"agentssh plan status",
	"agentssh plan wait",
	"agentssh diagnostics",
	"agentssh remote",
}

func commandIn(path string, commands []string) bool {
	for _, command := range commands {
		if path == command || strings.HasPrefix(path, command+" ") {
			return true
		}
	}
	return false
}

// gatewayHome reports whether the home is enrolled in gateway mode. An
// unreadable enrollment is not reported here: the commands that need the
// control plane fail on it when they load their configuration.
func gatewayHome() bool {
	home, err := config.ResolveHome()
	if err != nil {
		return false
	}
	mode, err := remoteclient.LoadMode(home)
	return err == nil && mode == remote.ModeGateway
}

func refuseInGateway(cmd *cobra.Command) error {
	path := cmd.CommandPath()
	if commandIn(path, gatewayCommands) || !gatewayHome() {
		return nil
	}
	return newUsageError("%s is not available in gateway mode: this device's inventory, policy, approvals and audit live on the gateway\n  ask the gateway's administrator; agentssh remote status shows which gateway", path)
}

// guardGatewayMode makes every command outside gatewayCommands refuse to run
// in gateway mode, before its own checks (such as the operator prompt).
func guardGatewayMode(root *cobra.Command) {
	var walk func(cmd *cobra.Command, inherited func(*cobra.Command, []string) error)
	walk = func(cmd *cobra.Command, inherited func(*cobra.Command, []string) error) {
		if cmd.PersistentPreRunE != nil {
			inherited = cmd.PersistentPreRunE
		}
		if !cmd.HasSubCommands() {
			// cobra runs only the nearest persistent hook, so the leaf's
			// replacement calls the one it would have run.
			next := inherited
			cmd.PersistentPreRunE = func(cmd *cobra.Command, args []string) error {
				if err := refuseInGateway(cmd); err != nil {
					return err
				}
				if next != nil {
					return next(cmd, args)
				}
				return nil
			}
			return
		}
		for _, sub := range cmd.Commands() {
			walk(sub, inherited)
		}
	}
	walk(root, nil)
}

// errGatewaySSH stands for a transport failure the gateway reported; its
// details stay in the gateway's audit and log.
var errGatewaySSH = errors.New("the gateway could not reach the host over SSH")

// runGateway sends one run to the gateway, which resolves, authorizes, runs
// and audits it, and presents the outcome exactly as runDirect does.
func runGateway(cmd *cobra.Command, cfg *config.Config, targetName, remoteCommand string, flags runFlags) error {
	var stdin stdinSpec
	var err error
	if flags.stdinSnapshot != nil {
		stdin = *flags.stdinSnapshot
	} else if stdin, err = loadStdinSpec("--stdin-file", flags.stdinFile); err != nil {
		return err
	}
	// The gateway refuses a missing session after it resolves the target, in
	// the same order as a local run.
	sessionID := ""
	if sessionCtx, err := (session.Resolver{}).Resolve(targetName, flags.session, flags.sessionLabel); err == nil {
		sessionID = sessionCtx.ID
	}
	req := remote.ExecRequest{
		Host:         targetName,
		Cmd:          remoteCommand,
		Stdin:        stdin.data,
		Session:      sessionID,
		SessionLabel: flags.sessionLabel,
		ExecutionID:  flags.executionID,
		StepID:       flags.stepID,
		ReviewSHA256: flags.reviewSHA256,
		Stream:       shouldStreamRun(flags),
	}

	// Streamed output is attributed to the request ID the run frame names,
	// which arrives before any output.
	var streams [2]io.Writer
	var streamErr error
	onRun := func(run remote.ExecRun) {
		if req.Stream && streams[0] == nil {
			streams[0], streams[1] = runStreamWriters(cmd, flags, targetName, run.ReqID)
		}
	}
	stdout := streamWriter{dst: &streams[0], err: &streamErr}
	stderr := streamWriter{dst: &streams[1], err: &streamErr}

	// A local Ctrl-C cancels the run on the gateway; a second one kills the
	// process.
	ctx, stopSignals := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
	defer stopSignals()
	go func() {
		<-ctx.Done()
		stopSignals()
	}()
	result, err := cfg.Gateway.ExecNotify(ctx, req, onRun, stdout, stderr)
	if err != nil {
		return gatewayError(err)
	}
	streamed := req.Stream && result.TargetKind == string(inventory.TargetKindHost)
	observer := runObserver{cmd: cmd, jsonOutput: flags.jsonOutput}
	for _, response := range result.Responses {
		presentGatewayResponse(observer, response, remoteCommand, streamed)
	}
	if result.Truncated {
		observer.Warning("the gateway's output limit for one run was reached, so this result is incomplete")
	}
	if flags.jsonOutput && len(result.Responses) > 0 {
		resolved := inventory.ResolvedTarget{Kind: inventory.TargetKind(result.TargetKind)}
		if err := writeRunResponses(cmd, resolved, result.Responses, flags); err != nil {
			return err
		}
	}
	if streamErr != nil {
		return streamErr
	}
	if result.ExitCode != exitOK {
		return commandExitError{Code: result.ExitCode}
	}
	return nil
}

// presentGatewayResponse tells observer what the gateway's runner told its
// own observer for this target.
func presentGatewayResponse(observer runObserver, response runResponse, command string, streamed bool) {
	switch response.Status {
	case "denied":
		observer.Denied(response.Host, command, policy.Decision{Action: policy.Action(response.PolicyAction), Rule: response.PolicyRule})
	case "approval_pending":
		observer.ApprovalPending(response.Host, approval.PendingRequest{ID: response.ApprovalID, Candidate: approval.Matcher{Regex: response.ApprovalMatcher}})
	case "not_run":
		observer.NotRun(response.Host)
	default:
		result := executor.Result{ExitCode: response.ExitCode, Duration: time.Duration(response.DurationMS) * time.Millisecond}
		if response.Status == "ssh_error" {
			result.Err = errGatewaySSH
		}
		observer.Finished(response.Host, result, output.FilterResult{
			Stdout:          response.Stdout,
			Stderr:          response.Stderr,
			OutputTruncated: response.OutputTruncated,
			Redactions:      response.Redactions,
		}, streamed)
	}
}

// streamWriter forwards to a stream writer chosen once the run frame
// arrives. Like a local run, a failing writer does not stop the command: its
// first error is kept and returned when the run ends.
type streamWriter struct {
	dst *io.Writer
	err *error
}

func (w streamWriter) Write(p []byte) (int, error) {
	if *w.dst != nil && *w.err == nil {
		if _, err := (*w.dst).Write(p); err != nil {
			*w.err = err
		}
	}
	return len(p), nil
}

// gatewayHosts lists the gateway's hosts and groups for this device.
func gatewayHosts(cmd *cobra.Command, cfg *config.Config) (inventory.PublicInventory, error) {
	public, err := cfg.Gateway.Hosts(cmd.Context())
	if err != nil {
		return inventory.PublicInventory{}, gatewayError(err)
	}
	return public, nil
}

func gatewayRequestStatus(cmd *cobra.Command, cfg *config.Config, reqID string) (runResponse, error) {
	response, err := cfg.Gateway.RequestStatus(cmd.Context(), reqID)
	if err != nil {
		return runResponse{}, gatewayError(err)
	}
	return response, nil
}

// gatewayError maps a gateway failure onto the CLI contract: what a local
// run would reject is a usage error (exit 2); a refusal or an unreachable
// gateway names the control plane (exit 1).
func gatewayError(err error) error {
	var apiErr *remote.APIError
	if errors.As(err, &apiErr) && (apiErr.Code == remote.CodeUsage || apiErr.Code == remote.CodeRequestNotFound) {
		return usageError(apiErr.Message)
	}
	if errors.Is(err, context.Canceled) {
		return err
	}
	var mismatch *remoteclient.ModeMismatchError
	if errors.As(err, &mismatch) {
		return fmt.Errorf("gateway: %w\n  the control plane's mode changed since this device enrolled; tell its administrator", err)
	}
	return fmt.Errorf("gateway: %w\n  check the control plane with: agentssh remote status", err)
}

// Approvals live where the home keeps them: in its own state directory, or
// for a gateway device on the gateway. These read them from either.

// approvalStatus reads one approval request, and the default wait for it.
func approvalStatus(ctx context.Context, cfg *config.Config, id string) (approval.StatusResult, time.Duration, error) {
	if cfg.Gateway != nil {
		resp, err := cfg.Gateway.ApprovalStatus(ctx, id)
		if err != nil {
			return approval.StatusResult{}, 0, gatewayError(err)
		}
		return resp.Status, time.Duration(resp.WaitTimeoutMS) * time.Millisecond, nil
	}
	status, err := approvalStore(cfg.Paths).Status(id)
	if errors.Is(err, approval.ErrPendingNotFound) || errors.Is(err, approval.ErrInvalidID) {
		return approval.StatusResult{}, 0, newUsageError("%v", err)
	}
	return status, approval.DefaultWaitTimeout, err
}

// planStatus reads one plan, and the default wait for it.
func planStatus(ctx context.Context, cfg *config.Config, id string) (approval.PlanStatus, time.Duration, error) {
	if cfg.Gateway != nil {
		resp, err := cfg.Gateway.PlanStatus(ctx, id)
		if err != nil {
			return approval.PlanStatus{}, 0, gatewayError(err)
		}
		return resp.Status, time.Duration(resp.WaitTimeoutMS) * time.Millisecond, nil
	}
	status, err := approvalStore(cfg.Paths).PlanStatus(id)
	if err != nil {
		return approval.PlanStatus{}, 0, mapPlanError(err)
	}
	return status, approval.DefaultWaitTimeout, nil
}

// preflight reports how each check would be authorized now, without side
// effects, and whether approvals are enabled at all. A local home rereads its
// configuration, so a policy edited meanwhile takes effect.
func preflight(ctx context.Context, cfg *config.Config, checks []remote.AuthorizeCheck) ([]approval.AuthorizationStatus, bool, error) {
	if cfg.Gateway != nil {
		resp, err := cfg.Gateway.Authorize(ctx, checks)
		if err != nil {
			return nil, false, gatewayError(err)
		}
		if len(resp.Results) != len(checks) {
			return nil, false, fmt.Errorf("gateway answered %d of %d authorization checks", len(resp.Results), len(checks))
		}
		return resp.Results, resp.ApprovalEnabled, nil
	}
	current, err := config.Load()
	if err != nil {
		return nil, false, classifyConfigError(err)
	}
	runtime, err := approvalRuntime(current)
	if err != nil {
		return nil, false, err
	}
	statuses := make([]approval.AuthorizationStatus, 0, len(checks))
	for _, check := range checks {
		auth, err := approval.PreflightAuthorize(current.Policy, current.Inventory, approval.SessionStore{Dir: current.Paths.SessionsDir}, runtime, check.Session, check.Host, check.Cmd, check.StdinSHA256)
		if err != nil {
			return nil, false, err
		}
		auth, _ = approval.CheckGrantedStdin(auth, check.StdinBytes)
		statuses = append(statuses, auth.Status)
	}
	return statuses, runtime.Enabled, nil
}

// pollInterval is how often a wait asks again: often for local files, at
// most every second for a gateway, where each question is a signed request.
func pollInterval(cfg *config.Config) time.Duration {
	if cfg.Gateway != nil {
		return time.Second
	}
	return 50 * time.Millisecond
}

// waitFor asks fetch again until done or timeout and returns the last
// answer. A gateway's answers back off from 200ms to 2s.
func waitFor[T any](ctx context.Context, timeout time.Duration, first T, done func(T) bool, fetch func(context.Context) (T, error)) (T, error) {
	deadline := time.Now().Add(timeout)
	current, sleep := first, 200*time.Millisecond
	for !done(current) && time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return current, ctx.Err()
		case <-time.After(min(sleep, time.Until(deadline))):
		}
		next, err := fetch(ctx)
		if err != nil {
			return current, err
		}
		current, sleep = next, min(2*sleep, 2*time.Second)
	}
	return current, nil
}

// gatewaySubmitPlan submits a plan to the gateway with each command's stdin
// identity; the content stays here until its step runs.
func gatewaySubmitPlan(cmd *cobra.Command, cfg *config.Config, planID, host string, sessionCtx session.Context, commands []runner.PlanCommand, review approval.PlanReview) (planSubmitResponse, int, error) {
	req := remote.PlanSubmitRequest{PlanID: planID, Host: host, Session: sessionCtx.ID, SessionLabel: sessionCtx.Label, Review: review}
	for _, command := range commands {
		req.Commands = append(req.Commands, remote.PlanSubmitCommand{
			ID: command.ID, Name: command.Name, Phase: command.Phase, OnFailure: command.OnFailure, Cmd: command.Cmd,
			StdinSHA256: command.Stdin.SHA256, StdinBytes: command.Stdin.Bytes, PayloadRef: command.PayloadRef,
		})
	}
	result, err := cfg.Gateway.SubmitPlan(cmd.Context(), req)
	if err != nil {
		return planSubmitResponse{}, exitOK, gatewayError(err)
	}
	return result.Response, result.ExitCode, nil
}
