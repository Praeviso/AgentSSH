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
	"github.com/Praeviso/AgentSSH/internal/session"
	"github.com/spf13/cobra"
)

// gatewayCommands are what a gateway device runs: the agent's commands, which
// the gateway answers, and the commands that touch only this machine's own
// state (plan snapshots, stdin payloads, enrollment). Every other command
// reads or changes inventory, policy, approvals or audit, which for a gateway
// device live on the gateway.
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
	"agentssh diagnostics",
	"agentssh remote",
}

// gatewayApprovalCommands wait on or report approvals, which gateway devices
// cannot do yet: their approvals are kept on the gateway.
var gatewayApprovalCommands = []string{
	"agentssh approval status",
	"agentssh approval wait",
	"agentssh plan submit",
	"agentssh plan status",
	"agentssh plan wait",
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
	if commandIn(path, gatewayApprovalCommands) {
		return newUsageError("%s is not available in gateway mode yet: this device's approvals are kept on the gateway\n  wait for the operator's decision, then re-run the original command", path)
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
	if flags.waitApproval != "" {
		return newUsageError("--wait-approval is not available in gateway mode yet: this device's approvals are kept on the gateway\n  wait for the operator's decision, then re-run the original command")
	}
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
