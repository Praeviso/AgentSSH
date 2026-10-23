// Package runner is the command execution pipeline shared by the agentssh CLI
// and control planes: per-target session binding, authorization, approval
// requests, audit, execution, output filtering, and exit-code merging.
//
// It performs no terminal I/O. Callers present progress through an Observer,
// receive streamed output through writers they supply, and read the finalized
// per-target responses and merged exit code from the returned Outcome.
package runner

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/Praeviso/AgentSSH/internal/approval"
	"github.com/Praeviso/AgentSSH/internal/audit"
	"github.com/Praeviso/AgentSSH/internal/executor"
	"github.com/Praeviso/AgentSSH/internal/inventory"
	"github.com/Praeviso/AgentSSH/internal/output"
	"github.com/Praeviso/AgentSSH/internal/policy"
	"github.com/Praeviso/AgentSSH/internal/session"
)

// Exit codes of the agent-facing contract (docs/DESIGN.md §A.5).
const (
	ExitOK               = 0
	ExitRemoteFailed     = 1
	ExitUsage            = 2
	ExitPolicyDenied     = 6
	ExitApprovalRequired = 7
	ExitSSHError         = 9
)

// UsageError reports a request the caller must fix before re-running; it maps
// to exit 2.
type UsageError string

func (e UsageError) Error() string {
	return string(e)
}

// ErrNoSession refuses a run that declares no session.
const ErrNoSession = UsageError("a session must be declared for run\n" +
	"  mint one id per task: agentssh session new\n" +
	"  then pass --session <id> on every run in the task (or export AGENTSSH_SESSION in a persistent shell)\n" +
	"  do not mint a new id per command — one session per task keeps the audit trail grouped by task")

// ResolveUsage explains a target that does not resolve.
func ResolveUsage(err error) UsageError {
	if inventory.IsUnknown(err) {
		return usageErrorf("%v\n  list all hosts: agentssh hosts", err)
	}
	// e.g. a group whose tags match no hosts.
	return usageErrorf("%v\n  list hosts and tags with: agentssh hosts", err)
}

func usageErrorf(format string, args ...any) UsageError {
	return UsageError(fmt.Sprintf(format, args...))
}

// AuditLog is the append side of the audit hash chain.
type AuditLog interface {
	Append(record audit.Record) (audit.Record, error)
}

// Env is everything a run needs, already loaded by the caller.
type Env struct {
	Policy    policy.Config
	Inventory inventory.Inventory
	Approval  approval.RuntimeConfig
	Sessions  approval.SessionStore
	Pending   approval.PendingStore
	Audit     AuditLog
	Executor  executor.Executor
	Output    output.Filter
	// HostOS, when set, receives the OS reported by a connection that did not
	// fail at the transport level.
	HostOS func(host string, osName string)
	// NewReqID, when set, replaces audit.NewReqID.
	NewReqID func() (string, error)
}

// Stdin is a command's stdin payload and the identity (hash + size) that binds
// it to grants, audit records, and responses.
type Stdin struct {
	Data   []byte
	SHA256 string
	Bytes  int64
}

// Request is one run against a resolved host or group.
type Request struct {
	Target       inventory.ResolvedTarget
	Command      string
	Stdin        Stdin
	Session      string
	SessionLabel string
	ExecutionID  string
	StepID       string
	ReviewSHA256 string
	// Stream, when set and Target is a single host, streams filtered output to
	// the returned writers as it arrives instead of buffering it.
	Stream func(host string, reqID string) (stdout io.Writer, stderr io.Writer)
	// Observer receives presentation events; nil discards them.
	Observer Observer
}

// Observer is told about each target's outcome as it happens, in target order.
type Observer interface {
	// Denied reports a target blocked by policy (exit 6).
	Denied(host string, command string, decision policy.Decision)
	// ApprovalPending reports a target that now has a pending approval request.
	ApprovalPending(host string, req approval.PendingRequest)
	// NotRun reports an authorized target held back because another target in
	// the same group needs approval.
	NotRun(host string)
	// Finished reports an executed target. out holds the filtered output that was
	// returned (streamed already when streamed is true).
	Finished(host string, result executor.Result, out output.FilterResult, streamed bool)
	// Warning reports a non-fatal problem.
	Warning(message string)
}

// Outcome is the result of a run that reached a per-target decision.
type Outcome struct {
	// Responses holds one finalized response per decided target, in order.
	Responses []Response
	// ExitCode is the most conservative per-target outcome (see MergeExitCode).
	ExitCode int
	// StreamErr is the first error returned by a streaming output writer.
	StreamErr error
}

type plan struct {
	Target     inventory.Target
	ReqID      string
	SessionCtx session.Context
	Auth       approval.Authorization
}

// Run authorizes and executes req.Command on every target. With approvals
// enabled, a group is preflighted first and executes nothing if any member
// needs approval. A returned error means the run stopped before producing a
// complete outcome (invalid policy, missing session, audit failure,
// cancellation between targets).
func Run(ctx context.Context, env Env, req Request) (Outcome, error) {
	obs := req.Observer
	if obs == nil {
		obs = nopObserver{}
	}
	plans, err := buildPlans(env, req)
	if err != nil {
		return Outcome{}, err
	}
	if env.Approval.Enabled && anyNeedsApproval(plans) {
		return preflightBlock(env, req, obs, plans)
	}

	outcome := Outcome{ExitCode: ExitOK, Responses: make([]Response, 0, len(plans))}
	for _, p := range plans {
		if ctx.Err() != nil {
			return Outcome{}, ctx.Err()
		}
		auth, err := approval.Authorize(env.Policy, env.Inventory, env.Sessions, env.Approval, p.SessionCtx.ID, p.Target.Name, req.Command, req.Stdin.SHA256, p.ReqID)
		if err != nil {
			return Outcome{}, invalidPolicyError(err)
		}
		if checked, ok := approval.CheckGrantedStdin(auth, req.Stdin.Bytes); !ok {
			// The refused once grant stays for a run with the stdin it was
			// approved for.
			if auth.GrantScope == approval.ScopeOnce {
				_ = env.Sessions.Release(p.SessionCtx.ID, p.ReqID)
			}
			auth = checked
		}
		p.Auth = auth
		switch auth.Status {
		case approval.AuthHardDeny:
			response, err := appendDenied(env, req, obs, p)
			if err != nil {
				return Outcome{}, err
			}
			outcome.Responses = append(outcome.Responses, response)
			outcome.ExitCode = MergeExitCode(outcome.ExitCode, ExitPolicyDenied)
			continue
		case approval.AuthNeedsApproval:
			if !env.Approval.Enabled {
				response, err := appendDenied(env, req, obs, p)
				if err != nil {
					return Outcome{}, err
				}
				outcome.Responses = append(outcome.Responses, response)
				outcome.ExitCode = MergeExitCode(outcome.ExitCode, ExitPolicyDenied)
				continue
			}
			response, err := appendPending(env, req, obs, p)
			if err != nil {
				return Outcome{}, err
			}
			outcome.Responses = append(outcome.Responses, response)
			outcome.ExitCode = MergeExitCode(outcome.ExitCode, ExitApprovalRequired)
			continue
		case approval.AuthAllow, approval.AuthAllowByGrant:
		default:
			return Outcome{}, fmt.Errorf("unknown approval authorization status %q", auth.Status)
		}

		ran, err := execute(ctx, env, req, obs, p, len(plans) == 1)
		if err != nil {
			return Outcome{}, err
		}
		outcome.Responses = append(outcome.Responses, ran.Response)
		if ran.StreamErr != nil && outcome.StreamErr == nil {
			outcome.StreamErr = ran.StreamErr
		}
		outcome.ExitCode = MergeExitCode(outcome.ExitCode, ExitCodeForResult(ran.Result))
		if ctx.Err() != nil {
			break
		}
	}
	Finalize(outcome.Responses, req.Stdin)
	return outcome, nil
}

type executed struct {
	Response  Response
	Result    executor.Result
	StreamErr error
}

func execute(ctx context.Context, env Env, req Request, obs Observer, p plan, single bool) (executed, error) {
	decision := p.Auth.Decision
	if _, err := env.Audit.Append(stampRun(baseRecord(p.ReqID, p.SessionCtx, audit.EventStarted, p.Target.Name, req.Command, decision, nil, "", 0), req)); err != nil {
		// The command never executed: hand the claimed once grant back.
		if p.Auth.Status == approval.AuthAllowByGrant && p.Auth.GrantScope == approval.ScopeOnce {
			_ = env.Sessions.Release(p.SessionCtx.ID, p.ReqID)
		}
		return executed{}, err
	}

	var result executor.Result
	var filtered output.FilterResult
	var streamErr error
	streamed := false
	streamExec, canStream := env.Executor.(executor.StreamingExecutor)
	streamFilter, canStreamFilter := env.Output.(output.StreamFilter)
	if canStream && canStreamFilter && single && req.Stream != nil {
		streamed = true
		stdoutDst, stderrDst := req.Stream(p.Target.Name, p.ReqID)
		stdout := streamFilter.NewStreamWriter(stdoutDst)
		stderr := streamFilter.NewStreamWriter(stderrDst)
		result = streamExec.RunStreaming(ctx, executor.Request{
			Target:  p.Target,
			Command: req.Command,
			Stdin:   req.Stdin.Data,
		}, stdout, stderr)
		stdout.Flush()
		stderr.Flush()
		streamErr = stdout.Err()
		if streamErr == nil {
			streamErr = stderr.Err()
		}
		filtered = output.FilterResult{
			Stdout:          string(stdout.Emitted()),
			Stderr:          string(stderr.Emitted()),
			OutputTruncated: stdout.Truncated() || stderr.Truncated(),
			Redactions:      stdout.Redactions() + stderr.Redactions(),
		}
	} else {
		result = env.Executor.Run(ctx, executor.Request{
			Target:  p.Target,
			Command: req.Command,
			Stdin:   req.Stdin.Data,
		})
		filtered = env.Output.Apply(result.Stdout, result.Stderr)
	}
	// The audit hash records the bytes that crossed the trust boundary and were
	// returned to the agent after output filtering.
	outputHash := audit.ComputeOutputSHA256(filtered.Stdout, filtered.Stderr)

	status := StatusForResult(result)
	event := audit.EventCompleted
	if status != "completed" {
		event = audit.EventFailed
	}
	record := stampRun(baseRecord(p.ReqID, p.SessionCtx, event, p.Target.Name, req.Command, decision, &result.ExitCode, outputHash, result.Duration.Milliseconds(), filtered), req)
	record.RemoteSignID = result.RemoteSignID
	if event == audit.EventFailed {
		record.Error = interruption(ctx)
	}
	if _, err := env.Audit.Append(record); err != nil {
		return executed{}, err
	}
	// Settling runs after the completion record is safely appended; an
	// unsettled claim fails closed (the grant stays reserved), so it is only a
	// warning.
	if err := settleOnceClaim(env.Sessions, p.SessionCtx.ID, p.ReqID, p.Auth, result); err != nil {
		obs.Warning(fmt.Sprintf("failed to settle once-approval grant: %v", err))
	}
	if !IsSSHErrorResult(result) && env.HostOS != nil {
		env.HostOS(p.Target.Name, result.OS)
	}
	response := stampResponse(Response{
		ReqID:           p.ReqID,
		SessionID:       p.SessionCtx.ID,
		Host:            p.Target.Name,
		Cmd:             req.Command,
		Status:          status,
		ExitCode:        result.ExitCode,
		DurationMS:      result.Duration.Milliseconds(),
		Stdout:          filtered.Stdout,
		Stderr:          filtered.Stderr,
		OutputTruncated: filtered.OutputTruncated,
		Redactions:      filtered.Redactions,
		PolicyAction:    string(decision.Action),
		PolicyRule:      decision.Rule,
		GrantScope:      string(p.Auth.GrantScope),
		GrantExpiresTS:  p.Auth.GrantExpiresTS,
		ApprovalReason:  AuthorizationReason(p.Auth, req.Stdin.SHA256),
	}, req)
	obs.Finished(p.Target.Name, result, filtered, streamed)
	return executed{Response: response, Result: result, StreamErr: streamErr}, nil
}

// interruption names why ctx ended while a command ran, so the audit shows a
// cancelled or timed-out run rather than a bare transport failure.
func interruption(ctx context.Context) string {
	switch {
	case ctx.Err() == nil:
		return ""
	case errors.Is(ctx.Err(), context.DeadlineExceeded):
		return "timed out"
	default:
		return "cancelled"
	}
}

func buildPlans(env Env, req Request) ([]plan, error) {
	resolver := session.Resolver{}
	plans := make([]plan, 0, len(req.Target.Targets))
	for _, target := range req.Target.Targets {
		reqID, err := env.newReqID()
		if err != nil {
			return nil, err
		}
		sessionCtx, err := resolver.Resolve(target.Name, req.Session, req.SessionLabel)
		if err != nil {
			if errors.Is(err, session.ErrNoSession) {
				return nil, ErrNoSession
			}
			return nil, fmt.Errorf("resolve session: %w", err)
		}
		sessionCtx.ID = SessionIDForTarget(sessionCtx.ID, target.Name, len(req.Target.Targets) > 1)
		var auth approval.Authorization
		if env.Approval.Enabled {
			auth, err = approval.PreflightAuthorize(env.Policy, env.Inventory, env.Sessions, env.Approval, sessionCtx.ID, target.Name, req.Command, req.Stdin.SHA256)
		} else {
			auth, err = approval.Authorize(env.Policy, env.Inventory, env.Sessions, env.Approval, sessionCtx.ID, target.Name, req.Command, req.Stdin.SHA256, reqID)
		}
		if err != nil {
			return nil, invalidPolicyError(err)
		}
		if checked, ok := approval.CheckGrantedStdin(auth, req.Stdin.Bytes); !ok {
			if !env.Approval.Enabled && auth.GrantScope == approval.ScopeOnce {
				_ = env.Sessions.Release(sessionCtx.ID, reqID)
			}
			auth = checked
		}
		plans = append(plans, plan{Target: target, ReqID: reqID, SessionCtx: sessionCtx, Auth: auth})
	}
	return plans, nil
}

func anyNeedsApproval(plans []plan) bool {
	for _, p := range plans {
		if p.Auth.Status == approval.AuthNeedsApproval {
			return true
		}
	}
	return false
}

// preflightBlock answers a run in which some target needs approval: nothing
// executes, so a group is never half run.
func preflightBlock(env Env, req Request, obs Observer, plans []plan) (Outcome, error) {
	outcome := Outcome{ExitCode: ExitOK, Responses: make([]Response, 0, len(plans))}
	for _, p := range plans {
		switch p.Auth.Status {
		case approval.AuthHardDeny:
			response, err := appendDenied(env, req, obs, p)
			if err != nil {
				return Outcome{}, err
			}
			outcome.Responses = append(outcome.Responses, response)
			outcome.ExitCode = MergeExitCode(outcome.ExitCode, ExitPolicyDenied)
		case approval.AuthNeedsApproval:
			response, err := appendPending(env, req, obs, p)
			if err != nil {
				return Outcome{}, err
			}
			outcome.Responses = append(outcome.Responses, response)
			outcome.ExitCode = MergeExitCode(outcome.ExitCode, ExitApprovalRequired)
		default:
			exit := ExitApprovalRequired
			if _, err := env.Audit.Append(stampRun(baseRecord(p.ReqID, p.SessionCtx, audit.EventDenied, p.Target.Name, req.Command, p.Auth.Decision, &exit, "", 0), req)); err != nil {
				return Outcome{}, err
			}
			outcome.Responses = append(outcome.Responses, stampResponse(Response{
				ReqID:          p.ReqID,
				SessionID:      p.SessionCtx.ID,
				Host:           p.Target.Name,
				Cmd:            req.Command,
				Status:         "not_run",
				ExitCode:       ExitApprovalRequired,
				PolicyAction:   string(p.Auth.Decision.Action),
				PolicyRule:     p.Auth.Decision.Rule,
				ApprovalReason: AuthorizationReason(p.Auth, req.Stdin.SHA256),
			}, req))
			obs.NotRun(p.Target.Name)
			outcome.ExitCode = MergeExitCode(outcome.ExitCode, ExitApprovalRequired)
		}
	}
	Finalize(outcome.Responses, req.Stdin)
	return outcome, nil
}

func appendDenied(env Env, req Request, obs Observer, p plan) (Response, error) {
	if _, err := env.Audit.Append(stampRun(baseRecord(p.ReqID, p.SessionCtx, audit.EventDenied, p.Target.Name, req.Command, p.Auth.Decision, nil, "", 0), req)); err != nil {
		return Response{}, err
	}
	response := stampResponse(Response{
		ReqID:          p.ReqID,
		SessionID:      p.SessionCtx.ID,
		Host:           p.Target.Name,
		Cmd:            req.Command,
		Status:         "denied",
		ExitCode:       ExitPolicyDenied,
		PolicyAction:   string(p.Auth.Decision.Action),
		PolicyRule:     p.Auth.Decision.Rule,
		ApprovalReason: AuthorizationReason(p.Auth, req.Stdin.SHA256),
	}, req)
	obs.Denied(p.Target.Name, req.Command, p.Auth.Decision)
	return response, nil
}

func appendPending(env Env, req Request, obs Observer, p plan) (Response, error) {
	pending, err := env.Pending.Create(approval.PendingRequest{
		ReqID:       p.ReqID,
		SessionID:   p.SessionCtx.ID,
		Host:        p.Target.Name,
		Cmd:         req.Command,
		Candidate:   p.Auth.ApprovalMatcher,
		StdinSHA256: req.Stdin.SHA256,
		StdinBytes:  req.Stdin.Bytes,
	})
	if err != nil {
		return Response{}, err
	}
	exit := ExitApprovalRequired
	record := stampRun(baseRecord(p.ReqID, p.SessionCtx, audit.EventApprovalRequested, p.Target.Name, req.Command, p.Auth.Decision, &exit, "", 0), req)
	record.ApprovalID = pending.ID
	record.ApprovalMatcher = pending.Candidate.Regex
	record.ApprovalChannel = approval.ChannelExit
	if _, err := env.Audit.Append(record); err != nil {
		return Response{}, err
	}
	response := stampResponse(Response{
		ReqID:           p.ReqID,
		SessionID:       p.SessionCtx.ID,
		Host:            p.Target.Name,
		Cmd:             req.Command,
		Status:          "approval_pending",
		ExitCode:        ExitApprovalRequired,
		PolicyAction:    string(p.Auth.Decision.Action),
		PolicyRule:      p.Auth.Decision.Rule,
		ApprovalID:      pending.ID,
		ApprovalMatcher: pending.Candidate.Regex,
		ProposedScopes:  scopeStrings(pending.ProposedScopes),
		Task:            approval.TaskCandidate(pending.Cmd, pending.StdinSHA256),
		ApprovalReason:  AuthorizationReason(p.Auth, req.Stdin.SHA256),
	}, req)
	obs.ApprovalPending(p.Target.Name, pending)
	return response, nil
}

// settleOnceClaim closes the two-phase consumption of a once grant after the
// execution outcome is known. A remote exit (success or failure) consumes the
// grant. A transport-level failure (dial failure, local cancel, dropped
// connection) restores it so the approval survives for a clean re-run.
//
// Deliberate trade-off: SSH cannot prove that a transport failure happened
// before the remote started the command. A connection dropped (or Ctrl-C
// pressed) mid-execution therefore restores a grant whose command may already
// have run, and the re-run executes it a second time. The restored grant is
// still pinned to the exact command, session, and stdin hash, and both
// attempts are in the audit log; treat once approvals for non-idempotent
// commands accordingly.
func settleOnceClaim(sessions approval.SessionStore, sessionID string, reqID string, auth approval.Authorization, result executor.Result) error {
	if auth.Status != approval.AuthAllowByGrant || auth.GrantScope != approval.ScopeOnce {
		return nil
	}
	if IsSSHErrorResult(result) {
		return sessions.Release(sessionID, reqID)
	}
	return sessions.Commit(sessionID, reqID)
}

func invalidPolicyError(err error) error {
	return usageErrorf("policy.yaml is invalid: %v\n  fix the rule in ~/.agentssh/policy.yaml, then re-run (check: agentssh policy show)", err)
}

func (e Env) newReqID() (string, error) {
	if e.NewReqID != nil {
		return e.NewReqID()
	}
	return audit.NewReqID()
}

// SessionIDForTarget binds a multi-target run's session to each host, so one
// stored session id stays bound to one host.
func SessionIDForTarget(baseID string, host string, multiTarget bool) string {
	if !multiTarget || strings.TrimSpace(host) == "" {
		return baseID
	}
	return baseID + "@" + strings.TrimSpace(host)
}

// AuthorizationReason explains an authorization in the response's
// approval_reason field.
func AuthorizationReason(auth approval.Authorization, stdinSHA256 string) string {
	switch auth.Status {
	case approval.AuthAllow:
		return "allowed by policy rule " + auth.Decision.Rule
	case approval.AuthAllowByGrant:
		scope := string(auth.GrantScope)
		if scope == "" {
			scope = "approval"
		}
		if auth.Task != nil {
			return "reused " + scope + " approval grant: " + auth.Task.Summary()
		}
		return "reused " + scope + " approval grant"
	case approval.AuthNeedsApproval:
		if stdinSHA256 != "" {
			return "approval required: no reusable grant matched this command with stdin sha256 " + stdinSHA256
		}
		return "approval required: default deny and no reusable grant matched this session and host"
	case approval.AuthHardDeny:
		return "denied by policy rule " + auth.Decision.Rule
	default:
		return ""
	}
}

// StatusForResult classifies an executed command for the response.
func StatusForResult(result executor.Result) string {
	if IsSSHErrorResult(result) {
		return "ssh_error"
	}
	if result.ExitCode != 0 {
		return "failed"
	}
	return "completed"
}

// ExitCodeForResult maps an executed command to the contract exit code.
func ExitCodeForResult(result executor.Result) int {
	if IsSSHErrorResult(result) {
		return ExitSSHError
	}
	if result.ExitCode != 0 {
		return ExitRemoteFailed
	}
	return ExitOK
}

// IsSSHErrorResult reports a transport-level failure rather than a remote exit.
func IsSSHErrorResult(result executor.Result) bool {
	if result.Err != nil && !executor.IsProcessExit(result) {
		return true
	}
	// OpenSSH reserves exit code 255 for client/connection errors. A remote
	// command can theoretically also exit 255; AgentSSH treats 255 from ssh as
	// a connection/SSH failure to match the CLI contract.
	return len(result.Argv) > 0 && result.Argv[0] == "ssh" && result.ExitCode == 255
}

// MergeExitCode keeps the most conservative outcome of a multi-target run:
// deny(6) > approval_required(7) > ssh_error(9) > remote_failed(1) > success(0).
func MergeExitCode(current int, next int) int {
	if current == ExitPolicyDenied || next == ExitPolicyDenied {
		return ExitPolicyDenied
	}
	if current == ExitApprovalRequired || next == ExitApprovalRequired {
		return ExitApprovalRequired
	}
	if current == ExitSSHError || next == ExitSSHError {
		return ExitSSHError
	}
	if current == ExitRemoteFailed || next == ExitRemoteFailed {
		return ExitRemoteFailed
	}
	return ExitOK
}

func scopeStrings(scopes []approval.Scope) []string {
	out := make([]string, 0, len(scopes))
	for _, scope := range scopes {
		out = append(out, string(scope))
	}
	return out
}

func baseRecord(reqID string, sessionCtx session.Context, event audit.Event, host string, command string, decision policy.Decision, exitCode *int, outputHash string, durationMS int64, filtered ...output.FilterResult) audit.Record {
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

func stampRun(record audit.Record, req Request) audit.Record {
	record.StdinSHA256 = req.Stdin.SHA256
	record.StdinBytes = req.Stdin.Bytes
	record.ExecutionID = strings.TrimSpace(req.ExecutionID)
	record.StepID = strings.TrimSpace(req.StepID)
	record.ReviewSHA256 = strings.TrimSpace(req.ReviewSHA256)
	return record
}

func stampResponse(response Response, req Request) Response {
	response.ExecutionID = strings.TrimSpace(req.ExecutionID)
	response.StepID = strings.TrimSpace(req.StepID)
	response.ReviewSHA256 = strings.TrimSpace(req.ReviewSHA256)
	return response
}

type nopObserver struct{}

func (nopObserver) Denied(string, string, policy.Decision)                      {}
func (nopObserver) ApprovalPending(string, approval.PendingRequest)             {}
func (nopObserver) NotRun(string)                                               {}
func (nopObserver) Finished(string, executor.Result, output.FilterResult, bool) {}
func (nopObserver) Warning(string)                                              {}
