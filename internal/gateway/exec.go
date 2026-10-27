package gateway

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"path/filepath"
	"slices"
	"strings"
	"time"
	"unicode"

	"github.com/Praeviso/AgentSSH/internal/approval"
	"github.com/Praeviso/AgentSSH/internal/audit"
	"github.com/Praeviso/AgentSSH/internal/controlplane"
	"github.com/Praeviso/AgentSSH/internal/executor"
	"github.com/Praeviso/AgentSSH/internal/inventory"
	"github.com/Praeviso/AgentSSH/internal/output"
	"github.com/Praeviso/AgentSSH/internal/policy"
	"github.com/Praeviso/AgentSSH/internal/remote"
	"github.com/Praeviso/AgentSSH/internal/runner"
	"golang.org/x/crypto/ssh"
)

const (
	// DefaultExecTimeout bounds one execution, including approval preflight.
	DefaultExecTimeout = 30 * time.Minute
	// DefaultMaxConcurrentPerDevice bounds executions running at once for one
	// device.
	DefaultMaxConcurrentPerDevice = 4

	// FileAudit is the gateway's audit hash chain, shared by all devices.
	FileAudit = "audit.jsonl"
	// FileKnownHosts holds the target host keys the gateway trusts.
	FileKnownHosts = "known_hosts"

	// Stdin travels base64 encoded inside the JSON body, and JSON may escape
	// each command byte as six.
	maxExecBody = (remote.MaxExecStdinBytes+2)/3*4 + 6*remote.MaxExecCommandBytes + 64<<10
)

func (s *Server) execRoutes() []controlplane.Route {
	return []controlplane.Route{
		{Method: "POST", Path: remote.PathExec, Handler: s.handleExec, MaxBody: maxExecBody, Streaming: true},
		{Method: "POST", Path: remote.PathExecAttach, Handler: s.handleAttach, Streaming: true},
		{Method: "POST", Path: remote.PathExecCancel, Handler: s.handleCancel},
	}
}

func (s *Server) handleExec(w http.ResponseWriter, r *http.Request, device controlplane.Device, body []byte) {
	var req remote.ExecRequest
	if controlplane.DecodeBody(body, &req) != nil {
		controlplane.WriteError(w, http.StatusBadRequest, remote.CodeBadRequest, "malformed execution request")
		return
	}
	if err := validateExec(req); err != nil {
		controlplane.WriteError(w, http.StatusBadRequest, remote.CodeUsage, err.Error())
		return
	}
	sum := sha256.Sum256(body)
	s.exec(w, device, req, hex.EncodeToString(sum[:]), func(rn *run) { s.streamRun(w, r.Context(), rn, 0) })
}

// exec starts req for device, or joins the run its ID already names, and
// hands the run to serve; when it cannot, it answers the request itself.
// requestSHA256 identifies the request, so a repeat joins its run and a
// different request with the same ID is refused.
func (s *Server) exec(w http.ResponseWriter, device controlplane.Device, req remote.ExecRequest, requestSHA256 string, serve func(*run)) {
	s.execAs(w, device, credential{}, req, requestSHA256, serve)
}

// execAs is exec for a request a token device made with cred, which its
// audit records name.
func (s *Server) execAs(w http.ResponseWriter, device controlplane.Device, cred credential, req remote.ExecRequest, requestSHA256 string, serve func(*run)) {
	// A repeated request for a run that already exists joins it, so a client
	// that lost the first response neither loses the run nor starts it twice.
	if req.RunID != "" && s.serveExisting(w, device.ID, req.RunID, requestSHA256, serve) {
		return
	}
	cfg, err := s.Store.Config(device.ID)
	if errors.Is(err, controlplane.ErrNotFound) {
		controlplane.WriteError(w, http.StatusNotFound, remote.CodeNoConfig, "no configuration has been pushed for this device")
		return
	}
	if err != nil {
		controlplane.WriteError(w, http.StatusInternalServerError, remote.CodeInternal, "configuration lookup failed")
		return
	}
	// Identities are checked when a connection is signed, so a disabled
	// identity fails only the hosts that use it.
	inv, pol, err := remote.ParseManaged(cfg.InventoryYAML, cfg.PolicyYAML, nil)
	if err != nil {
		controlplane.WriteError(w, http.StatusInternalServerError, remote.CodeInternal, "stored configuration is unreadable")
		return
	}
	resolved, err := inventory.NewResolver(inv).Resolve(req.Host)
	if err != nil {
		controlplane.WriteError(w, http.StatusBadRequest, remote.CodeUsage, runner.ResolveUsage(err).Error())
		return
	}
	// Checked after the target, in the CLI's order. The runner would fall
	// back to the gateway's own AGENTSSH_SESSION, which is never the device's.
	if req.Session == "" {
		controlplane.WriteError(w, http.StatusBadRequest, remote.CodeUsage, runner.ErrNoSession.Error())
		return
	}
	// Cap output so each target's response fits one frame; the cap applies in
	// the filter, so the audit hash still covers exactly what is returned.
	outputCfg := pol.Output
	if outputCfg.MaxBytes <= 0 || outputCfg.MaxBytes > remote.MaxExecOutputBytes {
		outputCfg.MaxBytes = remote.MaxExecOutputBytes
	}
	filter, err := output.NewFilter(outputCfg)
	if err != nil {
		controlplane.WriteError(w, http.StatusBadRequest, remote.CodeUsage, fmt.Sprintf("invalid output filter in the gateway policy: %v", err))
		return
	}
	// The run outlives this request: a dropped connection only detaches the
	// device, and /exec/cancel or the timeout stops the command.
	base, cancelBase := context.WithCancelCause(context.Background())
	ctx, stopTimer := context.WithTimeout(base, s.execTimeout())
	// cancel stops the run; a non-nil cause (lost standing) is named in its
	// audit record, while the device's own cancel gives none.
	cancel := func(cause error) {
		cancelBase(cause)
		stopTimer()
	}
	id := req.RunID
	if id == "" {
		id = remote.NewRunID()
	}
	// A single-host run's request ID is minted now, so the run frame can name
	// it before any output streams.
	reqID := ""
	if resolved.Kind == inventory.TargetKindHost {
		if reqID, err = audit.NewReqID(); err != nil {
			cancel(nil)
			controlplane.WriteError(w, http.StatusInternalServerError, remote.CodeInternal, "request id unavailable")
			return
		}
	}
	rn, err := s.startRun(runStart{
		deviceID: device.ID, id: id, requestSHA256: requestSHA256, reqID: reqID,
		targets: len(resolved.Targets), identities: targetIdentities(resolved.Targets), cancel: cancel,
	})
	if err != nil {
		cancel(nil)
		switch {
		case errors.Is(err, errRunExists):
			// The ID was claimed meanwhile: by a concurrent repeat of this
			// request, a different request, or a cancel that overtook it.
			if !s.serveExisting(w, device.ID, id, requestSHA256, serve) {
				controlplane.WriteError(w, http.StatusInternalServerError, remote.CodeInternal, "run record changed while starting; retry")
			}
		case errors.Is(err, errTooManyConcurrent):
			controlplane.WriteError(w, http.StatusTooManyRequests, remote.CodeBusy, fmt.Sprintf("this device already has %d executions running", s.maxConcurrent()))
		case errors.Is(err, errRunTooLarge):
			controlplane.WriteError(w, http.StatusBadRequest, remote.CodeUsage, fmt.Sprintf("%s has %d hosts; --run-max-bytes on the gateway allows at most %d per run", req.Host, len(resolved.Targets), s.maxRunTargets()))
		case errors.Is(err, errTooManyRecords):
			writeRunError(w, err, s.runRetention())
		default:
			log.Printf("agentssh-gateway: device %s: create run: %v", device.ID, err)
			controlplane.WriteError(w, http.StatusInternalServerError, remote.CodeInternal, "run storage unavailable")
		}
		return
	}
	exec := s.executor(inv)
	stores := s.approvals(device.ID)
	env := runner.Env{
		Policy:    pol,
		Inventory: inv,
		Approval:  approvalRuntime(device.ID, pol.Approval),
		Sessions:  stores.Sessions,
		Pending:   stores.Pending,
		Audit:     deviceAudit{log: s.deviceAudit(device.ID).log, deviceID: device.ID, cred: cred},
		Executor:  exec,
		Output:    filter,
	}
	if reqID != "" {
		env.NewReqID = func() (string, error) { return reqID, nil }
	}
	request := runner.Request{
		Target:       resolved,
		Command:      req.Cmd,
		Stdin:        execStdin(req.Stdin),
		Session:      req.Session,
		SessionLabel: req.SessionLabel,
		ExecutionID:  req.ExecutionID,
		StepID:       req.StepID,
		ReviewSHA256: req.ReviewSHA256,
		Observer:     logObserver{deviceID: device.ID},
	}
	if req.Stream {
		request.Stream = func(string, string) (io.Writer, io.Writer) {
			return spoolStream{rn, remote.FrameStdout}, spoolStream{rn, remote.FrameStderr}
		}
	}
	go func() {
		defer cancel(nil)
		defer func() { _ = exec.Close() }()
		s.execute(ctx, rn, env, request)
	}()
	serve(rn)
}

// execute runs the pipeline and spools its outcome as response frames and a
// result frame (or an error frame).
func (s *Server) execute(ctx context.Context, rn *run, env runner.Env, request runner.Request) {
	defer s.endRun(rn)
	outcome, err := runner.Run(ctx, env, request)
	if lost := rn.stoppedFor(); lost.reason != "" {
		// The device sees why the gateway stopped its command, not the
		// transport failure the interruption caused.
		payload, _ := json.Marshal(remote.ErrorResponse{Code: lost.code, Error: "the gateway stopped this command: " + lost.reason})
		rn.finish(remote.FrameError, payload, s.now())
		return
	}
	if err != nil {
		code, message := remote.CodeInternal, "execution failed"
		var usage runner.UsageError
		if errors.As(err, &usage) {
			code, message = remote.CodeUsage, usage.Error()
		} else if errors.Is(err, approval.ErrTooManyPending) {
			code, message = remote.CodeBusy, approval.ErrTooManyPending.Error()
		} else {
			log.Printf("agentssh-gateway: run %s: execution failed: %v", rn.id, err)
		}
		payload, _ := json.Marshal(remote.ErrorResponse{Code: code, Error: message})
		rn.finish(remote.FrameError, payload, s.now())
		return
	}
	for _, response := range outcome.Responses {
		rn.response(response)
	}
	final := remote.ExecFinal{ExitCode: outcome.ExitCode, Truncated: rn.isTruncated(), TargetKind: string(request.Target.Kind)}
	if final.Truncated {
		// A partial result must never pass for a complete one.
		final.ExitCode = runner.MergeExitCode(final.ExitCode, runner.ExitRemoteFailed)
	}
	payload, _ := json.Marshal(final)
	rn.finish(remote.FrameResult, payload, s.now())
}

// serveExisting answers a request whose run ID is already claimed: it hands
// the run to serve for a repeat of the same request, and refuses a different
// request, an ID cancelled before its request arrived, and an expired or
// interrupted run. It reports false only when the ID was never claimed, so
// the caller starts the run.
func (s *Server) serveExisting(w http.ResponseWriter, deviceID, id, requestSHA256 string, serve func(*run)) bool {
	rn, err := s.lookupRun(deviceID, id)
	if errors.Is(err, errRunNotFound) {
		return false
	}
	if err == nil && rn.requestSHA256 != requestSHA256 {
		err = errRunConflict
	}
	if err != nil {
		writeRunError(w, err, s.runRetention())
		return true
	}
	serve(rn)
	return true
}

func validateExec(req remote.ExecRequest) error {
	if req.RunID != "" && !remote.ValidRunID(req.RunID) {
		return errors.New("run id must be rn_ followed by 32 lowercase hex characters")
	}
	switch {
	case strings.TrimSpace(req.Host) == "":
		return errors.New("a target host or group is required")
	case strings.TrimSpace(req.Cmd) == "":
		return errors.New("a command is required")
	case len(req.Session) > remote.MaxExecFieldBytes || strings.IndexFunc(req.Session, unicode.IsControl) >= 0:
		return fmt.Errorf("session id must be at most %d bytes without control characters", remote.MaxExecFieldBytes)
	case len(req.Stdin) > remote.MaxExecStdinBytes:
		return fmt.Errorf("stdin is %d bytes; the limit is %d bytes (32 MiB)", len(req.Stdin), remote.MaxExecStdinBytes)
	case len(req.Cmd) > remote.MaxExecCommandBytes:
		return fmt.Errorf("command is %d bytes; the limit is %d bytes (128 KiB)", len(req.Cmd), remote.MaxExecCommandBytes)
	case len(req.SessionLabel) > remote.MaxExecLabelBytes:
		return fmt.Errorf("session label must be at most %d bytes", remote.MaxExecLabelBytes)
	}
	for name, value := range map[string]string{"host": req.Host, "execution id": req.ExecutionID, "step id": req.StepID, "review sha256": req.ReviewSHA256} {
		if len(value) > remote.MaxExecFieldBytes {
			return fmt.Errorf("%s must be at most %d bytes", name, remote.MaxExecFieldBytes)
		}
	}
	return nil
}

func execStdin(data []byte) runner.Stdin {
	if data == nil {
		return runner.Stdin{}
	}
	sum := sha256.Sum256(data)
	return runner.Stdin{Data: data, SHA256: hex.EncodeToString(sum[:]), Bytes: int64(len(data))}
}

// approvalRuntime reads approval settings from the device's policy only; the
// gateway's own environment never switches approvals on or off.
func approvalRuntime(deviceID string, cfg policy.Approval) approval.RuntimeConfig {
	runtime, err := approval.RuntimeConfigFromPolicy(cfg, "")
	if err != nil {
		log.Printf("agentssh-gateway: device %s: invalid approval configuration: %v; approvals disabled", deviceID, err)
		return approval.RuntimeConfig{
			Enabled:       false,
			HostGrantMode: approval.HostGrantSafePrefix,
			SessionTTL:    approval.DefaultSessionTTL,
			WaitTimeout:   approval.DefaultWaitTimeout,
		}
	}
	return runtime
}

// executor connects only with the gateway's identities: no agent, local keys,
// passwords or ssh_config, and no connection reuse, so disabling an identity
// takes effect on the next connection.
func (s *Server) executor(inv inventory.Inventory) executor.Executor {
	if s.Executor != nil {
		return s.Executor(inv)
	}
	return executor.NewNativeExecutor(executor.NativeOptions{
		ConfigPath:             filepath.Join(s.Dir, "ssh_config"),
		KnownHostsPath:         filepath.Join(s.Dir, FileKnownHosts),
		HostKeyPolicy:          inv.HostKeyPolicy,
		DisableConnectionReuse: true,
		RemoteSigner: func(host string) (ssh.Signer, error) {
			entry, ok := inv.Hosts[host]
			if !ok {
				return nil, fmt.Errorf("host %q is not in this device's inventory", host)
			}
			return s.identitySigner(entry.Identity)
		},
	})
}

func (s *Server) identitySigner(name string) (ssh.Signer, error) {
	identity, err := s.Store.Identity(name)
	if errors.Is(err, controlplane.ErrNotFound) {
		return nil, fmt.Errorf("identity %q does not exist", name)
	}
	if err != nil {
		return nil, err
	}
	if identity.Status != controlplane.IdentityActive {
		return nil, fmt.Errorf("identity %q is disabled", name)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if signer, ok := s.signers[name]; ok {
		return signer, nil
	}
	signer, err := s.Keys.DecryptIdentity(identity.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("identity %q key unavailable: %w", name, err)
	}
	if s.signers == nil {
		s.signers = map[string]ssh.Signer{}
	}
	s.signers[name] = signer
	return signer, nil
}

func (s *Server) execTimeout() time.Duration {
	if s.ExecTimeout > 0 {
		return s.ExecTimeout
	}
	return DefaultExecTimeout
}

func (s *Server) maxConcurrent() int {
	if s.MaxConcurrentPerDevice > 0 {
		return s.MaxConcurrentPerDevice
	}
	return DefaultMaxConcurrentPerDevice
}

func (s *Server) deviceAudit(deviceID string) deviceAudit {
	return deviceAudit{log: audit.NewStore(filepath.Join(s.Dir, FileAudit)), deviceID: deviceID}
}

// deviceAudit stamps every record with the device it ran for, and the token
// or OAuth grant a token device used.
type deviceAudit struct {
	log      audit.Store
	deviceID string
	cred     credential
}

func (a deviceAudit) Append(record audit.Record) (audit.Record, error) {
	record.DeviceID, record.TokenID, record.GrantID = a.deviceID, a.cred.tokenID, a.cred.grantID
	return a.log.Append(record)
}

// spoolStream feeds a running command's output into its run's spool.
type spoolStream struct {
	run  *run
	kind byte
}

func (s spoolStream) Write(p []byte) (int, error) {
	s.run.data(s.kind, p)
	return len(p), nil
}

// logObserver reports pipeline warnings in the gateway's log; everything else
// reaches the device through the result frame and the audit chain.
type logObserver struct {
	deviceID string
}

func (logObserver) Denied(string, string, policy.Decision)          {}
func (logObserver) ApprovalPending(string, approval.PendingRequest) {}
func (logObserver) NotRun(string)                                   {}

// Finished logs SSH failures: the device only learns that the connection
// failed, and the cause stays with the gateway's administrator.
func (o logObserver) Finished(host string, result executor.Result, _ output.FilterResult, _ bool) {
	if runner.IsSSHErrorResult(result) {
		log.Printf("agentssh-gateway: device %s: host %s: ssh: %v", o.deviceID, host, result.Err)
	}
}
func (o logObserver) Warning(message string) {
	log.Printf("agentssh-gateway: device %s: %s", o.deviceID, message)
}

// targetIdentities are the identities a run's targets connect with, so the
// run can be stopped when one is disabled.
func targetIdentities(targets []inventory.Target) []string {
	var names []string
	for _, target := range targets {
		if target.Host.Identity != "" && !slices.Contains(names, target.Host.Identity) {
			names = append(names, target.Host.Identity)
		}
	}
	return names
}
