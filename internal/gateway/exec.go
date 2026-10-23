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
	requestSHA256 := hex.EncodeToString(sum[:])
	// A repeated request for a run that already exists joins it, so a client
	// that lost the first response neither loses the run nor starts it twice.
	if req.RunID != "" && s.joinRun(w, r, device.ID, req.RunID, requestSHA256) {
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
	if !s.acquire(device.ID) {
		controlplane.WriteError(w, http.StatusTooManyRequests, remote.CodeBusy, fmt.Sprintf("this device already has %d executions running", s.maxConcurrent()))
		return
	}
	// Refuse a run that cannot start before making room for it, so a
	// refused request never evicts retained output.
	if int64(len(resolved.Targets)) > s.maxRunTargets() {
		s.release(device.ID)
		controlplane.WriteError(w, http.StatusBadRequest, remote.CodeUsage, fmt.Sprintf("%s has %d hosts; --run-max-bytes on the gateway allows at most %d per run", req.Host, len(resolved.Targets), s.maxRunTargets()))
		return
	}
	s.sweepRuns()
	s.makeRoom(device.ID, s.runMaxBytes())
	// The run outlives this request: a dropped connection only detaches the
	// device, and /exec/cancel or the timeout stops the command.
	ctx, cancel := context.WithTimeout(context.Background(), s.execTimeout())
	id := req.RunID
	if id == "" {
		id = remote.NewRunID()
	}
	// A single-host run's request ID is minted now, so the run frame can name
	// it before any output streams.
	reqID := ""
	if resolved.Kind == inventory.TargetKindHost {
		if reqID, err = audit.NewReqID(); err != nil {
			cancel()
			s.release(device.ID)
			controlplane.WriteError(w, http.StatusInternalServerError, remote.CodeInternal, "request id unavailable")
			return
		}
	}
	rn, err := s.startRun(device.ID, id, requestSHA256, reqID, len(resolved.Targets), cancel)
	if err != nil {
		cancel()
		s.release(device.ID)
		switch {
		case errors.Is(err, errRunExists):
			// The ID was claimed meanwhile: by a concurrent repeat of this
			// request, a different request, or a cancel that overtook it.
			if !s.joinRun(w, r, device.ID, id, requestSHA256) {
				controlplane.WriteError(w, http.StatusInternalServerError, remote.CodeInternal, "run record changed while starting; retry")
			}
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
		Audit:     s.deviceAudit(device.ID),
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
		defer s.release(device.ID)
		defer cancel()
		defer func() { _ = exec.Close() }()
		s.execute(ctx, rn, env, request)
	}()
	s.streamRun(w, r.Context(), rn, 0)
}

// execute runs the pipeline and spools its outcome as response frames and a
// result frame (or an error frame).
func (s *Server) execute(ctx context.Context, rn *run, env runner.Env, request runner.Request) {
	defer func() {
		s.endRun(rn)
		// Settle any quota overshoot now that this run is stored.
		s.makeRoom(rn.deviceID, 0)
	}()
	outcome, err := runner.Run(ctx, env, request)
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

// joinRun answers a request whose run ID is already claimed: it streams the
// run to a repeat of the same request, and refuses a different request, an
// ID cancelled before its request arrived, and an expired or interrupted
// run. It reports false only when the ID was never claimed, so the caller
// starts the run.
func (s *Server) joinRun(w http.ResponseWriter, r *http.Request, deviceID, id, requestSHA256 string) bool {
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
	s.streamRun(w, r.Context(), rn, 0)
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

func (s *Server) acquire(deviceID string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.running[deviceID] >= s.maxConcurrent() {
		return false
	}
	if s.running == nil {
		s.running = map[string]int{}
	}
	s.running[deviceID]++
	return true
}

func (s *Server) release(deviceID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.running[deviceID]--; s.running[deviceID] <= 0 {
		delete(s.running, deviceID)
	}
}

func (s *Server) deviceAudit(deviceID string) deviceAudit {
	return deviceAudit{log: audit.NewStore(filepath.Join(s.Dir, FileAudit)), deviceID: deviceID}
}

// deviceAudit stamps every record with the device it ran for.
type deviceAudit struct {
	log      audit.Store
	deviceID string
}

func (a deviceAudit) Append(record audit.Record) (audit.Record, error) {
	record.DeviceID = a.deviceID
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
