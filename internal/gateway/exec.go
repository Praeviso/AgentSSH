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
	"sync"
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

func (s *Server) execRoute() controlplane.Route {
	return controlplane.Route{Method: "POST", Path: remote.PathExec, Handler: s.handleExec, MaxBody: maxExecBody, Streaming: true}
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
		controlplane.WriteError(w, http.StatusBadRequest, remote.CodeUsage, fmt.Sprintf("%v\n  list all hosts: agentssh hosts", err))
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
	defer s.release(device.ID)

	ctx, cancel := context.WithTimeout(r.Context(), s.execTimeout())
	defer cancel()
	exec := s.executor(inv)
	defer func() { _ = exec.Close() }()
	approvalDir := filepath.Join(s.Dir, "devices", device.ID, "approval")
	env := runner.Env{
		Policy:    pol,
		Inventory: inv,
		Approval:  approvalRuntime(device.ID, pol.Approval),
		Sessions:  approval.SessionStore{Dir: filepath.Join(approvalDir, "sessions")},
		Pending: approval.PendingStore{
			PendingDir:   filepath.Join(approvalDir, "pending"),
			ResponsesDir: filepath.Join(approvalDir, "responses"),
			PlansDir:     filepath.Join(approvalDir, "plans"),
		},
		Audit:    deviceAudit{log: audit.NewStore(filepath.Join(s.Dir, FileAudit)), deviceID: device.ID},
		Executor: exec,
		Output:   filter,
	}
	frames := &frameWriter{w: w, rc: http.NewResponseController(w)}
	run := runner.Request{
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
		run.Stream = func(string, string) (io.Writer, io.Writer) {
			return frameStream{frames, remote.FrameStdout}, frameStream{frames, remote.FrameStderr}
		}
	}
	outcome, err := runner.Run(ctx, env, run)
	if err != nil {
		var usage runner.UsageError
		if errors.As(err, &usage) {
			frames.fail(http.StatusBadRequest, remote.CodeUsage, usage.Error())
			return
		}
		log.Printf("agentssh-gateway: device %s: execution failed: %v", device.ID, err)
		frames.fail(http.StatusInternalServerError, remote.CodeInternal, "execution failed")
		return
	}
	result := remote.ExecResult{ExitCode: outcome.ExitCode, Responses: outcome.Responses}
	if _, err := remote.EncodeExecResult(result); err != nil {
		// Unreachable with the output cap; say so rather than end the stream
		// without a result.
		log.Printf("agentssh-gateway: device %s: encode execution result: %v", device.ID, err)
		frames.fail(http.StatusInternalServerError, remote.CodeInternal, "execution finished but its result could not be encoded; see the gateway audit")
		return
	}
	if err := remote.WriteExecResult(frames.write, result); err != nil {
		// The device is gone; the audit already holds the outcome.
		log.Printf("agentssh-gateway: device %s: result not delivered: %v", device.ID, err)
	}
}

func validateExec(req remote.ExecRequest) error {
	switch {
	case strings.TrimSpace(req.Host) == "":
		return errors.New("a target host or group is required")
	case strings.TrimSpace(req.Cmd) == "":
		return errors.New("a command is required")
	case req.Session == "":
		return errors.New("a session must be declared for run\n  mint one id per task: agentssh session new, then pass --session <id> on every run in the task")
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

// deviceAudit stamps every record with the device it ran for.
type deviceAudit struct {
	log      audit.Store
	deviceID string
}

func (a deviceAudit) Append(record audit.Record) (audit.Record, error) {
	record.DeviceID = a.deviceID
	return a.log.Append(record)
}

// frameWriter commits the response on its first frame, so a failure before
// any output is an ordinary HTTP error. Writes are serialized because stdout
// and stderr are copied concurrently.
type frameWriter struct {
	mu      sync.Mutex
	w       http.ResponseWriter
	rc      *http.ResponseController
	started bool
	err     error
}

func (f *frameWriter) write(kind byte, payload []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return f.err
	}
	if !f.started {
		f.started = true
		f.w.Header().Set("Content-Type", remote.ExecContentType)
		// Ask buffering reverse proxies to pass frames through as they arrive.
		f.w.Header().Set("X-Accel-Buffering", "no")
		f.w.WriteHeader(http.StatusOK)
	}
	if f.err = remote.WriteFrame(f.w, kind, payload); f.err == nil {
		f.err = f.rc.Flush()
	}
	return f.err
}

func (f *frameWriter) fail(status int, code string, message string) {
	f.mu.Lock()
	started := f.started
	f.mu.Unlock()
	if !started {
		controlplane.WriteError(f.w, status, code, message)
		return
	}
	payload, _ := json.Marshal(remote.ErrorResponse{Code: code, Error: message})
	_ = f.write(remote.FrameError, payload)
}

type frameStream struct {
	frames *frameWriter
	kind   byte
}

func (s frameStream) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if err := s.frames.write(s.kind, p); err != nil {
		return 0, err
	}
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
func (logObserver) Finished(string, executor.Result, output.FilterResult, bool) {
}
func (o logObserver) Warning(message string) {
	log.Printf("agentssh-gateway: device %s: %s", o.deviceID, message)
}
