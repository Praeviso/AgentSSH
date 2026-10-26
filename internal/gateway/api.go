package gateway

import (
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/Praeviso/AgentSSH/internal/controlplane"
	"github.com/Praeviso/AgentSSH/internal/remote"
	"github.com/Praeviso/AgentSSH/internal/session"
)

// apiOperation is one operation of the token API: an HTTP route, and the
// MCP tool named tool that runs the same handler.
type apiOperation struct {
	method, path, tool string
	opts               tokenOptions
	handler            TokenHandler
}

// respondWithin lets a call wait up to MaxAPIWait for its run or approval,
// past the server's own response deadline.
const respondWithin = remote.MaxAPIWait + 15*time.Second

// apiOperations are the token API (see remote.APIRun). Every operation but
// /api/status and cancelling needs the device active; cancelling does not, as
// for /exec/cancel.
func (s *Server) apiOperations() []apiOperation {
	return []apiOperation{
		{"GET", remote.PathTokenStatus, "status", tokenOptions{}, s.handleTokenStatus},
		{"GET", remote.PathTokenHosts, "hosts", tokenOptions{needsActive: true}, func(w http.ResponseWriter, r *http.Request, device controlplane.Device, _ credential, body []byte) {
			s.handleHosts(w, r, device, body)
		}},
		{"POST", remote.PathAPISession, "new_session", tokenOptions{needsActive: true}, s.handleAPISession},
		{"POST", remote.PathAPIRun, "run", tokenOptions{needsActive: true, maxBody: maxExecBody, respondWithin: respondWithin}, s.handleAPIRun},
		{"POST", remote.PathAPIRunOutput, "run_output", tokenOptions{needsActive: true, respondWithin: respondWithin}, s.handleAPIRunOutput},
		{"POST", remote.PathAPIRunCancel, "cancel_run", tokenOptions{}, func(w http.ResponseWriter, r *http.Request, device controlplane.Device, _ credential, body []byte) {
			s.handleCancel(w, r, device, body)
		}},
		{"POST", remote.PathAPIRequestStatus, "request_status", tokenOptions{needsActive: true}, func(w http.ResponseWriter, r *http.Request, device controlplane.Device, _ credential, body []byte) {
			s.handleRequestStatus(w, r, device, body)
		}},
		{"POST", remote.PathAPIApprovalStatus, "approval_status", tokenOptions{needsActive: true, respondWithin: respondWithin}, s.handleAPIApprovalStatus},
	}
}

// apiWait is how long a call waits for its run.
func apiWait(ms *int64) time.Duration {
	if ms == nil {
		return remote.DefaultAPIWait
	}
	wait := time.Duration(*ms) * time.Millisecond
	switch {
	case *ms <= 0:
		return 0
	case wait > remote.MaxAPIWait:
		return remote.MaxAPIWait
	}
	return wait
}

func (s *Server) handleAPIRun(w http.ResponseWriter, r *http.Request, device controlplane.Device, cred credential, body []byte) {
	var req remote.APIRunRequest
	if controlplane.DecodeBody(body, &req) != nil {
		controlplane.WriteError(w, http.StatusBadRequest, remote.CodeBadRequest, "malformed run request")
		return
	}
	exec := remote.ExecRequest{
		RunID: req.RunID, Host: req.Host, Cmd: req.Command, Stdin: req.Stdin,
		Session: req.Session, SessionLabel: req.SessionLabel, Stream: true,
	}
	if err := validateExec(exec); err != nil {
		controlplane.WriteError(w, http.StatusBadRequest, remote.CodeUsage, err.Error())
		return
	}
	// The run is identified by what it runs, not by how long a call waits.
	canonical, _ := json.Marshal(exec)
	sum := sha256.Sum256(canonical)
	wait := apiWait(req.WaitMS)
	s.execAs(w, device, cred, exec, hex.EncodeToString(sum[:]), func(rn *run) { s.answerRun(w, r.Context(), rn, 0, wait) })
}

func (s *Server) handleAPIRunOutput(w http.ResponseWriter, r *http.Request, device controlplane.Device, _ credential, body []byte) {
	var req remote.APIRunOutputRequest
	if controlplane.DecodeBody(body, &req) != nil {
		controlplane.WriteError(w, http.StatusBadRequest, remote.CodeBadRequest, "malformed output request")
		return
	}
	s.sweepRuns()
	rn, err := s.lookupRun(device.ID, req.RunID)
	if err != nil {
		writeRunError(w, err, s.runRetention())
		return
	}
	s.answerRun(w, r.Context(), rn, req.Offset, apiWait(req.WaitMS))
}

// answerRun waits up to wait for rn to finish, then answers with its frames
// from offset: the output streamed since, the responses written since, and
// the result once it is there.
func (s *Server) answerRun(w http.ResponseWriter, ctx context.Context, rn *run, offset int64, wait time.Duration) {
	if size, _, _, _ := rn.snapshot(); offset < 0 || offset > size {
		controlplane.WriteError(w, http.StatusBadRequest, remote.CodeBadRequest, "offset is beyond the run's output")
		return
	}
	timer := time.NewTimer(wait)
	defer timer.Stop()
	for waiting := wait > 0; waiting; {
		_, done, broken, wake := rn.snapshot()
		if done || broken {
			break
		}
		select {
		case <-wake:
		case <-timer.C:
			waiting = false
		case <-ctx.Done():
			return
		}
	}
	size, done, _, _ := rn.snapshot()
	file, err := os.Open(rn.framesPath)
	if err != nil {
		controlplane.WriteError(w, http.StatusInternalServerError, remote.CodeInternal, "run output unavailable")
		return
	}
	defer func() { _ = file.Close() }()
	answer := remote.APIRun{RunID: rn.id, ReqID: rn.reqID, State: remote.APIRunRunning, Responses: []json.RawMessage{}, NextOffset: size}
	var stdout, stderr []byte
	frames := io.NewSectionReader(file, offset, size-offset)
	for {
		kind, payload, err := remote.ReadFrame(frames)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			// Offsets the API answers are frame boundaries; another is not.
			controlplane.WriteError(w, http.StatusBadRequest, remote.CodeBadRequest, "offset is not one this run answered")
			return
		}
		switch kind {
		case remote.FrameStdout:
			stdout = append(stdout, payload...)
		case remote.FrameStderr:
			stderr = append(stderr, payload...)
		case remote.FrameResponse:
			answer.Responses = append(answer.Responses, json.RawMessage(payload))
		case remote.FrameResult, remote.FrameError:
			applyFinal(&answer, kind, payload)
		}
	}
	if done && answer.State == remote.APIRunRunning {
		// The final frame lies before offset (the caller read past it
		// already): the result does not depend on where reading resumes.
		if kind, payload, ok := finalFrame(file, size); ok {
			applyFinal(&answer, kind, payload)
		} else {
			// The run ended without a final frame: its spool failed.
			answer.State, answer.Result = remote.APIRunFinished, remote.APIResultError
			answer.Error = &remote.ErrorResponse{Code: remote.CodeInternal, Error: "the run's output is incomplete; see the gateway's audit"}
		}
	}
	answer.Stdout, answer.Stderr = string(stdout), string(stderr)
	controlplane.WriteJSON(w, http.StatusOK, answer)
}

// applyFinal sets a finished run's result from its final frame.
func applyFinal(answer *remote.APIRun, kind byte, payload []byte) {
	switch kind {
	case remote.FrameResult:
		var final remote.ExecFinal
		if json.Unmarshal(payload, &final) == nil {
			answer.State, answer.Result, answer.ExitCode = remote.APIRunFinished, remote.APIResult(final.ExitCode), &final.ExitCode
			answer.Truncated, answer.TargetKind = final.Truncated, final.TargetKind
		}
	case remote.FrameError:
		var refusal remote.ErrorResponse
		if json.Unmarshal(payload, &refusal) == nil {
			answer.State, answer.Result, answer.Error = remote.APIRunFinished, remote.APIResultError, &refusal
		}
	}
}

// finalFrame finds a spool's final (result or error) frame by walking frame
// headers from the start, without reading the frames in between.
func finalFrame(spool io.ReaderAt, size int64) (byte, []byte, bool) {
	var header [remote.FrameHeaderBytes]byte
	var kind byte
	at, length := int64(-1), int64(0)
	for pos := int64(0); pos+remote.FrameHeaderBytes <= size; {
		if _, err := spool.ReadAt(header[:], pos); err != nil {
			return 0, nil, false
		}
		n := int64(binary.BigEndian.Uint32(header[1:]))
		if header[0] == remote.FrameResult || header[0] == remote.FrameError {
			kind, at, length = header[0], pos+remote.FrameHeaderBytes, n
		}
		pos += remote.FrameHeaderBytes + n
	}
	if at < 0 || length > remote.MaxMessageFrameBytes || at+length > size {
		return 0, nil, false
	}
	payload := make([]byte, length)
	if _, err := spool.ReadAt(payload, at); err != nil {
		return 0, nil, false
	}
	return kind, payload, true
}

// handleAPIApprovalStatus answers an approval request's status as `agentssh
// approval status` prints it, waiting up to wait_ms while it is pending.
func (s *Server) handleAPIApprovalStatus(w http.ResponseWriter, r *http.Request, device controlplane.Device, _ credential, body []byte) {
	var req remote.APIApprovalStatusRequest
	if controlplane.DecodeBody(body, &req) != nil {
		controlplane.WriteError(w, http.StatusBadRequest, remote.CodeBadRequest, "malformed approval status query")
		return
	}
	pending := s.approvals(device.ID).Pending
	deadline := time.Now().Add(apiWait(req.WaitMS))
	for {
		status, err := pending.Status(req.ApprovalID)
		if err != nil {
			writeApprovalError(w, err)
			return
		}
		if status.Status != "pending" || !time.Now().Before(deadline) {
			controlplane.WriteJSON(w, http.StatusOK, status)
			return
		}
		// Decisions are files another process writes; poll them.
		select {
		case <-time.After(min(approvalPoll, time.Until(deadline))):
		case <-r.Context().Done():
			return
		}
	}
}

// approvalPoll is how often a waiting approval status call looks again.
const approvalPoll = 250 * time.Millisecond

func (s *Server) handleAPISession(w http.ResponseWriter, _ *http.Request, _ controlplane.Device, _ credential, _ []byte) {
	id, err := session.NewID()
	if err != nil {
		controlplane.WriteError(w, http.StatusInternalServerError, remote.CodeInternal, "session id unavailable")
		return
	}
	controlplane.WriteJSON(w, http.StatusOK, remote.APISession{SessionID: id})
}

//go:embed openapi.json
var openAPIDocument []byte

// openAPIRoute serves the API's OpenAPI document, with base as its server,
// to anyone: it describes the API and holds no secret.
func openAPIRoute(base string) (controlplane.OpenRoute, error) {
	var doc map[string]any
	if err := json.Unmarshal(openAPIDocument, &doc); err != nil {
		return controlplane.OpenRoute{}, fmt.Errorf("openapi document: %w", err)
	}
	doc["servers"] = []map[string]string{{"url": base}}
	served, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return controlplane.OpenRoute{}, err
	}
	return controlplane.OpenRoute{Method: "GET", Path: remote.PathAPIOpenAPI, Handler: func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(served)
	}}, nil
}
