package gateway

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/Praeviso/AgentSSH/internal/controlplane"
	"github.com/Praeviso/AgentSSH/internal/remote"
)

// apiRoutes run commands for token devices with JSON in and out (see
// remote.APIRun). Starting and reading need the device active; cancelling
// does not, as for /exec/cancel.
func (s *Server) apiRoutes() []controlplane.OpenRoute {
	// A call may wait up to MaxAPIWait for its run, past the server's own
	// response deadline.
	respond := remote.MaxAPIWait + 15*time.Second
	return []controlplane.OpenRoute{
		s.tokenRoute("POST", remote.PathAPIRun, tokenOptions{needsActive: true, maxBody: maxExecBody, respondWithin: respond}, s.handleAPIRun),
		s.tokenRoute("POST", remote.PathAPIRunOutput, tokenOptions{needsActive: true, respondWithin: respond}, s.handleAPIRunOutput),
		s.tokenRoute("POST", remote.PathAPIRunCancel, tokenOptions{}, func(w http.ResponseWriter, r *http.Request, device controlplane.Device, _ string, body []byte) {
			s.handleCancel(w, r, device, body)
		}),
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

func (s *Server) handleAPIRun(w http.ResponseWriter, r *http.Request, device controlplane.Device, tokenID string, body []byte) {
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
	s.execAs(w, device, tokenID, exec, hex.EncodeToString(sum[:]), func(rn *run) { s.answerRun(w, r.Context(), rn, 0, wait) })
}

func (s *Server) handleAPIRunOutput(w http.ResponseWriter, r *http.Request, device controlplane.Device, _ string, body []byte) {
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
	if done && answer.State == remote.APIRunRunning {
		// The run ended without a final frame: its spool failed.
		answer.State, answer.Result = remote.APIRunFinished, remote.APIResultError
		answer.Error = &remote.ErrorResponse{Code: remote.CodeInternal, Error: "the run's output is incomplete; see the gateway's audit"}
	}
	answer.Stdout, answer.Stderr = string(stdout), string(stderr)
	controlplane.WriteJSON(w, http.StatusOK, answer)
}
