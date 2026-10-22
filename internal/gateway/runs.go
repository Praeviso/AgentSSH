package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/Praeviso/AgentSSH/internal/controlplane"
	"github.com/Praeviso/AgentSSH/internal/remote"
)

// streamRun sends the run frame and then the spool from offset, following a
// live run until its final frame or until the device goes away.
func (s *Server) streamRun(w http.ResponseWriter, ctx context.Context, rn *run, offset int64) {
	size, _, _, _ := rn.snapshot()
	if offset < 0 || offset > size {
		controlplane.WriteError(w, http.StatusBadRequest, remote.CodeBadRequest, "offset is beyond the run's output")
		return
	}
	file, err := os.Open(rn.framesPath)
	if err != nil {
		controlplane.WriteError(w, http.StatusInternalServerError, remote.CodeInternal, "run output unavailable")
		return
	}
	defer func() { _ = file.Close() }()
	runFrame, _ := json.Marshal(remote.ExecRun{RunID: rn.id})
	w.Header().Set("Content-Type", remote.ExecContentType)
	// Ask buffering reverse proxies to pass frames through as they arrive.
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	rc := http.NewResponseController(w)
	if remote.WriteFrame(w, remote.FrameRun, runFrame) != nil || rc.Flush() != nil {
		return
	}
	for {
		size, done, broken, wake := rn.snapshot()
		if offset < size {
			if _, err := io.Copy(w, io.NewSectionReader(file, offset, size-offset)); err != nil {
				return
			}
			offset = size
			if rc.Flush() != nil {
				return
			}
			continue
		}
		if done || broken {
			return
		}
		select {
		case <-wake:
		case <-ctx.Done():
			return
		}
	}
}

func (s *Server) handleAttach(w http.ResponseWriter, r *http.Request, device controlplane.Device, body []byte) {
	var req remote.ExecAttachRequest
	if controlplane.DecodeBody(body, &req) != nil {
		controlplane.WriteError(w, http.StatusBadRequest, remote.CodeBadRequest, "malformed attach request")
		return
	}
	s.sweepRuns()
	rn, err := s.lookupRun(device.ID, req.RunID)
	if err != nil {
		writeRunError(w, err, s.runRetention())
		return
	}
	s.streamRun(w, r.Context(), rn, req.Offset)
}

func (s *Server) handleCancel(w http.ResponseWriter, _ *http.Request, device controlplane.Device, body []byte) {
	var req remote.ExecCancelRequest
	if controlplane.DecodeBody(body, &req) != nil || !remote.ValidRunID(req.RunID) {
		controlplane.WriteError(w, http.StatusBadRequest, remote.CodeBadRequest, "malformed cancel request")
		return
	}
	cancelled, err := s.cancelRun(device.ID, req.RunID)
	if err != nil {
		// The cancel could not be recorded, so the device must not assume an
		// overtaken request will be refused.
		writeRunError(w, err, s.runRetention())
		return
	}
	controlplane.WriteJSON(w, http.StatusOK, remote.ExecCancelResponse{RunID: req.RunID, Cancelled: cancelled})
}

func writeRunError(w http.ResponseWriter, err error, retention time.Duration) {
	switch {
	case errors.Is(err, errRunInterrupted):
		controlplane.WriteError(w, http.StatusGone, remote.CodeRunInterrupted, "the gateway restarted while this run was in progress; its outcome is unknown (check the gateway audit)")
	case errors.Is(err, errRunConflict):
		controlplane.WriteError(w, http.StatusConflict, remote.CodeRunConflict, "this run id was already used for a different request")
	case errors.Is(err, errRunCancelled):
		controlplane.WriteError(w, http.StatusConflict, remote.CodeRunCancelled, "this run was cancelled before its request arrived")
	case errors.Is(err, errTooManyRecords):
		controlplane.WriteError(w, http.StatusTooManyRequests, remote.CodeBusy, "this device keeps too many runs on the gateway (serve --run-records); retry later")
	case errors.Is(err, errRunTooLarge):
		controlplane.WriteError(w, http.StatusBadRequest, remote.CodeUsage, err.Error())
	case errors.Is(err, errRunBroken):
		controlplane.WriteError(w, http.StatusInternalServerError, remote.CodeInternal, "the gateway could not store this run's output; its outcome is in the gateway audit")
	case errors.Is(err, errRunNotFound), errors.Is(err, errRunExpired):
		controlplane.WriteError(w, http.StatusNotFound, remote.CodeRunNotFound, fmt.Sprintf("no such run for this device, or its output expired (kept %s after a run finishes)", retention))
	default:
		log.Printf("agentssh-gateway: run storage: %v", err)
		controlplane.WriteError(w, http.StatusInternalServerError, remote.CodeInternal, "run storage unavailable")
	}
}
