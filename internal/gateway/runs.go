package gateway

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/Praeviso/AgentSSH/internal/controlplane"
	"github.com/Praeviso/AgentSSH/internal/fileutil"
	"github.com/Praeviso/AgentSSH/internal/remote"
	"github.com/Praeviso/AgentSSH/internal/runner"
)

const (
	// DefaultRunRetention is how long a finished run's output stays
	// reattachable.
	DefaultRunRetention = 24 * time.Hour
	// DefaultRunMaxBytes caps one run's spooled frames.
	DefaultRunMaxBytes = 64 << 20

	// runReserveBytes is kept back per target so a response, stripped of its
	// output, always fits after the cap is reached.
	runReserveBytes = 16 << 10
	runSweepEvery   = time.Minute

	dirRuns       = "runs"
	fileRunMeta   = "meta.json"
	fileRunFrames = "frames"
)

var (
	errRunNotFound    = errors.New("run not found")
	errRunInterrupted = errors.New("run interrupted")
	errRunBroken      = errors.New("run spool broken")
)

// runMeta is a run's durable record; FinishedAt is empty until the result
// frame is spooled.
type runMeta struct {
	RunID      string `json:"run_id"`
	DeviceID   string `json:"device_id"`
	CreatedAt  string `json:"created_at"`
	FinishedAt string `json:"finished_at,omitempty"`
	// Broken means a spool write failed, so the frames file lacks its result.
	Broken bool `json:"broken,omitempty"`
}

// run is one execution's spool. The runner writes frames; any number of
// device connections tail them.
type run struct {
	id       string
	deviceID string
	dir      string
	budget   int64

	mu        sync.Mutex
	meta      runMeta
	file      *os.File
	size      int64
	truncated bool
	done      bool
	err       error
	wake      chan struct{}
	cancel    context.CancelFunc
}

func newRunID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(fmt.Sprintf("crypto/rand: %v", err))
	}
	return "rn_" + hex.EncodeToString(b[:])
}

func (s *Server) runsDir() string { return filepath.Join(s.Dir, dirRuns) }

func (s *Server) runRetention() time.Duration {
	if s.RunRetention > 0 {
		return s.RunRetention
	}
	return DefaultRunRetention
}

func (s *Server) runMaxBytes() int64 {
	if s.RunMaxBytes > 0 {
		return s.RunMaxBytes
	}
	return DefaultRunMaxBytes
}

// startRun creates a run's spool and registers it; cancel stops its context.
func (s *Server) startRun(deviceID string, targets int, cancel context.CancelFunc) (*run, error) {
	id := newRunID()
	dir := filepath.Join(s.runsDir(), id)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	file, err := os.OpenFile(filepath.Join(dir, fileRunFrames), os.O_CREATE|os.O_EXCL|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, err
	}
	rn := &run{
		id: id, deviceID: deviceID, dir: dir,
		budget: max(0, s.runMaxBytes()-int64(targets)*runReserveBytes),
		meta:   runMeta{RunID: id, DeviceID: deviceID, CreatedAt: controlplane.FormatTime(s.now())},
		file:   file, wake: make(chan struct{}), cancel: cancel,
	}
	if err := rn.writeMeta(); err != nil {
		_ = file.Close()
		return nil, err
	}
	s.mu.Lock()
	if s.runs == nil {
		s.runs = map[string]*run{}
	}
	s.runs[id] = rn
	s.mu.Unlock()
	return rn, nil
}

func (r *run) writeMeta() error {
	data, err := json.Marshal(r.meta)
	if err != nil {
		return err
	}
	return fileutil.WriteFileAtomic(filepath.Join(r.dir, fileRunMeta), data, 0o600, fileRunMeta+"-*")
}

// appendLocked spools one frame and wakes readers. A failed write breaks the
// run: later frames are discarded and attach reports the spool as broken.
func (r *run) appendLocked(kind byte, payload []byte) {
	if r.err != nil {
		return
	}
	var frame bytes.Buffer
	if err := remote.WriteFrame(&frame, kind, payload); err != nil {
		r.err = err
		return
	}
	if _, err := r.file.Write(frame.Bytes()); err != nil {
		r.err = err
		return
	}
	r.size += int64(frame.Len())
	close(r.wake)
	r.wake = make(chan struct{})
}

// data spools output while it fits the budget; once it does not, the rest
// is dropped and the run is marked truncated.
func (r *run) data(kind byte, p []byte) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for len(p) > 0 {
		chunk := p[:min(len(p), remote.MaxDataFrameBytes)]
		if r.truncated || r.size+remote.FrameSize(len(chunk)) > r.budget {
			r.truncated = true
			return
		}
		r.appendLocked(kind, chunk)
		p = p[len(chunk):]
	}
}

// response spools one target's result, without its output if the full
// response does not fit the budget or a frame.
func (r *run) response(response runner.Response) {
	r.mu.Lock()
	defer r.mu.Unlock()
	payload, err := json.Marshal(response)
	if err == nil && (r.truncated || len(payload) > remote.MaxMessageFrameBytes || r.size+remote.FrameSize(len(payload)) > r.budget) {
		r.truncated = true
		response.Stdout, response.Stderr, response.OutputTruncated = "", "", true
		payload, err = json.Marshal(response)
	}
	if err != nil {
		r.err = err
		return
	}
	r.appendLocked(remote.FrameResponse, payload)
}

func (r *run) isTruncated() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.truncated
}

// finish spools the final frame, records completion, and wakes readers for
// the last time.
func (r *run) finish(kind byte, payload []byte, now time.Time) {
	r.mu.Lock()
	r.appendLocked(kind, payload)
	if err := r.file.Close(); err != nil && r.err == nil {
		r.err = err
	}
	r.meta.FinishedAt = controlplane.FormatTime(now)
	r.meta.Broken = r.err != nil
	if r.err != nil {
		log.Printf("agentssh-gateway: run %s: spool failed: %v", r.id, r.err)
	}
	if err := r.writeMeta(); err != nil {
		log.Printf("agentssh-gateway: run %s: record completion: %v", r.id, err)
	}
	r.done = true
	close(r.wake)
	r.mu.Unlock()
}

func (r *run) snapshot() (size int64, done bool, broken bool, wake <-chan struct{}) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.size, r.done, r.err != nil, r.wake
}

// lookupRun returns deviceID's run: live from memory, or finished from disk.
func (s *Server) lookupRun(deviceID, id string) (*run, error) {
	if !remote.ValidRunID(id) {
		return nil, errRunNotFound
	}
	s.mu.Lock()
	live, ok := s.runs[id]
	s.mu.Unlock()
	if ok {
		if live.deviceID != deviceID {
			return nil, errRunNotFound
		}
		return live, nil
	}
	dir := filepath.Join(s.runsDir(), id)
	data, err := os.ReadFile(filepath.Join(dir, fileRunMeta))
	if err != nil {
		return nil, errRunNotFound
	}
	var meta runMeta
	if json.Unmarshal(data, &meta) != nil || meta.RunID != id || meta.DeviceID != deviceID {
		return nil, errRunNotFound
	}
	if meta.FinishedAt == "" {
		return nil, errRunInterrupted
	}
	if s.now().After(controlplane.ParseTime(meta.FinishedAt).Add(s.runRetention())) {
		_ = os.RemoveAll(dir)
		return nil, errRunNotFound
	}
	if meta.Broken {
		return nil, errRunBroken
	}
	info, err := os.Stat(filepath.Join(dir, fileRunFrames))
	if err != nil {
		return nil, errRunNotFound
	}
	return &run{id: id, deviceID: deviceID, dir: dir, meta: meta, size: info.Size(), done: true}, nil
}

// sweepRuns deletes expired runs, and runs a restart left unfinished once
// they can no longer be running. It runs at most once a minute.
func (s *Server) sweepRuns() {
	now := s.now()
	s.mu.Lock()
	if now.Before(s.nextSweep) {
		s.mu.Unlock()
		return
	}
	s.nextSweep = now.Add(runSweepEvery)
	s.mu.Unlock()
	entries, err := os.ReadDir(s.runsDir())
	if err != nil {
		return
	}
	for _, entry := range entries {
		id := entry.Name()
		s.mu.Lock()
		_, live := s.runs[id]
		s.mu.Unlock()
		if live || !remote.ValidRunID(id) {
			continue
		}
		dir := filepath.Join(s.runsDir(), id)
		data, err := os.ReadFile(filepath.Join(dir, fileRunMeta))
		var meta runMeta
		if err != nil || json.Unmarshal(data, &meta) != nil {
			continue
		}
		expired := meta.FinishedAt != "" && now.After(controlplane.ParseTime(meta.FinishedAt).Add(s.runRetention()))
		abandoned := meta.FinishedAt == "" && now.After(controlplane.ParseTime(meta.CreatedAt).Add(s.runRetention()+s.execTimeout()))
		if expired || abandoned {
			_ = os.RemoveAll(dir)
		}
	}
}

// streamRun sends the run frame and then the spool from offset, following a
// live run until its final frame or until the device goes away.
func (s *Server) streamRun(w http.ResponseWriter, ctx context.Context, rn *run, offset int64) {
	size, _, _, _ := rn.snapshot()
	if offset < 0 || offset > size {
		controlplane.WriteError(w, http.StatusBadRequest, remote.CodeBadRequest, "offset is beyond the run's output")
		return
	}
	file, err := os.Open(filepath.Join(rn.dir, fileRunFrames))
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
	rn, err := s.lookupRun(device.ID, req.RunID)
	if err != nil {
		writeRunError(w, err, s.runRetention())
		return
	}
	s.streamRun(w, r.Context(), rn, req.Offset)
}

func (s *Server) handleCancel(w http.ResponseWriter, _ *http.Request, device controlplane.Device, body []byte) {
	var req remote.ExecCancelRequest
	if controlplane.DecodeBody(body, &req) != nil {
		controlplane.WriteError(w, http.StatusBadRequest, remote.CodeBadRequest, "malformed cancel request")
		return
	}
	rn, err := s.lookupRun(device.ID, req.RunID)
	if errors.Is(err, errRunInterrupted) || errors.Is(err, errRunBroken) {
		// Nothing is running; cancelling is a no-op.
		controlplane.WriteJSON(w, http.StatusOK, remote.ExecCancelResponse{RunID: req.RunID})
		return
	}
	if err != nil {
		writeRunError(w, err, s.runRetention())
		return
	}
	_, done, _, _ := rn.snapshot()
	if !done && rn.cancel != nil {
		rn.cancel()
	}
	controlplane.WriteJSON(w, http.StatusOK, remote.ExecCancelResponse{RunID: rn.id, Cancelled: !done})
}

func writeRunError(w http.ResponseWriter, err error, retention time.Duration) {
	switch {
	case errors.Is(err, errRunInterrupted):
		controlplane.WriteError(w, http.StatusGone, remote.CodeRunInterrupted, "the gateway restarted while this run was in progress; its outcome is unknown (check the gateway audit)")
	case errors.Is(err, errRunBroken):
		controlplane.WriteError(w, http.StatusInternalServerError, remote.CodeInternal, "the gateway could not store this run's output; its outcome is in the gateway audit")
	default:
		controlplane.WriteError(w, http.StatusNotFound, remote.CodeRunNotFound, fmt.Sprintf("no such run for this device, or its output expired (kept %s after a run finishes)", retention))
	}
}
