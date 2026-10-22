package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"
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
	// DefaultRunQuotaBytes caps the finished runs one device keeps; the oldest
	// are evicted first. With MaxConcurrentPerDevice runs in flight, a device
	// occupies at most quota + concurrency × DefaultRunMaxBytes.
	DefaultRunQuotaBytes = 512 << 20

	// runReserveBytes is kept back per target so a response, stripped of its
	// output, always fits after the cap is reached.
	runReserveBytes = 16 << 10
	runSweepEvery   = time.Minute
	// cancelTombstoneTTL is how long a cancel for a run the gateway has not
	// seen yet refuses that run's request, should it still arrive.
	cancelTombstoneTTL = 10 * time.Minute

	dirRuns       = "runs"
	fileRunMeta   = "meta.json"
	fileRunFrames = "frames"
)

var (
	errRunNotFound    = errors.New("run not found")
	errRunInterrupted = errors.New("run interrupted")
	errRunBroken      = errors.New("run spool broken")
	errRunExists      = errors.New("run already exists")
	errRunExpired     = errors.New("run output expired")
	errRunCancelled   = errors.New("run cancelled before it started")
	errRunConflict    = errors.New("run id reused for a different request")
)

// runMeta is a run's durable record; FinishedAt is empty until the result
// frame is spooled.
type runMeta struct {
	RunID      string `json:"run_id"`
	DeviceID   string `json:"device_id"`
	CreatedAt  string `json:"created_at"`
	FinishedAt string `json:"finished_at,omitempty"`
	// RequestSHA256 identifies the request that started the run, so a
	// repeated request can join it and a different one is refused.
	RequestSHA256 string `json:"request_sha256,omitempty"`
	// Broken means a spool write failed, so the frames file lacks its result.
	Broken bool `json:"broken,omitempty"`
	// EvictedAt is set once the output is deleted (expiry or quota). The
	// record stays for another retention period so the run ID cannot start
	// the command again.
	EvictedAt string `json:"evicted_at,omitempty"`
}

// run is one execution's spool. The runner writes frames; any number of
// device connections tail them.
type run struct {
	id       string
	deviceID string
	dir      string
	budget   int64
	// requestSHA256 is immutable; meta is guarded by mu.
	requestSHA256 string

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

func (s *Server) runsDir() string { return filepath.Join(s.Dir, dirRuns) }

// runKey names a run among live runs. Clients choose run IDs, so the same ID
// from two devices names two runs.
func runKey(deviceID, id string) string { return deviceID + "/" + id }

// runDir keeps each device's runs apart, so quota and lookups only ever see
// that device's runs.
func (s *Server) runDir(deviceID, id string) string {
	return filepath.Join(s.runsDir(), deviceID, id)
}

func (s *Server) runQuotaBytes() int64 {
	if s.RunQuotaBytes > 0 {
		return s.RunQuotaBytes
	}
	return DefaultRunQuotaBytes
}

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
// It refuses an ID that already names a run of the device, or that the
// device cancelled before this request arrived.
func (s *Server) startRun(deviceID, id, requestSHA256 string, targets int, cancel context.CancelFunc) (*run, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := runKey(deviceID, id)
	if at, ok := s.cancelled[key]; ok && s.now().Before(at.Add(cancelTombstoneTTL)) {
		return nil, errRunCancelled
	}
	if _, live := s.runs[key]; live {
		return nil, errRunExists
	}
	dir := s.runDir(deviceID, id)
	if err := os.MkdirAll(filepath.Dir(dir), 0o700); err != nil {
		return nil, err
	}
	if err := os.Mkdir(dir, 0o700); errors.Is(err, os.ErrExist) {
		return nil, errRunExists
	} else if err != nil {
		return nil, err
	}
	file, err := os.OpenFile(filepath.Join(dir, fileRunFrames), os.O_CREATE|os.O_EXCL|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, err
	}
	rn := &run{
		id: id, deviceID: deviceID, dir: dir, requestSHA256: requestSHA256,
		budget: max(0, s.runMaxBytes()-int64(targets)*runReserveBytes),
		meta:   runMeta{RunID: id, DeviceID: deviceID, CreatedAt: controlplane.FormatTime(s.now()), RequestSHA256: requestSHA256},
		file:   file, wake: make(chan struct{}), cancel: cancel,
	}
	if err := rn.writeMeta(); err != nil {
		_ = file.Close()
		return nil, err
	}
	if s.runs == nil {
		s.runs = map[string]*run{}
	}
	s.runs[key] = rn
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
	live, ok := s.runs[runKey(deviceID, id)]
	s.mu.Unlock()
	if ok {
		return live, nil
	}
	dir := s.runDir(deviceID, id)
	data, err := os.ReadFile(filepath.Join(dir, fileRunMeta))
	if err != nil {
		return nil, errRunNotFound
	}
	var meta runMeta
	if json.Unmarshal(data, &meta) != nil || meta.RunID != id || meta.DeviceID != deviceID {
		return nil, errRunNotFound
	}
	if meta.EvictedAt != "" {
		return nil, errRunExpired
	}
	if meta.FinishedAt == "" {
		return nil, errRunInterrupted
	}
	if s.now().After(controlplane.ParseTime(meta.FinishedAt).Add(s.runRetention())) {
		s.evict(storedRun{dir: dir, meta: meta})
		return nil, errRunExpired
	}
	if meta.Broken {
		return nil, errRunBroken
	}
	info, err := os.Stat(filepath.Join(dir, fileRunFrames))
	if err != nil {
		return nil, errRunNotFound
	}
	return &run{id: id, deviceID: deviceID, dir: dir, requestSHA256: meta.RequestSHA256, meta: meta, size: info.Size(), done: true}, nil
}

// storedRun is a run on disk that is not running in this process.
type storedRun struct {
	dir   string
	meta  runMeta
	bytes int64
	// at orders eviction: when the run finished, or was created if a
	// restart left it unfinished.
	at time.Time
}

// storedRuns lists deviceID's runs on disk that are not live.
func (s *Server) storedRuns(deviceID string) []storedRun {
	base := filepath.Join(s.runsDir(), deviceID)
	entries, err := os.ReadDir(base)
	if err != nil {
		return nil
	}
	var out []storedRun
	for _, entry := range entries {
		id := entry.Name()
		s.mu.Lock()
		_, live := s.runs[runKey(deviceID, id)]
		s.mu.Unlock()
		if live || !remote.ValidRunID(id) {
			continue
		}
		dir := filepath.Join(base, id)
		data, err := os.ReadFile(filepath.Join(dir, fileRunMeta))
		var meta runMeta
		if err != nil || json.Unmarshal(data, &meta) != nil {
			continue
		}
		run := storedRun{dir: dir, meta: meta, at: controlplane.ParseTime(meta.CreatedAt)}
		if meta.FinishedAt != "" {
			run.at = controlplane.ParseTime(meta.FinishedAt)
		}
		if info, err := os.Stat(filepath.Join(dir, fileRunFrames)); err == nil {
			run.bytes = info.Size()
		}
		out = append(out, run)
	}
	return out
}

// evict deletes a stored run's output but keeps its record, so the ID still
// answers "expired" and a repeat of its request cannot run the command again.
func (s *Server) evict(run storedRun) {
	if err := os.Remove(filepath.Join(run.dir, fileRunFrames)); err != nil && !os.IsNotExist(err) {
		return
	}
	run.meta.EvictedAt = controlplane.FormatTime(s.now())
	data, err := json.Marshal(run.meta)
	if err != nil {
		return
	}
	_ = fileutil.WriteFileAtomic(filepath.Join(run.dir, fileRunMeta), data, 0o600, fileRunMeta+"-*")
}

// makeRoom evicts deviceID's oldest stored runs until reserve more bytes fit
// the device's quota: a full run's worth before a run starts, nothing after
// one finishes. Calls are serialized so concurrent starts cannot all see the
// same free space.
func (s *Server) makeRoom(deviceID string, reserve int64) {
	s.quotaMu.Lock()
	defer s.quotaMu.Unlock()
	runs := s.storedRuns(deviceID)
	var total int64
	for _, run := range runs {
		total += run.bytes
	}
	sort.Slice(runs, func(i, j int) bool { return runs[i].at.Before(runs[j].at) })
	for _, run := range runs {
		if total+reserve <= s.runQuotaBytes() {
			return
		}
		if run.meta.EvictedAt != "" || run.bytes == 0 {
			continue
		}
		s.evict(run)
		total -= run.bytes
	}
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
	for key, at := range s.cancelled {
		if !now.Before(at.Add(cancelTombstoneTTL)) {
			delete(s.cancelled, key)
		}
	}
	s.mu.Unlock()
	devices, err := os.ReadDir(s.runsDir())
	if err != nil {
		return
	}
	for _, device := range devices {
		for _, run := range s.storedRuns(device.Name()) {
			switch {
			case run.meta.EvictedAt != "":
				// The record has guarded its ID for a retention period.
				if now.After(controlplane.ParseTime(run.meta.EvictedAt).Add(s.runRetention())) {
					_ = os.RemoveAll(run.dir)
				}
			case run.meta.FinishedAt != "" && now.After(run.at.Add(s.runRetention())):
				s.evict(run)
			case run.meta.FinishedAt == "" && now.After(run.at.Add(s.runRetention()+s.execTimeout())):
				_ = os.RemoveAll(run.dir)
			}
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
	controlplane.WriteJSON(w, http.StatusOK, remote.ExecCancelResponse{RunID: req.RunID, Cancelled: s.cancelRun(device.ID, req.RunID)})
}

// cancelRun stops deviceID's live run id, or, when the gateway has never seen
// that ID, refuses its request should it still arrive. It holds s.mu, the lock
// startRun registers runs under, so a run cannot start between the check and
// the tombstone. A run already on disk has finished; there is nothing to stop.
func (s *Server) cancelRun(deviceID, id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := runKey(deviceID, id)
	if rn, live := s.runs[key]; live {
		_, done, _, _ := rn.snapshot()
		if !done && rn.cancel != nil {
			rn.cancel()
		}
		return !done
	}
	if _, err := os.Stat(s.runDir(deviceID, id)); err == nil {
		return false
	}
	if s.cancelled == nil {
		s.cancelled = map[string]time.Time{}
	}
	s.cancelled[key] = s.now()
	return false
}

func writeRunError(w http.ResponseWriter, err error, retention time.Duration) {
	switch {
	case errors.Is(err, errRunInterrupted):
		controlplane.WriteError(w, http.StatusGone, remote.CodeRunInterrupted, "the gateway restarted while this run was in progress; its outcome is unknown (check the gateway audit)")
	case errors.Is(err, errRunConflict):
		controlplane.WriteError(w, http.StatusConflict, remote.CodeRunConflict, "this run id was already used for a different request")
	case errors.Is(err, errRunCancelled):
		controlplane.WriteError(w, http.StatusConflict, remote.CodeRunCancelled, "this run was cancelled before its request arrived")
	case errors.Is(err, errRunBroken):
		controlplane.WriteError(w, http.StatusInternalServerError, remote.CodeInternal, "the gateway could not store this run's output; its outcome is in the gateway audit")
	default:
		controlplane.WriteError(w, http.StatusNotFound, remote.CodeRunNotFound, fmt.Sprintf("no such run for this device, or its output expired (kept %s after a run finishes)", retention))
	}
}
