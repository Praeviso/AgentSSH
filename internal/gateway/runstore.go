package gateway

// Run storage. One record file per run ID is the single source of truth:
//
//	runs/<device-id>/<run-id>.json            the record
//	runs/<device-id>/<run-id>.<nonce>.frames  the spool the record names
//
// A record appears whole or not at all, and publishing it exclusively is the
// only way to claim an ID: a start and an early cancel race on that publish
// and the first writer wins, in this process or after a restart. Everything
// an attempt writes before its claim (its spool, under a name of its own) is
// private and removed if the claim fails, so a failure never leaves a
// half-made run behind. Later transitions rewrite the record atomically.
// Memory only caches live runs, for their cancel functions and reader
// wakeups; s.mu orders that cache against the records.
//
//	running ──► finished ──► evicted ──► deleted after retention
//	cancelled (claimed by a cancel that overtook its request) ──► deleted
//	running, not live in memory: interrupted by a restart
//
// A run's spool has a hard cap. Space is reserved up front for every
// target's response in its smallest form and for the result frame, so the
// cap holds no matter how much output or metadata the run produces.

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Praeviso/AgentSSH/internal/controlplane"
	"github.com/Praeviso/AgentSSH/internal/fileutil"
	"github.com/Praeviso/AgentSSH/internal/remote"
	"github.com/Praeviso/AgentSSH/internal/runner"
)

const (
	// DefaultRunRetention is how long a finished run's output stays
	// reattachable, and how long an evicted run's ID stays remembered.
	DefaultRunRetention = 24 * time.Hour
	// DefaultRunMaxBytes caps one run's spool.
	DefaultRunMaxBytes = 64 << 20
	// DefaultRunQuotaBytes caps the finished runs one device keeps; the oldest
	// are evicted first. With MaxConcurrentPerDevice runs in flight, a device
	// occupies at most quota + concurrency × DefaultRunMaxBytes.
	DefaultRunQuotaBytes = 512 << 20

	// responseReserveBytes is held back per target: the proven upper bound of
	// a minimal response frame (see minimalResponse).
	responseReserveBytes = 32 << 10
	// finalReserveBytes is held back for the result or error frame.
	finalReserveBytes = 1 << 10
	// minimalFieldBytes clips each text field of a minimal response.
	minimalFieldBytes = 256

	// DefaultRunRecords caps the run records one device keeps, whatever their
	// state; records are a resource of their own, beside the output bytes.
	DefaultRunRecords = 10000

	// orphanAge is when an unreferenced spool (an attempt that crashed before
	// its claim) is certainly abandoned.
	orphanAge = time.Hour

	dirRuns = "runs"

	stateRunning   = "running"
	stateFinished  = "finished"
	stateCancelled = "cancelled"
	stateEvicted   = "evicted"
)

// Record lifetimes; variables so tests can shorten them.
var (
	// runSweepEvery is how often a device's records are aged out.
	runSweepEvery = time.Minute
	// cancelTombstoneTTL is how long a cancel for a run the gateway has not
	// seen refuses that run's request. It outlasts the request proof lifetime
	// plus the upload deadline, the longest an overtaken request can be late.
	cancelTombstoneTTL = 10 * time.Minute
	// idempotencyWindow is how long after a run starts its ID is guaranteed to
	// keep deduplicating repeats of its request. Clients repeat a request
	// only while recovering a lost first response, within minutes; beyond
	// the window a record without output may be reclaimed.
	idempotencyWindow = time.Hour
)

var (
	errRunNotFound    = errors.New("run not found")
	errRunInterrupted = errors.New("run interrupted")
	errRunBroken      = errors.New("run spool broken")
	errRunExists      = errors.New("run already exists")
	errRunExpired     = errors.New("run output expired")
	errRunCancelled   = errors.New("run cancelled before it started")
	errRunConflict    = errors.New("run id reused for a different request")
	errRunTooLarge    = errors.New("too many targets for the per-run cap")
	errTooManyRecords = errors.New("too many runs kept for this device")
)

// runRecord is a run's durable state.
type runRecord struct {
	RunID      string `json:"run_id"`
	DeviceID   string `json:"device_id"`
	State      string `json:"state"`
	CreatedAt  string `json:"created_at"`
	FinishedAt string `json:"finished_at,omitempty"`
	EvictedAt  string `json:"evicted_at,omitempty"`
	// RequestSHA256 identifies the request that started the run, so a
	// repeated request can join it and a different one is refused.
	RequestSHA256 string `json:"request_sha256,omitempty"`
	// ReqID is a single-host run's request ID, sent in its run frame.
	ReqID string `json:"req_id,omitempty"`
	// Frames is the spool's file name while the output is kept.
	Frames string `json:"frames,omitempty"`
	// Broken means a spool write failed, so the spool lacks its result.
	Broken bool `json:"broken,omitempty"`
}

// claimRecord publishes a new record; an existing one fails with os.ErrExist.
// Tests replace it to inject storage failures.
var claimRecord = func(path string, data []byte) error {
	return fileutil.CreateFileExclusive(path, data, 0o600, ".claim-*.tmp")
}

// run is one execution's spool. The runner writes frames; any number of
// device connections tail them.
type run struct {
	id            string
	deviceID      string
	recordPath    string
	framesPath    string
	requestSHA256 string
	reqID         string
	limit         int64

	mu        sync.Mutex
	record    runRecord
	file      *os.File
	size      int64
	pending   int // responses not yet written
	truncated bool
	done      bool
	err       error
	wake      chan struct{}
	cancel    context.CancelFunc
}

func (s *Server) runsDir() string { return filepath.Join(s.Dir, dirRuns) }

func (s *Server) deviceRunsDir(deviceID string) string {
	return filepath.Join(s.runsDir(), deviceID)
}

func (s *Server) recordPath(deviceID, id string) string {
	return filepath.Join(s.deviceRunsDir(deviceID), id+".json")
}

// runKey names a run among live runs. Clients choose run IDs, so the same ID
// from two devices names two runs.
func runKey(deviceID, id string) string { return deviceID + "/" + id }

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

func (s *Server) runRecords() int {
	if s.RunRecords > 0 {
		return s.RunRecords
	}
	return DefaultRunRecords
}

func (s *Server) runQuotaBytes() int64 {
	if s.RunQuotaBytes > 0 {
		return s.RunQuotaBytes
	}
	return DefaultRunQuotaBytes
}

// maxRunTargets is the largest target count whose minimal responses fit the
// per-run cap.
func (s *Server) maxRunTargets() int64 {
	return max(0, (s.runMaxBytes()-finalReserveBytes)/responseReserveBytes)
}

func readRecord(path string) (runRecord, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return runRecord{}, err
	}
	var rec runRecord
	if err := json.Unmarshal(data, &rec); err != nil {
		return runRecord{}, fmt.Errorf("%w: unreadable record", errRunBroken)
	}
	return rec, nil
}

func writeRecord(path string, rec runRecord) error {
	data, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	return fileutil.WriteFileAtomic(path, data, 0o600, ".record-*.tmp")
}

func randomSuffix() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(fmt.Sprintf("crypto/rand: %v", err))
	}
	return hex.EncodeToString(b[:])
}

// startRun claims id for deviceID and opens its spool; cancel stops the
// run's context. errRunExists means the ID is already claimed: by a repeat
// of this request, a different request, or a cancel that overtook it.
func (s *Server) startRun(deviceID, id, requestSHA256, reqID string, targets int, cancel context.CancelFunc) (*run, error) {
	if int64(targets) > s.maxRunTargets() {
		return nil, errRunTooLarge
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	key := runKey(deviceID, id)
	if _, live := s.runs[key]; live {
		return nil, errRunExists
	}
	if err := s.admitLocked(deviceID); err != nil {
		return nil, err
	}
	dir := s.deviceRunsDir(deviceID)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	// The spool is private to this attempt until the record names it.
	frames := id + "." + randomSuffix() + ".frames"
	framesPath := filepath.Join(dir, frames)
	file, err := os.OpenFile(framesPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, err
	}
	rec := runRecord{
		RunID: id, DeviceID: deviceID, State: stateRunning,
		CreatedAt: controlplane.FormatTime(s.now()), RequestSHA256: requestSHA256, ReqID: reqID, Frames: frames,
	}
	data, err := json.Marshal(rec)
	if err == nil {
		err = claimRecord(s.recordPath(deviceID, id), data)
	}
	if err != nil {
		_ = file.Close()
		_ = os.Remove(framesPath)
		if errors.Is(err, os.ErrExist) {
			return nil, errRunExists
		}
		return nil, err
	}
	rn := &run{
		id: id, deviceID: deviceID, recordPath: s.recordPath(deviceID, id), framesPath: framesPath,
		requestSHA256: requestSHA256, reqID: reqID, limit: s.runMaxBytes(),
		record: rec, file: file, pending: targets, wake: make(chan struct{}), cancel: cancel,
	}
	if s.runs == nil {
		s.runs = map[string]*run{}
	}
	s.runs[key] = rn
	s.deviceRecords[deviceID]++
	return rn, nil
}

// endRun drops a finished run from the live cache; its record now answers.
func (s *Server) endRun(rn *run) {
	s.mu.Lock()
	delete(s.runs, runKey(rn.deviceID, rn.id))
	s.mu.Unlock()
}

// lookupRun returns deviceID's run: live from memory, or finished from disk.
func (s *Server) lookupRun(deviceID, id string) (*run, error) {
	if !remote.ValidRunID(id) {
		return nil, errRunNotFound
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if live, ok := s.runs[runKey(deviceID, id)]; ok {
		return live, nil
	}
	path := s.recordPath(deviceID, id)
	rec, err := readRecord(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, errRunNotFound
	}
	if err != nil {
		return nil, err
	}
	if rec.RunID != id || rec.DeviceID != deviceID {
		return nil, errRunBroken
	}
	switch rec.State {
	case stateCancelled:
		return nil, errRunCancelled
	case stateEvicted:
		return nil, errRunExpired
	case stateRunning:
		return nil, errRunInterrupted
	case stateFinished:
	default:
		return nil, errRunBroken
	}
	if s.now().After(controlplane.ParseTime(rec.FinishedAt).Add(s.runRetention())) {
		s.evictLocked(path, rec)
		return nil, errRunExpired
	}
	if rec.Broken {
		return nil, errRunBroken
	}
	framesPath := filepath.Join(s.deviceRunsDir(deviceID), rec.Frames)
	info, err := os.Stat(framesPath)
	if err != nil {
		return nil, errRunBroken
	}
	return &run{id: id, deviceID: deviceID, recordPath: path, framesPath: framesPath,
		requestSHA256: rec.RequestSHA256, reqID: rec.ReqID, record: rec, size: info.Size(), done: true}, nil
}

// cancelRun stops deviceID's live run id. When the ID was never claimed, it
// claims it as cancelled, so the request it overtook is refused even after a
// restart; that claim counts against the device's records like any other,
// and fails when they are exhausted. A claimed ID that is not live has
// nothing left to stop.
func (s *Server) cancelRun(deviceID, id string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if rn, live := s.runs[runKey(deviceID, id)]; live {
		_, done, _, _ := rn.snapshot()
		if !done && rn.cancel != nil {
			rn.cancel()
		}
		return !done, nil
	}
	if _, err := os.Stat(s.recordPath(deviceID, id)); err == nil {
		return false, nil
	}
	if err := s.admitLocked(deviceID); err != nil {
		return false, err
	}
	if err := os.MkdirAll(s.deviceRunsDir(deviceID), 0o700); err != nil {
		return false, err
	}
	data, _ := json.Marshal(runRecord{RunID: id, DeviceID: deviceID, State: stateCancelled, CreatedAt: controlplane.FormatTime(s.now())})
	switch err := claimRecord(s.recordPath(deviceID, id), data); {
	case err == nil:
		s.deviceRecords[deviceID]++
	case !errors.Is(err, os.ErrExist):
		return false, err
	}
	return false, nil
}

// admitLocked makes room for one more of deviceID's records. It ages the
// device's records out when due, then, if the device is still at its limit,
// reclaims the oldest finished or evicted runs past the idempotency window.
// Records still guarding an ID are never reclaimed: then the claim is
// refused. The caller holds s.mu.
func (s *Server) admitLocked(deviceID string) error {
	now := s.now()
	if s.deviceRecords == nil {
		s.deviceRecords, s.deviceSweeps = map[string]int{}, map[string]time.Time{}
	}
	if _, known := s.deviceRecords[deviceID]; !known || !now.Before(s.deviceSweeps[deviceID]) {
		s.sweepDeviceLocked(deviceID, now)
	}
	if s.deviceRecords[deviceID] < s.runRecords() {
		return nil
	}
	var reclaimable []storedRun
	for _, run := range s.storedRunsLocked(deviceID) {
		state := run.rec.State
		if (state == stateFinished || state == stateEvicted) && now.After(controlplane.ParseTime(run.rec.CreatedAt).Add(idempotencyWindow)) {
			reclaimable = append(reclaimable, run)
		}
	}
	sort.Slice(reclaimable, func(i, j int) bool {
		return controlplane.ParseTime(reclaimable[i].rec.CreatedAt).Before(controlplane.ParseTime(reclaimable[j].rec.CreatedAt))
	})
	for _, run := range reclaimable {
		if s.deviceRecords[deviceID] < s.runRecords() {
			break
		}
		s.deleteRecordLocked(deviceID, run)
	}
	if s.deviceRecords[deviceID] >= s.runRecords() {
		return errTooManyRecords
	}
	return nil
}

func (s *Server) deleteRecordLocked(deviceID string, run storedRun) {
	if run.rec.Frames != "" {
		_ = os.Remove(filepath.Join(filepath.Dir(run.path), run.rec.Frames))
	}
	if err := os.Remove(run.path); err == nil {
		s.deviceRecords[deviceID]--
	}
}

// evictLocked deletes a finished run's output and keeps its record, so the
// ID answers "expired" and a repeat of its request cannot run the command
// again. The caller holds s.mu.
func (s *Server) evictLocked(path string, rec runRecord) {
	if rec.Frames != "" {
		if err := os.Remove(filepath.Join(filepath.Dir(path), rec.Frames)); err != nil && !os.IsNotExist(err) {
			return
		}
	}
	rec.State, rec.Frames, rec.EvictedAt = stateEvicted, "", controlplane.FormatTime(s.now())
	if err := writeRecord(path, rec); err != nil {
		log.Printf("agentssh-gateway: run %s: record eviction: %v", rec.RunID, err)
	}
}

// storedRun is a record on disk whose run is not live.
type storedRun struct {
	path  string
	rec   runRecord
	bytes int64
}

// storedRuns lists deviceID's records whose runs are not live, with the size
// of the output each keeps. The caller holds s.mu.
func (s *Server) storedRunsLocked(deviceID string) []storedRun {
	dir := s.deviceRunsDir(deviceID)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var out []storedRun
	for _, entry := range entries {
		id, ok := strings.CutSuffix(entry.Name(), ".json")
		if !ok || !remote.ValidRunID(id) {
			continue
		}
		if _, live := s.runs[runKey(deviceID, id)]; live {
			continue
		}
		path := filepath.Join(dir, entry.Name())
		rec, err := readRecord(path)
		if err != nil {
			continue
		}
		stored := storedRun{path: path, rec: rec}
		if rec.State == stateFinished && rec.Frames != "" {
			if info, err := os.Stat(filepath.Join(dir, rec.Frames)); err == nil {
				stored.bytes = info.Size()
			}
		}
		out = append(out, stored)
	}
	return out
}

// makeRoom evicts deviceID's oldest finished runs until reserve more bytes
// fit the device's quota: a full run's worth before a run starts, nothing
// after one finishes. Holding s.mu serializes it, so runs that start together
// cannot all count the same free space, and the pass after each finish
// settles any overshoot.
func (s *Server) makeRoom(deviceID string, reserve int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	runs := s.storedRunsLocked(deviceID)
	var total int64
	for _, run := range runs {
		total += run.bytes
	}
	sort.Slice(runs, func(i, j int) bool {
		return controlplane.ParseTime(runs[i].rec.FinishedAt).Before(controlplane.ParseTime(runs[j].rec.FinishedAt))
	})
	for _, run := range runs {
		if total+reserve <= s.runQuotaBytes() {
			return
		}
		if run.bytes == 0 {
			continue
		}
		s.evictLocked(run.path, run.rec)
		total -= run.bytes
	}
}

// sweepRuns ages every device's records out, at most once a minute.
func (s *Server) sweepRuns() {
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	if now.Before(s.nextSweep) {
		return
	}
	s.nextSweep = now.Add(runSweepEvery)
	devices, err := os.ReadDir(s.runsDir())
	if err != nil {
		return
	}
	for _, device := range devices {
		s.sweepDeviceLocked(device.Name(), now)
	}
}

// sweepDeviceLocked ages deviceID's records out and recounts them: output
// past retention is evicted; evicted records past the idempotency window,
// cancel records past their TTL, and a restart's unfinished runs once they
// cannot be running are deleted; so are spools of attempts that crashed
// before their claim. The caller holds s.mu.
func (s *Server) sweepDeviceLocked(deviceID string, now time.Time) {
	if s.deviceRecords == nil {
		s.deviceRecords, s.deviceSweeps = map[string]int{}, map[string]time.Time{}
	}
	dir := s.deviceRunsDir(deviceID)
	referenced := map[string]bool{}
	count := 0
	for key, live := range s.runs {
		if strings.HasPrefix(key, deviceID+"/") {
			referenced[filepath.Base(live.framesPath)] = true
			count++
		}
	}
	for _, run := range s.storedRunsLocked(deviceID) {
		rec := run.rec
		created := controlplane.ParseTime(rec.CreatedAt)
		switch {
		case rec.State == stateEvicted && now.After(created.Add(idempotencyWindow)),
			rec.State == stateCancelled && now.After(created.Add(cancelTombstoneTTL)),
			rec.State == stateRunning && now.After(created.Add(s.runRetention()+s.execTimeout())):
			if rec.Frames != "" {
				_ = os.Remove(filepath.Join(dir, rec.Frames))
			}
			if os.Remove(run.path) != nil {
				count++
			}
			continue
		case rec.State == stateFinished && now.After(controlplane.ParseTime(rec.FinishedAt).Add(s.runRetention())):
			s.evictLocked(run.path, rec)
		default:
			referenced[rec.Frames] = true
		}
		count++
	}
	entries, _ := os.ReadDir(dir)
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".frames") || referenced[entry.Name()] {
			continue
		}
		if info, err := entry.Info(); err == nil && now.Sub(info.ModTime()) > orphanAge {
			_ = os.Remove(filepath.Join(dir, entry.Name()))
		}
	}
	s.deviceRecords[deviceID] = count
	s.deviceSweeps[deviceID] = now.Add(runSweepEvery)
}

// roomLocked is what the run may still spend while keeping space for the
// responses not yet written and for the final frame.
func (r *run) roomLocked() int64 {
	return r.limit - r.size - int64(r.pending)*responseReserveBytes - finalReserveBytes
}

// appendLocked spools one frame if it fits the hard cap, and wakes readers.
// A failed write breaks the run: later frames are discarded and the record
// marks the spool broken.
func (r *run) appendLocked(kind byte, payload []byte) bool {
	if r.err != nil {
		return false
	}
	var frame bytes.Buffer
	if err := remote.WriteFrame(&frame, kind, payload); err != nil {
		r.err = err
		return false
	}
	if r.size+int64(frame.Len()) > r.limit {
		return false
	}
	if _, err := r.file.Write(frame.Bytes()); err != nil {
		r.err = err
		return false
	}
	r.size += int64(frame.Len())
	close(r.wake)
	r.wake = make(chan struct{})
	return true
}

// data spools output while it fits; once it does not, the rest is dropped and
// the run is marked truncated.
func (r *run) data(kind byte, p []byte) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for len(p) > 0 {
		chunk := p[:min(len(p), remote.MaxDataFrameBytes)]
		if r.truncated || remote.FrameSize(len(chunk)) > r.roomLocked() {
			r.truncated = true
			return
		}
		r.appendLocked(kind, chunk)
		p = p[len(chunk):]
	}
}

// response spools one target's result in the largest form that fits: whole,
// without its output, or minimal. The minimal form always fits the space
// reserved for it.
func (r *run) response(response runner.Response) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.pending > 0 {
		r.pending--
	}
	fits := func(payload []byte) bool {
		return len(payload) <= remote.MaxMessageFrameBytes && remote.FrameSize(len(payload)) <= r.roomLocked()
	}
	if payload, err := json.Marshal(response); err == nil && !r.truncated && fits(payload) {
		r.appendLocked(remote.FrameResponse, payload)
		return
	}
	r.truncated = true
	stripped := response
	stripped.Stdout, stripped.Stderr, stripped.OutputTruncated = "", "", true
	if payload, err := json.Marshal(stripped); err == nil && fits(payload) {
		r.appendLocked(remote.FrameResponse, payload)
		return
	}
	payload, err := json.Marshal(minimalResponse(response))
	if err != nil || !r.appendLocked(remote.FrameResponse, payload) {
		r.err = errors.New("minimal response does not fit its reserve")
	}
}

// minimalResponse keeps what identifies a target's outcome, with every text
// field clipped, so its frame is at most responseReserveBytes even when JSON
// escapes each byte as six.
func minimalResponse(r runner.Response) runner.Response {
	clip := func(s string) string {
		if len(s) <= minimalFieldBytes {
			return s
		}
		return s[:minimalFieldBytes]
	}
	return runner.Response{
		ExecutionState:  clip(r.ExecutionState),
		NextAction:      clip(r.NextAction),
		ReqID:           clip(r.ReqID),
		SessionID:       clip(r.SessionID),
		Host:            clip(r.Host),
		CmdSHA256:       clip(r.CmdSHA256),
		Status:          clip(r.Status),
		ExitCode:        r.ExitCode,
		DurationMS:      r.DurationMS,
		OutputTruncated: true,
		PolicyAction:    clip(r.PolicyAction),
		PolicyRule:      clip(r.PolicyRule),
		ApprovalID:      clip(r.ApprovalID),
	}
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
	defer r.mu.Unlock()
	if !r.appendLocked(kind, payload) && r.err == nil {
		r.err = errors.New("final frame does not fit its reserve")
	}
	if err := r.file.Close(); err != nil && r.err == nil {
		r.err = err
	}
	r.record.State, r.record.FinishedAt, r.record.Broken = stateFinished, controlplane.FormatTime(now), r.err != nil
	if r.err != nil {
		log.Printf("agentssh-gateway: run %s: spool failed: %v", r.id, r.err)
	}
	if err := writeRecord(r.recordPath, r.record); err != nil {
		log.Printf("agentssh-gateway: run %s: record completion: %v", r.id, err)
	}
	r.done = true
	close(r.wake)
}

func (r *run) snapshot() (size int64, done bool, broken bool, wake <-chan struct{}) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.size, r.done, r.err != nil, r.wake
}
