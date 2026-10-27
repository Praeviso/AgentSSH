package gateway

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Praeviso/AgentSSH/internal/remote"
)

func admissionServer(t *testing.T) (*Server, string) {
	t.Helper()
	store, _, _ := operatorStore(t)
	dir := t.TempDir()
	device, err := CreateTokenDevice(dir, store, "admission-agent", "local:alice", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ActivateDevice(dir, store, device.DeviceID, time.Hour, "local:alice", "", time.Now()); err != nil {
		t.Fatal(err)
	}
	return NewServer(dir, store, nil), device.DeviceID
}

func finishAdmissionRun(rn *run, s *Server) {
	rn.finish(remote.FrameResult, []byte(`{"exit_code":0}`), time.Now())
	s.endRun(rn)
}

// Caller-owned slices must not change the identity set observed by the first
// standing sweep, even when the caller reuses its input immediately on return.
func TestRunAdmissionOwnsPublishedIdentityMetadata(t *testing.T) {
	s, deviceID := admissionServer(t)
	identities := []string{"disabled-at-publication"}
	cancelled := make(chan error, 1)
	rn, err := s.startRun(runStart{
		deviceID: deviceID, id: remote.NewRunID(), requestSHA256: "request", reqID: "req",
		targets: 1, identities: identities, cancel: func(err error) { cancelled <- err },
	})
	if err != nil {
		t.Fatal(err)
	}
	defer finishAdmissionRun(rn, s)
	identities[0] = "caller-reused-the-slice"
	if err := s.CancelRunsWithoutStanding(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-cancelled:
		if err == nil || !strings.Contains(err.Error(), "identity disabled-at-publication was disabled") {
			t.Fatalf("standing observed mutable/incomplete identity metadata: %v", err)
		}
	default:
		t.Fatal("the first sweep did not cancel the published run's disabled identity")
	}
}

// Independent processes share exclusive file claims, not live maps or slot
// counters. Force both through their prechecks before racing the actual claim.
func TestConcurrentExclusiveClaimsPublishOneRun(t *testing.T) {
	first, deviceID := admissionServer(t)
	second := NewServer(first.Dir, first.Store, nil)
	original := claimRecord
	arrived, proceed := make(chan struct{}, 2), make(chan struct{})
	claimRecord = func(path string, data []byte) error {
		arrived <- struct{}{}
		<-proceed
		return original(path, data)
	}
	var release sync.Once
	resume := func() { release.Do(func() { close(proceed) }) }
	var wg sync.WaitGroup
	t.Cleanup(func() { resume(); wg.Wait(); claimRecord = original })
	type result struct {
		server *Server
		run    *run
		err    error
	}
	results := make(chan result, 2)
	id := remote.NewRunID()
	for _, server := range []*Server{first, second} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rn, err := server.startRun(runStart{deviceID: deviceID, id: id, targets: 1, identities: []string{"web"}, cancel: func(error) {}})
			results <- result{server, rn, err}
		}()
	}
	for range 2 {
		select {
		case <-arrived:
		case <-time.After(5 * time.Second):
			t.Fatal("competing start did not reach the claim")
		}
	}
	resume()
	wg.Wait()
	close(results)
	accepted := 0
	var winner result
	for got := range results {
		if got.err == nil {
			accepted++
			winner = got
		} else if !errors.Is(got.err, errRunExists) {
			t.Fatalf("losing claim: %v", got.err)
		} else if len(got.server.runs) != 0 || got.server.running[deviceID] != 0 {
			t.Fatal("the losing claim leaked publication or a concurrency slot")
		}
	}
	if winner.run != nil {
		defer finishAdmissionRun(winner.run, winner.server)
	}
	paths, err := filepath.Glob(filepath.Join(first.deviceRunsDir(deviceID), "*.frames"))
	if err != nil || accepted != 1 || len(paths) != 1 {
		t.Fatalf("exclusive claim: accepted=%d, spools=%v, err=%v", accepted, paths, err)
	}
	record, err := readRecord(first.recordPath(deviceID, id))
	if err != nil || record.State != stateRunning || filepath.Base(paths[0]) != record.Frames {
		t.Fatalf("the durable claim does not name the one published spool: %+v, %v", record, err)
	}
}

func TestRunCompletionReleasesItsOwnSlotOnce(t *testing.T) {
	s, deviceID := admissionServer(t)
	s.MaxConcurrentPerDevice = 2
	start := func() (*run, error) {
		return s.startRun(runStart{deviceID: deviceID, id: remote.NewRunID(), targets: 1, cancel: func(error) {}})
	}
	first, err := start()
	if err != nil {
		t.Fatal(err)
	}
	second, err := start()
	if err != nil {
		finishAdmissionRun(first, s)
		t.Fatal(err)
	}
	defer finishAdmissionRun(second, s)
	if _, err := start(); !errors.Is(err, errTooManyConcurrent) {
		t.Fatalf("concurrency limit: %v", err)
	}
	finishAdmissionRun(first, s)
	s.endRun(first) // Repeated cleanup cannot release another live run's slot.
	third, err := start()
	if err != nil {
		t.Fatalf("completion did not release capacity: %v", err)
	}
	defer finishAdmissionRun(third, s)
	if _, err := start(); !errors.Is(err, errTooManyConcurrent) {
		t.Fatalf("duplicate completion released someone else's slot: %v", err)
	}
}

// A durable claim remains authoritative after a new server starts: a live run
// cannot be reconstructed from memory, and its request must not execute again.
func TestCommittedAdmissionSurvivesServerRestart(t *testing.T) {
	s, deviceID := admissionServer(t)
	id := remote.NewRunID()
	rn, err := s.startRun(runStart{deviceID: deviceID, id: id, targets: 1, cancel: func(error) {}})
	if err != nil {
		t.Fatal(err)
	}
	defer finishAdmissionRun(rn, s)
	restarted := NewServer(s.Dir, s.Store, nil)
	if _, err := restarted.lookupRun(deviceID, id); !errors.Is(err, errRunInterrupted) {
		t.Fatalf("committed run after restart: %v", err)
	}
	if _, err := restarted.startRun(runStart{deviceID: deviceID, id: id, targets: 1}); !errors.Is(err, errRunExists) {
		t.Fatalf("restarted server reclaimed a committed ID: %v", err)
	}
	paths, _ := filepath.Glob(filepath.Join(s.deviceRunsDir(deviceID), "*.frames"))
	if len(paths) != 1 {
		t.Fatalf("restart left additional private spools: %v", paths)
	}
	if _, err := os.Stat(s.recordPath(deviceID, id)); err != nil {
		t.Fatal(err)
	}
}
