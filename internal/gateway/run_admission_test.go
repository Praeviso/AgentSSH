package gateway_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Praeviso/AgentSSH/internal/gateway"
	"github.com/Praeviso/AgentSSH/internal/remote"
)

func retainedResult(t *testing.T, f *fixture, first remote.ExecResult, spool []byte) {
	t.Helper()
	paths, _ := spools(t, f, first.RunID)
	if len(paths) != 1 {
		t.Fatalf("a rejected attempt removed retained output: %v", paths)
	}
	data, err := os.ReadFile(paths[0])
	if err != nil || !bytes.Equal(data, spool) {
		t.Fatalf("a rejected attempt changed retained output: %v", err)
	}
	got, err := f.client.Attach(context.Background(), first.RunID, io.Discard, io.Discard)
	if err != nil || got.RunID != first.RunID || got.ExitCode != first.ExitCode || !reflect.DeepEqual(got.Responses, first.Responses) {
		t.Fatalf("retained result is no longer attachable unchanged: %+v, %v", got, err)
	}
}

func retainedUptime(t *testing.T, f *fixture) (remote.ExecResult, []byte) {
	t.Helper()
	first, err := f.client.Exec(context.Background(), execReq("uptime"), io.Discard, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	paths, _ := spools(t, f, first.RunID)
	if len(paths) != 1 {
		t.Fatalf("initial spool: %v", paths)
	}
	data, err := os.ReadFile(paths[0])
	if err != nil {
		t.Fatal(err)
	}
	return first, data
}

func TestRecordLimitRejectionPreservesRetainedOutput(t *testing.T) {
	f, host := execGateway(t)
	f.server.RunRecords = 1
	f.server.RunQuotaBytes = gateway.DefaultRunMaxBytes
	first, spool := retainedUptime(t, f)
	req := execReq("uptime")
	req.RunID = remote.NewRunID()
	_, err := f.client.Exec(context.Background(), req, io.Discard, io.Discard)
	busy(t, err)
	var apiErr *remote.APIError
	if !errors.As(err, &apiErr) || !strings.Contains(apiErr.Message, "keeps too many runs") {
		t.Fatalf("request was not rejected for record capacity: %v", err)
	}
	retainedResult(t, f, first, spool)
	if n := host.runs("uptime"); n != 1 {
		t.Fatalf("rejected command executed: uptime ran %d times", n)
	}
	if paths, _ := spools(t, f, req.RunID); len(paths) != 0 {
		t.Fatalf("record rejection left private spools: %v", paths)
	}
	if _, err := os.Stat(filepath.Join(f.dir, "runs", f.client.State.DeviceID, req.RunID+".json")); !os.IsNotExist(err) {
		t.Fatalf("record rejection left a claim: %v", err)
	}
}

// Exercise the public execution route while the same periodic operation used
// by serve continuously reads published metadata. No identity list may be
// populated after a run becomes visible to the standing snapshots.
func TestRunPublicationConcurrentWithStandingSweeps(t *testing.T) {
	f, host := execGateway(t)
	stop, failed := make(chan struct{}), make(chan error, 1)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			if err := f.server.CancelRunsWithoutStanding(); err != nil {
				failed <- err
				return
			}
			runtime.Gosched()
		}
	}()
	defer func() { close(stop); wg.Wait() }()
	const runs = 60
	for range runs {
		if _, err := f.client.Exec(context.Background(), execReq("uptime"), io.Discard, io.Discard); err != nil {
			t.Fatalf("a run in good standing was interrupted: %v", err)
		}
	}
	select {
	case err := <-failed:
		t.Fatal(err)
	default:
	}
	if n := host.runs("uptime"); n != runs {
		t.Fatalf("commands ran %d times, want %d", n, runs)
	}
}

// All competing requests cross admission together; only one protected record
// slot is left. The others must be rejected without creating claims or spools.
func TestConcurrentRecordAdmissionHonorsTheLimit(t *testing.T) {
	f, host := execGateway(t)
	f.server.RunRecords = 2
	f.server.RunQuotaBytes = 2 * gateway.DefaultRunMaxBytes
	f.server.MaxConcurrentPerDevice = 8
	first, spool := retainedUptime(t, f)
	start := make(chan struct{})
	errs := make(chan error, 8)
	for range cap(errs) {
		go func() {
			<-start
			_, err := f.client.Exec(context.Background(), execReq("uptime"), io.Discard, io.Discard)
			errs <- err
		}()
	}
	close(start)
	accepted := 0
	for range cap(errs) {
		if err := <-errs; err == nil {
			accepted++
		} else {
			busy(t, err)
		}
	}
	if accepted != 1 || records(t, f) != 2 || host.runs("uptime") != 2 {
		t.Fatalf("admission: accepted=%d, records=%d, executions=%d", accepted, records(t, f), host.runs("uptime"))
	}
	retainedResult(t, f, first, spool)
	if paths, _ := spools(t, f, ""); len(paths) != 2 {
		t.Fatalf("rejected starts left private spools: %v", paths)
	}
}

// At a concurrency limit, repeats join an existing run without consuming
// another slot. Conflicts and early cancellations do not consume slots either.
func TestRunAdmissionKeepsIdempotencyAtTheConcurrencyLimit(t *testing.T) {
	f, host := execGateway(t)
	f.server.MaxConcurrentPerDevice = 1
	req := run("web-1", "sleep")
	req.RunID = remote.NewRunID()
	req.WaitMS = waitMS(0)
	device := activeTokenDevice(t, f)
	first := runOf(t, apiCall(t, f, device.Token, remote.PathAPIRun, req))
	host.waitEvent(t, "sleep-started")
	defer f.server.StopRuns()
	req.RunID = first.RunID
	joined := runOf(t, apiCall(t, f, device.Token, remote.PathAPIRun, req))
	if joined.RunID != first.RunID || host.runs("sleep") != 1 {
		t.Fatalf("a repeat did not join the live run: %+v", joined)
	}
	conflict := req
	conflict.Command = "uptime"
	if got := apiCall(t, f, device.Token, remote.PathAPIRun, conflict); got.status != 409 {
		t.Fatalf("conflicting ID: %d %s", got.status, got.raw)
	}
	if got := apiCall(t, f, device.Token, remote.PathAPIRun, run("web-1", "uptime")); got.status != 429 {
		t.Fatalf("concurrency limit: %d %s", got.status, got.raw)
	}
	cancelled := apiCall(t, f, device.Token, remote.PathAPIRunCancel, remote.ExecCancelRequest{RunID: first.RunID})
	if cancelled.status != 200 {
		t.Fatalf("cancel: %d %s", cancelled.status, cancelled.raw)
	}
	host.waitEvent(t, "signal:TERM")
	deadline := time.Now().Add(5 * time.Second)
	for {
		got := apiCall(t, f, device.Token, remote.PathAPIRun, run("web-1", "uptime"))
		if got.status == 200 {
			break
		}
		if got.status != 429 || time.Now().After(deadline) {
			t.Fatalf("completed run did not release its slot: %d %s", got.status, got.raw)
		}
		time.Sleep(10 * time.Millisecond)
	}
	if host.runs("sleep") != 1 || host.runs("uptime") != 1 {
		t.Fatalf("slot/idempotency accounting: sleep=%d, uptime=%d", host.runs("sleep"), host.runs("uptime"))
	}
}
