package gateway_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Praeviso/AgentSSH/internal/remote"
	"github.com/Praeviso/AgentSSH/internal/remoteclient"
)

func runNotFound(t *testing.T, err error) {
	t.Helper()
	var apiErr *remote.APIError
	if !errors.As(err, &apiErr) || apiErr.Code != remote.CodeRunNotFound {
		t.Fatalf("err = %v, want %s", err, remote.CodeRunNotFound)
	}
}

func TestRunSurvivesDisconnectAndReattaches(t *testing.T) {
	f, host := execGateway(t)
	stdout := &chunkWriter{chunks: make(chan string, 8)}
	type outcome struct {
		result remote.ExecResult
		err    error
	}
	done := make(chan outcome, 1)
	go func() {
		req := execReq("stream")
		req.Stream = true
		result, err := f.client.Exec(context.Background(), req, stdout, io.Discard)
		done <- outcome{result, err}
	}()
	if chunk := <-stdout.chunks; chunk != "chunk-1\n" {
		t.Fatalf("first chunk = %q", chunk)
	}
	// The network drops mid-run; the command must keep going.
	f.ingress.CloseClientConnections()
	close(host.release)
	got := <-done
	if got.err != nil {
		t.Fatalf("exec across a disconnect: %v", got.err)
	}
	if got.result.ExitCode != 0 || got.result.RunID == "" || got.result.Responses[0].Status != "completed" {
		t.Fatalf("result = %+v", got.result)
	}
	if stdout.buf.String() != "chunk-1\nchunk-2\n" {
		t.Fatalf("stdout across the reattach = %q, want each chunk once", stdout.buf.String())
	}
	if n := host.runs("stream"); n != 1 {
		t.Fatalf("remote command ran %d times, want once", n)
	}
	// The finished run can be replayed in full.
	var replay strings.Builder
	again, err := f.client.Attach(context.Background(), got.result.RunID, &replay, io.Discard)
	if err != nil || replay.String() != "chunk-1\nchunk-2\n" || again.ExitCode != 0 || len(again.Responses) != 1 {
		t.Fatalf("replay: %q %+v %v", replay.String(), again, err)
	}
}

func TestOnlyTheStartingDeviceCanReattachOrCancel(t *testing.T) {
	f, _ := execGateway(t)
	result, err := f.client.Exec(context.Background(), execReq("uptime"), io.Discard, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	other := f.enroll(t, "other-agent")
	_, err = other.Attach(context.Background(), result.RunID, io.Discard, io.Discard)
	runNotFound(t, err)
	// Another device's cancel reveals nothing and touches nothing.
	if cancelled, err := other.Cancel(context.Background(), result.RunID); err != nil || cancelled {
		t.Fatalf("other device cancel: %v %v", cancelled, err)
	}
	if _, err := f.client.Attach(context.Background(), result.RunID, io.Discard, io.Discard); err != nil {
		t.Fatalf("owner's run affected by another device: %v", err)
	}
	// The owner still can; the run has finished, so nothing is cancelled.
	if cancelled, err := f.client.Cancel(context.Background(), result.RunID); err != nil || cancelled {
		t.Fatalf("owner cancel of a finished run: %v %v", cancelled, err)
	}
	_, err = f.client.Attach(context.Background(), "rn_00000000000000000000000000000000", io.Discard, io.Discard)
	runNotFound(t, err)
}

func TestReattachAfterRetentionIsRefused(t *testing.T) {
	f, _ := execGateway(t)
	f.server.RunRetention = 50 * time.Millisecond
	result, err := f.client.Exec(context.Background(), execReq("uptime"), io.Discard, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond)
	_, err = f.client.Attach(context.Background(), result.RunID, io.Discard, io.Discard)
	runNotFound(t, err)
	if !strings.Contains(err.Error(), "expired") {
		t.Fatalf("refusal does not explain expiry: %v", err)
	}
	if _, statErr := os.Stat(filepath.Join(f.dir, "runs", f.client.State.DeviceID, result.RunID)); !os.IsNotExist(statErr) {
		t.Fatalf("expired run still on disk: %v", statErr)
	}
}

// Output beyond the run cap is dropped, the result says so, and the exit code
// is non-zero, live and on replay alike.
func TestRunBeyondItsCapIsTruncatedAndFails(t *testing.T) {
	f, _ := execGateway(t)
	f.server.RunMaxBytes = 32 << 10
	req := execReq("flood")
	req.Stream = true
	var streamed strings.Builder
	result, err := f.client.Exec(context.Background(), req, &streamed, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	check := func(name string, got remote.ExecResult) {
		t.Helper()
		if !got.Truncated || got.ExitCode != 1 || !got.Responses[0].OutputTruncated || got.Responses[0].Stdout != "" || got.Responses[0].Status != "completed" {
			t.Fatalf("%s: %+v", name, got)
		}
	}
	check("live", result)
	if streamed.Len() == 0 || streamed.Len() > 32<<10 || streamed.Len()%1024 != 0 {
		t.Fatalf("streamed %d bytes, want whole lines up to the cap", streamed.Len())
	}
	replay, err := f.client.Attach(context.Background(), result.RunID, io.Discard, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	check("replay", replay)
	if info, err := os.Stat(filepath.Join(f.dir, "runs", f.client.State.DeviceID, result.RunID, "frames")); err != nil || info.Size() > 32<<10 {
		t.Fatalf("spool size: %v %v", info, err)
	}
}

func TestRunLostToARestartIsReportedAsInterrupted(t *testing.T) {
	f, _ := execGateway(t)
	// What a gateway that died mid-run leaves behind: a record without a
	// finish time.
	id := "rn_abcdefabcdefabcdefabcdefabcdefab"
	dir := filepath.Join(f.dir, "runs", f.client.State.DeviceID, id)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	meta, _ := json.Marshal(map[string]string{"run_id": id, "device_id": f.client.State.DeviceID, "created_at": time.Now().UTC().Format(time.RFC3339Nano)})
	if err := os.WriteFile(filepath.Join(dir, "meta.json"), meta, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "frames"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := f.client.Attach(context.Background(), id, io.Discard, io.Discard)
	var apiErr *remote.APIError
	if !errors.As(err, &apiErr) || apiErr.Code != remote.CodeRunInterrupted || apiErr.Status != 410 {
		t.Fatalf("err = %v, want 410 %s", err, remote.CodeRunInterrupted)
	}
}

// When the gateway stays unreachable, Exec gives up after ReattachTimeout and
// says the run may still be going rather than inventing an outcome.
func TestExecGivesUpReattachingWithoutClaimingAnOutcome(t *testing.T) {
	f, host := execGateway(t)
	// The abandoned command still ends, by the gateway's timeout.
	f.server.ExecTimeout = 2 * time.Second
	old := remoteclient.ReattachTimeout
	remoteclient.ReattachTimeout = 300 * time.Millisecond
	t.Cleanup(func() { remoteclient.ReattachTimeout = old })
	done := make(chan error, 1)
	go func() {
		_, err := f.client.Exec(context.Background(), execReq("sleep"), io.Discard, io.Discard)
		done <- err
	}()
	host.waitEvent(t, "sleep-started")
	f.down.Store(true)
	f.ingress.CloseClientConnections()
	err := <-done
	if err == nil || !strings.Contains(err.Error(), "may still be running") {
		t.Fatalf("err = %v", err)
	}
}

// An enrolled device cannot fill the gateway's disk with runs: its finished
// runs are kept within a quota, oldest evicted first.
func TestDeviceRunsAreKeptWithinAQuota(t *testing.T) {
	f, _ := execGateway(t)
	f.server.RunMaxBytes = 64 << 10
	f.server.RunQuotaBytes = 128 << 10
	req := execReq("flood")
	req.Stream = true
	var ids []string
	for range 4 {
		result, err := f.client.Exec(context.Background(), req, io.Discard, io.Discard)
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, result.RunID)
	}
	var total int64
	runs, _ := filepath.Glob(filepath.Join(f.dir, "runs", f.client.State.DeviceID, "rn_*", "frames"))
	for _, path := range runs {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		total += info.Size()
	}
	if total > f.server.RunQuotaBytes {
		t.Fatalf("device keeps %d bytes of runs, quota %d", total, f.server.RunQuotaBytes)
	}
	_, err := f.client.Attach(context.Background(), ids[0], io.Discard, io.Discard)
	runNotFound(t, err)
	if _, err := f.client.Attach(context.Background(), ids[3], io.Discard, io.Discard); err != nil {
		t.Fatalf("newest run evicted: %v", err)
	}
}

// The gateway accepted /exec but the response never arrived: repeating the
// request with the same run ID joins the run instead of starting it again.
func TestLostFirstResponseJoinsTheRun(t *testing.T) {
	f, host := execGateway(t)
	f.dropNextExec.Store(true)
	stdout := &chunkWriter{chunks: make(chan string, 8)}
	done := make(chan error, 1)
	var result remote.ExecResult
	go func() {
		req := execReq("stream")
		req.Stream = true
		var err error
		result, err = f.client.Exec(context.Background(), req, stdout, io.Discard)
		done <- err
	}()
	if chunk := <-stdout.chunks; chunk != "chunk-1\n" {
		t.Fatalf("first chunk after the lost response = %q", chunk)
	}
	close(host.release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if result.ExitCode != 0 || stdout.buf.String() != "chunk-1\nchunk-2\n" {
		t.Fatalf("result %+v stdout %q", result, stdout.buf.String())
	}
	if n := host.runs("stream"); n != 1 {
		t.Fatalf("remote command ran %d times, want once", n)
	}
}

func TestRunIDReuseJoinsTheSameRequestAndRefusesAnother(t *testing.T) {
	f, host := execGateway(t)
	req := execReq("uptime")
	req.RunID = remote.NewRunID()
	first, err := f.client.Exec(context.Background(), req, io.Discard, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	again, err := f.client.Exec(context.Background(), req, io.Discard, io.Discard)
	if err != nil || again.RunID != first.RunID || again.Responses[0].ReqID != first.Responses[0].ReqID {
		t.Fatalf("repeat did not join the run: %+v %v", again, err)
	}
	if n := host.runs("uptime"); n != 1 {
		t.Fatalf("uptime ran %d times, want once", n)
	}
	other := execReq("cat")
	other.RunID = req.RunID
	_, err = f.client.Exec(context.Background(), other, io.Discard, io.Discard)
	var apiErr *remote.APIError
	if !errors.As(err, &apiErr) || apiErr.Code != remote.CodeRunConflict || apiErr.Status != 409 {
		t.Fatalf("different request with a used run id: %v", err)
	}
}

// A cancel can overtake its own request; the request is then refused, so the
// command never starts.
func TestCancelBeforeTheRequestArrivesRefusesIt(t *testing.T) {
	f, host := execGateway(t)
	req := execReq("uptime")
	req.RunID = remote.NewRunID()
	if cancelled, err := f.client.Cancel(context.Background(), req.RunID); err != nil || cancelled {
		t.Fatalf("cancel of a run not yet seen: %v %v", cancelled, err)
	}
	_, err := f.client.Exec(context.Background(), req, io.Discard, io.Discard)
	var apiErr *remote.APIError
	if !errors.As(err, &apiErr) || apiErr.Code != remote.CodeRunCancelled {
		t.Fatalf("exec after its cancel: %v", err)
	}
	if n := host.runs("uptime"); n != 0 {
		t.Fatalf("cancelled command ran %d times", n)
	}
}

// Runs that start together each see the same free space; the quota still
// holds once they have all finished.
func TestConcurrentRunsStayWithinTheQuota(t *testing.T) {
	f, _ := execGateway(t)
	f.server.RunMaxBytes = 64 << 10
	f.server.RunQuotaBytes = 128 << 10
	req := execReq("flood")
	req.Stream = true
	errs := make(chan error, 4)
	for range 4 {
		go func() {
			_, err := f.client.Exec(context.Background(), req, io.Discard, io.Discard)
			errs <- err
		}()
	}
	for range 4 {
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		var total int64
		runs, _ := filepath.Glob(filepath.Join(f.dir, "runs", f.client.State.DeviceID, "rn_*", "frames"))
		for _, path := range runs {
			if info, err := os.Stat(path); err == nil {
				total += info.Size()
			}
		}
		if total <= f.server.RunQuotaBytes {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("device keeps %d bytes of runs after concurrent starts, quota %d", total, f.server.RunQuotaBytes)
		}
		time.Sleep(20 * time.Millisecond)
	}
}
