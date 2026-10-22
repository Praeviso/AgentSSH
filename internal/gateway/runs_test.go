package gateway_test

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/Praeviso/AgentSSH/internal/controlplane"
	"github.com/Praeviso/AgentSSH/internal/gateway"
	"github.com/Praeviso/AgentSSH/internal/remote"
	"github.com/Praeviso/AgentSSH/internal/remoteclient"
)

// spools lists the spool files on disk: one run's, or the device's when runID
// is empty.
func spools(t *testing.T, f *fixture, runID string) (paths []string, bytes int64) {
	t.Helper()
	pattern := "*.frames"
	if runID != "" {
		pattern = runID + ".*.frames"
	}
	paths, _ = filepath.Glob(filepath.Join(f.dir, "runs", f.client.State.DeviceID, pattern))
	for _, path := range paths {
		if info, err := os.Stat(path); err == nil {
			bytes += info.Size()
		}
	}
	return paths, bytes
}

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
	f, host := execGateway(t)
	f.server.RunRetention = 50 * time.Millisecond
	req := execReq("uptime")
	req.RunID = remote.NewRunID()
	if _, err := f.client.Exec(context.Background(), req, io.Discard, io.Discard); err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond)
	_, err := f.client.Attach(context.Background(), req.RunID, io.Discard, io.Discard)
	runNotFound(t, err)
	if !strings.Contains(err.Error(), "expired") {
		t.Fatalf("refusal does not explain expiry: %v", err)
	}
	if paths, _ := spools(t, f, req.RunID); len(paths) != 0 {
		t.Fatalf("expired output still on disk: %v", paths)
	}
	// The ID is remembered: repeating the original request (a client
	// recovering a lost response) must not run the command a second time.
	_, err = f.client.Exec(context.Background(), req, io.Discard, io.Discard)
	runNotFound(t, err)
	if n := host.runs("uptime"); n != 1 {
		t.Fatalf("expired run's command ran %d times, want once", n)
	}
}

// Cancelling a finished run changes nothing: a repeat of its request still
// joins it rather than being refused as cancelled.
func TestCancelOfAFinishedRunKeepsItJoinable(t *testing.T) {
	f, host := execGateway(t)
	req := execReq("uptime")
	req.RunID = remote.NewRunID()
	if _, err := f.client.Exec(context.Background(), req, io.Discard, io.Discard); err != nil {
		t.Fatal(err)
	}
	if cancelled, err := f.client.Cancel(context.Background(), req.RunID); err != nil || cancelled {
		t.Fatalf("cancel of a finished run: %v %v", cancelled, err)
	}
	if result, err := f.client.Exec(context.Background(), req, io.Discard, io.Discard); err != nil || result.ExitCode != 0 {
		t.Fatalf("repeat after cancel: %+v %v", result, err)
	}
	if n := host.runs("uptime"); n != 1 {
		t.Fatalf("uptime ran %d times, want once", n)
	}
}

// Output beyond the run cap is dropped, the result says so, and the exit code
// is non-zero, live and on replay alike.
func TestRunBeyondItsCapIsTruncatedAndFails(t *testing.T) {
	f, _ := execGateway(t)
	f.server.RunMaxBytes = 48 << 10
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
	if streamed.Len() == 0 || streamed.Len() > 48<<10 || streamed.Len()%1024 != 0 {
		t.Fatalf("streamed %d bytes, want whole lines up to the cap", streamed.Len())
	}
	replay, err := f.client.Attach(context.Background(), result.RunID, io.Discard, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	check("replay", replay)
	if paths, size := spools(t, f, result.RunID); len(paths) != 1 || size > f.server.RunMaxBytes {
		t.Fatalf("spool %v is %d bytes, cap %d", paths, size, f.server.RunMaxBytes)
	}
}

func TestRunLostToARestartIsReportedAsInterrupted(t *testing.T) {
	f, host := execGateway(t)
	f.server.ExecTimeout = 2 * time.Second // lets the orphaned command end
	req := execReq("sleep")
	req.RunID = remote.NewRunID()
	go func() { _, _ = f.client.Exec(context.Background(), req, io.Discard, io.Discard) }()
	host.waitEvent(t, "sleep-started")
	f.restart(t)
	_, err := f.client.Attach(context.Background(), req.RunID, io.Discard, io.Discard)
	var apiErr *remote.APIError
	if !errors.As(err, &apiErr) || apiErr.Code != remote.CodeRunInterrupted || apiErr.Status != 410 {
		t.Fatalf("err = %v, want 410 %s", err, remote.CodeRunInterrupted)
	}
}

// A cancel that overtook its request is remembered on disk, so the request
// is refused even when it reaches a restarted gateway.
func TestEarlyCancelSurvivesARestart(t *testing.T) {
	f, host := execGateway(t)
	req := execReq("uptime")
	req.RunID = remote.NewRunID()
	if cancelled, err := f.client.Cancel(context.Background(), req.RunID); err != nil || cancelled {
		t.Fatalf("cancel: %v %v", cancelled, err)
	}
	f.restart(t)
	_, err := f.client.Exec(context.Background(), req, io.Discard, io.Discard)
	var apiErr *remote.APIError
	if !errors.As(err, &apiErr) || apiErr.Code != remote.CodeRunCancelled {
		t.Fatalf("exec after cancel and restart: %v", err)
	}
	if n := host.runs("uptime"); n != 0 {
		t.Fatalf("cancelled command ran %d times", n)
	}
}

// A run whose claim fails (say, a full disk) leaves nothing behind, so the
// same request starts it once storage recovers.
func TestFailedClaimLeavesNothingBehind(t *testing.T) {
	f, host := execGateway(t)
	restore := gateway.FailNextClaim(syscall.ENOSPC)
	defer restore()
	req := execReq("uptime")
	req.RunID = remote.NewRunID()
	_, err := f.client.Exec(context.Background(), req, io.Discard, io.Discard)
	var apiErr *remote.APIError
	if !errors.As(err, &apiErr) || apiErr.Status != 500 {
		t.Fatalf("exec with storage failing: %v", err)
	}
	if paths, _ := spools(t, f, req.RunID); len(paths) != 0 {
		t.Fatalf("failed attempt left %v", paths)
	}
	if _, err := os.Stat(filepath.Join(f.dir, "runs", f.client.State.DeviceID, req.RunID+".json")); !os.IsNotExist(err) {
		t.Fatalf("failed attempt left a record: %v", err)
	}
	result, err := f.client.Exec(context.Background(), req, io.Discard, io.Discard)
	if err != nil || result.ExitCode != 0 {
		t.Fatalf("retry after storage recovered: %+v %v", result, err)
	}
	if n := host.runs("uptime"); n != 1 {
		t.Fatalf("uptime ran %d times, want once", n)
	}
}

// The per-run cap is hard: when even a response without its output does not
// fit, a minimal one does, and the spool stays within the cap.
func TestRunCapHoldsWhenResponseMetadataIsLarge(t *testing.T) {
	f, _ := execGateway(t)
	f.server.RunMaxBytes = 40 << 10
	// A gray-zone command whose approval matcher alone is far larger than
	// the cap.
	cmd := strings.Repeat("<", 100<<10)
	result, err := f.client.Exec(context.Background(), execReq(cmd), io.Discard, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	got := result.Responses[0]
	if !result.Truncated || result.ExitCode != 7 || got.Status != "approval_pending" || got.ApprovalID == "" || !got.OutputTruncated {
		t.Fatalf("result = %+v", result)
	}
	if _, size := spools(t, f, result.RunID); size > f.server.RunMaxBytes {
		t.Fatalf("spool is %d bytes, cap %d", size, f.server.RunMaxBytes)
	}
	// A group whose minimal responses cannot fit is refused up front.
	inv := `host_key_policy: accept-new
hosts:
  web-1: {addr: 127.0.0.1, port: 22, user: deploy, identity: web, tags: [web]}
  web-2: {addr: 127.0.0.1, port: 22, user: deploy, identity: web, tags: [web]}
groups:
  web: {tags: [web]}
`
	if _, err := controlplane.PushConfig(f.store, f.client.State.DeviceID, inv, testPolicy, time.Now()); err != nil {
		t.Fatal(err)
	}
	_, err = f.client.Exec(context.Background(), remote.ExecRequest{Host: "web", Cmd: "uptime", Session: "s_test"}, io.Discard, io.Discard)
	var apiErr *remote.APIError
	if !errors.As(err, &apiErr) || apiErr.Code != remote.CodeUsage || !strings.Contains(apiErr.Message, "--run-max-bytes") {
		t.Fatalf("oversized group: %v", err)
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
	f, host := execGateway(t)
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
	if _, total := spools(t, f, ""); total > f.server.RunQuotaBytes {
		t.Fatalf("device keeps %d bytes of runs, quota %d", total, f.server.RunQuotaBytes)
	}
	_, err := f.client.Attach(context.Background(), ids[0], io.Discard, io.Discard)
	runNotFound(t, err)
	// An evicted run's ID is remembered: repeating its request does not run
	// the command again.
	again := req
	again.RunID = ids[0]
	_, err = f.client.Exec(context.Background(), again, io.Discard, io.Discard)
	runNotFound(t, err)
	if n := host.runs("flood"); n != 4 {
		t.Fatalf("flood ran %d times, want 4", n)
	}
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
		_, total := spools(t, f, "")
		if total <= f.server.RunQuotaBytes {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("device keeps %d bytes of runs after concurrent starts, quota %d", total, f.server.RunQuotaBytes)
		}
		time.Sleep(20 * time.Millisecond)
	}
}
