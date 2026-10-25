package gateway_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Praeviso/AgentSSH/internal/audit"
	"github.com/Praeviso/AgentSSH/internal/controlplane"
	"github.com/Praeviso/AgentSSH/internal/gateway"
	"github.com/Praeviso/AgentSSH/internal/remote"
)

// apiCall posts body as JSON to a token route.
func apiCall(t *testing.T, f *fixture, token, path string, body any) apiAnswer {
	t.Helper()
	data, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodPost, f.base+path, bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	return send(t, req)
}

func runOf(t *testing.T, a apiAnswer) remote.APIRun {
	t.Helper()
	var run remote.APIRun
	if a.status != http.StatusOK || json.Unmarshal(a.raw, &run) != nil {
		t.Fatalf("run answer: %d %s", a.status, a.raw)
	}
	return run
}

func waitMS(ms int64) *int64 { return &ms }

// activeTokenDevice is a token device on the fixture's target, activated.
func activeTokenDevice(t *testing.T, f *fixture) gateway.IssuedToken {
	t.Helper()
	issued := tokenDevice(t, f)
	if _, err := gateway.ActivateDevice(f.dir, f.store, issued.DeviceID, time.Hour, "local:alice", "", time.Now()); err != nil {
		t.Fatal(err)
	}
	return issued
}

func run(host, command string) remote.APIRunRequest {
	return remote.APIRunRequest{Host: host, Command: command, Session: "s_api"}
}

// A short command finishes within one call, with its result and output.
func TestAShortCommandAnswersInOneCall(t *testing.T) {
	f, _ := execGateway(t)
	issued := activeTokenDevice(t, f)
	start := time.Now()
	got := runOf(t, apiCall(t, f, issued.Token, remote.PathAPIRun, run("web-1", "uptime")))
	// The call answers when the run finishes, not when its 20s wait ends.
	if took := time.Since(start); took > 5*time.Second {
		t.Fatalf("a finished run answered after %s", took)
	}
	if got.State != remote.APIRunFinished || got.Result != remote.APIResultOK || got.ExitCode == nil || *got.ExitCode != 0 || got.TargetKind != "host" {
		t.Fatalf("answer: %+v", got)
	}
	if len(got.Responses) != 1 || !strings.HasPrefix(got.RunID, "rn_") || got.ReqID == "" {
		t.Fatalf("answer: %+v", got)
	}
	var response map[string]any
	if err := json.Unmarshal(got.Responses[0], &response); err != nil || response["status"] != "completed" || response["req_id"] != got.ReqID {
		t.Fatalf("response: %s", got.Responses[0])
	}
	// The run is audited with the device and the token it used.
	var tokenRuns int
	for _, r := range auditRecords(t, f) {
		if r.DeviceID == issued.DeviceID && (r.Event == audit.EventStarted || r.Event == audit.EventCompleted) {
			if r.TokenID != issued.TokenID {
				t.Fatalf("run audited without its token: %+v", r)
			}
			tokenRuns++
		}
	}
	if tokenRuns != 2 {
		t.Fatalf("audited %d records of the run, want started and completed", tokenRuns)
	}
}

// A command that outlives the wait answers running with the output so far;
// reading from next_offset completes it, every byte once.
func TestALongCommandIsReadFromOffsets(t *testing.T) {
	f, host := execGateway(t)
	issued := activeTokenDevice(t, f)
	released := false
	t.Cleanup(func() {
		if !released {
			close(host.release)
		}
	})
	req := run("web-1", "stream")
	req.WaitMS = waitMS(300)
	first := runOf(t, apiCall(t, f, issued.Token, remote.PathAPIRun, req))
	if first.State != remote.APIRunRunning || first.ExitCode != nil || len(first.Responses) != 0 {
		t.Fatalf("first answer: %+v", first)
	}
	stdout := first.Stdout
	offset := first.NextOffset
	for deadline := time.Now().Add(10 * time.Second); !strings.Contains(stdout, "chunk-1"); {
		if time.Now().After(deadline) {
			t.Fatalf("chunk-1 never arrived: %q", stdout)
		}
		next := runOf(t, apiCall(t, f, issued.Token, remote.PathAPIRunOutput, remote.APIRunOutputRequest{RunID: first.RunID, Offset: offset, WaitMS: waitMS(100)}))
		stdout, offset = stdout+next.Stdout, next.NextOffset
	}
	close(host.release)
	released = true
	var last remote.APIRun
	for last.State != remote.APIRunFinished {
		last = runOf(t, apiCall(t, f, issued.Token, remote.PathAPIRunOutput, remote.APIRunOutputRequest{RunID: first.RunID, Offset: offset, WaitMS: waitMS(5000)}))
		stdout, offset = stdout+last.Stdout, last.NextOffset
	}
	if stdout != "chunk-1\nchunk-2\n" || last.Result != remote.APIResultOK || len(last.Responses) != 1 {
		t.Fatalf("streamed %q, last %+v", stdout, last)
	}
	// Reading again from the end adds nothing; reading from 0 replays it all.
	// Reading again from the end adds no output but keeps the run's result.
	again := runOf(t, apiCall(t, f, issued.Token, remote.PathAPIRunOutput, remote.APIRunOutputRequest{RunID: first.RunID, Offset: offset}))
	if again.Stdout != "" || len(again.Responses) != 0 || again.State != remote.APIRunFinished || again.NextOffset != offset ||
		again.Result != remote.APIResultOK || again.ExitCode == nil || *again.ExitCode != 0 || again.TargetKind != "host" || again.Error != nil {
		t.Fatalf("read past the end: %+v", again)
	}
	whole := runOf(t, apiCall(t, f, issued.Token, remote.PathAPIRunOutput, remote.APIRunOutputRequest{RunID: first.RunID}))
	if whole.Stdout != "chunk-1\nchunk-2\n" || len(whole.Responses) != 1 {
		t.Fatalf("read from the start: %+v", whole)
	}
}

func TestCancelStopsAnAPIRun(t *testing.T) {
	f, host := execGateway(t)
	issued := activeTokenDevice(t, f)
	req := run("web-1", "sleep")
	req.WaitMS = waitMS(0)
	started := runOf(t, apiCall(t, f, issued.Token, remote.PathAPIRun, req))
	host.waitEvent(t, "sleep-started")
	got := apiCall(t, f, issued.Token, remote.PathAPIRunCancel, remote.ExecCancelRequest{RunID: started.RunID})
	var cancel remote.ExecCancelResponse
	if got.status != http.StatusOK || json.Unmarshal(got.raw, &cancel) != nil || !cancel.Cancelled {
		t.Fatalf("cancel: %d %s", got.status, got.raw)
	}
	host.waitEvent(t, "signal:TERM")
	final := runOf(t, apiCall(t, f, issued.Token, remote.PathAPIRunOutput, remote.APIRunOutputRequest{RunID: started.RunID, WaitMS: waitMS(5000)}))
	if final.State != remote.APIRunFinished {
		t.Fatalf("after cancel: %+v", final)
	}
	// Polling once more from the end answers the same outcome.
	again := runOf(t, apiCall(t, f, issued.Token, remote.PathAPIRunOutput, remote.APIRunOutputRequest{RunID: started.RunID, Offset: final.NextOffset}))
	if again.State != final.State || again.Result != final.Result || fmt.Sprint(again.ExitCode != nil) != fmt.Sprint(final.ExitCode != nil) ||
		(again.ExitCode != nil && *again.ExitCode != *final.ExitCode) || fmt.Sprint(again.Error) != fmt.Sprint(final.Error) {
		t.Fatalf("re-poll %+v, final %+v", again, final)
	}
}

// comparable is a run --json object without what each run mints.
func comparable(t *testing.T, raw []byte) map[string]any {
	t.Helper()
	var object map[string]any
	if err := json.Unmarshal(raw, &object); err != nil {
		t.Fatal(err)
	}
	for _, minted := range []string{"req_id", "ts", "duration_ms", "approval_id", "session_id"} {
		delete(object, minted)
	}
	return object
}

// Deny, gray zone and an SSH error answer what /exec answers a signed device
// for the same command, with result naming the exit code.
func TestAPIAnswersMatchRunJSON(t *testing.T) {
	f, _ := execGateway(t)
	issued := activeTokenDevice(t, f)
	cfg, err := f.store.Config(f.client.State.DeviceID)
	if err != nil {
		t.Fatal(err)
	}
	// A host nothing listens on, for an SSH error, on both devices.
	inv := cfg.InventoryYAML + "  down-1: {addr: 127.0.0.1, port: 1, user: deploy, identity: web}\n"
	for _, id := range []string{f.client.State.DeviceID, issued.DeviceID} {
		if _, err := controlplane.PushConfig(f.store, id, inv, cfg.PolicyYAML, time.Now()); err != nil {
			t.Fatal(err)
		}
	}
	for _, tc := range []struct {
		host, command, result string
		exit                  int
	}{
		{"web-1", "reboot", remote.APIResultDenied, 6},
		{"web-1", "hostname", remote.APIResultApprovalRequired, 7},
		{"down-1", "uptime", remote.APIResultSSHError, 9},
	} {
		got := runOf(t, apiCall(t, f, issued.Token, remote.PathAPIRun, run(tc.host, tc.command)))
		if got.State != remote.APIRunFinished || got.Result != tc.result || got.ExitCode == nil || *got.ExitCode != tc.exit || len(got.Responses) != 1 {
			t.Fatalf("%s: %+v", tc.command, got)
		}
		signed, err := f.client.Exec(context.Background(), remote.ExecRequest{Host: tc.host, Cmd: tc.command, Session: "s_api"}, io.Discard, io.Discard)
		if err != nil || signed.ExitCode != tc.exit {
			t.Fatalf("%s over /exec: %+v %v", tc.command, signed, err)
		}
		want, _ := json.Marshal(signed.Responses[0])
		a, b := comparable(t, got.Responses[0]), comparable(t, want)
		if fmt.Sprint(a) != fmt.Sprint(b) {
			t.Fatalf("%s: API response %v\n/exec response %v", tc.command, a, b)
		}
	}
}

// A repeat with the same run ID joins the run instead of running the command
// again; a different request with that ID is refused.
func TestARepeatedRunIDRunsOnce(t *testing.T) {
	f, host := execGateway(t)
	issued := activeTokenDevice(t, f)
	req := run("web-1", "uptime")
	req.RunID = remote.NewRunID()
	first := runOf(t, apiCall(t, f, issued.Token, remote.PathAPIRun, req))
	req.WaitMS = waitMS(1000) // how long a call waits is not part of the run
	second := runOf(t, apiCall(t, f, issued.Token, remote.PathAPIRun, req))
	if first.RunID != req.RunID || second.RunID != req.RunID || second.ReqID != first.ReqID || second.Result != remote.APIResultOK {
		t.Fatalf("first %+v, second %+v", first, second)
	}
	if n := host.runs("uptime"); n != 1 {
		t.Fatalf("uptime ran %d times", n)
	}
	other := req
	other.Command = "stream"
	if got := apiCall(t, f, issued.Token, remote.PathAPIRun, other); got.status != http.StatusConflict || got.body.Code != remote.CodeRunConflict {
		t.Fatalf("a different request with the same ID: %d %s", got.status, got.raw)
	}
}

func TestAPIRefusals(t *testing.T) {
	f, _ := execGateway(t)
	issued := activeTokenDevice(t, f)
	for name, req := range map[string]remote.APIRunRequest{
		"no session":   {Host: "web-1", Command: "uptime"},
		"unknown host": run("db-9", "uptime"),
		"no command":   run("web-1", ""),
	} {
		if got := apiCall(t, f, issued.Token, remote.PathAPIRun, req); got.status != http.StatusBadRequest || got.body.Code != remote.CodeUsage {
			t.Errorf("%s: %d %s", name, got.status, got.raw)
		}
	}
	done := runOf(t, apiCall(t, f, issued.Token, remote.PathAPIRun, run("web-1", "uptime")))
	for name, offset := range map[string]int64{"beyond the end": done.NextOffset + 1, "inside a frame": 1, "negative": -1} {
		if got := apiCall(t, f, issued.Token, remote.PathAPIRunOutput, remote.APIRunOutputRequest{RunID: done.RunID, Offset: offset}); got.status != http.StatusBadRequest {
			t.Errorf("offset %s: %d %s", name, got.status, got.raw)
		}
	}
	// Another device's run is not found.
	other := activeTokenDevice(t, f)
	if got := apiCall(t, f, other.Token, remote.PathAPIRunOutput, remote.APIRunOutputRequest{RunID: done.RunID}); got.status != http.StatusNotFound {
		t.Fatalf("another device's run: %d %s", got.status, got.raw)
	}
	if _, err := gateway.DeactivateDevice(f.dir, f.store, issued.DeviceID, "local:alice", time.Now()); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{remote.PathAPIRun, remote.PathAPIRunOutput} {
		if got := apiCall(t, f, issued.Token, path, run("web-1", "uptime")); got.body.Code != remote.CodeDeviceInactive {
			t.Errorf("%s while inactive: %d %s", path, got.status, got.raw)
		}
	}
	// A token never runs anything through /exec.
	if got := bearer(t, f, remote.PathExec, issued.Token); got.status == http.StatusOK {
		t.Fatalf("token on /exec: %d", got.status)
	}
	if result, err := audit.NewStore(filepath.Join(f.dir, gateway.FileAudit)).Verify(); err != nil || !result.OK {
		t.Fatalf("verify: %+v, %v", result, err)
	}
}

// A call waits past the server's own response deadline (one second in this
// fixture) and still answers.
func TestAWaitOutlastsTheServersResponseDeadline(t *testing.T) {
	f, host := execGateway(t)
	issued := activeTokenDevice(t, f)
	t.Cleanup(f.server.StopRuns)
	req := run("web-1", "sleep")
	req.WaitMS = waitMS(2000)
	got := runOf(t, apiCall(t, f, issued.Token, remote.PathAPIRun, req))
	if got.State != remote.APIRunRunning {
		t.Fatalf("answer after a 2s wait: %+v", got)
	}
	host.waitEvent(t, "sleep-started")
	if got := apiCall(t, f, issued.Token, remote.PathAPIRunCancel, remote.ExecCancelRequest{RunID: got.RunID}); got.status != http.StatusOK {
		t.Fatalf("cancel: %d %s", got.status, got.raw)
	}
}

// A device that loses its standing, or a token rotated out, while a request's
// body is still uploading runs nothing: the gateway checks again once the
// body has arrived.
func TestStandingIsCheckedAgainAfterTheUpload(t *testing.T) {
	for name, tc := range map[string]struct {
		change func(t *testing.T, f *fixture, issued gateway.IssuedToken)
		code   string
	}{
		"deactivated": {func(t *testing.T, f *fixture, issued gateway.IssuedToken) {
			if _, err := gateway.DeactivateDevice(f.dir, f.store, issued.DeviceID, "local:alice", time.Now()); err != nil {
				t.Fatal(err)
			}
		}, remote.CodeDeviceInactive},
		"revoked": {func(t *testing.T, f *fixture, issued gateway.IssuedToken) {
			if err := f.store.RevokeDevice(issued.DeviceID, time.Now()); err != nil {
				t.Fatal(err)
			}
		}, remote.CodeDeviceRevoked},
		"token rotated": {func(t *testing.T, f *fixture, issued gateway.IssuedToken) {
			if _, err := gateway.RotateToken(f.dir, f.store, issued.DeviceID, "local:alice", time.Now()); err != nil {
				t.Fatal(err)
			}
		}, remote.CodeUnauthenticated},
	} {
		t.Run(name, func(t *testing.T) {
			f, host := execGateway(t)
			issued := activeTokenDevice(t, f)
			body, _ := json.Marshal(run("web-1", "uptime"))
			upload, uploading := io.Pipe()
			req, err := http.NewRequest(http.MethodPost, f.base+remote.PathAPIRun, upload)
			if err != nil {
				t.Fatal(err)
			}
			req.ContentLength = int64(len(body))
			req.Header.Set("Authorization", "Bearer "+issued.Token)
			answered := make(chan apiAnswer, 1)
			go func() { answered <- send(t, req) }()
			// A pipe write returns once the gateway has read it, so the first
			// half is in only after the request passed its first check.
			half := len(body) / 2
			if _, err := uploading.Write(body[:half]); err != nil {
				t.Fatal(err)
			}
			tc.change(t, f, issued)
			if _, err := uploading.Write(body[half:]); err != nil {
				t.Fatal(err)
			}
			_ = uploading.Close()
			got := <-answered
			if got.body.Code != tc.code {
				t.Fatalf("answer: %d %s, want %s", got.status, got.raw, tc.code)
			}
			if n := host.runs("uptime"); n != 0 {
				t.Fatalf("uptime ran %d times", n)
			}
		})
	}
}
