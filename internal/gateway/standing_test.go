package gateway_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Praeviso/AgentSSH/internal/audit"
	"github.com/Praeviso/AgentSSH/internal/controlplane"
	"github.com/Praeviso/AgentSSH/internal/gateway"
	"github.com/Praeviso/AgentSSH/internal/remote"
	"github.com/Praeviso/AgentSSH/internal/remoteclient"
)

// liveRun starts a command on client that runs until it is signalled, and
// returns its run ID and a channel that receives the client's result. The
// test's end cancels a run still going, so a failed check cannot leave the
// fixture waiting on it.
func liveRun(t *testing.T, f *fixture, client *remoteclient.Client, host *targetHost) (string, <-chan error) {
	t.Helper()
	req := execReq("sleep")
	req.RunID = remote.NewRunID()
	ctx, cancel := context.WithCancel(context.Background())
	done, finished := make(chan error, 1), make(chan struct{})
	go func() {
		defer close(finished)
		_, err := client.Exec(ctx, req, io.Discard, io.Discard)
		done <- err
	}()
	t.Cleanup(func() {
		cancel()
		f.server.StopRuns()
		select {
		case <-finished:
		case <-time.After(10 * time.Second):
		}
	})
	host.waitEvent(t, "sleep-started")
	return req.RunID, done
}

// stoppedFor waits for the run to end and checks that the device was told
// why (code and reason) and that the run's record and audit record name the
// reason.
func stoppedFor(t *testing.T, f *fixture, deviceID, runID string, done <-chan error, code, reason string) {
	t.Helper()
	select {
	case err := <-done:
		var apiErr *remote.APIError
		if !errors.As(err, &apiErr) || apiErr.Code != code || apiErr.Message != "the gateway stopped this command: "+reason {
			t.Fatalf("the device was told %v, want %s: the gateway stopped this command: %s", err, code, reason)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the run kept going after its device lost standing")
	}
	data, err := os.ReadFile(filepath.Join(f.dir, "runs", deviceID, runID+".json"))
	if err != nil {
		t.Fatal(err)
	}
	var record struct {
		State        string `json:"state"`
		CancelReason string `json:"cancel_reason"`
	}
	if err := json.Unmarshal(data, &record); err != nil || record.State != "finished" || record.CancelReason != reason {
		t.Fatalf("run record = %s, %v (want finished, cancelled because %s)", data, err, reason)
	}
	var failed []audit.Record
	for _, r := range auditRecords(t, f) {
		if r.Event == audit.EventFailed && r.DeviceID == deviceID {
			failed = append(failed, r)
		}
	}
	if len(failed) != 1 || failed[0].Error != "cancelled: "+reason {
		t.Fatalf("audit of the stopped run: %+v", failed)
	}
	if result, err := audit.NewStore(filepath.Join(f.dir, gateway.FileAudit)).Verify(); err != nil || !result.OK {
		t.Fatalf("verify: %+v, %v", result, err)
	}
}

func TestARevokedDevicesRunIsStopped(t *testing.T) {
	f, host := execGateway(t)
	id := f.client.State.DeviceID
	runID, done := liveRun(t, f, f.client, host)
	if err := f.store.RevokeDevice(id, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := f.server.CancelRunsWithoutStanding(); err != nil {
		t.Fatal(err)
	}
	host.waitEvent(t, "signal:TERM")
	stoppedFor(t, f, id, runID, done, remote.CodeDeviceRevoked, "the device was revoked")
}

// Deactivating one device stops its run and leaves another device's alone.
func TestADeactivatedDevicesRunIsStoppedAndOthersAreNot(t *testing.T) {
	f, host := execGateway(t)
	id := f.client.State.DeviceID
	other := f.enroll(t, "other-agent")
	cfg, err := f.store.Config(id)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := controlplane.PushConfig(f.store, other.State.DeviceID, cfg.InventoryYAML, cfg.PolicyYAML, time.Now()); err != nil {
		t.Fatal(err)
	}
	_, otherDone := liveRun(t, f, other, host)
	runID, done := liveRun(t, f, f.client, host)
	if _, err := gateway.DeactivateDevice(f.dir, f.store, id, "local:bob", time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := f.server.CancelRunsWithoutStanding(); err != nil {
		t.Fatal(err)
	}
	host.waitEvent(t, "signal:TERM")
	stoppedFor(t, f, id, runID, done, remote.CodeDeviceInactive, "the device was deactivated")
	select {
	case err := <-otherDone:
		t.Fatalf("the other device's run ended: %v", err)
	case <-time.After(300 * time.Millisecond):
	}
	if cancelled, err := other.Cancel(context.Background(), runIDOf(t, f, other.State.DeviceID)); err != nil || !cancelled {
		t.Fatalf("the other device's run was not live: %v, %v", cancelled, err)
	}
	<-otherDone
}

// runIDOf returns deviceID's only run.
func runIDOf(t *testing.T, f *fixture, deviceID string) string {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join(f.dir, "runs", deviceID))
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if name := entry.Name(); filepath.Ext(name) == ".json" {
			return name[:len(name)-len(".json")]
		}
	}
	t.Fatal("no run record")
	return ""
}

func TestARunIsStoppedWhenTheWindowEnds(t *testing.T) {
	f, host := execGateway(t)
	id := f.client.State.DeviceID
	if _, err := gateway.ActivateDevice(f.dir, f.store, id, time.Hour, "local:alice", "", time.Now()); err != nil {
		t.Fatal(err)
	}
	runID, done := liveRun(t, f, f.client, host)
	// The check runs two hours later; the request itself was signed now.
	f.server.Now = func() time.Time { return time.Now().Add(2 * time.Hour) }
	if err := f.server.CancelRunsWithoutStanding(); err != nil {
		t.Fatal(err)
	}
	host.waitEvent(t, "signal:TERM")
	stoppedFor(t, f, id, runID, done, remote.CodeDeviceInactive, "the device's activation ended")
}

func TestARunIsStoppedWhenItsIdentityIsDisabled(t *testing.T) {
	f, host := execGateway(t)
	id := f.client.State.DeviceID
	runID, done := liveRun(t, f, f.client, host)
	if err := f.store.DisableIdentity("web", time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := f.server.CancelRunsWithoutStanding(); err != nil {
		t.Fatal(err)
	}
	host.waitEvent(t, "signal:TERM")
	stoppedFor(t, f, id, runID, done, remote.CodeIdentityDisabled, "identity web was disabled")
}

// A device in good standing keeps its run.
func TestARunInGoodStandingKeepsGoing(t *testing.T) {
	f, host := execGateway(t)
	runID, done := liveRun(t, f, f.client, host)
	if err := f.server.CancelRunsWithoutStanding(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		t.Fatalf("the run ended: %v", err)
	case <-time.After(300 * time.Millisecond):
	}
	if cancelled, err := f.client.Cancel(context.Background(), runID); err != nil || !cancelled {
		t.Fatalf("cancel: %v, %v", cancelled, err)
	}
	<-done
}
