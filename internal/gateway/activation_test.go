package gateway_test

import (
	"context"
	"errors"
	"io"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/Praeviso/AgentSSH/internal/audit"
	"github.com/Praeviso/AgentSSH/internal/controlplane"
	"github.com/Praeviso/AgentSSH/internal/gateway"
	"github.com/Praeviso/AgentSSH/internal/remote"
	"github.com/Praeviso/AgentSSH/internal/remoteclient"
)

func activationEvents(t *testing.T, f *fixture, deviceID string) []audit.Record {
	t.Helper()
	records, err := audit.NewStore(filepath.Join(f.dir, gateway.FileAudit)).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	var out []audit.Record
	for _, record := range records {
		switch record.Event {
		case audit.EventDeviceActivated, audit.EventDeviceDeactivated, audit.EventDeviceActivationEnded:
			if record.DeviceID == deviceID {
				out = append(out, record)
			}
		}
	}
	return out
}

func inactiveClient(t *testing.T, f *fixture) *remoteclient.Client {
	t.Helper()
	client, err := remoteclient.NewClient(f.enrollInactive(t, "cloud-agent"))
	if err != nil {
		t.Fatal(err)
	}
	return client
}

// A device starts inactive: it can enroll and read its standing, nothing
// else, until an operator activates it.
func TestDevicesStartInactiveUntilAnOperatorActivatesThem(t *testing.T) {
	f := enrolledGateway(t)
	client := inactiveClient(t, f)
	if _, err := client.Hosts(context.Background()); !remote.IsInactive(err) {
		t.Fatalf("hosts before activation: %v, want device_inactive", err)
	}
	status, err := client.Status(context.Background())
	if err != nil || status.Activation == nil || status.Activation.State != remote.ActivationInactive {
		t.Fatalf("status before activation: %+v, %v", status, err)
	}
	now := time.Now()
	a, err := gateway.ActivateDevice(f.dir, f.store, client.State.DeviceID, 2*time.Hour, "local:alice", "deploy", now)
	if err != nil {
		t.Fatal(err)
	}
	// Past the activation check, the device has no configuration yet.
	if _, err := client.Hosts(context.Background()); remote.IsInactive(err) {
		t.Fatalf("hosts after activation: %v", err)
	}
	status, err = client.Status(context.Background())
	if err != nil || status.Activation == nil || status.Activation.State != remote.ActivationActive || status.Activation.Until != a.Until.UTC().Format(time.RFC3339) {
		t.Fatalf("status after activation: %+v, %v", status, err)
	}
	events := activationEvents(t, f, client.State.DeviceID)
	if len(events) != 1 || events[0].Operator != "local:alice" || events[0].Note != "deploy" || events[0].ActiveUntil != a.Until.UTC().Format(time.RFC3339) {
		t.Fatalf("activation audit: %+v", events)
	}
}

// When the window ends the device is refused again with no operator action,
// the end is recorded once however many requests find it, and activating
// again opens a new window.
func TestAWindowEndsOnItsOwnAndIsRecordedOnce(t *testing.T) {
	f, _ := execGateway(t)
	id := f.client.State.DeviceID
	// A window that ended a minute ago.
	if _, err := gateway.ActivateDevice(f.dir, f.store, id, time.Hour, "local:alice", "", time.Now().Add(-61*time.Minute)); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	refusals := make(chan error, 8)
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := f.client.Exec(context.Background(), execReq("uptime"), io.Discard, io.Discard)
			refusals <- err
		}()
	}
	wg.Wait()
	close(refusals)
	for err := range refusals {
		if !remote.IsInactive(err) {
			t.Fatalf("run after the window: %v, want device_inactive", err)
		}
	}
	if err := gateway.RecordEndedActivations(f.dir, f.store, time.Now()); err != nil {
		t.Fatal(err)
	}
	events := activationEvents(t, f, id)
	ended := 0
	for _, record := range events {
		if record.Event == audit.EventDeviceActivationEnded {
			ended++
		}
	}
	if ended != 1 {
		t.Fatalf("ended windows recorded %d times: %+v", ended, events)
	}
	if _, err := gateway.ActivateDevice(f.dir, f.store, id, time.Hour, "local:alice", "", time.Now()); err != nil {
		t.Fatal(err)
	}
	if result, err := f.client.Exec(context.Background(), execReq("uptime"), io.Discard, io.Discard); err != nil || result.ExitCode != 0 {
		t.Fatalf("run after reactivating: %+v, %v", result, err)
	}
	if result, err := audit.NewStore(filepath.Join(f.dir, gateway.FileAudit)).Verify(); err != nil || !result.OK {
		t.Fatalf("verify: %+v, %v", result, err)
	}
}

// serve's sweep records an ended window even when the device sends nothing.
func TestAnEndedWindowIsRecordedWithoutRequests(t *testing.T) {
	f := enrolledGateway(t)
	id := f.client.State.DeviceID
	if _, err := gateway.ActivateDevice(f.dir, f.store, id, time.Minute, "local:alice", "", time.Now().Add(-2*time.Minute)); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := gateway.RecordEndedActivations(f.dir, f.store, time.Now()); err != nil {
			t.Fatal(err)
		}
	}
	events := activationEvents(t, f, id)
	if last := events[len(events)-1]; last.Event != audit.EventDeviceActivationEnded || len(events) != 3 {
		t.Fatalf("events: %+v (want activated by the fixture, activated, ended)", events)
	}
}

func TestActivationNeedsAWindowWithinTheCap(t *testing.T) {
	f := enrolledGateway(t)
	id := f.client.State.DeviceID
	for _, d := range []time.Duration{0, -time.Minute, gateway.MaxActivation + time.Second} {
		if _, err := gateway.ActivateDevice(f.dir, f.store, id, d, "local:alice", "", time.Now()); !errors.Is(err, gateway.ErrActivationDuration) {
			t.Fatalf("activate for %s: %v", d, err)
		}
	}
	if _, err := gateway.ActivateDevice(f.dir, f.store, id, gateway.MaxActivation, "local:alice", "", time.Now()); err != nil {
		t.Fatalf("activate for the cap: %v", err)
	}
	if _, err := gateway.ActivateDevice(f.dir, f.store, "dev_unknown", time.Hour, "local:alice", "", time.Now()); !errors.Is(err, controlplane.ErrNotFound) {
		t.Fatalf("activate an unknown device: %v", err)
	}
}

// Revocation is terminal: a revoked device cannot be activated again.
func TestARevokedDeviceCannotBeActivated(t *testing.T) {
	f := enrolledGateway(t)
	id := f.client.State.DeviceID
	if err := f.store.RevokeDevice(id, time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := gateway.ActivateDevice(f.dir, f.store, id, time.Hour, "local:alice", "", time.Now()); !errors.Is(err, controlplane.ErrDeviceRevoked) {
		t.Fatalf("activate a revoked device: %v", err)
	}
	if _, err := f.client.Status(context.Background()); !remote.IsRevoked(err) {
		t.Fatalf("status: %v, want device_revoked", err)
	}
}

// Deactivating closes the window at once and can be undone by activating
// again; it records no expiry later.
func TestDeactivationTakesEffectOnTheNextRequest(t *testing.T) {
	f, _ := execGateway(t)
	id := f.client.State.DeviceID
	closed, err := gateway.DeactivateDevice(f.dir, f.store, id, "local:bob", time.Now())
	if err != nil || !closed {
		t.Fatalf("deactivate: %v, %v", closed, err)
	}
	if _, err := f.client.Exec(context.Background(), execReq("uptime"), io.Discard, io.Discard); !remote.IsInactive(err) {
		t.Fatalf("run after deactivating: %v, want device_inactive", err)
	}
	if closed, err := gateway.DeactivateDevice(f.dir, f.store, id, "local:bob", time.Now()); err != nil || closed {
		t.Fatalf("deactivate an inactive device: %v, %v", closed, err)
	}
	if err := gateway.RecordEndedActivations(f.dir, f.store, time.Now()); err != nil {
		t.Fatal(err)
	}
	events := activationEvents(t, f, id)
	if len(events) != 2 || events[1].Event != audit.EventDeviceDeactivated || events[1].Operator != "local:bob" {
		t.Fatalf("events: %+v (want activated, deactivated)", events)
	}
}

// Cancelling only stops a run, so an inactive device may still cancel; every
// other device endpoint refuses it.
func TestAnInactiveDeviceCanStillCancel(t *testing.T) {
	f, _ := execGateway(t)
	if _, err := gateway.DeactivateDevice(f.dir, f.store, f.client.State.DeviceID, "local:bob", time.Now()); err != nil {
		t.Fatal(err)
	}
	if cancelled, err := f.client.Cancel(context.Background(), "rn_0123456789abcdef0123456789abcdef"); err != nil || cancelled {
		t.Fatalf("cancel: %v, %v", cancelled, err)
	}
	for name, call := range map[string]func() error{
		"hosts":          func() error { _, err := f.client.Hosts(context.Background()); return err },
		"request status": func() error { _, err := f.client.RequestStatus(context.Background(), "abc123"); return err },
		"approval":       func() error { _, err := f.client.ApprovalStatus(context.Background(), "ap_0123"); return err },
		"attach": func() error {
			_, err := f.client.Attach(context.Background(), "rn_0123456789abcdef0123456789abcdef", io.Discard, io.Discard)
			return err
		},
	} {
		if err := call(); !remote.IsInactive(err) {
			t.Errorf("%s: %v, want device_inactive", name, err)
		}
	}
}
