package main

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Praeviso/AgentSSH/internal/audit"
	"github.com/Praeviso/AgentSSH/internal/gateway"
	"github.com/Praeviso/AgentSSH/internal/remote"
)

// Dispatch through the real operator command, rather than the store helper,
// so silently using managed mode's unaudited operation is a regression.
func TestDeviceRevokeCommandAuditsSignedAndTokenDevices(t *testing.T) {
	dir, signedID := enrolledDevice(t)
	store, err := gateway.OpenStore(filepath.Join(dir, gateway.FileDatabase))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()
	token, err := gateway.CreateTokenDevice(dir, store, "hosted-agent", "local:alice", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{signedID, token.DeviceID} {
		for range 2 {
			if out, err := runGatewayCLI(t, "--data", dir, "device", "revoke", id); err != nil || out != "Revoked "+id+"\n" {
				t.Fatalf("revoke: %q, %v", out, err)
			}
		}
		device, err := store.Device(id)
		if err != nil || device.Status != remote.DeviceRevoked || device.RevokedAt.IsZero() {
			t.Fatalf("revoked device: %+v, %v", device, err)
		}
		records, err := audit.NewStore(filepath.Join(dir, gateway.FileAudit)).ReadAll()
		if err != nil {
			t.Fatal(err)
		}
		count := 0
		for _, r := range records {
			if r.Event == audit.Event("device_revoked") && r.DeviceID == id {
				count++
				recordedAt, err := time.Parse(time.RFC3339Nano, r.TS)
				if err != nil || r.Operator != localOperator() || !recordedAt.Equal(device.RevokedAt) {
					t.Fatalf("revocation actor/time: %+v, device %+v", r, device)
				}
			}
		}
		if count != 1 {
			t.Fatalf("device %s has %d revocation records, want one", id, count)
		}
	}
	if _, err := runGatewayCLI(t, "--data", dir, "device", "revoke", "dev_unknown"); err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("unknown device: %v", err)
	}
	if out, err := runGatewayCLI(t, "--data", dir, "audit", "verify"); err != nil || out != "audit chain ok · records=3\n" {
		t.Fatalf("verify token issuance and two revocations: %q, %v", out, err)
	}
}
