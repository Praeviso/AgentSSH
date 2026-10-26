package gateway_test

import (
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Praeviso/AgentSSH/internal/audit"
	"github.com/Praeviso/AgentSSH/internal/controlplane"
	"github.com/Praeviso/AgentSSH/internal/gateway"
	"github.com/Praeviso/AgentSSH/internal/remote"
)

// Failed audit storage cannot leave a revoked device usable. The first
// actor/time survive a new process, concurrent retries and the serve sweep.
func TestDeviceRevocationAuditRecoversWithTheOriginalOperator(t *testing.T) {
	for _, repair := range []string{"command retry", "serve sweep"} {
		t.Run(repair, func(t *testing.T) {
			f, _ := execGateway(t)
			device := activeTokenDevice(t, f)
			logPath := filepath.Join(f.dir, gateway.FileAudit)
			backup := logPath + ".saved"
			if err := os.Rename(logPath, backup); err != nil {
				t.Fatal(err)
			}
			// A directory makes appending fail for root too, unlike chmod.
			if err := os.Mkdir(logPath, 0o700); err != nil {
				t.Fatal(err)
			}
			when := time.Now().UTC().Truncate(time.Second)
			err := gateway.RevokeDevice(f.dir, f.store, device.DeviceID, "local:alice", when)
			if err == nil || !strings.Contains(err.Error(), "the device is revoked, but its audit record failed") {
				t.Fatalf("audit failure: %v", err)
			}
			if got := bearer(t, f, remote.PathTokenHosts, device.Token); got.status != http.StatusForbidden || got.body.Code != remote.CodeDeviceRevoked {
				t.Fatalf("device after failed audit: %d %s", got.status, got.raw)
			}
			if _, err := gateway.ActivateDevice(f.dir, f.store, device.DeviceID, time.Hour, "local:bob", "", when); !errors.Is(err, controlplane.ErrDeviceRevoked) {
				t.Fatalf("activate after failed audit: %v", err)
			}
			if err := os.Remove(logPath); err != nil {
				t.Fatal(err)
			}
			if err := os.Rename(backup, logPath); err != nil {
				t.Fatal(err)
			}
			// Separate store handles stand in for a restarted serve process
			// and other operator commands; no in-memory recovery state helps.
			var wg sync.WaitGroup
			errorsFound := make(chan error, 8)
			for range 8 {
				store, err := gateway.OpenStore(filepath.Join(f.dir, gateway.FileDatabase))
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = store.Close() })
				wg.Add(1)
				go func() {
					defer wg.Done()
					if repair == "serve sweep" {
						errorsFound <- gateway.RecordDeviceRevocations(f.dir, store)
					} else {
						errorsFound <- gateway.RevokeDevice(f.dir, store, device.DeviceID, "local:bob", when.Add(time.Minute))
					}
				}()
			}
			wg.Wait()
			close(errorsFound)
			for err := range errorsFound {
				if err != nil {
					t.Fatal(err)
				}
			}
			var events []audit.Record
			for _, record := range auditRecords(t, f) {
				if record.Event == audit.EventDeviceRevoked {
					events = append(events, record)
				}
			}
			if len(events) != 1 || events[0].DeviceID != device.DeviceID || events[0].Operator != "local:alice" || events[0].TS != when.Format(time.RFC3339) {
				t.Fatalf("repaired revocation: %+v", events)
			}
			if result, err := audit.NewStore(logPath).Verify(); err != nil || !result.OK {
				t.Fatalf("audit chain: %+v, %v", result, err)
			}
		})
	}
}

func TestUnknownDeviceRevocationAddsNoAuditRecord(t *testing.T) {
	f := enrolledGateway(t)
	before := len(auditRecords(t, f))
	if err := gateway.RevokeDevice(f.dir, f.store, "dev_unknown", "local:alice", time.Now()); !errors.Is(err, controlplane.ErrNotFound) {
		t.Fatalf("unknown revocation: %v", err)
	}
	if err := gateway.RecordDeviceRevocations(f.dir, f.store); err != nil {
		t.Fatal(err)
	}
	if after := len(auditRecords(t, f)); after != before {
		t.Fatalf("unknown device changed audit count from %d to %d", before, after)
	}
}
