package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Praeviso/AgentSSH/internal/audit"
	"github.com/Praeviso/AgentSSH/internal/gateway"
)

func TestRestrictionCommandsReportPendingAuditAndRepairOnRetry(t *testing.T) {
	dir, id := enrolledDevice(t)
	grant := grantedClient(t, dir)
	if _, err := runGatewayCLI(t, "--data", dir, "device", "activate", id, "--for", "1h"); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, gateway.FileAudit)
	backup := path + ".saved"
	if err := os.Rename(path, backup); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	operations := []struct {
		args    []string
		applied string
		retried string
	}{
		{[]string{"device", "deactivate", id}, "the device is inactive", id + " was not active\n"},
		{[]string{"oauth", "revoke", grant.ID}, "the grant is revoked", grant.ID + " was already revoked\n"},
	}
	for _, operation := range operations {
		_, err := runGatewayCLI(t, append([]string{"--data", dir}, operation.args...)...)
		if err == nil || !strings.Contains(err.Error(), operation.applied) || !strings.Contains(err.Error(), "audit repair is pending") {
			t.Fatalf("CLI did not distinguish committed restriction from failed commit: %v", err)
		}
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(backup, path); err != nil {
		t.Fatal(err)
	}
	for _, operation := range operations {
		out, err := runGatewayCLI(t, append([]string{"--data", dir}, operation.args...)...)
		if err != nil || out != operation.retried {
			t.Fatalf("retry did not repair the already-effective restriction: %q, %v", out, err)
		}
	}
	records, err := audit.NewStore(path).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	for _, event := range []audit.Event{audit.EventDeviceDeactivated, audit.EventOAuthGrantRevoked} {
		count := 0
		for _, record := range records {
			if record.Event == event {
				count++
				if record.Operator != localOperator() || record.EventID == "" {
					t.Fatalf("repaired CLI attribution: %+v", record)
				}
			}
		}
		if count != 1 {
			t.Fatalf("%s records after command retries: %d", event, count)
		}
	}
	store, err := gateway.OpenStore(filepath.Join(dir, gateway.FileDatabase))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()
	if err := gateway.RecordEndedActivations(dir, store, time.Now()); err != nil {
		t.Fatal(err)
	}
	if result, err := audit.NewStore(path).Verify(); err != nil || !result.OK {
		t.Fatalf("CLI audit chain: %+v, %v", result, err)
	}
}
