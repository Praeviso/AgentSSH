package gateway_test

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/Praeviso/AgentSSH/internal/gateway"
	"github.com/Praeviso/AgentSSH/internal/remote"
)

func waitForIdleRuns(t *testing.T, f *fixture) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for f.server.LiveRunCount(f.client.State.DeviceID) != 0 {
		if time.Now().After(deadline) {
			t.Fatal("run did not release its live registration")
		}
		time.Sleep(time.Millisecond)
	}
}

// The quota would require eviction if this attempt committed. Failed file
// creation/claim must preserve the old result and release all attempt resources.
func TestFailedRunAdmissionPreservesResultsAndCapacity(t *testing.T) {
	for _, failure := range []struct {
		name   string
		inject func(error) func()
	}{
		{"spool", gateway.FailNextSpool},
		{"claim", gateway.FailNextClaim},
	} {
		t.Run(failure.name, func(t *testing.T) {
			f, host := execGateway(t)
			f.server.RunQuotaBytes = gateway.DefaultRunMaxBytes
			f.server.MaxConcurrentPerDevice = 1
			first, spool := retainedUptime(t, f)
			waitForIdleRuns(t, f)
			restore := failure.inject(syscall.ENOSPC)
			t.Cleanup(restore)
			req := execReq("uptime")
			req.RunID = remote.NewRunID()
			_, err := f.client.Exec(context.Background(), req, io.Discard, io.Discard)
			var apiErr *remote.APIError
			if !errors.As(err, &apiErr) || apiErr.Status != 500 {
				t.Fatalf("storage failure: %v", err)
			}
			retainedResult(t, f, first, spool)
			if f.server.LiveRunCount(f.client.State.DeviceID) != 0 || records(t, f) != 1 || host.runs("uptime") != 1 {
				t.Fatalf("failed attempt leaked admission or executed: live=%d, records=%d, executions=%d", f.server.LiveRunCount(f.client.State.DeviceID), records(t, f), host.runs("uptime"))
			}
			if paths, _ := spools(t, f, req.RunID); len(paths) != 0 {
				t.Fatalf("failed attempt left private spools: %v", paths)
			}
			if _, err := os.Stat(filepath.Join(f.dir, "runs", f.client.State.DeviceID, req.RunID+".json")); !os.IsNotExist(err) {
				t.Fatalf("failed attempt left a record: %v", err)
			}
			restore()
			got, err := f.client.Exec(context.Background(), req, io.Discard, io.Discard)
			if err != nil || got.RunID != req.RunID || got.ExitCode != 0 {
				t.Fatalf("retry did not recover the failed attempt's capacity: %+v, %v", got, err)
			}
			waitForIdleRuns(t, f)
			if host.runs("uptime") != 2 {
				t.Fatalf("retried command did not run exactly once: total=%d", host.runs("uptime"))
			}
			// Normal eviction remains effective after successful admission.
			if _, err := f.client.Attach(context.Background(), first.RunID, io.Discard, io.Discard); err == nil {
				t.Fatal("committed run failed to apply the normal output quota")
			}
		})
	}
}
