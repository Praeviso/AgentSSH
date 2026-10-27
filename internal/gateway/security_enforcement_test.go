package gateway_test

import (
	"context"
	"encoding/json"
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

// Both failures work as root: one prevents opening the file for append, the
// other leaves valid JSON whose hash no longer matches the stored record.
func interruptAudit(t *testing.T, dir, failure string) func() {
	t.Helper()
	path := filepath.Join(dir, gateway.FileAudit)
	original, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	switch failure {
	case "unwritable":
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatal(err)
		}
	case "corrupt":
		lines := strings.Split(strings.TrimSpace(string(original)), "\n")
		var record audit.Record
		if err := json.Unmarshal([]byte(lines[0]), &record); err != nil {
			t.Fatal(err)
		}
		record.Note += "tampered"
		data, err := json.Marshal(record)
		if err != nil {
			t.Fatal(err)
		}
		lines[0] = string(data)
		if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	default:
		t.Fatalf("unknown audit failure %q", failure)
	}
	var once sync.Once
	restore := func() {
		t.Helper()
		once.Do(func() {
			if failure == "unwritable" {
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.WriteFile(path, original, 0o600); err != nil {
				t.Fatal(err)
			}
		})
	}
	t.Cleanup(restore)
	return restore
}

func TestOAuthReplayRevokesDuringAuditFailure(t *testing.T) {
	for _, failure := range []string{"unwritable", "corrupt"} {
		for _, replay := range []string{"refresh", "code"} {
			t.Run(failure+"/"+replay, func(t *testing.T) {
				f, o := oauthGateway(t)
				device := activeTokenDevice(t, f)
				client := publicClient(t, f)
				verifier, challenge := pkce("audit")
				code, grant := consent(t, f, o, client, challenge, device.DeviceID)
				first := issued(t, tokenRequest(t, f, exchange(client, code, verifier)))
				second := issued(t, tokenRequest(t, f, refreshWith(client, first.RefreshToken)))
				restore := interruptAudit(t, f.dir, failure)
				form := refreshWith(client, first.RefreshToken)
				if replay == "code" {
					form = exchange(client, code, verifier)
				}
				answer := tokenRequest(t, f, form)
				if answer.status != http.StatusInternalServerError {
					t.Fatalf("replay during audit failure: %d %s", answer.status, answer.raw)
				}
				grants, err := gateway.Grants(f.store)
				if err != nil || len(grants) != 1 || grants[0].ID != grant.ID || grants[0].RevokedAt.IsZero() {
					t.Fatalf("replay left the grant usable: %+v, %v", grants, err)
				}
				if !strings.Contains(string(answer.raw), "the grant is revoked") {
					t.Fatalf("response did not distinguish committed revocation: %s", answer.raw)
				}
				for _, access := range []string{first.AccessToken, second.AccessToken} {
					if got := mcpInit(&mcpClient{t: t, f: f, token: access}); got.status != http.StatusUnauthorized {
						t.Fatalf("access after replay: %d %s", got.status, got.raw)
					}
				}
				if got := tokenRequest(t, f, refreshWith(client, second.RefreshToken)); got.status == http.StatusOK {
					t.Fatalf("refresh succeeded after replay: %s", got.raw)
				}
				restore()
			})
		}
	}
}

func TestAuditFailureDoesNotPreventStandingCancellation(t *testing.T) {
	for _, failure := range []string{"unwritable", "corrupt"} {
		for _, loss := range []string{"expiry", "deactivation"} {
			t.Run(failure+"/"+loss, func(t *testing.T) {
				f, host := execGateway(t)
				id := f.client.State.DeviceID
				when := time.Now()
				if _, err := gateway.ActivateDevice(f.dir, f.store, id, time.Minute, "local:alice", "", when); err != nil {
					t.Fatal(err)
				}
				other := f.enroll(t, "unaffected-agent")
				cfg, err := f.store.Config(id)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := controlplane.PushConfig(f.store, other.State.DeviceID, cfg.InventoryYAML, cfg.PolicyYAML, when); err != nil {
					t.Fatal(err)
				}
				_, otherDone := liveRun(t, f, other, host)
				runID, done := liveRun(t, f, f.client, host)
				restore := interruptAudit(t, f.dir, failure)
				reason := "the device's activation ended"
				if loss == "expiry" {
					f.server.Now = func() time.Time { return when.Add(2 * time.Minute) }
				} else {
					reason = "the device was deactivated"
					closed, err := gateway.DeactivateDevice(f.dir, f.store, id, "local:alice", time.Now())
					if !closed || err == nil {
						t.Fatalf("deactivate with failed audit: %v, %v", closed, err)
					}
				}
				if err := f.server.CancelRunsWithoutStanding(); err != nil {
					t.Fatalf("audit failure became unknown standing: %v", err)
				}
				host.waitEvent(t, "signal:TERM")
				select {
				case err := <-done:
					var apiErr *remote.APIError
					if !errors.As(err, &apiErr) || apiErr.Code != remote.CodeDeviceInactive || !strings.Contains(apiErr.Message, reason) {
						t.Fatalf("cancelled run result: %v", err)
					}
				case <-time.After(10 * time.Second):
					t.Fatal("expired/deactivated command kept running during audit failure")
				}
				data, err := os.ReadFile(filepath.Join(f.dir, "runs", id, runID+".json"))
				if err != nil || !strings.Contains(string(data), reason) {
					t.Fatalf("durable cancellation reason: %s, %v", data, err)
				}
				select {
				case err := <-otherDone:
					t.Fatalf("another device's run was cancelled: %v", err)
				case <-time.After(100 * time.Millisecond):
				}
				// Signed cancellation uses the real client's clock. Restore it
				// after the sweep that observed the target window's expiry.
				f.server.Now = time.Now
				if cancelled, err := other.Cancel(context.Background(), runIDOf(t, f, other.State.DeviceID)); err != nil || !cancelled {
					t.Fatalf("unaffected run was not still live: %v, %v", cancelled, err)
				}
				<-otherDone
				restore()
			})
		}
	}
}

func TestUnknownStandingDoesNotCancelOrAuthorize(t *testing.T) {
	f, host := execGateway(t)
	_, done := liveRun(t, f, f.client, host)
	if err := f.store.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.server.CancelRunsWithoutStanding(); err == nil {
		t.Fatal("a state-store failure was treated as known standing")
	}
	select {
	case err := <-done:
		t.Fatalf("unknown standing cancelled the existing run: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	if _, err := f.client.Hosts(context.Background()); err == nil {
		t.Fatal("a new request was allowed with an unavailable state store")
	}
	// The test-only cleanup stops runs directly because request cancellation
	// cannot authenticate against the closed store.
	f.server.StopRuns()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("the run did not settle before fixture cleanup")
	}
}
