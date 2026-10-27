package gateway_test

import (
	"errors"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/Praeviso/AgentSSH/internal/audit"
	"github.com/Praeviso/AgentSSH/internal/gateway"
)

func TestAuditWriteFailureLeavesRevocationDurable(t *testing.T) {
	f, o := oauthGateway(t)
	device := activeTokenDevice(t, f)
	client := publicClient(t, f)
	_, challenge := pkce("full-disk")
	_, grant := consent(t, f, o, client, challenge, device.DeviceID)
	restore := gateway.FailSecurityAudit(syscall.ENOSPC)
	t.Cleanup(restore)
	changed, err := gateway.RevokeGrant(f.dir, f.store, grant.ID, "local:alice", time.Now())
	if !changed || !errors.Is(err, syscall.ENOSPC) {
		t.Fatalf("revocation with a failed audit write: %v, %v", changed, err)
	}
	requireAuditPending(t, err)
	restore()
	restartSecurityGateway(t, f)
	repairSecurityConcurrently(t, f, time.Now())
	count := 0
	for _, record := range oauthEvents(t, f) {
		if record.Event == audit.EventOAuthGrantRevoked && record.GrantID == grant.ID {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("repair after ENOSPC published %d revocations", count)
	}
}

func requireAuditPending(t *testing.T, err error) {
	t.Helper()
	var pending *gateway.AuditPendingError
	if !errors.As(err, &pending) {
		t.Fatalf("want a committed restriction with pending audit repair, got %v", err)
	}
}

// Reopen the database as well as the handler: no old process memory helps
// restore pending facts or refuse tokens revoked before the audit failure.
func restartSecurityGateway(t *testing.T, f *fixture) {
	t.Helper()
	origin, now := f.server.WebOrigin, f.server.Now
	if err := f.store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err := gateway.OpenStore(filepath.Join(f.dir, gateway.FileDatabase))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	f.store = store
	f.server = gateway.NewServer(f.dir, store, f.keys)
	f.server.WebOrigin, f.server.Now = origin, now
	handler, err := f.server.Handler(f.base)
	if err != nil {
		t.Fatal(err)
	}
	f.handler.Store(&handler)
}

func repairSecurityConcurrently(t *testing.T, f *fixture, now time.Time) {
	t.Helper()
	var wg sync.WaitGroup
	failures := make(chan error, 6)
	for range cap(failures) {
		store, err := gateway.OpenStore(filepath.Join(f.dir, gateway.FileDatabase))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = store.Close() })
		wg.Add(1)
		go func() {
			defer wg.Done()
			failures <- gateway.RecordEndedActivations(f.dir, store, now)
		}()
	}
	wg.Wait()
	close(failures)
	for err := range failures {
		if err != nil {
			t.Fatal(err)
		}
	}
	if result, err := audit.NewStore(filepath.Join(f.dir, gateway.FileAudit)).Verify(); err != nil || !result.OK {
		t.Fatalf("repaired audit chain: %+v, %v", result, err)
	}
}

func TestSecurityAuditsSurviveRestartAndConcurrentRepair(t *testing.T) {
	for _, failure := range []string{"unwritable", "corrupt"} {
		for _, operation := range []string{"grant revocation", "refresh replay", "deactivation", "expiry"} {
			t.Run(failure+"/"+operation, func(t *testing.T) {
				f, o := oauthGateway(t)
				device := activeTokenDevice(t, f)
				client := publicClient(t, f)
				verifier, challenge := pkce("recover")
				code, grant := consent(t, f, o, client, challenge, device.DeviceID)
				first := issued(t, tokenRequest(t, f, exchange(client, code, verifier)))
				second := issued(t, tokenRequest(t, f, refreshWith(client, first.RefreshToken)))
				when := time.Now().UTC().Truncate(time.Second)
				if operation == "expiry" {
					if _, err := gateway.ActivateDevice(f.dir, f.store, device.DeviceID, time.Minute, "local:alice", "original window", when); err != nil {
						t.Fatal(err)
					}
					when = when.Add(2 * time.Minute)
				}
				f.server.Now = func() time.Time { return when }
				restore := interruptAudit(t, f.dir, failure)
				want, operator, note := audit.EventOAuthGrantRevoked, "local:alice", ""
				switch operation {
				case "grant revocation":
					changed, err := gateway.RevokeGrant(f.dir, f.store, grant.ID, "local:alice", when)
					if !changed {
						t.Fatal("grant was not revoked")
					}
					requireAuditPending(t, err)
					changed, err = gateway.RevokeGrant(f.dir, f.store, grant.ID, "local:bob", when.Add(time.Minute))
					if changed {
						t.Fatal("retry replaced the original revocation")
					}
					requireAuditPending(t, err)
				case "refresh replay":
					operator, note = "", "refresh token reused"
					answer := tokenRequest(t, f, refreshWith(client, first.RefreshToken))
					if answer.status != http.StatusInternalServerError || !strings.Contains(string(answer.raw), "the grant is revoked") {
						t.Fatalf("replay response: %d %s", answer.status, answer.raw)
					}
				case "deactivation":
					want = audit.EventDeviceDeactivated
					changed, err := gateway.DeactivateDevice(f.dir, f.store, device.DeviceID, "local:alice", when)
					if !changed {
						t.Fatal("device was not deactivated")
					}
					requireAuditPending(t, err)
					changed, err = gateway.DeactivateDevice(f.dir, f.store, device.DeviceID, "local:bob", when.Add(time.Minute))
					if changed {
						t.Fatal("retry replaced the original deactivation")
					}
					requireAuditPending(t, err)
				case "expiry":
					want, note = audit.EventDeviceActivationEnded, "original window"
					requireAuditPending(t, gateway.RecordEndedActivations(f.dir, f.store, when))
					if _, err := gateway.ActivateDevice(f.dir, f.store, device.DeviceID, time.Hour, "local:bob", "replacement", when.Add(time.Minute)); err == nil {
						t.Fatal("reactivation succeeded without its required audit")
					}
				}
				restartSecurityGateway(t, f)
				if operation == "grant revocation" || operation == "refresh replay" {
					if got := mcpInit(&mcpClient{t: t, f: f, token: second.AccessToken}); got.status != http.StatusUnauthorized {
						t.Fatalf("revocation did not survive restart: %d %s", got.status, got.raw)
					}
					if got := tokenRequest(t, f, refreshWith(client, second.RefreshToken)); got.status == http.StatusOK {
						t.Fatalf("refresh survived revoked grant: %s", got.raw)
					}
				}
				restore()
				if operation == "expiry" {
					if _, err := gateway.ActivateDevice(f.dir, f.store, device.DeviceID, time.Hour, "local:bob", "replacement", when.Add(time.Minute)); err != nil {
						t.Fatal(err)
					}
				}
				repairSecurityConcurrently(t, f, when.Add(2*time.Minute))
				records, err := audit.NewStore(filepath.Join(f.dir, gateway.FileAudit)).ReadAll()
				if err != nil {
					t.Fatal(err)
				}
				count, refusals := 0, 0
				for _, record := range records {
					if record.DeviceID != device.DeviceID {
						continue
					}
					if record.Event == want {
						count++
						if record.TS != when.Format(time.RFC3339) || record.Operator != operator || record.Note != note || record.EventID == "" {
							t.Fatalf("original fact was lost or replaced: %+v", record)
						}
					}
					if record.Event == audit.EventOAuthRefreshRefused && record.Note == "refresh token reused" {
						refusals++
						if record.TS != when.Format(time.RFC3339) || record.GrantID != grant.ID || record.EventID == "" {
							t.Fatalf("replay refusal was not preserved: %+v", record)
						}
					}
				}
				if count != 1 || operation == "refresh replay" && refusals != 1 {
					t.Fatalf("repaired events: restrictions=%d, replay refusals=%d", count, refusals)
				}
			})
		}
	}
}

func TestAuditCompletionFailureDoesNotDuplicateTheEvent(t *testing.T) {
	f, o := oauthGateway(t)
	device := activeTokenDevice(t, f)
	client := publicClient(t, f)
	_, challenge := pkce("marker")
	_, grant := consent(t, f, o, client, challenge, device.DeviceID)
	if _, err := f.store.DB().Exec(`CREATE TRIGGER fail_audit_completion BEFORE UPDATE OF audited ON security_audit_events BEGIN SELECT RAISE(FAIL, 'injected completion failure'); END`); err != nil {
		t.Fatal(err)
	}
	changed, err := gateway.RevokeGrant(f.dir, f.store, grant.ID, "local:alice", time.Now())
	if !changed {
		t.Fatal("revocation was not committed")
	}
	requireAuditPending(t, err)
	if _, err := f.store.DB().Exec(`DROP TRIGGER fail_audit_completion`); err != nil {
		t.Fatal(err)
	}
	restartSecurityGateway(t, f)
	repairSecurityConcurrently(t, f, time.Now())
	count := 0
	for _, record := range oauthEvents(t, f) {
		if record.Event == audit.EventOAuthGrantRevoked && record.GrantID == grant.ID {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("completion retry published %d revocations", count)
	}
}

func TestRestrictionAndPendingAuditCommitAtomically(t *testing.T) {
	f, o := oauthGateway(t)
	device := activeTokenDevice(t, f)
	client := publicClient(t, f)
	_, challenge := pkce("atomic")
	_, grant := consent(t, f, o, client, challenge, device.DeviceID)
	if _, err := f.store.DB().Exec(`CREATE TRIGGER fail_audit_enqueue BEFORE INSERT ON security_audit_events BEGIN SELECT RAISE(FAIL, 'injected pending-event failure'); END`); err != nil {
		t.Fatal(err)
	}
	for _, operation := range []string{"grant", "device"} {
		var changed bool
		var err error
		if operation == "grant" {
			changed, err = gateway.RevokeGrant(f.dir, f.store, grant.ID, "local:alice", time.Now())
		} else {
			changed, err = gateway.DeactivateDevice(f.dir, f.store, device.DeviceID, "local:alice", time.Now())
		}
		var pending *gateway.AuditPendingError
		if changed || err == nil || errors.As(err, &pending) {
			t.Fatalf("%s commit failure was reported as applied: %v, %v", operation, changed, err)
		}
	}
	grants, err := gateway.Grants(f.store)
	if err != nil || len(grants) != 1 || !grants[0].RevokedAt.IsZero() {
		t.Fatalf("grant update escaped the failed transaction: %+v, %v", grants, err)
	}
	a, err := gateway.DeviceActivation(f.store, device.DeviceID)
	if err != nil || !a.Active(time.Now()) {
		t.Fatalf("deactivation escaped the failed transaction: %+v, %v", a, err)
	}
}

func TestAuditFailureStillPreventsActivation(t *testing.T) {
	f := enrolledGateway(t)
	device, err := gateway.CreateTokenDevice(f.dir, f.store, "inactive-agent", "local:alice", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	restore := interruptAudit(t, f.dir, "unwritable")
	if _, err := gateway.ActivateDevice(f.dir, f.store, device.DeviceID, time.Hour, "local:alice", "", time.Now()); err == nil {
		t.Fatal("activation succeeded without its audit record")
	}
	a, err := gateway.DeviceActivation(f.store, device.DeviceID)
	if err != nil || a.Active(time.Now()) {
		t.Fatalf("failed activation granted access: %+v, %v", a, err)
	}
	restore()
}

func TestBlockedActivationAuditDoesNotBlockOrUndoRestriction(t *testing.T) {
	for _, restriction := range []string{"deactivation", "revocation"} {
		t.Run(restriction, func(t *testing.T) {
			f := enrolledGateway(t)
			id := f.client.State.DeviceID
			started, release := gateway.PauseActivationAudit()
			var once sync.Once
			resume := func() { once.Do(release) }
			var wg sync.WaitGroup
			t.Cleanup(func() { resume(); wg.Wait() })
			activation := make(chan error, 1)
			wg.Add(1)
			go func() {
				defer wg.Done()
				_, err := gateway.ActivateDevice(f.dir, f.store, id, time.Hour, "local:alice", "blocked activation", time.Now())
				activation <- err
			}()
			select {
			case <-started:
			case <-time.After(2 * time.Second):
				t.Fatal("activation did not reach audit publication")
			}
			restricted := make(chan error, 1)
			wg.Add(1)
			go func() {
				defer wg.Done()
				if restriction == "revocation" {
					restricted <- gateway.RevokeDevice(f.dir, f.store, id, "local:bob", time.Now())
				} else {
					_, err := gateway.DeactivateDevice(f.dir, f.store, id, "local:bob", time.Now())
					restricted <- err
				}
			}()
			select {
			case err := <-restricted:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("blocked activation audit held the database writer lock")
			}
			resume()
			if err := <-activation; err == nil {
				t.Fatal("stale activation overwrote a concurrent restriction")
			}
			if restriction == "deactivation" {
				a, err := gateway.DeviceActivation(f.store, id)
				if err != nil || a.Active(time.Now()) {
					t.Fatalf("deactivation was undone: %+v, %v", a, err)
				}
			}
		})
	}
}

// Two holders race to rotate the same token while auditing is unavailable.
// At most one rotation succeeds, and replay revokes even the winning tokens.
func TestConcurrentRefreshReplayDuringAuditFailure(t *testing.T) {
	f, o := oauthGateway(t)
	device := activeTokenDevice(t, f)
	client := publicClient(t, f)
	verifier, challenge := pkce("concurrent")
	code, grant := consent(t, f, o, client, challenge, device.DeviceID)
	first := issued(t, tokenRequest(t, f, exchange(client, code, verifier)))
	restore := interruptAudit(t, f.dir, "unwritable")
	start := make(chan struct{})
	answers := make(chan oauthAnswer, 2)
	var wg sync.WaitGroup
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			answers <- tokenRequest(t, f, refreshWith(client, first.RefreshToken))
		}()
	}
	close(start)
	wg.Wait()
	close(answers)
	issuedCount := 0
	for answer := range answers {
		if answer.status == http.StatusOK {
			issuedCount++
			if got := mcpInit(&mcpClient{t: t, f: f, token: answer.body["access_token"].(string)}); got.status != http.StatusUnauthorized {
				t.Fatalf("winning access token survived replay: %d %s", got.status, got.raw)
			}
		} else if answer.status != http.StatusInternalServerError {
			t.Fatalf("concurrent replay response: %d %s", answer.status, answer.raw)
		}
	}
	if issuedCount != 1 {
		t.Fatalf("rotated the same refresh token %d times", issuedCount)
	}
	grants, err := gateway.Grants(f.store)
	if err != nil || len(grants) != 1 || grants[0].ID != grant.ID || grants[0].RevokedAt.IsZero() {
		t.Fatalf("concurrent replay left a grant valid: %+v, %v", grants, err)
	}
	restore()
	repairSecurityConcurrently(t, f, time.Now())
}
