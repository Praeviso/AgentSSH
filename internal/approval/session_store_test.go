package approval

import (
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestSessionStoreGrantMatchTTLHostAndEnd(t *testing.T) {
	now := time.Date(2026, 6, 30, 0, 0, 0, 0, time.UTC)
	store := SessionStore{Dir: t.TempDir(), Now: func() time.Time { return now }}
	matcher, err := Exact("systemctl restart nginx")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Grant("s_test", "web-1", ScopeSession, matcher, "", "ap_0123456789abcdef01234567", "r1", time.Hour, ChannelCLI); err != nil {
		t.Fatalf("Grant: %v", err)
	}
	if _, ok, err := store.Peek("s_test", "web-2", "systemctl restart nginx", ""); err != nil || ok {
		t.Fatalf("wrong host match ok=%v err=%v", ok, err)
	}
	if grant, ok, err := store.Peek("s_test", "web-1", "systemctl restart nginx", ""); err != nil || !ok || grant.Scope != ScopeSession {
		t.Fatalf("session grant match grant=%#v ok=%v err=%v", grant, ok, err)
	}
	now = now.Add(2 * time.Hour)
	if _, ok, err := store.Peek("s_test", "web-1", "systemctl restart nginx", ""); err != nil || ok {
		t.Fatalf("expired grant match ok=%v err=%v", ok, err)
	}

	now = time.Date(2026, 6, 30, 1, 0, 0, 0, time.UTC)
	if _, err := store.Grant("s_test", "web-1", ScopeSession, matcher, "", "ap_0123456789abcdef01234568", "r2", time.Hour, ChannelCLI); err != nil {
		t.Fatalf("Grant again: %v", err)
	}
	if err := store.End("s_test"); err != nil {
		t.Fatalf("End: %v", err)
	}
	if _, ok, err := store.Peek("s_test", "web-1", "systemctl restart nginx", ""); err != nil || ok {
		t.Fatalf("ended session match ok=%v err=%v", ok, err)
	}
}

func TestSessionStoreOnceConcurrentClaimsOnce(t *testing.T) {
	store := SessionStore{Dir: t.TempDir()}
	matcher, err := Exact("id")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Grant("s_once", "web-1", ScopeOnce, matcher, "", "ap_0123456789abcdef01234567", "r1", time.Hour, ChannelCLI); err != nil {
		t.Fatalf("Grant: %v", err)
	}
	var matched int32
	var wg sync.WaitGroup
	for i := 0; i < 24; i++ {
		wg.Add(1)
		go func(seq int) {
			defer wg.Done()
			if _, ok, err := store.Claim("s_once", "web-1", "id", "", fmt.Sprintf("req-%d", seq)); err != nil {
				t.Errorf("Claim: %v", err)
			} else if ok {
				atomic.AddInt32(&matched, 1)
			}
		}(i)
	}
	wg.Wait()
	if got := atomic.LoadInt32(&matched); got != 1 {
		t.Fatalf("once grant claimed by %d requests, want 1", got)
	}
}

func TestSessionStoreOnceTwoPhaseClaimCommitRelease(t *testing.T) {
	store := SessionStore{Dir: t.TempDir()}
	matcher, err := Exact("id")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Grant("s_2p", "web-1", ScopeOnce, matcher, "", "ap_0123456789abcdef01234567", "r1", time.Hour, ChannelCLI); err != nil {
		t.Fatalf("Grant: %v", err)
	}

	// Claim reserves the grant for one request and hides it from everyone else.
	if _, ok, err := store.Claim("s_2p", "web-1", "id", "", "req-a"); err != nil || !ok {
		t.Fatalf("claim ok=%v err=%v", ok, err)
	}
	if _, ok, err := store.Peek("s_2p", "web-1", "id", ""); err != nil || ok {
		t.Fatalf("claimed grant visible to peek ok=%v err=%v", ok, err)
	}
	if _, ok, err := store.Claim("s_2p", "web-1", "id", "", "req-b"); err != nil || ok {
		t.Fatalf("claimed grant claimable by other request ok=%v err=%v", ok, err)
	}
	// Re-claim by the same request is idempotent.
	if _, ok, err := store.Claim("s_2p", "web-1", "id", "", "req-a"); err != nil || !ok {
		t.Fatalf("same-request re-claim ok=%v err=%v", ok, err)
	}

	// Release restores the grant for a clean re-run under a new request id.
	if err := store.Release("s_2p", "req-a"); err != nil {
		t.Fatalf("Release: %v", err)
	}
	if _, ok, err := store.Claim("s_2p", "web-1", "id", "", "req-c"); err != nil || !ok {
		t.Fatalf("released grant not claimable ok=%v err=%v", ok, err)
	}

	// Commit consumes it for good.
	if err := store.Commit("s_2p", "req-c"); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	if _, ok, err := store.Claim("s_2p", "web-1", "id", "", "req-d"); err != nil || ok {
		t.Fatalf("committed grant still claimable ok=%v err=%v", ok, err)
	}
}

func TestSessionStoreCommitReleaseIgnoreOtherClaims(t *testing.T) {
	store := SessionStore{Dir: t.TempDir()}
	matcher, err := Exact("id")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Grant("s_iso", "web-1", ScopeOnce, matcher, "", "ap_0123456789abcdef01234567", "r1", time.Hour, ChannelCLI); err != nil {
		t.Fatalf("Grant: %v", err)
	}
	if _, ok, err := store.Claim("s_iso", "web-1", "id", "", "req-a"); err != nil || !ok {
		t.Fatalf("claim ok=%v err=%v", ok, err)
	}
	// Settling under an unrelated request id must not touch req-a's claim.
	if err := store.Commit("s_iso", "req-x"); err != nil {
		t.Fatalf("Commit other: %v", err)
	}
	if err := store.Release("s_iso", "req-y"); err != nil {
		t.Fatalf("Release other: %v", err)
	}
	if _, ok, err := store.Claim("s_iso", "web-1", "id", "", "req-a"); err != nil || !ok {
		t.Fatalf("claim lost after unrelated settle ok=%v err=%v", ok, err)
	}
}

func TestSessionStoreAllowsSameSessionAcrossHosts(t *testing.T) {
	store := SessionStore{Dir: t.TempDir()}
	webMatcher, err := Exact("systemctl restart web")
	if err != nil {
		t.Fatal(err)
	}
	dbMatcher, err := Exact("systemctl restart db")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Grant("s_shared", "web-1", ScopeSession, webMatcher, "", "ap_0123456789abcdef01234567", "r1", time.Hour, ChannelCLI); err != nil {
		t.Fatalf("Grant web: %v", err)
	}
	if _, err := store.Grant("s_shared", "db-1", ScopeSession, dbMatcher, "", "ap_0123456789abcdef01234568", "r2", time.Hour, ChannelCLI); err != nil {
		t.Fatalf("Grant db: %v", err)
	}
	if grant, ok, err := store.Peek("s_shared", "web-1", "systemctl restart web", ""); err != nil || !ok || grant.Host != "web-1" {
		t.Fatalf("web match grant=%#v ok=%v err=%v", grant, ok, err)
	}
	if grant, ok, err := store.Peek("s_shared", "db-1", "systemctl restart db", ""); err != nil || !ok || grant.Host != "db-1" {
		t.Fatalf("db match grant=%#v ok=%v err=%v", grant, ok, err)
	}
	if _, ok, err := store.Peek("s_shared", "db-1", "systemctl restart web", ""); err != nil || ok {
		t.Fatalf("cross-host command match ok=%v err=%v", ok, err)
	}
}

func TestSessionStoreEndRemovesDerivedSessions(t *testing.T) {
	store := SessionStore{Dir: t.TempDir()}
	matcher, err := Exact("id")
	if err != nil {
		t.Fatal(err)
	}
	for _, sessionID := range []string{"s_batch", "s_batch@web-1", "s_batch@web-2", "s_batch_other@web-3"} {
		if _, err := store.Grant(sessionID, "web-1", ScopeSession, matcher, "", "ap_0123456789abcdef01234567", "r1", time.Hour, ChannelCLI); err != nil {
			t.Fatalf("Grant %s: %v", sessionID, err)
		}
	}
	if err := store.End("s_batch"); err != nil {
		t.Fatalf("End: %v", err)
	}
	for _, sessionID := range []string{"s_batch", "s_batch@web-1", "s_batch@web-2"} {
		if _, ok, err := store.Peek(sessionID, "web-1", "id", ""); err != nil || ok {
			t.Fatalf("ended session %s match ok=%v err=%v", sessionID, ok, err)
		}
	}
	if _, ok, err := store.Peek("s_batch_other@web-3", "web-1", "id", ""); err != nil || !ok {
		t.Fatalf("unrelated derived session match ok=%v err=%v", ok, err)
	}
}
