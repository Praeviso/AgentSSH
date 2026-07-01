package approval

import (
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
	if _, err := store.Grant("s_test", "web-1", ScopeSession, matcher, "ap_0123456789abcdef01234567", "r1", time.Hour, ChannelCLI); err != nil {
		t.Fatalf("Grant: %v", err)
	}
	if _, ok, err := store.Match("s_test", "web-2", "systemctl restart nginx"); err != nil || ok {
		t.Fatalf("wrong host match ok=%v err=%v", ok, err)
	}
	if grant, ok, err := store.Match("s_test", "web-1", "systemctl restart nginx"); err != nil || !ok || grant.Scope != ScopeSession {
		t.Fatalf("session grant match grant=%#v ok=%v err=%v", grant, ok, err)
	}
	now = now.Add(2 * time.Hour)
	if _, ok, err := store.Match("s_test", "web-1", "systemctl restart nginx"); err != nil || ok {
		t.Fatalf("expired grant match ok=%v err=%v", ok, err)
	}

	now = time.Date(2026, 6, 30, 1, 0, 0, 0, time.UTC)
	if _, err := store.Grant("s_test", "web-1", ScopeSession, matcher, "ap_0123456789abcdef01234568", "r2", time.Hour, ChannelCLI); err != nil {
		t.Fatalf("Grant again: %v", err)
	}
	if err := store.End("s_test"); err != nil {
		t.Fatalf("End: %v", err)
	}
	if _, ok, err := store.Match("s_test", "web-1", "systemctl restart nginx"); err != nil || ok {
		t.Fatalf("ended session match ok=%v err=%v", ok, err)
	}
}

func TestSessionStoreOnceConcurrentConsumesOnce(t *testing.T) {
	store := SessionStore{Dir: t.TempDir()}
	matcher, err := Exact("id")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Grant("s_once", "web-1", ScopeOnce, matcher, "ap_0123456789abcdef01234567", "r1", time.Hour, ChannelCLI); err != nil {
		t.Fatalf("Grant: %v", err)
	}
	var matched int32
	var wg sync.WaitGroup
	for i := 0; i < 24; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, ok, err := store.Match("s_once", "web-1", "id"); err != nil {
				t.Errorf("Match: %v", err)
			} else if ok {
				atomic.AddInt32(&matched, 1)
			}
		}()
	}
	wg.Wait()
	if got := atomic.LoadInt32(&matched); got != 1 {
		t.Fatalf("once grant matched %d times, want 1", got)
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
	if _, err := store.Grant("s_shared", "web-1", ScopeSession, webMatcher, "ap_0123456789abcdef01234567", "r1", time.Hour, ChannelCLI); err != nil {
		t.Fatalf("Grant web: %v", err)
	}
	if _, err := store.Grant("s_shared", "db-1", ScopeSession, dbMatcher, "ap_0123456789abcdef01234568", "r2", time.Hour, ChannelCLI); err != nil {
		t.Fatalf("Grant db: %v", err)
	}
	if grant, ok, err := store.Match("s_shared", "web-1", "systemctl restart web"); err != nil || !ok || grant.Host != "web-1" {
		t.Fatalf("web match grant=%#v ok=%v err=%v", grant, ok, err)
	}
	if grant, ok, err := store.Match("s_shared", "db-1", "systemctl restart db"); err != nil || !ok || grant.Host != "db-1" {
		t.Fatalf("db match grant=%#v ok=%v err=%v", grant, ok, err)
	}
	if _, ok, err := store.Match("s_shared", "db-1", "systemctl restart web"); err != nil || ok {
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
		if _, err := store.Grant(sessionID, "web-1", ScopeSession, matcher, "ap_0123456789abcdef01234567", "r1", time.Hour, ChannelCLI); err != nil {
			t.Fatalf("Grant %s: %v", sessionID, err)
		}
	}
	if err := store.End("s_batch"); err != nil {
		t.Fatalf("End: %v", err)
	}
	for _, sessionID := range []string{"s_batch", "s_batch@web-1", "s_batch@web-2"} {
		if _, ok, err := store.Match(sessionID, "web-1", "id"); err != nil || ok {
			t.Fatalf("ended session %s match ok=%v err=%v", sessionID, ok, err)
		}
	}
	if _, ok, err := store.Match("s_batch_other@web-3", "web-1", "id"); err != nil || !ok {
		t.Fatalf("unrelated derived session match ok=%v err=%v", ok, err)
	}
}
