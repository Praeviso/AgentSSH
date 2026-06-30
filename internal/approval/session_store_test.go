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
