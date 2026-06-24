package session

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Praeviso/AgentSSH/internal/audit"
)

func TestSummariesCountsDeniedAndFailed(t *testing.T) {
	recs := []audit.Record{
		{SessionID: "s1", ReqID: "r1", Event: audit.EventCompleted, TS: "2026-06-20T10:00:00Z"},
		{SessionID: "s1", ReqID: "r2", Event: audit.EventDenied, TS: "2026-06-20T10:01:00Z"},
		{SessionID: "s1", ReqID: "r3", Event: audit.EventFailed, TS: "2026-06-20T10:02:00Z"},
		{SessionID: "s1", ReqID: "r4", Event: audit.EventDenied, TS: "2026-06-20T10:03:00Z"},
	}
	sums := Summaries(recs)
	if len(sums) != 1 {
		t.Fatalf("want 1 summary, got %d", len(sums))
	}
	if sums[0].Denied != 2 || sums[0].Failed != 1 {
		t.Fatalf("denied=%d failed=%d, want 2/1", sums[0].Denied, sums[0].Failed)
	}
}

func TestSummariesBindsSingleHost(t *testing.T) {
	// Legacy data: a session id that touched two hosts. The bound model resolves
	// it to the first host seen (first-write wins), never a list.
	recs := []audit.Record{
		{SessionID: "s1", ReqID: "r1", Host: "web-1", Event: audit.EventCompleted, TS: "2026-06-20T10:00:00Z"},
		{SessionID: "s1", ReqID: "r2", Host: "web-2", Event: audit.EventCompleted, TS: "2026-06-20T10:01:00Z"},
		{SessionID: "s1", ReqID: "r3", Host: "web-1", Event: audit.EventCompleted, TS: "2026-06-20T10:02:00Z"},
	}
	sums := Summaries(recs)
	if len(sums) != 1 {
		t.Fatalf("want 1 summary, got %d", len(sums))
	}
	if sums[0].Host != "web-1" {
		t.Fatalf("host = %q, want web-1 (first seen)", sums[0].Host)
	}
}

func TestResolveOrder(t *testing.T) {
	resolver := Resolver{Path: filepath.Join(t.TempDir(), "session"), NewID: fixedID("s_new")}
	ctx, err := resolver.Resolve("web-1", "s_explicit", "label")
	if err != nil {
		t.Fatalf("explicit resolve: %v", err)
	}
	if ctx.ID != "s_explicit" || ctx.Label != "label" || ctx.Host != "web-1" {
		t.Fatalf("explicit ctx = %#v", ctx)
	}

	t.Setenv(EnvSession, "s_env")
	ctx, err = resolver.Resolve("web-1", "", "")
	if err != nil {
		t.Fatalf("env resolve: %v", err)
	}
	if ctx.ID != "s_env" || ctx.Host != "web-1" {
		t.Fatalf("env ctx = %#v", ctx)
	}
}

func TestResolveIdleWindow(t *testing.T) {
	now := time.Date(2026, 6, 16, 8, 0, 0, 0, time.UTC)
	path := filepath.Join(t.TempDir(), "session")
	resolver := Resolver{Path: path, Clock: fixedClock{now: now}, NewID: fixedID("s_new")}
	if err := resolver.Update("web-1", "s_existing", now.Add(-29*time.Minute)); err != nil {
		t.Fatalf("seed pointer: %v", err)
	}
	ctx, err := resolver.Resolve("web-1", "", "")
	if err != nil {
		t.Fatalf("resolve within idle window: %v", err)
	}
	if ctx.ID != "s_existing" {
		t.Fatalf("within idle ctx = %#v", ctx)
	}

	if err := resolver.Update("web-1", "s_old", now.Add(-31*time.Minute)); err != nil {
		t.Fatalf("seed old pointer: %v", err)
	}
	ctx, err = resolver.Resolve("web-1", "", "")
	if err != nil {
		t.Fatalf("resolve beyond idle window: %v", err)
	}
	if ctx.ID != "s_new" {
		t.Fatalf("beyond idle ctx = %#v", ctx)
	}
}

// TestResolveBindsPerHost is the core one-session-per-host invariant: a live
// session for one host is never reused for a different host, even within the
// idle window — the second host gets its own fresh id.
func TestResolveBindsPerHost(t *testing.T) {
	now := time.Date(2026, 6, 16, 8, 0, 0, 0, time.UTC)
	path := filepath.Join(t.TempDir(), "session")
	resolver := Resolver{Path: path, Clock: fixedClock{now: now}, NewID: fixedID("s_new")}
	if err := resolver.Update("web-1", "s_web1", now.Add(-1*time.Minute)); err != nil {
		t.Fatalf("seed web-1 pointer: %v", err)
	}
	// web-1 resumes its own live session.
	ctx, err := resolver.Resolve("web-1", "", "")
	if err != nil {
		t.Fatalf("resolve web-1: %v", err)
	}
	if ctx.ID != "s_web1" {
		t.Fatalf("web-1 ctx = %#v, want s_web1", ctx)
	}
	// web-2 must NOT inherit web-1's session; it gets a new one bound to web-2.
	ctx, err = resolver.Resolve("web-2", "", "")
	if err != nil {
		t.Fatalf("resolve web-2: %v", err)
	}
	if ctx.ID != "s_new" || ctx.Host != "web-2" {
		t.Fatalf("web-2 ctx = %#v, want fresh s_new bound to web-2", ctx)
	}
	// web-1's pointer is untouched by the web-2 run.
	ctx, err = resolver.Resolve("web-1", "", "")
	if err != nil {
		t.Fatalf("re-resolve web-1: %v", err)
	}
	if ctx.ID != "s_web1" {
		t.Fatalf("web-1 ctx after web-2 run = %#v, want s_web1 preserved", ctx)
	}
}

func TestSummaries(t *testing.T) {
	summaries := Summaries([]audit.Record{
		{ReqID: "r1", SessionID: "s1", SessionLabel: "one", TS: "2026-06-16T08:00:00Z"},
		{ReqID: "r1", SessionID: "s1", TS: "2026-06-16T08:00:01Z"},
		{ReqID: "r2", SessionID: "s1", TS: "2026-06-16T08:01:00Z"},
		{ReqID: "r3", SessionID: "s2", TS: "2026-06-16T09:00:00Z"},
	})
	if len(summaries) != 2 {
		t.Fatalf("summaries = %#v", summaries)
	}
	if summaries[0].ID != "s2" || summaries[1].ID != "s1" {
		t.Fatalf("sort = %#v", summaries)
	}
	if summaries[1].CommandCount != 2 || summaries[1].Label != "one" {
		t.Fatalf("s1 summary = %#v", summaries[1])
	}
}

func fixedID(id string) func() (string, error) {
	return func() (string, error) {
		return id, nil
	}
}

type fixedClock struct {
	now time.Time
}

func (c fixedClock) Now() time.Time {
	return c.now
}

func TestMain(m *testing.M) {
	_ = os.Unsetenv(EnvSession)
	os.Exit(m.Run())
}
