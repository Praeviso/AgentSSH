package session

import (
	"errors"
	"os"
	"testing"

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
	var resolver Resolver
	// Explicit --session wins, even over an ambient env session.
	t.Setenv(EnvSession, "s_env")
	ctx, err := resolver.Resolve("web-1", "s_explicit", "label")
	if err != nil {
		t.Fatalf("explicit resolve: %v", err)
	}
	if ctx.ID != "s_explicit" || ctx.Label != "label" || ctx.Host != "web-1" {
		t.Fatalf("explicit ctx = %#v", ctx)
	}

	// With no flag, the env session is used.
	ctx, err = resolver.Resolve("web-1", "", "")
	if err != nil {
		t.Fatalf("env resolve: %v", err)
	}
	if ctx.ID != "s_env" || ctx.Host != "web-1" {
		t.Fatalf("env ctx = %#v", ctx)
	}
}

// A run that declares no session is a hard error: AgentSSH never invents or resumes
// an id, so logically distinct tasks can't merge into one audit session.
func TestResolveErrorsWithoutSession(t *testing.T) {
	_ = os.Unsetenv(EnvSession)
	var resolver Resolver
	_, err := resolver.Resolve("web-1", "", "")
	if !errors.Is(err, ErrNoSession) {
		t.Fatalf("resolve without session: err = %v, want ErrNoSession", err)
	}
}

// NewID mints distinct, well-formed ids so each task can claim a fresh session.
func TestNewIDIsFreshAndPrefixed(t *testing.T) {
	a, err := NewID()
	if err != nil {
		t.Fatalf("NewID: %v", err)
	}
	b, err := NewID()
	if err != nil {
		t.Fatalf("NewID: %v", err)
	}
	if a == b {
		t.Fatalf("NewID returned the same id twice: %q", a)
	}
	if len(a) < 3 || a[:2] != "s_" {
		t.Fatalf("id = %q, want an s_ prefix", a)
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

func TestSummariesSortsSameEndBySessionID(t *testing.T) {
	summaries := Summaries([]audit.Record{
		{ReqID: "r2", SessionID: "s_b", TS: "2026-06-20T10:00:00Z"},
		{ReqID: "r1", SessionID: "s_a", TS: "2026-06-20T10:00:00Z"},
	})
	if len(summaries) != 2 {
		t.Fatalf("summaries = %#v", summaries)
	}
	if summaries[0].ID != "s_a" || summaries[1].ID != "s_b" {
		t.Fatalf("sort = %#v, want same End sorted by id", summaries)
	}
}

func TestMain(m *testing.M) {
	_ = os.Unsetenv(EnvSession)
	os.Exit(m.Run())
}
