package session

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Kritoooo/agentssh/internal/audit"
)

func TestResolveOrder(t *testing.T) {
	resolver := Resolver{Path: filepath.Join(t.TempDir(), "session"), NewID: fixedID("s_new")}
	ctx, err := resolver.Resolve("s_explicit", "label")
	if err != nil {
		t.Fatalf("explicit resolve: %v", err)
	}
	if ctx.ID != "s_explicit" || ctx.Label != "label" {
		t.Fatalf("explicit ctx = %#v", ctx)
	}

	t.Setenv(EnvSession, "s_env")
	ctx, err = resolver.Resolve("", "")
	if err != nil {
		t.Fatalf("env resolve: %v", err)
	}
	if ctx.ID != "s_env" {
		t.Fatalf("env ctx = %#v", ctx)
	}
}

func TestResolveIdleWindow(t *testing.T) {
	now := time.Date(2026, 6, 16, 8, 0, 0, 0, time.UTC)
	path := filepath.Join(t.TempDir(), "session")
	resolver := Resolver{Path: path, Clock: fixedClock{now: now}, NewID: fixedID("s_new")}
	if err := resolver.Update("s_existing", now.Add(-29*time.Minute)); err != nil {
		t.Fatalf("seed pointer: %v", err)
	}
	ctx, err := resolver.Resolve("", "")
	if err != nil {
		t.Fatalf("resolve within idle window: %v", err)
	}
	if ctx.ID != "s_existing" {
		t.Fatalf("within idle ctx = %#v", ctx)
	}

	if err := resolver.Update("s_old", now.Add(-31*time.Minute)); err != nil {
		t.Fatalf("seed old pointer: %v", err)
	}
	ctx, err = resolver.Resolve("", "")
	if err != nil {
		t.Fatalf("resolve beyond idle window: %v", err)
	}
	if ctx.ID != "s_new" {
		t.Fatalf("beyond idle ctx = %#v", ctx)
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
	os.Unsetenv(EnvSession)
	os.Exit(m.Run())
}
