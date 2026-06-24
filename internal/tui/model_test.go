package tui

import (
	"os"
	"testing"

	"github.com/Praeviso/AgentSSH/internal/audit"
	"github.com/charmbracelet/lipgloss"
)

func twoHostRecords() []audit.Record {
	return []audit.Record{
		{Seq: 0, ReqID: "r1", SessionID: "s_web", Host: "web-1", Event: audit.EventCompleted, TS: "2026-06-20T10:00:00Z"},
		{Seq: 1, ReqID: "r2", SessionID: "s_web", Host: "web-1", Event: audit.EventCompleted, TS: "2026-06-20T10:01:00Z"},
		{Seq: 2, ReqID: "r3", SessionID: "s_db", Host: "db-1", Event: audit.EventDenied, TS: "2026-06-20T11:00:00Z"},
	}
}

func TestRecordsForHost(t *testing.T) {
	got := recordsForHost(twoHostRecords(), "web-1")
	if len(got) != 2 {
		t.Fatalf("web-1 records = %d, want 2", len(got))
	}
	for _, r := range got {
		if r.Host != "web-1" {
			t.Fatalf("recordsForHost leaked host %q", r.Host)
		}
	}
}

func TestWithHostFilterScopesSessions(t *testing.T) {
	r := lipgloss.NewRenderer(os.Stdout)
	m := newModel(twoHostRecords(), map[string]HostMeta{}, newStyles(r), nil)
	m = m.withHostFilter("web-1")
	if len(m.groups) != 1 {
		t.Fatalf("web-1 groups = %d, want 1", len(m.groups))
	}
	if m.groups[0].id != "s_web" {
		t.Fatalf("web-1 session = %q, want s_web", m.groups[0].id)
	}
	// db-1's session must not appear under web-1.
	m2 := newModel(twoHostRecords(), map[string]HostMeta{}, newStyles(r), nil)
	m2 = m2.withHostFilter("db-1")
	if len(m2.groups) != 1 || m2.groups[0].id != "s_db" {
		t.Fatalf("db-1 groups = %#v, want one s_db", m2.groups)
	}
}

func TestModelAtRoot(t *testing.T) {
	r := lipgloss.NewRenderer(os.Stdout)
	m := newModel(twoHostRecords(), map[string]HostMeta{}, newStyles(r), nil)
	if !m.atRoot() {
		t.Fatal("fresh model should be at root")
	}
	m.focus = focusDetail
	if m.atRoot() {
		t.Fatal("model in detail focus is not at root")
	}
}
