package tui

import (
	"io"
	"strings"
	"testing"

	"github.com/Praeviso/AgentSSH/internal/audit"
	"github.com/charmbracelet/lipgloss"
	"github.com/muesli/termenv"
)

func intp(n int) *int { return &n }

func rec(seq uint64, ts, sessionID, label string, event audit.Event, reqID string) audit.Record {
	return audit.Record{
		Seq:          seq,
		TS:           ts,
		ReqID:        reqID,
		SessionID:    sessionID,
		SessionLabel: label,
		Event:        event,
		Host:         "web-1",
		Cmd:          "systemctl status nginx",
		PolicyAction: "allow",
		PolicyRule:   "default",
	}
}

func sampleRecords() []audit.Record {
	return []audit.Record{
		rec(0, "2026-06-16T09:00:00Z", "", "", audit.EventCompleted, "r3"),
		rec(1, "2026-06-16T10:00:00Z", "s_a", "task a", audit.EventStarted, "r1"),
		rec(2, "2026-06-16T10:00:01Z", "s_a", "task a", audit.EventCompleted, "r1"),
		rec(3, "2026-06-16T11:00:00Z", "s_b", "task b", audit.EventDenied, "r2"),
	}
}

func TestBuildGroupsOrderingAndBuckets(t *testing.T) {
	groups := buildGroups(sampleRecords(), "", "")
	if len(groups) != 3 {
		t.Fatalf("want 3 groups, got %d", len(groups))
	}
	// session.Summaries sorts by End descending: s_b (11:00) before s_a (10:00).
	if groups[0].id != "s_b" || groups[1].id != "s_a" {
		t.Fatalf("unexpected session order: %q, %q", groups[0].id, groups[1].id)
	}
	// The synthetic no-session bucket is always last.
	if groups[2].id != "" || groups[2].label != "(no session)" {
		t.Fatalf("expected trailing no-session group, got id=%q label=%q", groups[2].id, groups[2].label)
	}
	if groups[0].denied != 1 {
		t.Fatalf("s_b should have 1 denied, got %d", groups[0].denied)
	}
	if groups[1].commandCount != 1 {
		t.Fatalf("s_a should count 1 distinct request, got %d", groups[1].commandCount)
	}
	// Records within a group display most-recent (highest seq) first.
	sa := groups[1]
	if len(sa.records) != 2 || sa.records[0].Seq != 2 || sa.records[1].Seq != 1 {
		t.Fatalf("s_a records not in seq-descending order: %+v", sa.records)
	}
}

func TestBuildGroupsFilter(t *testing.T) {
	groups := buildGroups(sampleRecords(), "s_b", "")
	if len(groups) != 1 || groups[0].id != "s_b" {
		t.Fatalf("filter s_b should yield only s_b, got %d groups", len(groups))
	}

	denied := buildGroups(sampleRecords(), "denied", "")
	if len(denied) != 1 || denied[0].id != "s_b" {
		t.Fatalf("filter by status should match the denied record's session")
	}

	none := buildGroups(sampleRecords(), "nonexistent-xyz", "")
	if len(none) != 0 {
		t.Fatalf("non-matching filter should yield no groups, got %d", len(none))
	}
}

func TestBuildGroupsSessionFocus(t *testing.T) {
	groups := buildGroups(sampleRecords(), "", "s_a")
	if len(groups) != 1 || groups[0].id != "s_a" {
		t.Fatalf("session focus should isolate s_a, got %d groups", len(groups))
	}
}

func TestRecordMatches(t *testing.T) {
	r := rec(1, "2026-06-16T10:00:00Z", "s_a", "fix 502", audit.EventCompleted, "abc")
	r.Skill = "restart-service"
	cases := []struct {
		query string
		want  bool
	}{
		{"", true},
		{"WEB-1", true},      // host, case-insensitive
		{"restart", true},    // skill
		{"s_a", true},        // session id
		{"fix 502", true},    // label
		{"completed", true},  // status
		{"2026-06-16", true}, // date prefix in ts
		{"does-not-exist", false},
	}
	for _, c := range cases {
		if got := recordMatches(r, c.query); got != c.want {
			t.Errorf("recordMatches(%q) = %v, want %v", c.query, got, c.want)
		}
	}
}

func TestRecordMatchesStructured(t *testing.T) {
	r := rec(1, "2026-06-16T10:00:00Z", "s_a", "fix 502", audit.EventDenied, "abc")
	r.Host = "web-1"
	r.Skill = "restart-service"
	r.PolicyAction = "deny"
	cases := []struct {
		query string
		want  bool
	}{
		{"host:web-1", true},
		{"host:db", false},
		{"skill:restart", true},
		{"skill:deploy", false},
		{"session:s_a", true},
		{"session:s_b", false},
		{"status:deny", true},   // matches policy action
		{"status:denied", true}, // matches lifecycle event
		{"status:allow", false}, // policy action is deny, not allow
		{"status:completed", false},
		{"date:2026-06-16", true},
		{"date:2026-06-17", false},
		{"host:web-1 status:denied", true}, // both dimensions must hold
		{"host:web-1 status:allow", false}, // host ok but status fails
	}
	for _, c := range cases {
		if got := recordMatches(r, c.query); got != c.want {
			t.Errorf("recordMatches(%q) = %v, want %v", c.query, got, c.want)
		}
	}
}

func TestDurStr(t *testing.T) {
	cases := map[int64]string{
		0:    "-",
		-1:   "-",
		412:  "412ms",
		2300: "2.3s",
	}
	for ms, want := range cases {
		if got := durStr(ms); got != want {
			t.Errorf("durStr(%d) = %q, want %q", ms, got, want)
		}
	}
}

func TestRenderDetailNilExit(t *testing.T) {
	r := rec(7, "2026-06-16T10:00:00Z", "s_a", "task", audit.EventDenied, "abc")
	r.Cmd = "rm -rf /tmp/x"
	out := renderDetail(r, nil)
	if !strings.Contains(out, "Exit     -") {
		t.Errorf("nil ExitCode should render as '-':\n%s", out)
	}
	if !strings.Contains(out, "rm -rf /tmp/x") {
		t.Errorf("detail should contain the command:\n%s", out)
	}
	if !strings.Contains(out, "seq 7") {
		t.Errorf("detail should contain the seq:\n%s", out)
	}
}

func TestRenderDetailWithExitAndHostMeta(t *testing.T) {
	r := rec(2, "2026-06-16T10:00:00Z", "s_a", "task", audit.EventCompleted, "abc")
	r.ExitCode = intp(0)
	hosts := map[string]HostMeta{"web-1": {User: "deploy", Addr: "10.0.0.11", Tags: []string{"web", "prod"}}}
	out := renderDetail(r, hosts)
	if !strings.Contains(out, "Exit     0") {
		t.Errorf("exit 0 should render:\n%s", out)
	}
	if !strings.Contains(out, "deploy@10.0.0.11") {
		t.Errorf("host detail should include user@addr:\n%s", out)
	}
	if !strings.Contains(out, "Tags     web, prod") {
		t.Errorf("host tags should render:\n%s", out)
	}
}

func TestReasonText(t *testing.T) {
	if got := reasonText("hash"); got != "record body altered" {
		t.Errorf("hash reason = %q", got)
	}
	if got := reasonText("prev_hash"); !strings.Contains(got, "chain link") {
		t.Errorf("prev_hash reason = %q", got)
	}
	if got := reasonText("custom"); got != "custom" {
		t.Errorf("unknown reason should pass through, got %q", got)
	}
}

func TestIconFor(t *testing.T) {
	cases := map[audit.Event]string{
		audit.EventCompleted: "✓",
		audit.EventFailed:    "✗",
		audit.EventDenied:    "⊘",
		audit.EventStarted:   "●",
	}
	for event, want := range cases {
		if got := iconFor(event); got != want {
			t.Errorf("iconFor(%q) = %q, want %q", event, got, want)
		}
	}
}

func TestIsProd(t *testing.T) {
	hosts := map[string]HostMeta{
		"web-1": {Tags: []string{"web", "prod"}},
		"db-1":  {Tags: []string{"db"}},
	}
	if !isProd(hosts, "web-1") {
		t.Error("web-1 should be prod")
	}
	if isProd(hosts, "db-1") {
		t.Error("db-1 should not be prod")
	}
	if isProd(hosts, "unknown") {
		t.Error("unknown host should not be prod")
	}
}

func TestTruncate(t *testing.T) {
	if got := truncate("short", 40); got != "short" {
		t.Errorf("short string unchanged, got %q", got)
	}
	long := truncate(strings.Repeat("a", 50), 10)
	if r := []rune(long); len(r) != 10 || !strings.HasSuffix(long, "…") {
		t.Errorf("truncate should cap to 10 runes ending in ellipsis, got %q (len=%d)", long, len([]rune(long)))
	}
}

func TestNoColorStylesEscapeFree(t *testing.T) {
	r := lipgloss.NewRenderer(io.Discard)
	r.SetColorProfile(termenv.Ascii) // what tui.run() does when NO_COLOR is set
	s := newStyles(r)
	for name, st := range map[string]lipgloss.Style{
		"header": s.header, "cursor": s.cursor, "dim": s.dim,
		"prod": s.prod, "ok": s.ok, "bad": s.bad,
	} {
		if out := st.Render("x"); strings.Contains(out, "\x1b") {
			t.Errorf("style %q emitted ANSI escapes under NO_COLOR: %q", name, out)
		}
	}
	// Sanity: the same styles DO emit escapes under a color profile, proving the
	// test is meaningful (styles are genuinely color-bearing).
	rc := lipgloss.NewRenderer(io.Discard)
	rc.SetColorProfile(termenv.TrueColor)
	if out := newStyles(rc).header.Render("x"); !strings.Contains(out, "\x1b") {
		t.Errorf("expected ANSI under TrueColor, got %q", out)
	}
}

func TestCountReqIDs(t *testing.T) {
	records := []audit.Record{
		{ReqID: "a"}, {ReqID: "a"}, {ReqID: "b"}, {ReqID: ""},
	}
	if got := countReqIDs(records); got != 2 {
		t.Errorf("countReqIDs = %d, want 2", got)
	}
}
