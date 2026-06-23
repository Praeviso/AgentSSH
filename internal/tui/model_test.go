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
	// Records with the same req_id collapse to one operator-facing command.
	sa := groups[1]
	if len(sa.runs) != 1 {
		t.Fatalf("s_a should display one command, got %+v", sa.runs)
	}
	if recs := sa.runs[0].records; len(recs) != 2 || recs[0].Seq != 1 || recs[1].Seq != 2 {
		t.Fatalf("s_a event chain should stay seq-ascending inside the run: %+v", recs)
	}
	if sa.runs[0].latest.Event != audit.EventCompleted {
		t.Fatalf("s_a latest outcome should be completed, got %s", sa.runs[0].latest.Event)
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

func TestRunMatches(t *testing.T) {
	r := rec(1, "2026-06-16T10:00:00Z", "s_a", "fix 502", audit.EventCompleted, "abc")
	run := buildRuns([]audit.Record{r})[0]
	cases := []struct {
		query string
		want  bool
	}{
		{"", true},
		{"WEB-1", true},      // host, case-insensitive
		{"s_a", true},        // session id
		{"fix 502", true},    // label
		{"completed", true},  // status
		{"2026-06-16", true}, // date prefix in ts
		{"does-not-exist", false},
	}
	for _, c := range cases {
		if got := runMatches(run, c.query); got != c.want {
			t.Errorf("runMatches(%q) = %v, want %v", c.query, got, c.want)
		}
	}
}

func TestRunMatchesStructured(t *testing.T) {
	r := rec(1, "2026-06-16T10:00:00Z", "s_a", "fix 502", audit.EventDenied, "abc")
	r.Host = "web-1"
	r.PolicyAction = "deny"
	run := buildRuns([]audit.Record{r})[0]
	cases := []struct {
		query string
		want  bool
	}{
		{"host:web-1", true},
		{"host:db", false},
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
		if got := runMatches(run, c.query); got != c.want {
			t.Errorf("runMatches(%q) = %v, want %v", c.query, got, c.want)
		}
	}
}

func TestRunMatchesStatusUsesLatestOutcome(t *testing.T) {
	started := rec(1, "2026-06-16T10:00:00Z", "s_a", "task", audit.EventStarted, "abc")
	completed := rec(2, "2026-06-16T10:00:01Z", "s_a", "task", audit.EventCompleted, "abc")
	run := buildRuns([]audit.Record{started, completed})[0]
	if runMatches(run, "status:started") {
		t.Fatal("completed run must not match status:started just because it has a started event")
	}
	if !runMatches(run, "status:completed") {
		t.Fatal("completed run should match latest status")
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

func TestAuditListRowsAreSessionsOnly(t *testing.T) {
	m := newModel(sampleRecords(), nil, newStyles(lipgloss.NewRenderer(io.Discard)), nil)
	m.w, m.h, m.ready = 120, 24, true
	if got := len(m.rows); got != 3 {
		t.Fatalf("top-level Audit list should contain sessions only, got %d rows", got)
	}
	out := m.View()
	if strings.Contains(out, "systemctl status nginx") {
		t.Fatalf("session list should not expose command rows:\n%s", out)
	}
	if strings.Contains(m.statusBar(), "3 sessions") || strings.Contains(m.statusBar(), "3 commands") {
		t.Fatalf("status bar should not expose aggregate counts: %q", m.statusBar())
	}
	if !strings.Contains(m.statusBar(), "Audit") || strings.Contains(m.statusBar(), "链") {
		t.Fatalf("status bar should stay compact and contextual: %q", m.statusBar())
	}
}

func TestAuditStatusBarOnlyShowsChainWhenActionable(t *testing.T) {
	m := newModel(sampleRecords(), nil, newStyles(lipgloss.NewRenderer(io.Discard)), nil)
	if got := m.statusBar(); got != "Audit" {
		t.Fatalf("default status bar should hide audit-chain implementation detail, got %q", got)
	}
	m.verifying = true
	if got := m.statusBar(); !strings.Contains(got, "审计日志校验中") {
		t.Fatalf("verifying status should be visible, got %q", got)
	}
	m.verifying = false
	m.verifyDone = true
	m.verifyResult = audit.VerifyResult{OK: true}
	if got := m.statusBar(); got != "Audit" {
		t.Fatalf("successful verification should stay quiet, got %q", got)
	}
	m.verifyResult = audit.VerifyResult{OK: false, BrokenSeq: 7}
	if got := m.statusBar(); !strings.Contains(got, "审计日志异常") || !strings.Contains(got, "seq=7") {
		t.Fatalf("broken audit log should be visible, got %q", got)
	}
}

func TestAuditSessionListColumnsAlign(t *testing.T) {
	r := lipgloss.NewRenderer(io.Discard)
	r.SetColorProfile(termenv.Ascii)
	m := newModel(sampleRecords(), nil, newStyles(r), nil)
	m.w, m.h, m.ready = 120, 24, true
	lines := strings.Split(m.renderList(), "\n")
	if len(lines) < 4 {
		t.Fatalf("expected header plus rows, got:\n%s", m.renderList())
	}
	header := lines[0]
	rows := lines[1:4]
	columns := map[string][]string{
		"STATUS":   {"D DENIED", "+ OK", "+ OK"},
		"SESSION":  {"s_b", "s_a", "(none)"},
		"LABEL":    {"task b", "task a", "(no session)"},
		"UPDATED":  {"updated 11:00:00", "updated 10:00:01", "updated 09:00:00"},
		"COMMANDS": {"1 command", "1 command", "1 command"},
	}
	for heading, values := range columns {
		want := strings.Index(header, heading)
		if want < 0 {
			t.Fatalf("heading %q missing from header %q", heading, header)
		}
		for i, value := range values {
			got := strings.Index(rows[i], value)
			if got != want {
				t.Fatalf("%s column not aligned for value %q: got %d want %d\nheader=%q\nrow=%q", heading, value, got, want, header, rows[i])
			}
		}
	}
}

func TestAuditSessionListColumnsResizeWithWindow(t *testing.T) {
	groups := buildGroups(sampleRecords(), "", "")
	glyphs := newStyles(lipgloss.NewRenderer(io.Discard)).glyphs
	narrow := auditListWidths(glyphs, groups, nil, 80)
	wide := auditListWidths(glyphs, groups, nil, 160)
	if wide.label <= narrow.label {
		t.Fatalf("LABEL column should grow with window width: narrow=%d wide=%d", narrow.label, wide.label)
	}
	if wide.hosts <= narrow.hosts {
		t.Fatalf("HOSTS column should grow with window width: narrow=%d wide=%d", narrow.hosts, wide.hosts)
	}
}

func TestAuditEnterOpensSessionCommandResults(t *testing.T) {
	r := rec(7, "2026-06-16T10:00:00Z", "s_a", "task", audit.EventDenied, "abc")
	r.Cmd = "rm -rf /tmp/x"
	m := newModel([]audit.Record{r}, nil, newStyles(lipgloss.NewRenderer(io.Discard)), nil)
	m.w, m.h, m.ready = 120, 24, true
	updated, _ := m.Update(keyMsg("enter"))
	next := updated.(model)
	if next.focus != focusDetail {
		t.Fatalf("enter should open session detail, focus=%v", next.focus)
	}
	out := next.View()
	if !strings.Contains(out, "Session s_a") || !strings.Contains(out, "rm -rf /tmp/x") {
		t.Fatalf("session detail should contain selected session command results:\n%s", out)
	}
	if !strings.Contains(out, "DENIED") || !strings.Contains(out, "exit 6") || !strings.Contains(out, "not executed") {
		t.Fatalf("denied command result should render CLI semantics:\n%s", out)
	}
	if strings.Contains(out, "Event chain") || strings.Contains(out, "seq 7") {
		t.Fatalf("session detail should not expose raw record evidence by default:\n%s", out)
	}
}

func TestRenderSessionDetailWithExitAndHostMeta(t *testing.T) {
	started := rec(1, "2026-06-16T10:00:00Z", "s_a", "task", audit.EventStarted, "abc")
	r := rec(2, "2026-06-16T10:00:01Z", "s_a", "task", audit.EventCompleted, "abc")
	r.ExitCode = intp(0)
	hosts := map[string]HostMeta{"web-1": {User: "deploy", Addr: "10.0.0.11", Tags: []string{"web", "prod"}}}
	m := newModel([]audit.Record{started, r}, hosts, newStyles(lipgloss.NewRenderer(io.Discard)), nil)
	m.w, m.h, m.ready = 120, 24, true
	m.openSessionDetail(0)
	out := m.renderSessionDetail()
	if !strings.Contains(out, "exit 0") {
		t.Errorf("exit 0 should render:\n%s", out)
	}
	if !strings.Contains(out, "deploy@10.0.0.11") {
		t.Errorf("host detail should include user@addr:\n%s", out)
	}
	if !strings.Contains(out, "[prod]") {
		t.Errorf("prod host marker should render:\n%s", out)
	}
	if strings.Contains(out, "Event chain") || strings.Contains(out, "seq 1") || strings.Contains(out, "seq 2") {
		t.Errorf("session detail should hide started/completed records:\n%s", out)
	}
}

func TestRenderCommandResultNilExit(t *testing.T) {
	r := rec(7, "2026-06-16T10:00:00Z", "s_a", "task", audit.EventDenied, "abc")
	r.Cmd = "rm -rf /tmp/x"
	m := newModel([]audit.Record{r}, nil, newStyles(lipgloss.NewRenderer(io.Discard)), nil)
	out := m.renderCommandResult(buildRuns([]audit.Record{r})[0], true)
	if !strings.Contains(out, "exit 6") {
		t.Errorf("denied run should render CLI exit 6:\n%s", out)
	}
	if !strings.Contains(out, "rm -rf /tmp/x") {
		t.Errorf("detail should contain the command:\n%s", out)
	}
	if !strings.Contains(out, "not executed") {
		t.Errorf("denied command should explain it was not executed:\n%s", out)
	}
}

func TestSessionHostsShowsAdditionalHostCount(t *testing.T) {
	r1 := rec(1, "2026-06-16T10:00:00Z", "s_a", "task", audit.EventCompleted, "a")
	r1.Host = "web-1"
	r2 := rec(2, "2026-06-16T10:01:00Z", "s_a", "task", audit.EventCompleted, "b")
	r2.Host = "web-2"
	r3 := rec(3, "2026-06-16T10:02:00Z", "s_a", "task", audit.EventCompleted, "c")
	r3.Host = "web-3"
	g := buildGroups([]audit.Record{r1, r2, r3}, "", "")[0]
	out := sessionHosts(g, map[string]HostMeta{"web-3": {Tags: []string{"prod"}}})
	if !strings.Contains(out, "web-3 [prod]") || !strings.Contains(out, "+1") {
		t.Fatalf("session hosts should show first two hosts and overflow count, got %q", out)
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
		"ok": s.ok, "bad": s.bad,
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

func TestInitAutoVerifiesChain(t *testing.T) {
	st := newStyles(lipgloss.NewRenderer(io.Discard))

	// With a verify function wired, Init must return a command (the auto-verify)
	// and the badge must read as in-flight until the result lands.
	verified := false
	m := newModel(sampleRecords(), nil, st, func() (audit.VerifyResult, error) {
		verified = true
		return audit.VerifyResult{OK: true, Count: 4}, nil
	})
	if !m.verifying {
		t.Fatal("model should be in verifying state before the result arrives")
	}
	if !strings.Contains(m.chainStatus(), "校验中") {
		t.Fatalf("in-flight badge should say 校验中, got %q", m.chainStatus())
	}
	cmd := m.Init()
	if cmd == nil {
		t.Fatal("Init should return the auto-verify command when a verify fn is set")
	}
	if _, ok := cmd().(verifyMsg); !ok || !verified {
		t.Fatalf("Init command should run verify and yield verifyMsg, got %T verified=%t", cmd(), verified)
	}

	// Without a verify function (e.g. tests), Init is a no-op and the badge falls
	// back to the manual prompt rather than getting stuck on "校验中".
	none := newModel(sampleRecords(), nil, st, nil)
	if none.verifying || none.Init() != nil {
		t.Fatalf("nil verify fn: verifying=%t initNil=%t", none.verifying, none.Init() == nil)
	}
	if !strings.Contains(none.chainStatus(), "press v") {
		t.Fatalf("no-verify badge should prompt for v, got %q", none.chainStatus())
	}
}

func TestApplyVerifyClearsInFlight(t *testing.T) {
	st := newStyles(lipgloss.NewRenderer(io.Discard))
	m := newModel(sampleRecords(), nil, st, func() (audit.VerifyResult, error) {
		return audit.VerifyResult{OK: true, Count: 4}, nil
	})
	m.applyVerify(verifyMsg{result: audit.VerifyResult{OK: true, Count: 4}})
	if m.verifying || !m.verifyDone {
		t.Fatalf("after result: verifying=%t done=%t", m.verifying, m.verifyDone)
	}
	if !strings.Contains(m.chainStatus(), "完整") {
		t.Fatalf("resolved badge should report 完整, got %q", m.chainStatus())
	}
}
