package tui

import (
	"io"
	"strings"
	"testing"

	"github.com/Praeviso/AgentSSH/internal/discovery"
	"github.com/Praeviso/AgentSSH/internal/executor"
	"github.com/Praeviso/AgentSSH/internal/inventory"
	"github.com/Praeviso/AgentSSH/internal/policy"
	"github.com/Praeviso/AgentSSH/internal/theme"
	"github.com/charmbracelet/lipgloss"
	"github.com/muesli/termenv"
)

func lineWith(out, needle string) string {
	for _, ln := range strings.Split(out, "\n") {
		if strings.Contains(ln, needle) {
			return ln
		}
	}
	return ""
}

func TestScrollWindow(t *testing.T) {
	cases := []struct{ cursor, n, height, wantStart, wantEnd int }{
		{0, 0, 5, 0, 0},   // empty list
		{0, 3, 5, 0, 3},   // height >= n: show all
		{0, 10, 0, 0, 10}, // height <= 0 (unknown size): show all
		{0, 10, 4, 0, 4},  // cursor at top
		{5, 10, 4, 2, 6},  // cursor mid: window follows
		{9, 10, 4, 6, 10}, // cursor at bottom
	}
	for _, c := range cases {
		if s, e := scrollWindow(c.cursor, c.n, c.height); s != c.wantStart || e != c.wantEnd {
			t.Errorf("scrollWindow(%d,%d,%d) = (%d,%d), want (%d,%d)", c.cursor, c.n, c.height, s, e, c.wantStart, c.wantEnd)
		}
	}
}

func TestRenderTableMarksCursorAndKeepsHeaders(t *testing.T) {
	r := lipgloss.NewRenderer(io.Discard)
	st := newAppStyles(r)
	marker := theme.GlyphsFor(r).Marker
	cols := []tableColumn{{header: "NAME"}, {header: "PORT", right: true}}
	rows := [][]string{{"web-1", "22"}, {"db-2", "5432"}}
	out := renderTable(st, cols, rows, 1)

	if !strings.Contains(out, "NAME") || !strings.Contains(out, "PORT") {
		t.Fatalf("headers missing:\n%s", out)
	}
	if sel := lineWith(out, "db-2"); !strings.Contains(sel, marker) {
		t.Fatalf("selected row should carry the %q marker:\n%s", marker, out)
	}
	if other := lineWith(out, "web-1"); strings.Contains(other, marker) {
		t.Fatalf("non-selected row must not carry the marker:\n%s", out)
	}
	t.Logf("\n%s", out) // eyeball alignment in -v
}

func TestRenderTableNoCursorHasNoMarker(t *testing.T) {
	r := lipgloss.NewRenderer(io.Discard)
	st := newAppStyles(r)
	marker := theme.GlyphsFor(r).Marker
	out := renderTable(st, policyRuleColumns, [][]string{{"r1", "ALLOW", "^ls"}}, -1)
	if strings.Contains(out, marker) {
		t.Fatalf("cursor=-1 must not mark any row:\n%s", out)
	}
}

func TestRenderTableNoColorEscapeFree(t *testing.T) {
	r := lipgloss.NewRenderer(io.Discard)
	r.SetColorProfile(termenv.Ascii) // what tui.run() does under NO_COLOR
	st := newAppStyles(r)
	out := renderTable(st, hostColumns, [][]string{hostRow("web-1", inventory.Host{Addr: "10.0.0.11"})}, 0)
	if strings.Contains(out, "\x1b") {
		t.Fatalf("table emitted ANSI escapes under NO_COLOR:\n%q", out)
	}
}

func TestHostRowSignalsAuthWithoutLeakingKeyPath(t *testing.T) {
	row := hostRow("web-1", inventory.Host{
		Addr: "10.0.0.11", User: "deploy", Port: 2222,
		IdentityFile: "~/.ssh/web-1_secret", Tags: []string{"web", "prod"},
	})
	if !strings.Contains(row[0], "[prod]") {
		t.Errorf("prod host should be marked in NAME: %q", row[0])
	}
	if row[2] != "2222" {
		t.Errorf("PORT cell = %q, want 2222", row[2])
	}
	if row[4] != "key" {
		t.Errorf("AUTH cell = %q, want key", row[4])
	}
	for _, cell := range row {
		if strings.Contains(cell, "~/.ssh/web-1_secret") {
			t.Fatalf("identity_file path must not appear in the row: %#v", row)
		}
	}
}

func TestHostRowDefaultsPortAndAlias(t *testing.T) {
	row := hostRow("gw", inventory.Host{SSHConfigAlias: "bastion"})
	if row[2] != "22" {
		t.Errorf("unset port should display as 22, got %q", row[2])
	}
	if row[4] != "alias:bastion" {
		t.Errorf("alias auth cell = %q", row[4])
	}
}

func TestDiscoveryStatusCellMapping(t *testing.T) {
	g := theme.GlyphsFor(nil) // Unicode set
	cases := []struct {
		c    discovery.Candidate
		want string
	}{
		{discovery.Candidate{ProbeStatus: executor.ProbeConnectable}, g.OK + " reachable"},
		{discovery.Candidate{ProbeStatus: executor.ProbeUnreachable}, g.Fail + " unreachable"},
		{discovery.Candidate{ProbeStatus: executor.ProbeAuthFailed}, g.Warn + " auth-failed"},
		{discovery.Candidate{InInventory: true}, g.Absent + " in inventory"},
		{discovery.Candidate{HasKey: true}, g.Maybe + " looks-connectable"},
		{discovery.Candidate{}, g.Absent + " needs-auth"},
	}
	for _, tc := range cases {
		if got := discoveryStatusCell(g, tc.c); got != tc.want {
			t.Errorf("discoveryStatusCell(%+v) = %q, want %q", tc.c, got, tc.want)
		}
	}
	if glyphBool(g, true) != g.OK || glyphBool(g, false) != g.Absent {
		t.Errorf("glyphBool glyphs wrong: %q %q", glyphBool(g, true), glyphBool(g, false))
	}
}

func TestPolicyActionCell(t *testing.T) {
	g := theme.GlyphsFor(nil)
	if policyActionCell(g, policy.ActionDeny) != g.Deny+" DENY" {
		t.Errorf("deny cell = %q", policyActionCell(g, policy.ActionDeny))
	}
	if policyActionCell(g, policy.ActionAllow) != g.OK+" ALLOW" {
		t.Errorf("allow cell = %q", policyActionCell(g, policy.ActionAllow))
	}
}
