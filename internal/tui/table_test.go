package tui

import (
	"io"
	"strings"
	"testing"

	"github.com/Praeviso/AgentSSH/internal/discovery"
	"github.com/Praeviso/AgentSSH/internal/executor"
	"github.com/Praeviso/AgentSSH/internal/inventory"
	"github.com/Praeviso/AgentSSH/internal/policy"
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

func TestRenderTableMarksCursorAndKeepsHeaders(t *testing.T) {
	st := newAppStyles(lipgloss.NewRenderer(io.Discard))
	cols := []tableColumn{{header: "NAME"}, {header: "PORT", right: true}}
	rows := [][]string{{"web-1", "22"}, {"db-2", "5432"}}
	out := renderTable(st, cols, rows, 1)

	if !strings.Contains(out, "NAME") || !strings.Contains(out, "PORT") {
		t.Fatalf("headers missing:\n%s", out)
	}
	if sel := lineWith(out, "db-2"); !strings.Contains(sel, "▌") {
		t.Fatalf("selected row should carry the ▌ marker:\n%s", out)
	}
	if other := lineWith(out, "web-1"); strings.Contains(other, "▌") {
		t.Fatalf("non-selected row must not carry the marker:\n%s", out)
	}
	t.Logf("\n%s", out) // eyeball alignment in -v
}

func TestRenderTableNoCursorHasNoMarker(t *testing.T) {
	st := newAppStyles(lipgloss.NewRenderer(io.Discard))
	out := renderTable(st, policyRuleColumns, [][]string{{"r1", "● ALLOW", "^ls"}}, -1)
	if strings.Contains(out, "▌") {
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
	cases := []struct {
		c    discovery.Candidate
		want string
	}{
		{discovery.Candidate{ProbeStatus: executor.ProbeConnectable}, "● reachable"},
		{discovery.Candidate{ProbeStatus: executor.ProbeUnreachable}, "✖ unreachable"},
		{discovery.Candidate{ProbeStatus: executor.ProbeAuthFailed}, "▲ auth-failed"},
		{discovery.Candidate{InInventory: true}, "· in inventory"},
		{discovery.Candidate{HasKey: true}, "○ looks-connectable"},
		{discovery.Candidate{}, "· needs-auth"},
	}
	for _, tc := range cases {
		if got := discoveryStatusCell(tc.c); got != tc.want {
			t.Errorf("discoveryStatusCell(%+v) = %q, want %q", tc.c, got, tc.want)
		}
	}
	if glyphBool(true) != "●" || glyphBool(false) != "·" {
		t.Errorf("glyphBool glyphs wrong: %q %q", glyphBool(true), glyphBool(false))
	}
}

func TestPolicyActionCell(t *testing.T) {
	if policyActionCell(policy.ActionDeny) != "⊘ DENY" {
		t.Errorf("deny cell = %q", policyActionCell(policy.ActionDeny))
	}
	if policyActionCell(policy.ActionAllow) != "● ALLOW" {
		t.Errorf("allow cell = %q", policyActionCell(policy.ActionAllow))
	}
}
