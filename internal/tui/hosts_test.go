package tui

import (
	"os"
	"strings"
	"testing"

	"github.com/Praeviso/AgentSSH/internal/audit"
	"github.com/Praeviso/AgentSSH/internal/inventory"
	"github.com/Praeviso/AgentSSH/internal/policy"
)

func TestOSMeta(t *testing.T) {
	cases := map[string]string{
		"linux":   "LNX",
		"Linux":   "LNX",
		"macos":   "MAC",
		"darwin":  "MAC",
		"windows": "WIN",
		"bsd":     "BSD",
		"":        "SRV",
		"plan9":   "SRV",
	}
	for in, want := range cases {
		if code, _ := osMeta(in); code != want {
			t.Errorf("osMeta(%q) = %q, want %q", in, code, want)
		}
	}
}

func TestGridColsResponsiveAndBounded(t *testing.T) {
	m := buildApp(t) // 5 hosts
	prev := 0
	for _, w := range []int{40, 56, 80, 120, 200} {
		mm := sized(t, m, w, 30)
		cols := mm.hosts.gridCols()
		if cols < 1 {
			t.Fatalf("w=%d cols=%d, want >=1", w, cols)
		}
		if cols > len(mm.hosts.names) {
			t.Fatalf("w=%d cols=%d exceeds host count %d", w, cols, len(mm.hosts.names))
		}
		if cols < prev {
			t.Fatalf("cols not monotonic with width: w=%d cols=%d < prev %d", w, cols, prev)
		}
		prev = cols
	}
}

func TestCardOuterWidthEqualAndFits(t *testing.T) {
	m := buildApp(t)
	for _, w := range []int{40, 60, 80, 120} {
		mm := sized(t, m, w, 30)
		cols := mm.hosts.gridCols()
		cw := mm.hosts.cardOuterWidth(cols)
		if cw < cardMinOuter {
			t.Fatalf("w=%d card width %d < min %d", w, cw, cardMinOuter)
		}
		total := cw*cols + cardGap*(cols-1)
		if total > w {
			t.Fatalf("w=%d cols=%d card row %d overflows frame", w, cols, total)
		}
	}
}

func TestRenderHostCardContents(t *testing.T) {
	m := sized(t, buildApp(t), 100, 30)
	cols := m.hosts.gridCols()
	cw := m.hosts.cardOuterWidth(cols)
	card := m.hosts.renderHostCard("prod-web-01", cw, true)
	for _, want := range []string{"prod-web-01", "LNX", "prod", "web"} {
		if !strings.Contains(card, want) {
			t.Fatalf("card missing %q\n%s", want, card)
		}
	}
	// No rendered line may exceed the card's outer width.
	if max, _ := maxLineWidth(card); max > cw {
		t.Fatalf("card line width %d > outer %d\n%s", max, cw, card)
	}
}

// A host with no tags still renders both content rows so cards stay equal-height.
func TestRenderHostCardNoTags(t *testing.T) {
	m := sized(t, buildApp(t), 100, 30)
	cw := m.hosts.cardOuterWidth(m.hosts.gridCols())
	card := m.hosts.renderHostCard("bare", cw, false)
	if _, lines := maxLineWidth(card); lines != cardOuterH {
		t.Fatalf("card height = %d lines, want %d\n%s", lines, cardOuterH, card)
	}
}

func TestGrid2DNavigation(t *testing.T) {
	m := sized(t, buildApp(t), 80, 30) // 5 hosts, 2 columns
	if got := m.hosts.gridCols(); got != 2 {
		t.Fatalf("precondition: cols = %d, want 2", got)
	}
	// names sorted: [bare build-mac db-replica prod-web-01 win-box], cursor at 0.
	m = press(t, m, "down") // +cols -> 2
	if m.hosts.cursor != 2 {
		t.Fatalf("down: cursor = %d, want 2", m.hosts.cursor)
	}
	m = press(t, m, "right") // -> 3
	if m.hosts.cursor != 3 {
		t.Fatalf("right: cursor = %d, want 3", m.hosts.cursor)
	}
	m = press(t, m, "up") // -cols -> 1
	if m.hosts.cursor != 1 {
		t.Fatalf("up: cursor = %d, want 1", m.hosts.cursor)
	}
	m = press(t, m, "left") // -> 0
	if m.hosts.cursor != 0 {
		t.Fatalf("left: cursor = %d, want 0", m.hosts.cursor)
	}
	// Left at the first card clamps.
	m = press(t, m, "left")
	if m.hosts.cursor != 0 {
		t.Fatalf("left at start: cursor = %d, want 0", m.hosts.cursor)
	}
	// 'down' from the last full row snaps onto the trailing partial row's card.
	m = press(t, m, "G") // jump to last (win-box, index 4)
	if m.hosts.cursor != 4 {
		t.Fatalf("G: cursor = %d, want 4", m.hosts.cursor)
	}
}

func TestHostsEditUpdatesInventory(t *testing.T) {
	m := sized(t, buildApp(t), 100, 30)
	hs := m.hosts
	// Each Info-pane field is committed on its own (enter saves one field), and every
	// other field — including the probed OS — is preserved.
	for _, f := range []struct{ key, val string }{
		{"addr", "10.0.0.99"},
		{"user", "admin"},
		{"port", "2222"},
		{"alias", "prod-web"},
		{"identity", "~/.ssh/prod-web"},
		{"tags", "prod, api"},
	} {
		if err := hs.setHostField("prod-web-01", f.key, f.val); err != nil {
			t.Fatalf("setHostField %s: %v", f.key, err)
		}
	}
	inv, err := inventory.Load(hs.paths.InventoryFile)
	if err != nil {
		t.Fatalf("load inventory: %v", err)
	}
	host := inv.Hosts["prod-web-01"]
	if host.Addr != "10.0.0.99" || host.User != "admin" || host.Port != 2222 || host.SSHConfigAlias != "prod-web" || host.IdentityFile != "~/.ssh/prod-web" || host.OS != "linux" {
		t.Fatalf("updated host = %#v", host)
	}
	if got := strings.Join(host.Tags, ","); got != "prod,api" {
		t.Fatalf("tags = %q", got)
	}
}

func TestSetHostFieldRejectsBadInput(t *testing.T) {
	m := sized(t, buildApp(t), 100, 30)
	hs := m.hosts
	if err := hs.setHostField("prod-web-01", "addr", "   "); err == nil {
		t.Fatal("empty addr should be rejected")
	}
	if err := hs.setHostField("prod-web-01", "port", "notaport"); err == nil {
		t.Fatal("non-numeric port should be rejected")
	}
	// A rejected edit must not have touched inventory.yaml.
	inv, err := inventory.Load(hs.paths.InventoryFile)
	if err != nil {
		t.Fatalf("load inventory: %v", err)
	}
	if got := inv.Hosts["prod-web-01"].Addr; got != "10.0.0.11" {
		t.Fatalf("addr changed despite rejected edits: %q", got)
	}
}

func TestHostsRemoveSelectedWritesAudit(t *testing.T) {
	m := sized(t, buildApp(t), 100, 30)
	m.hosts.cursor = hostIndex(t, m.hosts.names, "prod-web-01")
	removed, _ := m.hosts.removeSelected()
	if !removed {
		t.Fatalf("removeSelected failed: status=%q err=%v", m.hosts.status, m.hosts.err)
	}
	if _, ok := m.hosts.inventory.Hosts["prod-web-01"]; ok {
		t.Fatalf("prod-web-01 still present: %#v", m.hosts.inventory.Hosts)
	}
	records, err := audit.NewStore(m.hosts.paths.AuditFile).ReadAll()
	if err != nil {
		t.Fatalf("read audit: %v", err)
	}
	if len(records) != 1 || records[0].Event != audit.EventCompleted || records[0].Host != "prod-web-01" || records[0].Cmd != "inventory rm prod-web-01" {
		t.Fatalf("delete audit records = %#v", records)
	}
}

func TestHostsRemoveSelectedClearsOnlyDeletedHostRules(t *testing.T) {
	m := sized(t, buildAppWith(t, sampleInventory, `version: 1
host_overrides:
  host:prod-web-01:
    rules:
      - match: { cmd_regex: '^whoami$' }
        action: allow
  web:
    rules:
      - match: { cmd_regex: '^id$' }
        action: deny
rule_groups:
  readonly:
    rules:
      - match: { cmd_regex: '^ls$' }
        action: allow
`), 100, 30)
	m.hosts.cursor = hostIndex(t, m.hosts.names, "prod-web-01")

	removed, cmd := m.hosts.removeSelected()
	if !removed {
		t.Fatalf("removeSelected failed: status=%q err=%v", m.hosts.status, m.hosts.err)
	}
	if cmd == nil {
		t.Fatal("removeSelected did not emit policyChangedMsg")
	}
	msg := cmd()
	changed, ok := msg.(policyChangedMsg)
	if !ok {
		t.Fatalf("policy command message = %T %[1]v, want policyChangedMsg", msg)
	}
	if _, ok := changed.config.HostOverrides["host:prod-web-01"]; ok {
		t.Fatalf("deleted host rules still present in message: %#v", changed.config.HostOverrides)
	}
	cfg, err := policy.Load(m.paths.PolicyFile)
	if err != nil {
		t.Fatalf("load policy: %v", err)
	}
	if _, ok := cfg.HostOverrides["host:prod-web-01"]; ok {
		t.Fatalf("deleted host rules still present: %#v", cfg.HostOverrides)
	}
	if _, ok := cfg.HostOverrides["web"]; !ok {
		t.Fatalf("group override removed: %#v", cfg.HostOverrides)
	}
	if _, ok := cfg.RuleGroups["readonly"]; !ok {
		t.Fatalf("rule group removed: %#v", cfg.RuleGroups)
	}
}

func TestHostsRemoveSelectedParseFailureWritesAudit(t *testing.T) {
	m := sized(t, buildApp(t), 100, 30)
	m.hosts.cursor = hostIndex(t, m.hosts.names, "prod-web-01")
	if err := os.WriteFile(m.hosts.paths.InventoryFile, []byte("::: not: yaml: ["), 0o600); err != nil {
		t.Fatalf("write malformed inventory: %v", err)
	}
	removed, _ := m.hosts.removeSelected()
	if removed {
		t.Fatal("removeSelected unexpectedly succeeded")
	}
	records, err := audit.NewStore(m.hosts.paths.AuditFile).ReadAll()
	if err != nil {
		t.Fatalf("read audit: %v", err)
	}
	if len(records) != 1 || records[0].Event != audit.EventFailed || records[0].Host != "prod-web-01" || !strings.Contains(records[0].Error, "yaml") {
		t.Fatalf("failed delete audit records = %#v", records)
	}
}

func hostIndex(t *testing.T, names []string, name string) int {
	t.Helper()
	for i, got := range names {
		if got == name {
			return i
		}
	}
	t.Fatalf("host %q not found in %#v", name, names)
	return 0
}
