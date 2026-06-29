package tui

import (
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/Praeviso/AgentSSH/internal/audit"
	"github.com/Praeviso/AgentSSH/internal/hostform"
	"github.com/Praeviso/AgentSSH/internal/inventory"
	"github.com/Praeviso/AgentSSH/internal/secrets"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// fieldIndex is the position of an editable Info-pane field, so tests place the
// field cursor without hard-coding the order.
func fieldIndex(key string) int {
	for i, k := range editableInfoFields() {
		if k == key {
			return i
		}
	}
	return -1
}

// filterFor enters the host grid's / filter and types query through the real key
// path, asserting it actually opened the filter box.
func filterFor(t *testing.T, m appModel, query string) appModel {
	t.Helper()
	m = press(t, m, "/")
	if !m.hosts.filtering {
		t.Fatalf("/ did not enter filter mode")
	}
	return press(t, m, query)
}

func TestHostFilterByName(t *testing.T) {
	m := filterFor(t, sized(t, buildApp(t), 100, 30), "prod")
	vis := m.hosts.visible()
	if len(vis) != 1 || vis[0] != "prod-web-01" {
		t.Fatalf("filter prod visible = %v, want [prod-web-01]", vis)
	}
	if got := m.hosts.selectedHost(); got != "prod-web-01" {
		t.Fatalf("selectedHost = %q, want prod-web-01", got)
	}
	view := m.hosts.View()
	if !strings.Contains(view, "prod-web-01") || strings.Contains(view, "db-replica") {
		t.Fatalf("filtered grid view did not narrow:\n%s", view)
	}
}

// The filter matches name, tag, address, and user — not just the name.
func TestHostFilterMatchesEveryField(t *testing.T) {
	cases := map[string]string{
		"backup":    "db-replica", // tag
		"10.0.0.40": "win-box",    // addr
		"postgres":  "db-replica", // user
	}
	for q, want := range cases {
		m := filterFor(t, sized(t, buildApp(t), 100, 30), q)
		vis := m.hosts.visible()
		if len(vis) != 1 || vis[0] != want {
			t.Fatalf("filter %q visible = %v, want [%s]", q, vis, want)
		}
	}
}

func TestHostFilterEmptyStateGuidance(t *testing.T) {
	m := filterFor(t, sized(t, buildApp(t), 100, 30), "zzznomatch")
	if len(m.hosts.visible()) != 0 {
		t.Fatalf("expected no matches, got %v", m.hosts.visible())
	}
	if got := m.hosts.selectedHost(); got != "" {
		t.Fatalf("selectedHost on empty match = %q, want empty", got)
	}
	if !strings.Contains(m.hosts.View(), "No hosts match") {
		t.Fatalf("empty-match view missing guidance:\n%s", m.hosts.View())
	}
}

func TestHostFilterCursorClampsThenEscClears(t *testing.T) {
	m := sized(t, buildApp(t), 100, 30)
	m.hosts.cursor = 4 // win-box, the last card
	m = filterFor(t, m, "prod")
	if m.hosts.cursor != 0 {
		t.Fatalf("cursor after narrowing to one match = %d, want 0", m.hosts.cursor)
	}
	m = press(t, m, "enter") // commit, back to nav
	if m.hosts.filtering {
		t.Fatal("enter should exit filter editing")
	}
	if !m.hosts.filterActive() {
		t.Fatal("enter should keep the filter applied")
	}
	m = press(t, m, "esc") // esc in nav clears the committed filter
	if m.hosts.filterActive() || len(m.hosts.visible()) != len(m.hosts.names) {
		t.Fatalf("esc did not restore the full grid: active=%v shown=%d total=%d",
			m.hosts.filterActive(), len(m.hosts.visible()), len(m.hosts.names))
	}
}

func TestHostFilterEscWhileEditingCancels(t *testing.T) {
	m := filterFor(t, sized(t, buildApp(t), 100, 30), "prod")
	m = press(t, m, "esc")
	if m.hosts.filtering || m.hosts.filterActive() {
		t.Fatalf("esc while editing should cancel: filtering=%v active=%v",
			m.hosts.filtering, m.hosts.filterActive())
	}
}

func TestHostFilterShownCountInStatusBar(t *testing.T) {
	m := filterFor(t, sized(t, buildApp(t), 100, 30), "prod")
	m = press(t, m, "enter")
	if bar := m.renderStatusBar(); !strings.Contains(bar, "shown") {
		t.Fatalf("status bar missing filtered count:\n%s", bar)
	}
}

// Command letters (a/e/d/t/r) must type into the query while filtering, not fire
// their grid actions.
func TestHostFilterSwallowsCommandKeys(t *testing.T) {
	m := sized(t, buildApp(t), 100, 30)
	m = press(t, m, "/")
	m = press(t, m, "a")
	if m.hosts.focus == hostFocusForm {
		t.Fatal("'a' while filtering opened the add form")
	}
	if m.hosts.query != "a" {
		t.Fatalf("query = %q, want \"a\"", m.hosts.query)
	}
}

// A failed probe must read as an error (red), not the green success style; an OK
// probe reads as success. This guards the status-line severity coloring.
func TestHostStatusSeverityFromProbe(t *testing.T) {
	m := sized(t, buildApp(t), 100, 30)

	next, _ := m.Update(hostProbeMsg{name: "prod-web-01", hint: "connection refused"})
	m = next.(appModel)
	if m.hosts.statusLevel != statusErr {
		t.Fatalf("failed probe level = %v, want statusErr", m.hosts.statusLevel)
	}
	if !strings.HasPrefix(m.hosts.status, "FAILED") {
		t.Fatalf("failed probe status = %q", m.hosts.status)
	}
	if m.hosts.statusStyle().Render("x") != m.hosts.styles.err.Render("x") {
		t.Fatal("failed status is not rendered in the error style")
	}

	next, _ = m.Update(hostProbeMsg{name: "prod-web-01", ok: true})
	m = next.(appModel)
	if m.hosts.statusLevel != statusOK {
		t.Fatalf("ok probe level = %v, want statusOK", m.hosts.statusLevel)
	}
	if m.hosts.statusStyle().Render("x") != m.hosts.styles.ok.Render("x") {
		t.Fatal("ok status is not rendered in the success style")
	}
}

// The audit chain badge is English and carries a glyph so it survives NO_COLOR.
func TestChainBadgeIsEnglish(t *testing.T) {
	r := lipgloss.NewRenderer(os.Stdout)
	m := newModel(twoHostRecords(), map[string]HostMeta{}, newStyles(r), nil)

	m.applyVerify(verifyMsg{result: audit.VerifyResult{OK: false, BrokenSeq: 7}})
	tamper := m.chainBadge()
	if !strings.Contains(tamper, "audit chain broken") || !strings.Contains(tamper, "seq=7") {
		t.Fatalf("tamper badge = %q", tamper)
	}

	m.applyVerify(verifyMsg{err: errors.New("boom")})
	verr := m.chainBadge()
	if !strings.Contains(verr, "audit verify error") {
		t.Fatalf("verify-error badge = %q", verr)
	}

	for _, b := range []string{tamper, verr} {
		for _, ru := range b {
			if ru >= 0x4e00 && ru <= 0x9fff {
				t.Fatalf("badge still contains CJK: %q", b)
			}
		}
	}
}

func TestSessionsHomeEndNavigation(t *testing.T) {
	r := lipgloss.NewRenderer(os.Stdout)
	m := newModel(twoHostRecords(), map[string]HostMeta{}, newStyles(r), nil)
	if len(m.rows) < 2 {
		t.Fatalf("precondition: rows = %d, want >= 2", len(m.rows))
	}
	last := len(m.rows) - 1

	end, _ := m.updateList(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("G")})
	if got := end.(model).cursor; got != last {
		t.Fatalf("G: cursor = %d, want %d", got, last)
	}
	home, _ := end.(model).updateList(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("g")})
	if got := home.(model).cursor; got != 0 {
		t.Fatalf("g: cursor = %d, want 0", got)
	}
}

// Regression: moveRuleCursor used to have a value receiver, so j/k never moved
// the policy host-rule selection. With two rules, j must advance and G jump.
func TestPolicyRuleCursorMoves(t *testing.T) {
	m := sized(t, buildApp(t), 100, 30)
	m.hosts.cursor = hostIndex(t, m.hosts.names, "bare")
	m = press(t, m, "enter")
	m = press(t, m, "3") // policy pane

	for _, rule := range []string{"^foo", "^bar"} {
		m = press(t, m, "a")
		m.policy.input.SetValue("allow " + rule)
		m = press(t, m, "enter")
	}
	if b, ok := m.policy.hostRuleSet(); !ok || len(b.Override.Rules) != 2 {
		t.Fatalf("precondition: want 2 host rules, got ok=%v hostRules=%#v", ok, b)
	}

	m.policy.ruleCursor = 0
	m = press(t, m, "j")
	if m.policy.ruleCursor != 1 {
		t.Fatalf("j: ruleCursor = %d, want 1 (value-receiver regression)", m.policy.ruleCursor)
	}
	m = press(t, m, "k")
	if m.policy.ruleCursor != 0 {
		t.Fatalf("k: ruleCursor = %d, want 0", m.policy.ruleCursor)
	}
	m = press(t, m, "G")
	last := len(m.policy.hostPolicyRows()) - 1
	if m.policy.ruleCursor != last {
		t.Fatalf("G: ruleCursor = %d, want %d", m.policy.ruleCursor, last)
	}
	m = press(t, m, "g")
	if m.policy.ruleCursor != 0 {
		t.Fatalf("g: ruleCursor = %d, want 0", m.policy.ruleCursor)
	}
}

// --- round 2: keybinding rework, form markers, info hint ---

// D opens discovery on the grid; d/x are no longer grid delete shortcuts — delete
// moved to the Info pane (see TestInfoPaneDeleteFlow).
func TestGridDeleteAndDiscoverKeys(t *testing.T) {
	base := sized(t, buildApp(t), 100, 30)

	if mD := press(t, base, "D"); mD.hosts.focus != hostFocusDiscover {
		t.Fatalf("'D' should open discovery, focus = %v", mD.hosts.focus)
	}
	if md := press(t, base, "d"); md.hosts.focus != hostFocusList {
		t.Fatalf("'d' on the grid should be inert now, focus = %v", md.hosts.focus)
	}
	if mx := press(t, base, "x"); mx.hosts.focus != hostFocusList {
		t.Fatalf("'x' on the grid should be inert now, focus = %v", mx.hosts.focus)
	}
}

// Delete now lives on the Info pane: open a host's detail, d opens the confirm,
// and y removes the host and pops back to the grid (its detail host is gone).
func TestInfoPaneDeleteFlow(t *testing.T) {
	m := sized(t, buildApp(t), 100, 30)
	m.hosts.cursor = hostIndex(t, m.hosts.names, "prod-web-01")
	m = press(t, m, "enter")
	m = press(t, m, "d")
	if m.hosts.focus != hostFocusConfirm {
		t.Fatalf("'d' did not open the delete confirm, focus = %v", m.hosts.focus)
	}
	if v := m.View(); !strings.Contains(v, "Remove host") {
		t.Fatalf("confirm card not rendered in the detail body:\n%s", v)
	}
	m = press(t, m, "y")
	if _, ok := m.hosts.inventory.Hosts["prod-web-01"]; ok {
		t.Fatalf("prod-web-01 still present after delete")
	}
	// The runtime runs updateConfirm's inventoryChangedCmd; deliver it so the shell
	// applies the change and pops the now-deleted host's detail back to the grid.
	next, _ := m.Update(inventoryChangedMsg{inventory: m.hosts.inventory})
	m = next.(appModel)
	if m.screen != screenGrid {
		t.Fatalf("after delete screen = %v, want grid", m.screen)
	}
}

// Editing happens in place on the Info pane — the same field list, no separate
// form: enter opens the focused field as an input, enter saves just that field.
func TestInfoPaneInlineEdit(t *testing.T) {
	m := sized(t, buildApp(t), 100, 30)
	m.hosts.cursor = hostIndex(t, m.hosts.names, "prod-web-01")
	m = press(t, m, "enter") // open detail; field cursor starts on addr
	m = press(t, m, "enter") // edit the focused field in place
	if !m.hosts.infoEditing || m.hosts.infoEditField != "addr" {
		t.Fatalf("enter did not begin inline edit of addr: editing=%v field=%q", m.hosts.infoEditing, m.hosts.infoEditField)
	}
	// No separate form swaps in — it is still the Info pane, same layout.
	if v := m.View(); strings.Contains(v, "Edit inventory host") {
		t.Fatalf("inline edit must not show a separate form:\n%s", v)
	}
	m.hosts.infoInput.SetValue("10.0.0.99")
	m = press(t, m, "enter") // save just this field
	if m.hosts.infoEditing {
		t.Fatalf("enter did not commit the field")
	}
	if got := m.hosts.inventory.Hosts["prod-web-01"].Addr; got != "10.0.0.99" {
		t.Fatalf("addr not saved inline: %q", got)
	}

	// esc while editing cancels without saving.
	m = press(t, m, "j")     // move cursor to user
	m = press(t, m, "enter") // edit user
	if m.hosts.infoEditField != "user" {
		t.Fatalf("field cursor did not move to user: %q", m.hosts.infoEditField)
	}
	m.hosts.infoInput.SetValue("nope")
	m = press(t, m, "esc")
	if m.hosts.infoEditing {
		t.Fatalf("esc did not cancel the inline edit")
	}
	if m.screen != screenDetail {
		t.Fatalf("esc cancel should stay in detail, screen = %v", m.screen)
	}
	if got := m.hosts.inventory.Hosts["prod-web-01"].User; got != "deploy" {
		t.Fatalf("esc cancel must not save: user = %q", got)
	}

	// esc from browse exits the detail screen.
	m = press(t, m, "esc")
	if m.screen != screenGrid {
		t.Fatalf("esc from browse did not exit to grid, screen = %v", m.screen)
	}
}

// The auth row is a two-stage edit: pick "key", then enter a path that lands in
// inventory's IdentityFile (empty would fall back to the default ssh keys).
func TestInfoPaneAuthKeyEdit(t *testing.T) {
	m := sized(t, buildApp(t), 100, 30)
	m.hosts.cursor = hostIndex(t, m.hosts.names, "prod-web-01")
	m = press(t, m, "enter") // detail
	m.hosts.infoFieldCursor = fieldIndex("auth")
	m = press(t, m, "enter") // begin auth edit → mode-select
	if !m.hosts.infoEditing || !m.hosts.infoAuthChoosing {
		t.Fatalf("auth edit did not open mode-select: editing=%v choosing=%v", m.hosts.infoEditing, m.hosts.infoAuthChoosing)
	}
	if m.hosts.infoAuthMode != "key" {
		t.Fatalf("default auth mode = %q, want key", m.hosts.infoAuthMode)
	}
	m = press(t, m, "enter") // pick key → value input
	if m.hosts.infoAuthChoosing {
		t.Fatalf("enter did not advance to the value input")
	}
	m.hosts.infoInput.SetValue("~/.ssh/prod-web")
	m = press(t, m, "enter") // save
	if m.hosts.infoEditing {
		t.Fatalf("enter did not commit the key path")
	}
	if got := m.hosts.inventory.Hosts["prod-web-01"].IdentityFile; got != "~/.ssh/prod-web" {
		t.Fatalf("identity not saved: %q", got)
	}
}

// The auth row's password mode masks the input and writes the encrypted secrets
// store (requires AGENTSSH_MASTER_PASSWORD).
func TestInfoPaneAuthPasswordEdit(t *testing.T) {
	t.Setenv("AGENTSSH_MASTER_PASSWORD", "correct-horse")
	m := sized(t, buildApp(t), 100, 30)
	m.hosts.cursor = hostIndex(t, m.hosts.names, "prod-web-01")
	m = press(t, m, "enter") // detail
	m.hosts.infoFieldCursor = fieldIndex("auth")
	m = press(t, m, "enter") // mode-select
	m = press(t, m, "right") // key → password
	if m.hosts.infoAuthMode != "password" {
		t.Fatalf("toggle did not select password: %q", m.hosts.infoAuthMode)
	}
	m = press(t, m, "enter") // value input (masked)
	if m.hosts.infoInput.EchoMode != textinput.EchoPassword {
		t.Fatalf("password input is not masked")
	}
	m.hosts.infoInput.SetValue("s3cret")
	m = press(t, m, "enter") // save → secrets store
	if m.hosts.infoEditing {
		t.Fatalf("enter did not commit the password")
	}
	if !m.hosts.secretHosts["prod-web-01"] {
		t.Fatalf("password not recorded for host")
	}
	store, err := secrets.Open(m.hosts.paths.SecretsFile, "correct-horse")
	if err != nil {
		t.Fatalf("open secrets: %v", err)
	}
	if pw, ok := store.Password("prod-web-01"); !ok || pw != "s3cret" {
		t.Fatalf("stored password = %q ok=%v", pw, ok)
	}
}

// Editing a password without a master password set is refused with guidance.
func TestSetHostPasswordRequiresMaster(t *testing.T) {
	t.Setenv("AGENTSSH_MASTER_PASSWORD", "")
	m := sized(t, buildApp(t), 100, 30)
	hs := m.hosts
	if err := hs.setHostPassword("prod-web-01", "x"); err == nil {
		t.Fatal("setHostPassword without a master password should error")
	}
}

// r reloads inventory.yaml from disk, picking up an external edit.
func TestGridReloadKey(t *testing.T) {
	m := sized(t, buildApp(t), 100, 30)
	inv, err := inventory.Load(m.hosts.paths.InventoryFile)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	next, err := inventory.AddHost(inv, "zeta", inventory.Host{Addr: "10.0.0.99"})
	if err != nil {
		t.Fatalf("addhost: %v", err)
	}
	if err := inventory.Save(m.hosts.paths.InventoryFile, next); err != nil {
		t.Fatalf("save: %v", err)
	}
	m = press(t, m, "r")
	if !contains(m.hosts.names, "zeta") {
		t.Fatalf("'r' did not reload the new host: %v", m.hosts.names)
	}
}

func contains(xs []string, want string) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}

// The sessions viewer's d=open alias is gone; d is now inert there.
func TestSessionsDKeyNoLongerOpens(t *testing.T) {
	r := lipgloss.NewRenderer(os.Stdout)
	m := newModel(twoHostRecords(), map[string]HostMeta{}, newStyles(r), nil)
	next, _ := m.updateList(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("d")})
	if got := next.(model).focus; got != focusList {
		t.Fatalf("'d' should no longer open detail; focus = %v", got)
	}
}

// The add form marks required fields and explains the * legend.
func TestFormMarksRequiredFields(t *testing.T) {
	f := hostform.New(hostform.Options{}, lipgloss.NewRenderer(os.Stdout)).SetSize(80, 24)
	v := f.View()
	if !strings.Contains(v, "* required") {
		t.Fatalf("form missing required legend:\n%s", v)
	}
	if strings.Count(v, "*") < 3 { // name marker + addr marker + legend
		t.Fatalf("expected required markers on name and addr plus the legend:\n%s", v)
	}
}

// The host Info pane shows the CLI run template, bridging viewer to action.
func TestInfoPaneShowsRunHint(t *testing.T) {
	m := sized(t, buildApp(t), 100, 30)
	v := m.hosts.infoView("prod-web-01", 80, 20, true)
	if !strings.Contains(v, "agentssh run prod-web-01") {
		t.Fatalf("info pane missing run hint:\n%s", v)
	}
}

// The policy pane is one calm Info-style card with a unified, borderless rule
// list: host tier rows first, then global read-only context rows.
func TestPolicyPaneShowsPlainEffectiveOutcome(t *testing.T) {
	m := sized(t, buildApp(t), 92, 34)
	m.hosts.cursor = hostIndex(t, m.hosts.names, "bare")
	m = press(t, m, "enter")
	m = press(t, m, "3") // policy pane

	// No host rules: global context still renders with a scope column.
	v := m.policy.View()
	for _, want := range []string{"bare", "SCOPE", "PRIORITY", "ACTION", "COMMAND", "GROUP", "global", "output"} {
		if !strings.Contains(v, want) {
			t.Fatalf("policy pane missing %q:\n%s", want, v)
		}
	}
	for _, gone := range []string{"status=", "allow=0", "Host overrides", "This host", "policy for this host", "host tier: no host-specific rules"} {
		if strings.Contains(v, gone) {
			t.Fatalf("policy pane still shows superseded text %q:\n%s", gone, v)
		}
	}

	// Adding a host rule lists it under the host tier ahead of global context.
	m = press(t, m, "a")
	m.policy.input.SetValue("allow 5 ^journalctl\\b")
	m = press(t, m, "enter")
	v = m.policy.View()
	hostIdx := strings.Index(v, "host")
	globalIdx := strings.Index(v, "global")
	if hostIdx < 0 || globalIdx < 0 || hostIdx > globalIdx || !strings.Contains(v, "^journalctl") {
		t.Fatalf("host rule not surfaced under host tier:\n%s", v)
	}
}

// The rule/test input and its feedback render INSIDE the card (before the bottom
// border), not as detached lines floating below the box.
// The host Policy pane is borderless (a flat list like Sessions). Opening the rule
// input attaches it below the pane's content rather than floating it detached.
func TestPolicyInputRendersAttached(t *testing.T) {
	m := sized(t, buildApp(t), 92, 24)
	m.hosts.cursor = hostIndex(t, m.hosts.names, "bare")
	m = press(t, m, "enter")
	m = press(t, m, "3")
	m = press(t, m, "a") // open the rule input

	view := m.policy.View()
	if strings.Contains(view, "╰") {
		t.Fatalf("host policy pane should be borderless, found a card border:\n%s", view)
	}
	lines := strings.Split(view, "\n")
	prompt, hint := -1, -1
	for i, ln := range lines {
		if strings.Contains(ln, "rule>") {
			prompt = i
		}
		if strings.Contains(ln, "host tier") {
			hint = i
		}
	}
	if prompt < 0 {
		t.Fatalf("rule input not shown:\n%s", view)
	}
	if hint < 0 || prompt < hint {
		t.Fatalf("rule input must render attached below the pane content:\n%s", view)
	}
}

// Adding a host rule is direct in the default-deny model: the action and priority
// are part of the rule rather than an implicit lockdown posture.
func TestPolicyAddRuleCreatesHostRuleSet(t *testing.T) {
	m := sized(t, buildApp(t), 92, 24)
	m.hosts.cursor = hostIndex(t, m.hosts.names, "bare")
	m = press(t, m, "enter")
	m = press(t, m, "3")

	m = press(t, m, "a")
	if !m.policy.capturing() {
		t.Fatal("'a' should open the rule input")
	}
	m.policy.input.SetValue("deny 50 ^rm")
	m = press(t, m, "enter")
	if b, ok := m.policy.hostRuleSet(); !ok || len(b.Override.Rules) != 1 {
		t.Fatalf("'a' should create host rules: ok=%v hostRules=%#v", ok, b)
	}
}
