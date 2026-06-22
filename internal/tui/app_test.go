package tui

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Praeviso/AgentSSH/internal/audit"
	"github.com/Praeviso/AgentSSH/internal/config"
	"github.com/Praeviso/AgentSSH/internal/discovery"
	"github.com/Praeviso/AgentSSH/internal/executor"
	"github.com/Praeviso/AgentSSH/internal/hostform"
	"github.com/Praeviso/AgentSSH/internal/inventory"
	"github.com/Praeviso/AgentSSH/internal/policy"
	"github.com/Praeviso/AgentSSH/internal/secrets"
	"github.com/charmbracelet/bubbles/key"
	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

func testAppStyles() appStyles {
	return newAppStyles(lipgloss.NewRenderer(io.Discard))
}

func TestSwitchTarget(t *testing.T) {
	tests := []struct {
		key    string
		active int
		want   int
		ok     bool
	}{
		{key: "tab", active: sectionHosts, want: sectionAudit, ok: true},
		{key: "shift+tab", active: sectionHosts, want: sectionSessions, ok: true},
		{key: "3", active: sectionHosts, want: sectionPolicy, ok: true},
		{key: "x", active: sectionHosts, want: sectionHosts, ok: false},
	}
	for _, tt := range tests {
		got, ok := switchTarget(tt.active, 4, keyMsg(tt.key))
		if got != tt.want || ok != tt.ok {
			t.Fatalf("switchTarget(%q,%d) = %d,%t want %d,%t", tt.key, tt.active, got, ok, tt.want, tt.ok)
		}
	}
}

func TestSectionsTitleAndCapturing(t *testing.T) {
	st := testAppStyles()
	hosts := newHostsSection(config.Paths{}, lipgloss.NewRenderer(io.Discard), st, inventory.Inventory{}, nil)
	if hosts.title() != "Hosts" || hosts.capturing() {
		t.Fatalf("hosts title/capturing = %q/%t", hosts.title(), hosts.capturing())
	}
	hosts.focus = hostFocusForm
	if !hosts.capturing() {
		t.Fatal("hosts should capture while form is active")
	}
	hosts.focus = hostFocusConfirm
	if !hosts.capturing() {
		t.Fatal("hosts should capture during a delete confirm (else tab/q abandons it)")
	}
	hosts.focus = hostFocusDiscover
	if !hosts.capturing() {
		t.Fatal("hosts should capture while discovery overlay is active")
	}
	hosts.focus = hostFocusDetail
	if hosts.capturing() {
		t.Fatal("the detail panel is non-modal and must not capture the keyboard")
	}

	pol := newPolicySection("", inventory.Inventory{}, policy.Config{}, st, nil)
	if pol.title() != "Policy" || pol.capturing() {
		t.Fatalf("policy title/capturing = %q/%t", pol.title(), pol.capturing())
	}
	updated, _ := pol.Update(keyMsg("t"))
	focused, ok := updated.(policySection)
	if !ok || !focused.capturing() {
		t.Fatalf("policy t should focus input, updated=%T capturing=%t", updated, ok && focused.capturing())
	}

	sessions := newSessionsSection(nil, st, nil)
	if sessions.title() != "Sessions" || sessions.capturing() {
		t.Fatalf("sessions title/capturing = %q/%t", sessions.title(), sessions.capturing())
	}
}

func TestHostsDiscoverOpensOverlayAndToggleSelection(t *testing.T) {
	st := testAppStyles()
	section := newHostsSection(testPaths(t), lipgloss.NewRenderer(io.Discard), st, inventory.Inventory{}, nil)
	updated, cmd := section.Update(keyMsg("d"))
	hosts, ok := updated.(hostsSection)
	if !ok {
		t.Fatalf("updated = %T", updated)
	}
	if !hosts.discover.active || !hosts.capturing() || cmd == nil {
		t.Fatalf("discover not active/capturing/cmd: active=%t capturing=%t cmdNil=%t", hosts.discover.active, hosts.capturing(), cmd == nil)
	}
	hosts.discover.loading = false
	hosts.discover.candidates = []discovery.Candidate{{Name: "web-1", Addr: "10.0.0.11"}}
	hosts.discover.selected = map[int]bool{0: true}
	updated, _ = hosts.Update(keyMsg(" "))
	hosts = updated.(hostsSection)
	if hosts.discover.selected[0] {
		t.Fatal("space should toggle selected candidate off")
	}
}

func TestHostsDiscoverImportDedupsEndpointAndUsesAlias(t *testing.T) {
	paths := testPaths(t)
	base := inventory.Inventory{Hosts: map[string]inventory.Host{
		"existing": {Addr: "10.0.0.11", Port: 22},
	}}
	if err := inventory.Save(paths.InventoryFile, base); err != nil {
		t.Fatal(err)
	}
	section := newHostsSection(paths, lipgloss.NewRenderer(io.Discard), testAppStyles(), base, nil)
	section.focus = hostFocusDiscover
	section.discover = discoveryOverlay{
		active: true,
		candidates: []discovery.Candidate{
			{Name: "dupe", Source: discovery.SourceKnownHosts, Addr: "10.0.0.11", Port: 22, ProbeStatus: executor.ProbeConnectable},
			{Name: "prod-web", Source: discovery.SourceSSHConfig, Addr: "10.0.0.12", Port: 22, ProbeStatus: executor.ProbeConnectable},
		},
		selected: map[int]bool{0: true, 1: true},
	}
	updated, cmd := section.Update(keyMsg("enter"))
	hosts := updated.(hostsSection)
	if cmd == nil {
		t.Fatal("successful import should emit inventoryChangedMsg")
	}
	msg, ok := cmd().(inventoryChangedMsg)
	if !ok {
		t.Fatalf("cmd msg = %T", cmd())
	}
	if _, ok := msg.inventory.Hosts["dupe"]; ok {
		t.Fatalf("endpoint duplicate imported: %#v", msg.inventory.Hosts)
	}
	if got := msg.inventory.Hosts["prod-web"].SSHConfigAlias; got != "prod-web" {
		t.Fatalf("ssh_config candidate should import by alias, got %#v", msg.inventory.Hosts["prod-web"])
	}
	if hosts.discover.active {
		t.Fatal("discovery overlay should close after successful import")
	}
}

func TestHostsTestActionProducesProbeCommandAndRendersResult(t *testing.T) {
	section := newHostsSection(testPaths(t), lipgloss.NewRenderer(io.Discard), testAppStyles(), inventory.Inventory{
		Hosts: map[string]inventory.Host{"web-1": {Addr: "127.0.0.1", Port: 1}},
	}, nil)
	updated, cmd := section.Update(keyMsg("t"))
	hosts := updated.(hostsSection)
	if cmd == nil || !strings.Contains(hosts.status, "testing web-1") {
		t.Fatalf("test action status=%q cmdNil=%t", hosts.status, cmd == nil)
	}
	updated, _ = hosts.Update(hostProbeMsg{name: "web-1", ok: true})
	hosts = updated.(hostsSection)
	if !strings.Contains(hosts.View(), "OK web-1") {
		t.Fatalf("OK result not rendered: %q", hosts.View())
	}
	updated, _ = hosts.Update(hostProbeMsg{name: "web-1", err: errors.New("no SSH auth methods available")})
	hosts = updated.(hostsSection)
	if !strings.Contains(hosts.View(), "no SSH credentials available") {
		t.Fatalf("hint not rendered: %q", hosts.View())
	}
}

func TestHostsAddStoresIdentityAndPasswordWithoutInventoryLeak(t *testing.T) {
	paths := testPaths(t)
	t.Setenv("AGENTSSH_MASTER_PASSWORD", "master")
	section := newHostsSection(paths, lipgloss.NewRenderer(io.Discard), testAppStyles(), inventory.Inventory{}, nil)
	err := section.addHost(hostform.Result{
		Name: "web-1", Addr: "10.0.0.11", User: "deploy", Port: 22,
		Identity: "~/.ssh/web-1", Password: "ssh-password", Submitted: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := inventory.Load(paths.InventoryFile)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Hosts["web-1"].IdentityFile != "~/.ssh/web-1" {
		t.Fatalf("identity_file = %#v", loaded.Hosts["web-1"])
	}
	data, err := os.ReadFile(paths.InventoryFile)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "ssh-password") || strings.Contains(string(data), "password") {
		t.Fatalf("password leaked into inventory.yaml: %s", data)
	}
	store, err := secrets.Open(paths.SecretsFile, "master")
	if err != nil {
		t.Fatal(err)
	}
	if got, ok := store.Password("web-1"); !ok || got != "ssh-password" {
		t.Fatalf("stored password = %q/%t", got, ok)
	}
}

func TestHostsAddPasswordWithoutMasterRefusesHost(t *testing.T) {
	paths := testPaths(t)
	section := newHostsSection(paths, lipgloss.NewRenderer(io.Discard), testAppStyles(), inventory.Inventory{}, nil)
	err := section.addHost(hostform.Result{Name: "web-1", Addr: "10.0.0.11", Port: 22, Password: "ssh-password", Submitted: true})
	if err == nil || !strings.Contains(err.Error(), "set AGENTSSH_MASTER_PASSWORD") {
		t.Fatalf("err = %v", err)
	}
	loaded, loadErr := inventory.Load(paths.InventoryFile)
	if loadErr != nil {
		t.Fatal(loadErr)
	}
	if len(loaded.Hosts) != 0 {
		t.Fatalf("host persisted despite missing master: %#v", loaded.Hosts)
	}
}

func TestHostsAddPasswordWrongMasterAborts(t *testing.T) {
	paths := testPaths(t)
	if err := os.MkdirAll(paths.Home, 0o700); err != nil {
		t.Fatal(err)
	}
	store, err := secrets.Open(paths.SecretsFile, "right")
	if err != nil {
		t.Fatal(err)
	}
	store.Set("existing", "pw")
	if err := store.Save("right"); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AGENTSSH_MASTER_PASSWORD", "wrong")
	section := newHostsSection(paths, lipgloss.NewRenderer(io.Discard), testAppStyles(), inventory.Inventory{}, nil)
	err = section.addHost(hostform.Result{Name: "web-1", Addr: "10.0.0.11", Port: 22, Password: "ssh-password", Submitted: true})
	if err == nil || !strings.Contains(err.Error(), "wrong master password") {
		t.Fatalf("err = %v", err)
	}
	loaded, loadErr := inventory.Load(paths.InventoryFile)
	if loadErr != nil {
		t.Fatal(loadErr)
	}
	if len(loaded.Hosts) != 0 {
		t.Fatalf("host persisted despite wrong master: %#v", loaded.Hosts)
	}
}

func TestPolicySectionEvaluate(t *testing.T) {
	st := testAppStyles()
	section := newPolicySection(
		"",
		inventory.Inventory{Hosts: map[string]inventory.Host{"web-1": {Tags: []string{"prod"}}}},
		policy.Config{
			Defaults: policy.Defaults{Policy: policy.ActionAllow},
			Rules: []policy.Rule{
				{Name: "catastrophic", Match: policy.Match{CmdRegex: `rm\s+-rf`}, Action: policy.ActionDeny},
			},
		},
		st,
		nil,
	)
	section.input.SetValue("web-1:rm -rf /")
	section.evaluate()
	if !strings.Contains(section.result, "deny") || !strings.Contains(section.result, "rules:catastrophic") || section.err != nil {
		t.Fatalf("policy result=%q err=%v", section.result, section.err)
	}
}

func TestSessionsEnterProducesAuditFilterMessage(t *testing.T) {
	st := testAppStyles()
	records := []audit.Record{{ReqID: "r1", SessionID: "s_a", TS: "2026-06-17T10:00:00Z"}}
	section := newSessionsSection(records, st, nil)
	updated, cmd := section.Update(keyMsg("enter"))
	if cmd == nil {
		t.Fatal("enter should produce sessionSelectedMsg")
	}
	if _, ok := updated.(sessionsSection); !ok {
		t.Fatalf("updated = %T", updated)
	}
	msg := cmd()
	selected, ok := msg.(sessionSelectedMsg)
	if !ok || selected.id != "s_a" {
		t.Fatalf("msg = %#v", msg)
	}
}

func TestAuditWithSessionFilter(t *testing.T) {
	m := newModel(sampleRecords(), nil, newStyles(lipgloss.NewRenderer(io.Discard)), nil)
	m = m.withSessionFilter("s_a")
	if m.sessionFocus != "s_a" || m.filterQuery != "" || len(m.groups) != 1 || m.groups[0].id != "s_a" {
		t.Fatalf("session focus failed: focus=%q query=%q groups=%#v", m.sessionFocus, m.filterQuery, m.groups)
	}
}

func TestInventoryChangedUpdatesAuditAndPolicySections(t *testing.T) {
	app := newAppModel(config.Paths{}, lipgloss.NewRenderer(io.Discard))
	inv := inventory.Inventory{Hosts: map[string]inventory.Host{"web-1": {Addr: "10.0.0.11", Tags: []string{"prod"}}}}
	app.applyInventoryChange(inv)

	auditModel, ok := app.sections[sectionAudit].(model)
	if !ok || auditModel.hosts["web-1"].Addr != "10.0.0.11" {
		t.Fatalf("audit hosts not updated: %T %#v", app.sections[sectionAudit], ok)
	}
	policyModel, ok := app.sections[sectionPolicy].(policySection)
	if !ok || policyModel.inventory.Hosts["web-1"].Addr != "10.0.0.11" {
		t.Fatalf("policy inventory not updated: %T %#v", app.sections[sectionPolicy], ok)
	}
}

func TestTooSmallTerminalShowsResizeCard(t *testing.T) {
	app := newAppModel(testPaths(t), lipgloss.NewRenderer(io.Discard))
	app.w, app.h, app.ready = 20, 5, true
	if v := app.View(); !strings.Contains(v, "too small") {
		t.Fatalf("a tiny terminal should show the resize card:\n%s", v)
	}
	app.w, app.h = 80, 24
	if v := app.View(); strings.Contains(v, "too small") {
		t.Fatal("an adequate terminal must not show the resize card")
	}
}

func TestHostsListChromeShrinksWithMoreLines(t *testing.T) {
	s := newHostsSection(testPaths(t), lipgloss.NewRenderer(io.Discard), testAppStyles(),
		inventory.Inventory{Transport: "native", Hosts: map[string]inventory.Host{"a": {Addr: "1"}}}, nil)
	base := s.listChromeHeight()
	s.status = "testing…"
	if s.listChromeHeight() <= base {
		t.Fatalf("a status line should grow chrome (shrinking the table): base=%d with-status=%d", base, s.listChromeHeight())
	}
}

func TestFooterShowsSectionAndGlobalKeys(t *testing.T) {
	app := newAppModel(testPaths(t), lipgloss.NewRenderer(io.Discard))
	app.help.Width = 200 // wide enough that short help shows every binding
	app.active = sectionHosts
	footer := app.renderFooter()
	for _, want := range []string{"add", "discover", "test", "switch", "quit"} {
		if !strings.Contains(footer, want) {
			t.Fatalf("footer missing %q:\n%s", want, footer)
		}
	}
}

func TestHostsFooterIsContextual(t *testing.T) {
	s := newHostsSection(testPaths(t), lipgloss.NewRenderer(io.Discard), testAppStyles(), inventory.Inventory{}, nil)
	s.focus = hostFocusDiscover
	hasDesc := func(km interface{ ShortHelp() []key.Binding }, desc string) bool {
		for _, b := range km.ShortHelp() {
			if b.Help().Desc == desc {
				return true
			}
		}
		return false
	}
	if !hasDesc(s.helpKeyMap(), "import") {
		t.Fatalf("discover-active footer should advertise import, got %+v", s.helpKeyMap().ShortHelp())
	}
	s.focus = hostFocusList
	if !hasDesc(s.helpKeyMap(), "add") {
		t.Fatalf("list footer should advertise add")
	}
}

func TestHelpKeyTogglesFullHelp(t *testing.T) {
	app := newAppModel(testPaths(t), lipgloss.NewRenderer(io.Discard))
	app.active = sectionHosts
	if app.help.ShowAll {
		t.Fatal("help should start collapsed")
	}
	updated, _ := app.Update(keyMsg("?"))
	app = updated.(appModel)
	if !app.help.ShowAll {
		t.Fatal("'?' should toggle full help on")
	}
}

func TestFirstRunWelcomeShownThenDismissed(t *testing.T) {
	app := newAppModel(testPaths(t), lipgloss.NewRenderer(io.Discard))
	app.firstRun = true
	updated, _ := app.Update(tea.WindowSizeMsg{Width: 80, Height: 24})
	app = updated.(appModel)
	if !strings.Contains(app.View(), "Welcome to AgentSSH") {
		t.Fatalf("first run should show the welcome banner:\n%s", app.View())
	}
	updated, _ = app.Update(keyMsg("j"))
	app = updated.(appModel)
	if app.firstRun || strings.Contains(app.View(), "Welcome to AgentSSH") {
		t.Fatal("any key should dismiss the welcome banner")
	}
}

func TestEmptyStatesTeachNextAction(t *testing.T) {
	st := testAppStyles()
	hosts := newHostsSection(testPaths(t), lipgloss.NewRenderer(io.Discard), st, inventory.Inventory{}, nil)
	if v := hosts.View(); !strings.Contains(v, "No hosts yet") || !strings.Contains(v, "[a]") || !strings.Contains(v, "[d]") {
		t.Fatalf("empty Hosts should teach a/d:\n%s", v)
	}
	sessions := newSessionsSection(nil, st, nil)
	if v := sessions.View(); !strings.Contains(v, "No sessions recorded") || !strings.Contains(v, "agentssh run") {
		t.Fatalf("empty Sessions should teach the run command:\n%s", v)
	}
}

func TestProbeShowsSpinnerUntilResult(t *testing.T) {
	section := newHostsSection(testPaths(t), lipgloss.NewRenderer(io.Discard), testAppStyles(), inventory.Inventory{
		Hosts: map[string]inventory.Host{"web-1": {Addr: "127.0.0.1", Port: 1}},
	}, nil)

	updated, cmd := section.Update(keyMsg("t"))
	hs := updated.(hostsSection)
	if !hs.testing || !hs.busy() || cmd == nil {
		t.Fatalf("probe should mark testing/busy and emit a cmd: testing=%t busy=%t cmdNil=%t", hs.testing, hs.busy(), cmd == nil)
	}

	// A tick while busy advances the spinner and reschedules the next frame.
	updated, tickCmd := hs.Update(spinner.TickMsg{})
	hs = updated.(hostsSection)
	if tickCmd == nil {
		t.Fatal("a tick while busy should reschedule the spinner")
	}

	// The probe result clears the busy flag.
	updated, _ = hs.Update(hostProbeMsg{name: "web-1", ok: true})
	hs = updated.(hostsSection)
	if hs.testing || hs.busy() {
		t.Fatalf("result should clear testing/busy: testing=%t busy=%t", hs.testing, hs.busy())
	}

	// A tick after the result is dropped, so the spinner chain stops.
	if _, after := hs.Update(spinner.TickMsg{}); after != nil {
		t.Fatal("a tick after the result must not reschedule")
	}
}

func TestSpinnerTickRoutedToHostsWhileAnotherTabActive(t *testing.T) {
	app := newAppModel(testPaths(t), lipgloss.NewRenderer(io.Discard))
	// Put the Hosts section into an in-flight probe, then switch away.
	hs := app.sections[sectionHosts].(hostsSection)
	hs.testing = true
	app.sections[sectionHosts] = hs
	app.active = sectionAudit

	_, cmd := app.Update(spinner.TickMsg{})
	if cmd == nil {
		t.Fatal("spinner tick must route to the Hosts section and reschedule even when another tab is active")
	}
}

func TestProbeReentryDoesNotRestartSpinner(t *testing.T) {
	section := newHostsSection(testPaths(t), lipgloss.NewRenderer(io.Discard), testAppStyles(), inventory.Inventory{
		Hosts: map[string]inventory.Host{"web-1": {Addr: "127.0.0.1", Port: 1}},
	}, nil)
	updated, cmd := section.Update(keyMsg("t"))
	hs := updated.(hostsSection)
	if !hs.testing || cmd == nil {
		t.Fatalf("first probe should start: testing=%t cmdNil=%t", hs.testing, cmd == nil)
	}
	// A second 't' while the probe is in flight must be ignored (no fresh tick).
	if _, cmd2 := hs.Update(keyMsg("t")); cmd2 != nil {
		t.Fatal("re-pressing t while a probe is in flight must not emit a second spinner tick")
	}
}

func TestFirstRunSwallowsQuitKeyButCtrlCStillQuits(t *testing.T) {
	app := newAppModel(testPaths(t), lipgloss.NewRenderer(io.Discard))
	app.firstRun = true
	updated, cmd := app.Update(keyMsg("q"))
	app = updated.(appModel)
	if cmd != nil {
		t.Fatal("q on the first-run banner should be swallowed, not quit the app")
	}
	if app.firstRun {
		t.Fatal("the dismiss keystroke should clear firstRun")
	}

	fresh := newAppModel(testPaths(t), lipgloss.NewRenderer(io.Discard))
	fresh.firstRun = true
	_, quit := fresh.Update(tea.KeyMsg{Type: tea.KeyCtrlC})
	if quit == nil {
		t.Fatal("ctrl+c must still quit even on the first-run banner")
	}
	if _, ok := quit().(tea.QuitMsg); !ok {
		t.Fatalf("ctrl+c should produce tea.QuitMsg, got %T", quit())
	}
}

func TestHostsMasterDetailShowsCardWhenWide(t *testing.T) {
	s := newHostsSection(testPaths(t), lipgloss.NewRenderer(io.Discard), testAppStyles(), inventory.Inventory{
		Hosts: map[string]inventory.Host{"web-1": {Addr: "10.0.0.11", User: "deploy", IdentityFile: "~/.ssh/web-1", Tags: []string{"prod"}}},
	}, nil)
	s.w, s.h = 100, 20
	v := s.View()
	for _, want := range []string{"10.0.0.11", "deploy", "[key]", "[PROD]", "~/.ssh/web-1"} {
		if !strings.Contains(v, want) {
			t.Fatalf("wide Hosts view should show %q in the detail card:\n%s", want, v)
		}
	}
	s.w = 50
	if s.detailVisible() {
		t.Fatal("the detail panel must hide on a narrow terminal")
	}
}

func TestHostsEnterFocusesDetailWhenWide(t *testing.T) {
	s := newHostsSection(testPaths(t), lipgloss.NewRenderer(io.Discard), testAppStyles(), inventory.Inventory{
		Hosts: map[string]inventory.Host{"web-1": {Addr: "10.0.0.11"}, "db-2": {Addr: "10.0.0.31"}},
	}, nil)
	s.w, s.h = 100, 20

	updated, _ := s.Update(keyMsg("enter"))
	hs := updated.(hostsSection)
	if hs.focus != hostFocusDetail {
		t.Fatal("enter should focus the detail panel when it is visible")
	}
	cur := hs.cursor
	updated, _ = hs.Update(keyMsg("j"))
	hs = updated.(hostsSection)
	if hs.cursor == cur {
		t.Fatal("j while detail-focused should still browse host selection")
	}
	updated, _ = hs.Update(keyMsg("esc"))
	if updated.(hostsSection).focus != hostFocusList {
		t.Fatal("esc should return focus to the list")
	}

	s.w = 50 // narrow: enter must not focus a hidden panel
	updated, _ = s.Update(keyMsg("enter"))
	if updated.(hostsSection).focus == hostFocusDetail {
		t.Fatal("enter must not focus the detail panel when it is hidden")
	}
}

func TestDeleteConfirmSurvivesCursorKeys(t *testing.T) {
	s := newHostsSection(testPaths(t), lipgloss.NewRenderer(io.Discard), testAppStyles(), inventory.Inventory{
		Hosts: map[string]inventory.Host{"web-1": {Addr: "10.0.0.11"}, "db-2": {Addr: "10.0.0.31"}},
	}, nil)

	updated, _ := s.Update(keyMsg("r"))
	hs := updated.(hostsSection)
	if hs.focus != hostFocusConfirm {
		t.Fatalf("'r' should enter the confirm focus, got %v", hs.focus)
	}
	cur := hs.cursor

	// The footgun fix: a cursor key during confirm must neither move the cursor
	// nor silently cancel the pending delete.
	updated, _ = hs.Update(keyMsg("j"))
	hs = updated.(hostsSection)
	if hs.focus != hostFocusConfirm {
		t.Fatal("a cursor key must not cancel a pending delete confirm")
	}
	if hs.cursor != cur {
		t.Fatal("the cursor must not move while a confirm is pending")
	}

	updated, _ = hs.Update(keyMsg("n"))
	if updated.(hostsSection).focus != hostFocusList {
		t.Fatal("'n' should cancel the confirm and return to the list")
	}
}

func TestVerifyMsgRoutedToAuditWhileAnotherTabActive(t *testing.T) {
	app := newAppModel(config.Paths{}, lipgloss.NewRenderer(io.Discard))
	app.active = sectionHosts // launch lands here; auto-verify targets Audit

	updated, _ := app.Update(verifyMsg{result: audit.VerifyResult{OK: true, Count: 3}})
	next := updated.(appModel)
	if next.active != sectionHosts {
		t.Fatalf("routing a verifyMsg must not change the active tab, got %d", next.active)
	}
	auditModel, ok := next.sections[sectionAudit].(model)
	if !ok || !auditModel.verifyDone || !auditModel.verifyResult.OK {
		t.Fatalf("verifyMsg did not reach the inactive Audit section: %T done=%t", next.sections[sectionAudit], ok && auditModel.verifyDone)
	}
}

func TestHostProbeMsgRoutedToHostsWhileAnotherTabActive(t *testing.T) {
	app := newAppModel(testPaths(t), lipgloss.NewRenderer(io.Discard))
	app.active = sectionAudit // operator switched away while a probe was in flight

	updated, _ := app.Update(hostProbeMsg{name: "web-1", ok: true})
	next := updated.(appModel)
	if next.active != sectionAudit {
		t.Fatalf("routing a hostProbeMsg must not change the active tab, got %d", next.active)
	}
	hosts, ok := next.sections[sectionHosts].(hostsSection)
	if !ok || !strings.Contains(hosts.status, "OK web-1") {
		t.Fatalf("hostProbeMsg did not reach the inactive Hosts section: %T status=%q", next.sections[sectionHosts], hosts.status)
	}
}

func keyMsg(value string) tea.KeyMsg {
	switch value {
	case "tab":
		return tea.KeyMsg{Type: tea.KeyTab}
	case "shift+tab":
		return tea.KeyMsg{Type: tea.KeyShiftTab}
	case "enter":
		return tea.KeyMsg{Type: tea.KeyEnter}
	default:
		return tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(value)}
	}
}

func testPaths(t *testing.T) config.Paths {
	t.Helper()
	home := t.TempDir()
	return config.Paths{
		Home:          home,
		InventoryFile: filepath.Join(home, "inventory.yaml"),
		PolicyFile:    filepath.Join(home, "policy.yaml"),
		AuditFile:     filepath.Join(home, "audit.log"),
		SessionFile:   filepath.Join(home, "session"),
		SecretsFile:   filepath.Join(home, "secrets.enc"),
	}
}

func TestMergeProbedCandidatesMatchesByIdentityNotPosition(t *testing.T) {
	current := []discovery.Candidate{
		{Source: discovery.SourceSSHConfig, Name: "a"},
		{Source: discovery.SourceSSHConfig, Name: "b"},
	}
	// Only b was probed; a must stay untouched even though b is at index 1.
	probed := []discovery.Candidate{
		{Source: discovery.SourceSSHConfig, Name: "b", ProbeStatus: executor.ProbeConnectable},
	}
	merged := mergeProbedCandidates(current, probed)
	if merged[0].ProbeStatus != "" {
		t.Fatalf("row a should be untouched, got %#v", merged[0])
	}
	if merged[1].ProbeStatus != executor.ProbeConnectable {
		t.Fatalf("row b should carry its own probe result, got %#v", merged[1])
	}
}

func TestDiscoveryProbedMsgIgnoredWhenStaleOrInactive(t *testing.T) {
	st := testAppStyles()
	s := newHostsSection(config.Paths{}, lipgloss.NewRenderer(io.Discard), st, inventory.Inventory{}, nil)
	s.discover = discoveryOverlay{
		active:     true,
		runID:      2,
		candidates: []discovery.Candidate{{Name: "a", Source: discovery.SourceSSHConfig}},
	}
	probed := discoveryProbedMsg{runID: 1, candidates: []discovery.Candidate{{Name: "a", Source: discovery.SourceSSHConfig, ProbeStatus: executor.ProbeConnectable}}}
	updated, _ := s.Update(probed)
	if hs := updated.(hostsSection); hs.discover.candidates[0].ProbeStatus != "" {
		t.Fatalf("stale-runID probe result must be ignored, got %#v", hs.discover.candidates[0])
	}

	s.discover.active = false
	s.discover.runID = 2
	updated2, _ := s.Update(discoveryProbedMsg{runID: 2, candidates: []discovery.Candidate{{Name: "a", Source: discovery.SourceSSHConfig, ProbeStatus: executor.ProbeConnectable}}})
	if hs := updated2.(hostsSection); hs.discover.candidates[0].ProbeStatus != "" {
		t.Fatalf("probe result for inactive overlay must be ignored")
	}
}

func TestImportDiscoverySelectedSkipsAliasOnlyDuplicate(t *testing.T) {
	home := t.TempDir()
	paths := config.NewPaths(home)
	// An existing alias-only host under a different name, aliasing "web-1".
	base := inventory.Inventory{Version: 1, Hosts: map[string]inventory.Host{
		"existing": {SSHConfigAlias: "web-1"},
	}}
	if err := inventory.Save(paths.InventoryFile, base); err != nil {
		t.Fatalf("save inventory: %v", err)
	}
	s := newHostsSection(paths, lipgloss.NewRenderer(io.Discard), testAppStyles(), base, nil)
	s.discover = discoveryOverlay{
		active: true,
		candidates: []discovery.Candidate{
			{Name: "web-1", Source: discovery.SourceSSHConfig, Addr: "10.0.0.11", Port: 22, ProbeStatus: executor.ProbeConnectable},
		},
		selected: map[int]bool{0: true},
	}
	changed, err := s.importDiscoverySelected()
	if err != nil {
		t.Fatalf("import err: %v", err)
	}
	if changed {
		t.Fatal("a candidate already present as an alias-only host must not be imported")
	}
}
