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
	hosts.adding = true
	if !hosts.capturing() {
		t.Fatal("hosts should capture while form is active")
	}
	hosts.adding = false
	hosts.confirm = true
	if !hosts.capturing() {
		t.Fatal("hosts should capture during a delete confirm (else tab/q abandons it)")
	}
	hosts.confirm = false
	hosts.discover.active = true
	if !hosts.capturing() {
		t.Fatal("hosts should capture while discovery overlay is active")
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
