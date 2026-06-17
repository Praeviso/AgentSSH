package tui

import (
	"io"
	"strings"
	"testing"

	"github.com/Praeviso/AgentSSH/internal/audit"
	"github.com/Praeviso/AgentSSH/internal/config"
	"github.com/Praeviso/AgentSSH/internal/inventory"
	"github.com/Praeviso/AgentSSH/internal/policy"
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
