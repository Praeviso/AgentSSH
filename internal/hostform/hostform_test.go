package hostform

import (
	"io"
	"strings"
	"testing"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

func TestCtrlCQuitsAndEscCancels(t *testing.T) {
	m := New(Options{}, lipgloss.NewRenderer(io.Discard))
	_, cmd := m.Update(tea.KeyMsg{Type: tea.KeyCtrlC})
	if cmd == nil {
		t.Fatal("ctrl+c should return a command")
	}
	if _, ok := cmd().(tea.QuitMsg); !ok {
		t.Fatalf("ctrl+c should produce tea.QuitMsg (quit the program), got %T", cmd())
	}

	// Esc still cancels the form (done, not submitted) without quitting.
	updated, _ := New(Options{}, lipgloss.NewRenderer(io.Discard)).Update(tea.KeyMsg{Type: tea.KeyEsc})
	fm, ok := updated.(Model)
	if !ok || !fm.Done() || fm.Result().Submitted {
		t.Fatalf("esc should cancel: done=%t submitted=%t", ok && fm.Done(), ok && fm.Result().Submitted)
	}
}

func TestFormGroupedAndWarnsOnPasswordWithoutMaster(t *testing.T) {
	t.Setenv("AGENTSSH_MASTER_PASSWORD", "") // ensure unset
	m := New(Options{}, lipgloss.NewRenderer(io.Discard))
	for _, g := range []string{"Connection", "Routing", "Auth"} {
		if !strings.Contains(m.View(), g) {
			t.Fatalf("grouped form should contain the %q section:\n%s", g, m.View())
		}
	}
	if strings.Contains(m.View(), "won't be saved") {
		t.Fatal("no warning expected before a password is entered")
	}
	m.inputs[fieldPassword].SetValue("ssh-secret")
	if !strings.Contains(m.View(), "AGENTSSH_MASTER_PASSWORD not set") {
		t.Fatalf("form should warn when a password is set without the master:\n%s", m.View())
	}
	// The password value must never appear in the rendered form (masked).
	if strings.Contains(m.View(), "ssh-secret") {
		t.Fatal("password value leaked into the rendered form")
	}
	if strings.Contains(m.View(), "linux/macos/windows/bsd") || strings.Contains(m.View(), "\nos\n") {
		t.Fatalf("OS should be detected after connecting, not manually entered:\n%s", m.View())
	}
}

func TestValidateNormalizesHostFields(t *testing.T) {
	t.Setenv("USER", "alice")
	result, errs := Validate(Options{
		Name: " web-1 ",
		Addr: " 10.0.0.11 ",
		Tags: []string{"web", "prod"},
	})
	if len(errs) != 0 {
		t.Fatalf("errs = %#v", errs)
	}
	if result.Name != "web-1" || result.Addr != "10.0.0.11" || result.User != "alice" || result.Port != 22 {
		t.Fatalf("result = %#v", result)
	}
	if got := result.Tags; len(got) != 2 || got[0] != "web" || got[1] != "prod" {
		t.Fatalf("tags = %#v", got)
	}
}

func TestValidateAllowsAliasWithoutAddr(t *testing.T) {
	result, errs := Validate(Options{Name: "web-1", Alias: "prod-web"})
	if len(errs) != 0 {
		t.Fatalf("errs = %#v", errs)
	}
	if result.Alias != "prod-web" || result.Addr != "" {
		t.Fatalf("result = %#v", result)
	}
}

func TestValidateIdentityFileRoundTrip(t *testing.T) {
	result, errs := Validate(Options{Name: "web-1", Addr: "10.0.0.11", IdentityFile: " ~/.ssh/web-1 "})
	if len(errs) != 0 {
		t.Fatalf("errs = %#v", errs)
	}
	if result.Identity != "~/.ssh/web-1" {
		t.Fatalf("identity = %q", result.Identity)
	}
}

func TestPasswordFieldMaskedAndNotRendered(t *testing.T) {
	model := New(Options{Name: "web-1", Addr: "10.0.0.11"}, lipgloss.NewRenderer(io.Discard))
	model.inputs[fieldPassword].SetValue("super-secret")
	if model.inputs[fieldPassword].EchoMode != textinput.EchoPassword {
		t.Fatalf("password echo mode = %v, want EchoPassword", model.inputs[fieldPassword].EchoMode)
	}
	view := model.View()
	if strings.Contains(view, "super-secret") {
		t.Fatalf("password leaked into view: %q", view)
	}
}

func TestValidateRejectsInvalidFields(t *testing.T) {
	existing := map[string]struct{}{"web-1": {}}
	tests := []struct {
		name string
		opts Options
		key  string
	}{
		{name: "missing name", opts: Options{Addr: "10.0.0.11"}, key: "name"},
		{name: "whitespace name", opts: Options{Name: "web 1", Addr: "10.0.0.11"}, key: "name"},
		{name: "duplicate", opts: Options{Name: "web-1", Addr: "10.0.0.11", ExistingNames: existing}, key: "name"},
		{name: "missing addr and alias", opts: Options{Name: "web-2"}, key: "addr"},
		{name: "bad port", opts: Options{Name: "web-2", Addr: "10.0.0.12", Port: 70000}, key: "port"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, errs := Validate(tt.opts)
			if errs[tt.key] == "" {
				t.Fatalf("errs[%q] = %#v", tt.key, errs)
			}
		})
	}
}

func TestSplitTags(t *testing.T) {
	got := SplitTags(" web,prod,, db ")
	want := []string{"web", "prod", "db"}
	if len(got) != len(want) {
		t.Fatalf("tags = %#v, want %#v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("tags = %#v, want %#v", got, want)
		}
	}
}
