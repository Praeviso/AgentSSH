package tui

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Praeviso/AgentSSH/internal/config"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// maxLineWidth returns the widest rendered line and the number of physical lines.
func maxLineWidth(s string) (max, lines int) {
	parts := strings.Split(strings.TrimRight(s, "\n"), "\n")
	for _, ln := range parts {
		if w := lipgloss.Width(ln); w > max {
			max = w
		}
	}
	return max, len(parts)
}

const sampleInventory = `version: 1
transport: native
hosts:
  prod-web-01:
    addr: 10.0.0.11
    user: deploy
    os: linux
    tags: [prod, web]
  db-replica:
    addr: 10.0.0.20
    user: postgres
    os: bsd
    tags: [db, backup]
  build-mac:
    addr: 10.0.0.30
    user: ci
    os: macos
    tags: [ci]
  win-box:
    addr: 10.0.0.40
    user: admin
    os: windows
  bare:
    addr: 10.0.0.50
groups:
  web:
    tags: [web]
`

const samplePolicy = `version: 1
defaults:
  policy: allow
rules:
  - name: no-rm
    match:
      cmd_regex: "rm -rf"
    action: deny
host_overrides:
  web:
    policy: deny
    allow_rules:
      - cmd_regex: "^ls"
output:
  max_bytes: 1048576
`

// buildApp constructs an appModel backed by temp inventory/policy files. The
// renderer targets io.Discard-equivalent stdout but keeps a real color profile so
// width math matches production.
func buildApp(t *testing.T) appModel {
	t.Helper()
	return buildAppWith(t, sampleInventory, samplePolicy)
}

func buildAppWith(t *testing.T, inv, pol string) appModel {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "inventory.yaml"), []byte(inv), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "policy.yaml"), []byte(pol), 0o600); err != nil {
		t.Fatal(err)
	}
	paths := config.Paths{
		Home:          dir,
		InventoryFile: filepath.Join(dir, "inventory.yaml"),
		PolicyFile:    filepath.Join(dir, "policy.yaml"),
		AuditFile:     filepath.Join(dir, "audit.log"),
		SessionFile:   filepath.Join(dir, "session"),
		SecretsFile:   filepath.Join(dir, "secrets.enc"),
	}
	return newAppModel(paths, lipgloss.NewRenderer(os.Stdout))
}

// sized returns the app after a window-size message.
func sized(t *testing.T, m appModel, w, h int) appModel {
	t.Helper()
	next, _ := m.Update(tea.WindowSizeMsg{Width: w, Height: h})
	return next.(appModel)
}

// press sends a single key (by its string form) and returns the updated app.
func press(t *testing.T, m appModel, keys string) appModel {
	t.Helper()
	var msg tea.KeyMsg
	switch keys {
	case "enter":
		msg = tea.KeyMsg{Type: tea.KeyEnter}
	case "esc":
		msg = tea.KeyMsg{Type: tea.KeyEsc}
	case "tab":
		msg = tea.KeyMsg{Type: tea.KeyTab}
	case "up":
		msg = tea.KeyMsg{Type: tea.KeyUp}
	case "down":
		msg = tea.KeyMsg{Type: tea.KeyDown}
	case "left":
		msg = tea.KeyMsg{Type: tea.KeyLeft}
	case "right":
		msg = tea.KeyMsg{Type: tea.KeyRight}
	default:
		msg = tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(keys)}
	}
	next, _ := m.Update(msg)
	return next.(appModel)
}
