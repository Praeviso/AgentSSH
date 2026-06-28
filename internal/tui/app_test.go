package tui

import (
	"strings"
	"testing"

	"github.com/Praeviso/AgentSSH/internal/inventory"
)

func TestGridIsEntryScreen(t *testing.T) {
	m := sized(t, buildApp(t), 100, 30)
	if m.screen != screenGrid {
		t.Fatalf("entry screen = %v, want grid", m.screen)
	}
	v := m.View()
	for _, want := range []string{"AgentSSH", "prod-web-01", "db-replica", "LNX", "BSD", "MAC", "WIN", "SRV"} {
		if !strings.Contains(v, want) {
			t.Fatalf("grid view missing %q\n%s", want, v)
		}
	}
}

func TestEnterOpensDetailOnSelectedHost(t *testing.T) {
	m := sized(t, buildApp(t), 100, 30)
	// Hosts sort alphabetically; the cursor starts on the first ("bare").
	m = press(t, m, "enter")
	if m.screen != screenDetail {
		t.Fatalf("screen = %v, want detail", m.screen)
	}
	if m.pane != paneInfo {
		t.Fatalf("pane = %v, want info", m.pane)
	}
	if m.detailHost != "bare" {
		t.Fatalf("detailHost = %q, want bare", m.detailHost)
	}
	if !strings.Contains(m.View(), "bare") {
		t.Fatalf("detail view missing host name\n%s", m.View())
	}
}

func TestDetailPaneSwitching(t *testing.T) {
	m := sized(t, buildApp(t), 100, 30)
	m = press(t, m, "enter")
	m = press(t, m, "2")
	if m.pane != paneSessions {
		t.Fatalf("after '2' pane = %v, want sessions", m.pane)
	}
	m = press(t, m, "3")
	if m.pane != panePolicy {
		t.Fatalf("after '3' pane = %v, want policy", m.pane)
	}
	m = press(t, m, "tab") // policy -> info (wraps)
	if m.pane != paneInfo {
		t.Fatalf("after tab from policy pane = %v, want info", m.pane)
	}
	m = press(t, m, "1")
	if m.pane != paneInfo {
		t.Fatalf("after '1' pane = %v, want info", m.pane)
	}
}

func TestEscReturnsToGrid(t *testing.T) {
	m := sized(t, buildApp(t), 100, 30)
	m = press(t, m, "enter")
	m = press(t, m, "esc")
	if m.screen != screenGrid {
		t.Fatalf("after esc screen = %v, want grid", m.screen)
	}
}

// A focused text input (policy test box) captures the keyboard: esc blurs it and
// stays in detail; only a second esc at root exits to the grid.
func TestEscPopsPaneBeforeExitingDetail(t *testing.T) {
	m := sized(t, buildApp(t), 100, 30)
	m = press(t, m, "enter")
	m = press(t, m, "3") // policy pane
	m = press(t, m, "t") // focus the test input
	if !m.paneCapturing() {
		t.Fatal("policy test input should be capturing after 't'")
	}
	m = press(t, m, "esc") // blur input, stay in detail
	if m.screen != screenDetail {
		t.Fatalf("first esc exited detail; screen = %v", m.screen)
	}
	if m.paneCapturing() {
		t.Fatal("policy input still capturing after esc")
	}
	m = press(t, m, "esc") // now exit to grid
	if m.screen != screenGrid {
		t.Fatalf("second esc screen = %v, want grid", m.screen)
	}
}

// While the policy test input is focused, tab must not switch panes — the input
// owns the keyboard.
func TestCapturingPaneKeepsTabKey(t *testing.T) {
	m := sized(t, buildApp(t), 100, 30)
	m = press(t, m, "enter")
	m = press(t, m, "3")
	m = press(t, m, "t")
	m = press(t, m, "tab")
	if m.pane != panePolicy {
		t.Fatalf("tab switched pane while input focused; pane = %v", m.pane)
	}
}

// The core smoothness invariant: at every usable size, on every screen, no
// rendered line exceeds the frame width and the body never exceeds the height.
func TestResizeNeverOverflows(t *testing.T) {
	widths := []int{40, 50, 60, 72, 84, 100, 120, 160}
	heights := []int{11, 12, 16, 24, 40}
	// Visit each screen/pane.
	type variant struct {
		name string
		keys []string
	}
	variants := []variant{
		{"grid", nil},
		{"info", []string{"enter"}},
		{"sessions", []string{"enter", "2"}},
		{"policy", []string{"enter", "3"}},
	}
	for _, w := range widths {
		for _, h := range heights {
			for _, vr := range variants {
				m := sized(t, buildApp(t), w, h)
				for _, k := range vr.keys {
					m = press(t, m, k)
				}
				m = sized(t, m, w, h) // re-send size after navigating
				v := m.View()
				max, lines := maxLineWidth(v)
				if max > w {
					t.Fatalf("%s %dx%d: line width %d > %d\n%s", vr.name, w, h, max, w, v)
				}
				if lines > h {
					t.Fatalf("%s %dx%d: %d lines > %d", vr.name, w, h, lines, h)
				}
			}
		}
	}
}

func TestTooSmallFallback(t *testing.T) {
	for _, sz := range [][2]int{{20, 6}, {39, 10}, {40, 10}, {30, 11}} {
		m := sized(t, buildApp(t), sz[0], sz[1])
		v := m.View()
		if !strings.Contains(v, "too small") {
			t.Fatalf("%dx%d should show too-small card\n%s", sz[0], sz[1], v)
		}
		max, lines := maxLineWidth(v)
		if max > sz[0] || lines > sz[1] {
			t.Fatalf("%dx%d too-small overflow: %dx%d", sz[0], sz[1], max, lines)
		}
	}
}

func TestWelcomeBannerFitsAndDismisses(t *testing.T) {
	m := buildApp(t)
	m.firstRun = true
	m = sized(t, m, 60, 16)
	v := m.View()
	if !strings.Contains(v, "Welcome to AgentSSH") {
		t.Fatalf("welcome banner missing\n%s", v)
	}
	if max, lines := maxLineWidth(v); max > 60 || lines > 16 {
		t.Fatalf("welcome overflow: %dx%d", max, lines)
	}
	// A neutral key dismisses the banner and lands on the grid.
	m = press(t, m, "g")
	if m.firstRun {
		t.Fatal("first key should dismiss the welcome banner")
	}
	if strings.Contains(m.View(), "Welcome to AgentSSH") {
		t.Fatal("welcome banner still shown after a keypress")
	}
	if m.hosts.focus != hostFocusList {
		t.Fatalf("neutral first key left grid in focus %v, want list", m.hosts.focus)
	}
}

// The first keystroke isn't wasted: it dismisses the banner and also performs its
// action (here, 'a' opens the add form) — except 'q', which only dismisses so a
// curious keypress can't quit on the greeting.
func TestWelcomeBannerReDispatchesFirstKey(t *testing.T) {
	m := sized(t, func() appModel { mm := buildApp(t); mm.firstRun = true; return mm }(), 80, 24)
	m = press(t, m, "a")
	if m.firstRun {
		t.Fatal("'a' should dismiss the banner")
	}
	if m.hosts.focus != hostFocusForm {
		t.Fatalf("'a' on first run did not open the add form: focus=%v", m.hosts.focus)
	}
}

func TestWelcomeBannerQuitKeyOnlyDismisses(t *testing.T) {
	m := sized(t, func() appModel { mm := buildApp(t); mm.firstRun = true; return mm }(), 80, 24)
	m = press(t, m, "q")
	if m.firstRun {
		t.Fatal("'q' should still dismiss the banner")
	}
	// q must not have quit to a confirm/form; the grid is shown with hosts.
	if m.hosts.focus != hostFocusList || !strings.Contains(m.View(), "bare") {
		t.Fatalf("'q' on first run did not land cleanly on the grid:\n%s", m.View())
	}
}

func TestEmptyInventoryShowsAddHint(t *testing.T) {
	m := sized(t, buildAppWith(t, "version: 1\n", samplePolicy), 80, 24)
	v := m.View()
	if !strings.Contains(v, "No hosts yet") {
		t.Fatalf("empty grid missing hint\n%s", v)
	}
}

// Removing the open host while in its detail screen falls back to the grid.
func TestRemovedHostFallsBackToGrid(t *testing.T) {
	m := sized(t, buildApp(t), 100, 30)
	m = press(t, m, "enter") // open "bare"
	if m.screen != screenDetail {
		t.Fatal("expected detail screen")
	}
	withoutBare := inventory.Inventory{Version: 1, Hosts: map[string]inventory.Host{
		"prod-web-01": {Addr: "10.0.0.11"},
	}}
	next, _ := m.Update(inventoryChangedMsg{inventory: withoutBare})
	m = next.(appModel)
	if m.screen != screenGrid {
		t.Fatalf("after removing open host, screen = %v, want grid", m.screen)
	}
}
