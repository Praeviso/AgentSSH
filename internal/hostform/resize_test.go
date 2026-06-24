package hostform

import (
	"io"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

func maxLineWidth(s string) int {
	max := 0
	for _, ln := range strings.Split(strings.TrimRight(s, "\n"), "\n") {
		if w := lipgloss.Width(ln); w > max {
			max = w
		}
	}
	return max
}

// TestFormFitsWidth guards the responsive field layout: after a resize, no
// rendered line may exceed the frame (which would force a wrap), at narrow and
// wide widths alike.
func TestFormFitsWidth(t *testing.T) {
	m := New(Options{}, lipgloss.NewRenderer(io.Discard))
	for _, w := range []int{40, 50, 60, 80, 120, 160} {
		updated, _ := m.Update(tea.WindowSizeMsg{Width: w, Height: 40})
		fm := updated.(Model)
		if max := maxLineWidth(fm.View()); max > w {
			t.Errorf("form at w=%d overflows: widest line %d > %d\n%s", w, max, w, fm.View())
		}
	}
}

// TestFormSpreadsOnWideFrame guards the grow-to-fill path: a wide frame must use
// more columns than a narrow one instead of hugging the left edge.
func TestFormSpreadsOnWideFrame(t *testing.T) {
	m := New(Options{}, lipgloss.NewRenderer(io.Discard))
	narrow, _ := m.Update(tea.WindowSizeMsg{Width: 60, Height: 40})
	wide, _ := m.Update(tea.WindowSizeMsg{Width: 160, Height: 40})
	if n, w := maxLineWidth(narrow.(Model).View()), maxLineWidth(wide.(Model).View()); w <= n {
		t.Errorf("form should spread on a wide frame: w60=%d w160=%d", n, w)
	}
}

// TestFormHeightWindow guards the height contract: on a short terminal the form
// scrolls to a window of the available rows rather than overflowing, and keeps the
// focused field on screen.
func TestFormHeightWindow(t *testing.T) {
	m := New(Options{}, lipgloss.NewRenderer(io.Discard))
	updated, _ := m.Update(tea.WindowSizeMsg{Width: 80, Height: 8})
	fm := updated.(Model)
	v := fm.View()
	if lines := strings.Count(v, "\n") + 1; lines > 8 {
		t.Errorf("form renders %d lines, exceeds height 8:\n%s", lines, v)
	}

	// Move focus to the last field; it must remain within the rendered window.
	for i := 0; i < int(fieldPassword); i++ {
		next, _ := fm.Update(tea.KeyMsg{Type: tea.KeyTab})
		fm = next.(Model)
	}
	if !strings.Contains(fm.View(), fieldLabels[fieldPassword]) {
		t.Errorf("the focused field should stay visible in the height window:\n%s", fm.View())
	}
}

// TestFormSizelessRenderKeepsFullLayout guards the unknown-size fallback: a direct
// render with no WindowSizeMsg keeps every group and field (the natural layout),
// so a sizeless caller isn't truncated.
func TestFormSizelessRenderKeepsFullLayout(t *testing.T) {
	v := New(Options{}, lipgloss.NewRenderer(io.Discard)).View()
	for _, want := range []string{"Connection", "Routing", "Auth", "tab/down next"} {
		if !strings.Contains(v, want) {
			t.Errorf("sizeless form should contain %q:\n%s", want, v)
		}
	}
}
