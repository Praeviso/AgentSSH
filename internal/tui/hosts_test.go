package tui

import (
	"strings"
	"testing"
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
