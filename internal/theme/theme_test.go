package theme

import (
	"io"
	"strings"
	"testing"

	"github.com/charmbracelet/lipgloss"
	"github.com/muesli/termenv"
)

func TestGlyphsForDegradesToASCIIUnderNoColor(t *testing.T) {
	r := lipgloss.NewRenderer(io.Discard)
	r.SetColorProfile(termenv.Ascii) // what tui.run() does when NO_COLOR is set
	g := GlyphsFor(r)

	// Every glyph must be pure ASCII under the Ascii profile — otherwise the
	// "glyph survives NO_COLOR" guarantee is a lie (color is stripped, not glyphs).
	for name, s := range map[string]string{
		"OK": g.OK, "Maybe": g.Maybe, "Absent": g.Absent, "Warn": g.Warn,
		"Fail": g.Fail, "Deny": g.Deny, "Check": g.Check, "Cross": g.Cross,
		"Marker": g.Marker,
	} {
		for _, r := range s {
			if r > 0x7F {
				t.Errorf("glyph %q = %q contains non-ASCII rune %q under NO_COLOR", name, s, r)
			}
		}
	}
}

func TestGlyphsForUsesUnicodeWithColor(t *testing.T) {
	r := lipgloss.NewRenderer(io.Discard)
	r.SetColorProfile(termenv.TrueColor)
	if g := GlyphsFor(r); g.OK != "●" || g.Deny != "⊘" {
		t.Fatalf("color profile should use Unicode glyphs, got OK=%q Deny=%q", g.OK, g.Deny)
	}
	if g := GlyphsFor(nil); g.Marker != "▌" {
		t.Fatalf("nil renderer should default to Unicode, got Marker=%q", g.Marker)
	}
}

func TestColorTokensRenderEscapeFreeUnderAscii(t *testing.T) {
	r := lipgloss.NewRenderer(io.Discard)
	r.SetColorProfile(termenv.Ascii)
	for name, c := range map[string]lipgloss.TerminalColor{
		"Accent": Accent, "Danger": Danger, "Deny": Deny, "Prod": Prod, "Success": Success,
	} {
		if out := r.NewStyle().Foreground(c).Render("x"); strings.Contains(out, "\x1b") {
			t.Errorf("token %q emitted ANSI under Ascii: %q", name, out)
		}
	}
}
