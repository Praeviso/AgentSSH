// Package theme is the single source of design tokens for the AgentSSH TUI —
// colors and status glyphs — shared by the console (internal/tui) and the
// add-host form (internal/hostform) so the two never drift. Colors are
// AdaptiveColor so light terminals stay legible; glyphs degrade to ASCII when
// the renderer has no color (NO_COLOR), because termenv.Ascii strips color but
// NOT Unicode glyphs — so the glyph must be degraded in code, not relied upon.
package theme

import (
	"github.com/charmbracelet/lipgloss"
	"github.com/muesli/termenv"
)

// Color tokens. 256-color values, light/dark adaptive. Exactly one red for
// failure (Danger); Deny and Prod get distinct hues so a routine policy deny or
// a prod marker never reads as a crash.
var (
	Accent     = lipgloss.AdaptiveColor{Light: "61", Dark: "63"}   // focus, titles, active tab bg
	AccentText = lipgloss.AdaptiveColor{Light: "231", Dark: "15"}  // text on accent bg
	Border     = lipgloss.AdaptiveColor{Light: "250", Dark: "240"} // unfocused borders
	Dim        = lipgloss.AdaptiveColor{Light: "245", Dark: "241"} // help, placeholders, secondary
	Cursor     = lipgloss.AdaptiveColor{Light: "168", Dark: "212"} // selection accent (pink)
	Success    = lipgloss.AdaptiveColor{Light: "28", Dark: "42"}   // ok / allow / reachable / chain intact
	Warn       = lipgloss.AdaptiveColor{Light: "130", Dark: "220"} // caution / confirm / needs-auth
	Danger     = lipgloss.AdaptiveColor{Light: "160", Dark: "196"} // the ONE red: errors, failed, tamper
	Deny       = lipgloss.AdaptiveColor{Light: "166", Dark: "208"} // policy DENY — distinct orange
	Prod       = lipgloss.AdaptiveColor{Light: "124", Dark: "203"} // prod host marker
	SelBg      = lipgloss.AdaptiveColor{Light: "254", Dark: "237"} // current-row band
)

// Glyphs is a resolved status-glyph set. The same vocabulary is used in every
// STATUS column, boolean cell, audit icon, selection marker, and chain badge.
type Glyphs struct {
	OK     string // ● ok / present / started
	Maybe  string // ○ looks-connectable
	Absent string // · absent / neutral
	Warn   string // ▲ caution
	Fail   string // ✖ failure / unreachable
	Deny   string // ⊘ policy deny
	Check  string // ✓ audit completed / chain intact
	Cross  string // ✗ audit failed
	Marker string // ▌ selection bar
}

var unicodeGlyphs = Glyphs{
	OK:     "●",
	Maybe:  "○",
	Absent: "·",
	Warn:   "▲",
	Fail:   "✖",
	Deny:   "⊘",
	Check:  "✓",
	Cross:  "✗",
	Marker: "▌",
}

// asciiGlyphs are single-character fallbacks (alignment-preserving) for terminals
// with no color, where Unicode glyphs may also be unsupported.
var asciiGlyphs = Glyphs{
	OK:     "*",
	Maybe:  "o",
	Absent: ".",
	Warn:   "!",
	Fail:   "x",
	Deny:   "D",
	Check:  "+",
	Cross:  "x",
	Marker: ">",
}

// GlyphsFor returns the glyph set appropriate for the renderer: ASCII fallbacks
// when the renderer has no color profile (the NO_COLOR / dumb-terminal case),
// Unicode otherwise. A nil renderer yields the Unicode set.
func GlyphsFor(r *lipgloss.Renderer) Glyphs {
	if r != nil && r.ColorProfile() == termenv.Ascii {
		return asciiGlyphs
	}
	return unicodeGlyphs
}
