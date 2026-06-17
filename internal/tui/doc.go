// Package tui implements the terminal audit viewer: a read-only Bubble Tea UI
// that lists audit records grouped by session, shows record detail, and
// verifies the hash chain. It refuses to start on a non-TTY (see
// ErrNotInteractive) so the caller can fall back to the plain audit/session
// commands.
package tui
