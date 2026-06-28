// Package tui implements the terminal operator console: host management, audit
// browsing, policy inspection/host rules, and session navigation. It refuses
// to start on a non-TTY (see ErrNotInteractive) so the caller can fall back to
// the plain CLI commands.
package tui
