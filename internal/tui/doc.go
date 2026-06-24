// Package tui implements the terminal console, including a read-only Audit UI
// that lists sessions, opens each session into command results, and verifies the
// hash chain. It refuses to start on a non-TTY (see ErrNotInteractive) so the
// caller can fall back to the plain audit/session commands.
package tui
