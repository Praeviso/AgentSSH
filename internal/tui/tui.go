package tui

import (
	"errors"
	"os"

	"github.com/Praeviso/AgentSSH/internal/config"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/muesli/termenv"
	xterm "golang.org/x/term"
)

// HostMeta is the credential-free host information the viewer uses to enrich a
// record (host address/user and a prod marker) in the detail panel.
type HostMeta struct {
	User string
	Addr string
	Tags []string
}

// Options configures the terminal console.
type Options struct {
	// Paths contains the AgentSSH home layout used by the console sections.
	Paths config.Paths
}

// Runner starts the terminal console.
type Runner interface {
	Run(options Options) error
}

// NewRunner returns the default terminal console.
func NewRunner() Runner { return runner{} }

type runner struct{}

func (runner) Run(options Options) error { return run(options) }

// ErrNotInteractive is returned when stdin or stdout is not a terminal. The
// caller should fall back to the plain audit/session commands.
var ErrNotInteractive = errors.New("tui: stdin/stdout is not a terminal")

// IsNotInteractive reports whether err signals a non-interactive environment.
func IsNotInteractive(err error) bool { return errors.Is(err, ErrNotInteractive) }

func run(options Options) error {
	// Refuse to start outside a real terminal so the tool stays pipeable; the
	// caller falls back to the line-oriented audit/session commands.
	if !interactive() {
		return ErrNotInteractive
	}

	renderer := lipgloss.NewRenderer(os.Stdout)
	if _, ok := os.LookupEnv("NO_COLOR"); ok {
		renderer.SetColorProfile(termenv.Ascii)
	}

	m := newAppModel(options.Paths, renderer)
	_, err := tea.NewProgram(m, tea.WithAltScreen()).Run()
	return err
}

func interactive() bool {
	return xterm.IsTerminal(int(os.Stdin.Fd())) && xterm.IsTerminal(int(os.Stdout.Fd()))
}
