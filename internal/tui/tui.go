package tui

// Options configures the future audit viewer.
type Options struct {
	ConfigHome string
}

// Runner starts the terminal audit viewer.
type Runner interface {
	Run(options Options) error
}
