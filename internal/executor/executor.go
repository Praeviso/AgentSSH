package executor

import "time"

// Request describes a single remote command execution.
type Request struct {
	Host    string
	Command []string
}

// Result captures the outcome of a remote command execution.
type Result struct {
	Stdout     string
	Stderr     string
	ExitCode   int
	Duration   time.Duration
	ConnectErr error
}

// Executor runs commands against remote hosts.
type Executor interface {
	Run(request Request) Result
}
