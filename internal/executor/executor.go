package executor

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/Kritoooo/agentssh/internal/inventory"
)

// Request describes a single remote command execution.
type Request struct {
	Target  inventory.Target
	Command string
}

// Result captures the outcome of a remote command execution.
type Result struct {
	Stdout   string
	Stderr   string
	ExitCode int
	Duration time.Duration
	Err      error
	Argv     []string
}

// Executor runs commands against remote hosts.
type Executor interface {
	Run(ctx context.Context, request Request) Result
}

// Runner executes an argv vector. Tests can inject a runner to avoid real SSH.
type Runner interface {
	Run(ctx context.Context, argv []string) RunResult
}

// RunnerFunc adapts a function into a Runner.
type RunnerFunc func(ctx context.Context, argv []string) RunResult

func (fn RunnerFunc) Run(ctx context.Context, argv []string) RunResult {
	return fn(ctx, argv)
}

// RunResult is the low-level process result from a Runner.
type RunResult struct {
	Stdout   string
	Stderr   string
	ExitCode int
	Err      error
}

// SSHExecutor shells out to the system ssh binary.
type SSHExecutor struct {
	Runner Runner
}

// NewSSHExecutor returns an executor backed by the system ssh binary.
func NewSSHExecutor(runner Runner) SSHExecutor {
	if runner == nil {
		runner = ExecRunner{}
	}
	return SSHExecutor{Runner: runner}
}

func (e SSHExecutor) Run(ctx context.Context, request Request) Result {
	start := time.Now()
	argv := BuildSSHArgv(request.Target, request.Command)
	runResult := e.Runner.Run(ctx, argv)
	return Result{
		Stdout:   runResult.Stdout,
		Stderr:   runResult.Stderr,
		ExitCode: runResult.ExitCode,
		Duration: time.Since(start),
		Err:      runResult.Err,
		Argv:     append([]string{}, argv...),
	}
}

// BuildSSHArgv constructs the local process argv for one remote command.
//
// The remote command is appended as a single argv element; AgentSSH does not
// locally shell-join or reinterpret it.
func BuildSSHArgv(target inventory.Target, command string) []string {
	host := target.Host
	hostSpec := host.SSHConfigAlias
	if hostSpec == "" {
		hostSpec = host.Addr
		if host.User != "" {
			hostSpec = host.User + "@" + hostSpec
		}
	}

	argv := []string{"ssh"}
	if host.Port != 0 && host.Port != 22 && host.SSHConfigAlias == "" {
		argv = append(argv, "-p", strconv.Itoa(host.Port))
	}
	return append(argv, hostSpec, command)
}

// ExecRunner executes argv directly with os/exec.
type ExecRunner struct{}

func (ExecRunner) Run(ctx context.Context, argv []string) RunResult {
	if len(argv) == 0 {
		return RunResult{ExitCode: -1, Err: errors.New("empty argv")}
	}

	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	exitCode := 0
	if err != nil {
		exitCode = -1
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			exitCode = exitErr.ExitCode()
		}
	}

	return RunResult{
		Stdout:   stdout.String(),
		Stderr:   stderr.String(),
		ExitCode: exitCode,
		Err:      err,
	}
}

// IsProcessExit reports whether a result represents a completed remote command.
func IsProcessExit(result Result) bool {
	if result.Err == nil {
		return true
	}
	var exitErr *exec.ExitError
	return errors.As(result.Err, &exitErr)
}

// FormatArgv returns a shell-like debug rendering without changing execution.
func FormatArgv(argv []string) string {
	quoted := make([]string, 0, len(argv))
	for _, arg := range argv {
		quoted = append(quoted, strconv.Quote(arg))
	}
	return strings.Join(quoted, " ")
}

func (r Result) Error() string {
	if r.Err == nil {
		return ""
	}
	return fmt.Sprintf("%v", r.Err)
}
