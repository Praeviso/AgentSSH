package executor

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/Praeviso/AgentSSH/internal/inventory"
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
	OS       string
}

// Executor runs commands against remote hosts.
type Executor interface {
	Run(ctx context.Context, request Request) Result
}

// StreamingExecutor optionally streams stdout/stderr into supplied writers.
//
// Result.Stdout and Result.Stderr are empty because the bytes have already been
// written to the supplied writers. Exit/error semantics match Executor.Run.
type StreamingExecutor interface {
	RunStreaming(ctx context.Context, request Request, stdout io.Writer, stderr io.Writer) Result
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
	result := Result{
		Stdout:   runResult.Stdout,
		Stderr:   runResult.Stderr,
		ExitCode: runResult.ExitCode,
		Duration: time.Since(start),
		Err:      runResult.Err,
		Argv:     append([]string{}, argv...),
	}
	if sshResultConnected(result) {
		if request.Command == OSProbeCommand {
			result.OS = NormalizeOS(result.Stdout)
		} else {
			result.OS = e.detectOS(ctx, request.Target)
		}
	}
	return result
}

func (e SSHExecutor) RunStreaming(ctx context.Context, request Request, stdout io.Writer, stderr io.Writer) Result {
	start := time.Now()
	argv := BuildSSHArgv(request.Target, request.Command)
	runResult := runStreamingProcess(ctx, argv, stdout, stderr)
	result := Result{
		ExitCode: runResult.ExitCode,
		Duration: time.Since(start),
		Err:      runResult.Err,
		Argv:     append([]string{}, argv...),
	}
	if sshResultConnected(result) {
		if request.Command != OSProbeCommand {
			result.OS = e.detectOS(ctx, request.Target)
		}
	}
	return result
}

func sshResultConnected(result Result) bool {
	return (result.Err == nil || IsProcessExit(result)) && result.ExitCode != 255
}

func (e SSHExecutor) detectOS(ctx context.Context, target inventory.Target) string {
	probeCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	result := e.Runner.Run(probeCtx, BuildSSHArgv(target, OSProbeCommand))
	if result.Err != nil || result.ExitCode != 0 {
		return ""
	}
	return NormalizeOS(result.Stdout)
}

// OSProbeCommand is the remote command AgentSSH uses for internal host metadata
// refreshes. Callers must never mix its stdout into agent-visible command output.
const OSProbeCommand = "uname -s"

// NormalizeOS maps common remote OS probe outputs to the inventory display
// vocabulary. Unknown values are ignored so a failed or unusual probe never
// overwrites a known host OS with noisy metadata.
func NormalizeOS(value string) string {
	v := strings.ToLower(strings.TrimSpace(value))
	switch v {
	case "linux":
		return "linux"
	case "darwin":
		return "macos"
	case "freebsd", "openbsd", "netbsd":
		return "bsd"
	default:
		if strings.Contains(v, "mingw") || strings.Contains(v, "msys") || strings.Contains(v, "cygwin") || strings.Contains(v, "windows") {
			return "windows"
		}
		return ""
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
	cmd.Env = scrubbedEnv()
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

func runStreamingProcess(ctx context.Context, argv []string, stdout io.Writer, stderr io.Writer) RunResult {
	if len(argv) == 0 {
		return RunResult{ExitCode: -1, Err: errors.New("empty argv")}
	}

	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	cmd.Env = scrubbedEnv()
	cmd.Stdout = stdout
	cmd.Stderr = stderr

	err := cmd.Run()
	exitCode := 0
	if err != nil {
		exitCode = -1
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			exitCode = exitErr.ExitCode()
		}
	}

	return RunResult{ExitCode: exitCode, Err: err}
}

// scrubbedEnv returns the process environment with AgentSSH secret-bearing
// variables removed, so the shell-out ssh subprocess (and anything it spawns via
// ssh_config ProxyCommand/LocalCommand) never inherits the secrets-store master
// password. The shell transport cannot use the encrypted store anyway, so there
// is no reason for it to see the master. SSH_AUTH_SOCK and the rest of the
// environment are preserved so normal key/agent auth keeps working.
func scrubbedEnv() []string {
	env := os.Environ()
	out := env[:0:0]
	for _, kv := range env {
		if strings.HasPrefix(kv, "AGENTSSH_MASTER_PASSWORD=") {
			continue
		}
		out = append(out, kv)
	}
	return out
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
