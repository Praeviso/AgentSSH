package executor

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Praeviso/AgentSSH/internal/inventory"
)

// Request describes a single remote command execution.
type Request struct {
	Target  inventory.Target
	Command string
	// Stdin, when non-nil, is fed to the remote command's standard input.
	// A nil Stdin preserves the historical behavior (/dev/null).
	Stdin []byte
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
	Close() error
}

// StreamingExecutor optionally streams stdout/stderr into supplied writers.
//
// Result.Stdout and Result.Stderr are empty because the bytes have already been
// written to the supplied writers. Exit/error semantics match Executor.Run.
type StreamingExecutor interface {
	RunStreaming(ctx context.Context, request Request, stdout io.Writer, stderr io.Writer) Result
}

// Runner executes an argv vector. Tests can inject a runner to avoid real SSH.
// stdin is nil for commands without an input stream.
type Runner interface {
	Run(ctx context.Context, argv []string, stdin []byte) RunResult
}

// RunnerFunc adapts a function into a Runner.
type RunnerFunc func(ctx context.Context, argv []string, stdin []byte) RunResult

func (fn RunnerFunc) Run(ctx context.Context, argv []string, stdin []byte) RunResult {
	return fn(ctx, argv, stdin)
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
	Runner  Runner
	Options SSHOptions
	mux     *sshMultiplexer
}

// SSHOptions configures the shell-out SSH transport.
type SSHOptions struct {
	// DisableMultiplexing preserves the old one-process-per-command argv shape.
	DisableMultiplexing bool
	ControlPersist      time.Duration
	ControlDir          string
	KeepAliveInterval   time.Duration
}

const maxControlPathLen = 90

// NewSSHExecutor returns an executor backed by the system ssh binary.
func NewSSHExecutor(runner Runner) SSHExecutor {
	return NewSSHExecutorWithOptions(runner, SSHOptions{})
}

// NewSSHExecutorWithOptions returns a shell-out executor with explicit SSH
// transport options.
func NewSSHExecutorWithOptions(runner Runner, options SSHOptions) SSHExecutor {
	if runner == nil {
		runner = ExecRunner{}
	}
	if options.ControlPersist == 0 {
		options.ControlPersist = 60 * time.Second
	}
	exec := SSHExecutor{Runner: runner, Options: options}
	if !options.DisableMultiplexing {
		exec.mux = newSSHMultiplexer(options.ControlDir)
	}
	return exec
}

// Close drops this process's in-memory mux cache. It intentionally leaves
// ControlPath sockets on disk: OpenSSH masters remove them when their
// ControlPersist lifetime ends, and keeping the stable path available is what
// lets later AgentSSH invocations reuse the master.
func (e SSHExecutor) Close() error {
	if e.mux == nil {
		return nil
	}
	return e.mux.Close()
}

func (e SSHExecutor) Run(ctx context.Context, request Request) Result {
	start := time.Now()
	argv := e.buildArgv(request.Target, request.Command)
	runResult := e.Runner.Run(ctx, argv, request.Stdin)
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
			e.cacheOS(request.Target, result.OS)
		} else {
			result.OS = e.detectOS(ctx, request.Target)
		}
	}
	return result
}

func (e SSHExecutor) RunStreaming(ctx context.Context, request Request, stdout io.Writer, stderr io.Writer) Result {
	start := time.Now()
	argv := e.buildArgv(request.Target, request.Command)
	runResult := runStreamingProcess(ctx, argv, request.Stdin, stdout, stderr)
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
	if osName := e.cachedOS(target); osName != "" {
		return osName
	}
	probeCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	result := e.Runner.Run(probeCtx, e.buildArgv(target, OSProbeCommand), nil)
	if result.Err != nil || result.ExitCode != 0 {
		return ""
	}
	osName := NormalizeOS(result.Stdout)
	e.cacheOS(target, osName)
	return osName
}

func (e SSHExecutor) buildArgv(target inventory.Target, command string) []string {
	if e.mux == nil || e.Options.DisableMultiplexing {
		return BuildSSHArgv(target, command)
	}
	if target.Host.SSHConfigAlias != "" {
		return BuildSSHArgv(target, command)
	}
	controlPath := e.mux.controlPath(target)
	if controlPath == "" {
		return BuildSSHArgv(target, command)
	}
	return BuildSSHArgvWithOptions(target, command, SSHArgvOptions{
		ControlPath:       controlPath,
		ControlPersist:    e.Options.ControlPersist,
		KeepAliveInterval: e.Options.KeepAliveInterval,
	})
}

func (e SSHExecutor) cachedOS(target inventory.Target) string {
	if e.mux == nil || e.Options.DisableMultiplexing {
		return ""
	}
	return e.mux.cachedOS(sshControlKey(target))
}

func (e SSHExecutor) cacheOS(target inventory.Target, osName string) {
	if e.mux == nil || e.Options.DisableMultiplexing || osName == "" {
		return
	}
	e.mux.setOS(sshControlKey(target), osName)
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
	return BuildSSHArgvWithOptions(target, command, SSHArgvOptions{})
}

// SSHArgvOptions carries local ssh(1) process options that AgentSSH owns.
type SSHArgvOptions struct {
	ControlPath       string
	ControlPersist    time.Duration
	KeepAliveInterval time.Duration
}

// BuildSSHArgvWithOptions constructs the local ssh(1) argv with optional
// ControlMaster multiplexing. The remote command is still appended as one argv
// element and is never locally shell-joined.
func BuildSSHArgvWithOptions(target inventory.Target, command string, options SSHArgvOptions) []string {
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
	if options.ControlPath != "" && host.SSHConfigAlias == "" {
		persist := options.ControlPersist
		if persist <= 0 {
			persist = 60 * time.Second
		}
		argv = append(argv,
			"-o", "ControlMaster=auto",
			"-o", "ControlPersist="+formatControlPersist(persist),
			"-o", "ControlPath="+options.ControlPath,
		)
		if options.KeepAliveInterval > 0 {
			argv = append(argv, "-o", "ServerAliveInterval="+formatSeconds(options.KeepAliveInterval))
		}
	}
	return append(argv, hostSpec, command)
}

func formatControlPersist(duration time.Duration) string {
	return formatControlSeconds(duration)
}

func formatControlSeconds(duration time.Duration) string {
	return formatSeconds(duration) + "s"
}

func formatSeconds(duration time.Duration) string {
	seconds := int(duration.Round(time.Second) / time.Second)
	if seconds < 1 {
		seconds = 1
	}
	return strconv.Itoa(seconds)
}

type sshMultiplexer struct {
	mu         sync.Mutex
	dir        string
	configured string
	paths      map[string]struct{}
	disabled   map[string]struct{}
	osByKey    map[string]string
}

func newSSHMultiplexer(controlDir string) *sshMultiplexer {
	return &sshMultiplexer{
		configured: controlDir,
		paths:      map[string]struct{}{},
		disabled:   map[string]struct{}{},
		osByKey:    map[string]string{},
	}
}

func (m *sshMultiplexer) controlPath(target inventory.Target) string {
	key := sshControlKey(target)
	m.mu.Lock()
	if _, ok := m.disabled[key]; ok {
		m.mu.Unlock()
		return ""
	}
	m.mu.Unlock()

	dir := m.dirPath()
	if dir == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(key))
	path := filepath.Join(dir, "cm-"+hex.EncodeToString(sum[:])[:24])
	if len(path) > maxControlPathLen {
		m.mu.Lock()
		m.disabled[key] = struct{}{}
		m.mu.Unlock()
		return ""
	}

	m.mu.Lock()
	m.paths[path] = struct{}{}
	m.mu.Unlock()

	return path
}

func (m *sshMultiplexer) dirPath() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.dir != "" {
		return m.dir
	}
	if m.configured != "" {
		dir := filepath.Clean(m.configured)
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return ""
		}
		m.dir = dir
		return m.dir
	}
	if dir, err := defaultControlDir(); err == nil {
		m.dir = dir
		return m.dir
	}
	dir, err := os.MkdirTemp("", "agentssh-ssh-*")
	if err != nil {
		return ""
	}
	m.dir = dir
	return m.dir
}

func (m *sshMultiplexer) Close() error {
	m.mu.Lock()
	m.dir = ""
	m.paths = map[string]struct{}{}
	m.disabled = map[string]struct{}{}
	m.osByKey = map[string]string{}
	m.mu.Unlock()

	return nil
}

func (m *sshMultiplexer) cachedOS(key string) string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.osByKey[key]
}

func (m *sshMultiplexer) setOS(key string, osName string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.osByKey[key] = osName
}

func defaultControlDir() (string, error) {
	cacheDir, err := os.UserCacheDir()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(cacheDir, "agentssh", "ssh-mux")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return "", err
	}
	return dir, nil
}

func sshControlKey(target inventory.Target) string {
	host := target.Host
	if host.SSHConfigAlias != "" {
		return "alias\x00" + host.SSHConfigAlias
	}
	port := host.Port
	if port == 0 {
		port = 22
	}
	return strings.Join([]string{
		"direct",
		host.User,
		strings.ToLower(host.Addr),
		strconv.Itoa(port),
	}, "\x00")
}

// ExecRunner executes argv directly with os/exec.
type ExecRunner struct{}

func (ExecRunner) Run(ctx context.Context, argv []string, stdin []byte) RunResult {
	if len(argv) == 0 {
		return RunResult{ExitCode: -1, Err: errors.New("empty argv")}
	}

	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	cmd.Env = scrubbedEnv()
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
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

func runStreamingProcess(ctx context.Context, argv []string, stdin []byte, stdout io.Writer, stderr io.Writer) RunResult {
	if len(argv) == 0 {
		return RunResult{ExitCode: -1, Err: errors.New("empty argv")}
	}

	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	cmd.Env = scrubbedEnv()
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
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
