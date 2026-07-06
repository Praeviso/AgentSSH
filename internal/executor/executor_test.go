package executor

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/Praeviso/AgentSSH/internal/inventory"
)

func TestBuildSSHArgvKeepsRemoteCommandAsSingleArg(t *testing.T) {
	target := inventory.Target{
		Name: "web-1",
		Host: inventory.Host{
			Addr: "10.0.0.11",
			User: "deploy",
			Port: 2222,
		},
	}
	command := `printf 'a|b;$(whoami)' | sed 's/a/x/'`

	got := BuildSSHArgv(target, command)
	want := []string{"ssh", "-p", "2222", "deploy@10.0.0.11", command}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("argv = %#v, want %#v", got, want)
	}
	if got[len(got)-1] != command {
		t.Fatalf("remote command was changed: %q", got[len(got)-1])
	}
}

func TestBuildSSHArgvWithControlMasterOptions(t *testing.T) {
	target := inventory.Target{
		Name: "web-1",
		Host: inventory.Host{
			Addr: "10.0.0.11",
			User: "deploy",
			Port: 2222,
		},
	}
	command := `printf 'a|b;$(whoami)' | sed 's/a/x/'`
	controlPath := filepath.Join(t.TempDir(), "cm-web-1")

	got := BuildSSHArgvWithOptions(target, command, SSHArgvOptions{
		ControlPath:    controlPath,
		ControlPersist: 90 * time.Second,
	})
	want := []string{
		"ssh",
		"-p", "2222",
		"-o", "ControlMaster=auto",
		"-o", "ControlPersist=90s",
		"-o", "ControlPath=" + controlPath,
		"deploy@10.0.0.11",
		command,
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("argv = %#v, want %#v", got, want)
	}
	if got[len(got)-1] != command {
		t.Fatalf("remote command was changed: %q", got[len(got)-1])
	}
}

func TestBuildSSHArgvUsesSSHConfigAlias(t *testing.T) {
	target := inventory.Target{
		Name: "web-1",
		Host: inventory.Host{
			Addr:           "10.0.0.11",
			User:           "deploy",
			Port:           2222,
			SSHConfigAlias: "web-prod",
		},
	}

	got := BuildSSHArgv(target, "uptime")
	want := []string{"ssh", "web-prod", "uptime"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("argv = %#v, want %#v", got, want)
	}
}

func TestSSHExecutorUsesInjectedRunner(t *testing.T) {
	var calls [][]string
	runner := RunnerFunc(func(_ context.Context, argv []string, _ []byte) RunResult {
		calls = append(calls, append([]string{}, argv...))
		if argv[len(argv)-1] == OSProbeCommand {
			return RunResult{Stdout: "Linux\n", ExitCode: 0}
		}
		return RunResult{Stdout: "ok\n", ExitCode: 0}
	})
	exec := NewSSHExecutorWithOptions(runner, SSHOptions{DisableMultiplexing: true})

	result := exec.Run(context.Background(), Request{
		Target: inventory.Target{
			Name: "web-1",
			Host: inventory.Host{Addr: "10.0.0.11", User: "deploy"},
		},
		Command: "echo ok",
	})

	wantArgv := []string{"ssh", "deploy@10.0.0.11", "echo ok"}
	if len(calls) != 2 {
		t.Fatalf("runner calls = %#v, want command + OS probe", calls)
	}
	if !reflect.DeepEqual(calls[0], wantArgv) {
		t.Fatalf("command argv = %#v, want %#v", calls[0], wantArgv)
	}
	if !reflect.DeepEqual(result.Argv, wantArgv) {
		t.Fatalf("result argv = %#v, want %#v", result.Argv, wantArgv)
	}
	if result.Stdout != "ok\n" || result.ExitCode != 0 || result.Err != nil {
		t.Fatalf("result = %#v", result)
	}
	if result.OS != "linux" {
		t.Fatalf("result OS = %q, want linux", result.OS)
	}
	wantProbeArgv := []string{"ssh", "deploy@10.0.0.11", OSProbeCommand}
	if !reflect.DeepEqual(calls[1], wantProbeArgv) {
		t.Fatalf("probe argv = %#v, want %#v", calls[1], wantProbeArgv)
	}
}

func TestSSHExecutorMultiplexesCommandAndProbe(t *testing.T) {
	controlDir := t.TempDir()
	var calls [][]string
	runner := RunnerFunc(func(_ context.Context, argv []string, _ []byte) RunResult {
		calls = append(calls, append([]string{}, argv...))
		if argv[len(argv)-1] == OSProbeCommand {
			return RunResult{Stdout: "Linux\n", ExitCode: 0}
		}
		return RunResult{Stdout: "ok\n", ExitCode: 0}
	})
	exec := NewSSHExecutorWithOptions(runner, SSHOptions{ControlDir: controlDir, ControlPersist: 42 * time.Second})
	defer func() { _ = exec.Close() }()

	result := exec.Run(context.Background(), Request{
		Target: inventory.Target{
			Name: "web-1",
			Host: inventory.Host{Addr: "10.0.0.11", User: "deploy"},
		},
		Command: "echo ok",
	})

	if len(calls) != 2 {
		t.Fatalf("runner calls = %#v, want command + OS probe", calls)
	}
	commandPath := sshOptionValue(t, calls[0], "ControlPath")
	probePath := sshOptionValue(t, calls[1], "ControlPath")
	if commandPath == "" || probePath == "" || commandPath != probePath {
		t.Fatalf("control paths command=%q probe=%q", commandPath, probePath)
	}
	if !strings.HasPrefix(commandPath, controlDir+string(os.PathSeparator)) {
		t.Fatalf("control path %q is not under %q", commandPath, controlDir)
	}
	for _, argv := range calls {
		if got := sshOptionValue(t, argv, "ControlMaster"); got != "auto" {
			t.Fatalf("ControlMaster = %q, want auto in %#v", got, argv)
		}
		if got := sshOptionValue(t, argv, "ControlPersist"); got != "42s" {
			t.Fatalf("ControlPersist = %q, want 42s in %#v", got, argv)
		}
	}
	if result.Stdout != "ok\n" || result.ExitCode != 0 || result.Err != nil || result.OS != "linux" {
		t.Fatalf("result = %#v", result)
	}
	if !reflect.DeepEqual(result.Argv, calls[0]) {
		t.Fatalf("result argv = %#v, want first runner argv %#v", result.Argv, calls[0])
	}
}

func TestSSHExecutorCachesOSPerMuxKey(t *testing.T) {
	controlDir := t.TempDir()
	var probes int
	runner := RunnerFunc(func(_ context.Context, argv []string, _ []byte) RunResult {
		if argv[len(argv)-1] == OSProbeCommand {
			probes++
			return RunResult{Stdout: "Linux\n", ExitCode: 0}
		}
		return RunResult{Stdout: "ok\n", ExitCode: 0}
	})
	exec := NewSSHExecutorWithOptions(runner, SSHOptions{ControlDir: controlDir})
	defer func() { _ = exec.Close() }()
	target := inventory.Target{Name: "web-1", Host: inventory.Host{Addr: "10.0.0.11", User: "deploy"}}

	for i := 0; i < 2; i++ {
		result := exec.Run(context.Background(), Request{Target: target, Command: "echo ok"})
		if result.Err != nil || result.OS != "linux" {
			t.Fatalf("run %d result = %#v", i, result)
		}
	}
	if probes != 1 {
		t.Fatalf("OS probes = %d, want 1 cached probe", probes)
	}
}

func TestSSHExecutorLeavesAliasMuxOptionsToSSHConfig(t *testing.T) {
	controlDir := t.TempDir()
	var call []string
	runner := RunnerFunc(func(_ context.Context, argv []string, _ []byte) RunResult {
		call = append([]string{}, argv...)
		return RunResult{ExitCode: 255, Err: errors.New("connect failed")}
	})
	exec := NewSSHExecutorWithOptions(runner, SSHOptions{ControlDir: controlDir})
	defer func() { _ = exec.Close() }()

	_ = exec.Run(context.Background(), Request{
		Target:  inventory.Target{Name: "prod", Host: inventory.Host{SSHConfigAlias: "prod-web", Addr: "ignored", User: "ignored", Port: 2222}},
		Command: "uptime",
	})

	if got := sshOptionValue(t, call, "ControlPath"); got != "" {
		t.Fatalf("alias ControlPath = %q, want no injected mux options in %#v", got, call)
	}
	want := []string{"ssh", "prod-web", "uptime"}
	if !reflect.DeepEqual(call, want) {
		t.Fatalf("alias argv = %#v, want %#v", call, want)
	}
}

func TestBuildSSHArgvWithOptionsDoesNotOverrideAliasMuxConfig(t *testing.T) {
	target := inventory.Target{Name: "prod", Host: inventory.Host{SSHConfigAlias: "prod-web"}}
	got := BuildSSHArgvWithOptions(target, "uptime", SSHArgvOptions{
		ControlPath:    filepath.Join(t.TempDir(), "cm-prod"),
		ControlPersist: time.Minute,
	})
	want := []string{"ssh", "prod-web", "uptime"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("argv = %#v, want %#v", got, want)
	}
}

func TestSSHExecutorStableControlDirSurvivesClose(t *testing.T) {
	cacheRoot, err := os.MkdirTemp("/tmp", "agentssh-cache-*")
	if err != nil {
		t.Fatalf("create short cache dir: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(cacheRoot) })
	t.Setenv("XDG_CACHE_HOME", cacheRoot)
	var controlPath string
	runner := RunnerFunc(func(_ context.Context, argv []string, _ []byte) RunResult {
		if controlPath == "" {
			controlPath = sshOptionValue(t, argv, "ControlPath")
			if err := os.WriteFile(controlPath, []byte("socket placeholder"), 0o600); err != nil {
				t.Fatalf("write control path placeholder: %v", err)
			}
		}
		return RunResult{ExitCode: 255, Err: errors.New("connect failed")}
	})
	exec := NewSSHExecutor(runner)

	_ = exec.Run(context.Background(), Request{
		Target:  inventory.Target{Name: "web-1", Host: inventory.Host{Addr: "10.0.0.11", User: "deploy"}},
		Command: "uptime",
	})
	if controlPath == "" {
		t.Fatal("runner did not receive a ControlPath")
	}
	controlDir := filepath.Dir(controlPath)
	wantDir := filepath.Join(cacheRoot, "agentssh", "ssh-mux")
	if controlDir != wantDir {
		t.Fatalf("control dir = %q, want %q", controlDir, wantDir)
	}
	if err := exec.Close(); err != nil {
		t.Fatalf("close executor: %v", err)
	}
	if _, err := os.Stat(controlPath); err != nil {
		t.Fatalf("control path after close: %v", err)
	}
}

func TestSSHExecutorFallsBackWhenControlPathTooLong(t *testing.T) {
	controlDir := filepath.Join(t.TempDir(), strings.Repeat("long-segment-", 12))
	var call []string
	runner := RunnerFunc(func(_ context.Context, argv []string, _ []byte) RunResult {
		call = append([]string{}, argv...)
		return RunResult{ExitCode: 255, Err: errors.New("connect failed")}
	})
	exec := NewSSHExecutorWithOptions(runner, SSHOptions{ControlDir: controlDir})
	defer func() { _ = exec.Close() }()

	_ = exec.Run(context.Background(), Request{
		Target:  inventory.Target{Name: "web-1", Host: inventory.Host{Addr: "10.0.0.11", User: "deploy"}},
		Command: "uptime",
	})

	if got := sshOptionValue(t, call, "ControlPath"); got != "" {
		t.Fatalf("long ControlPath still injected as %q in %#v", got, call)
	}
	want := []string{"ssh", "deploy@10.0.0.11", "uptime"}
	if !reflect.DeepEqual(call, want) {
		t.Fatalf("fallback argv = %#v, want %#v", call, want)
	}
}

func TestSSHExecutorInjectsServerAliveIntervalWhenConfigured(t *testing.T) {
	target := inventory.Target{Name: "web-1", Host: inventory.Host{Addr: "10.0.0.11", User: "deploy"}}
	got := BuildSSHArgvWithOptions(target, "uptime", SSHArgvOptions{
		ControlPath:       filepath.Join(t.TempDir(), "cm-web-1"),
		ControlPersist:    time.Minute,
		KeepAliveInterval: 7 * time.Second,
	})
	if value := sshOptionValue(t, got, "ServerAliveInterval"); value != "7" {
		t.Fatalf("ServerAliveInterval = %q, want 7 in %#v", value, got)
	}
}

func TestSSHExecutorMultiplexingCanBeDisabled(t *testing.T) {
	var calls [][]string
	runner := RunnerFunc(func(_ context.Context, argv []string, _ []byte) RunResult {
		calls = append(calls, append([]string{}, argv...))
		return RunResult{ExitCode: 255, Err: errors.New("connect failed")}
	})
	exec := NewSSHExecutorWithOptions(runner, SSHOptions{DisableMultiplexing: true})

	result := exec.Run(context.Background(), Request{
		Target:  inventory.Target{Name: "web-1", Host: inventory.Host{Addr: "10.0.0.11", User: "deploy"}},
		Command: "uptime",
	})

	want := []string{"ssh", "deploy@10.0.0.11", "uptime"}
	if result.Err == nil {
		t.Fatal("result err = nil")
	}
	if len(calls) != 1 || !reflect.DeepEqual(calls[0], want) || !reflect.DeepEqual(result.Argv, want) {
		t.Fatalf("calls=%#v result argv=%#v, want %#v", calls, result.Argv, want)
	}
}

func TestSSHExecutorCloseLeavesConfiguredControlPath(t *testing.T) {
	var controlPath string
	controlDir, err := os.MkdirTemp("/tmp", "agentssh-mux-*")
	if err != nil {
		t.Fatalf("create short control dir: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(controlDir) })
	runner := RunnerFunc(func(_ context.Context, argv []string, _ []byte) RunResult {
		if controlPath == "" {
			controlPath = sshOptionValue(t, argv, "ControlPath")
			if err := os.WriteFile(controlPath, []byte("socket placeholder"), 0o600); err != nil {
				t.Fatalf("write control path placeholder: %v", err)
			}
		}
		return RunResult{ExitCode: 255, Err: errors.New("connect failed")}
	})
	exec := NewSSHExecutorWithOptions(runner, SSHOptions{ControlDir: controlDir})

	result := exec.Run(context.Background(), Request{
		Target:  inventory.Target{Name: "web-1", Host: inventory.Host{Addr: "10.0.0.11", User: "deploy"}},
		Command: "uptime",
	})
	if result.Err == nil {
		t.Fatal("result err = nil")
	}
	if controlPath == "" {
		t.Fatal("runner did not receive a ControlPath")
	}
	if _, err := os.Stat(controlPath); err != nil {
		t.Fatalf("control path placeholder before close: %v", err)
	}
	if err := exec.Close(); err != nil {
		t.Fatalf("close executor: %v", err)
	}
	if _, err := os.Stat(controlPath); err != nil {
		t.Fatalf("control path after close: %v", err)
	}
	if _, err := os.Stat(controlDir); err != nil {
		t.Fatalf("control dir after close: %v", err)
	}
}

func TestSSHExecutorDoesNotParseUserStdoutAsOS(t *testing.T) {
	var probeCalled bool
	runner := RunnerFunc(func(_ context.Context, argv []string, _ []byte) RunResult {
		if argv[len(argv)-1] == OSProbeCommand {
			probeCalled = true
			return RunResult{Stdout: "Darwin\n", ExitCode: 0}
		}
		return RunResult{Stdout: "Linux\n", ExitCode: 0}
	})
	exec := NewSSHExecutorWithOptions(runner, SSHOptions{DisableMultiplexing: true})
	result := exec.Run(context.Background(), Request{
		Target:  inventory.Target{Name: "web-1", Host: inventory.Host{Addr: "10.0.0.11", User: "deploy"}},
		Command: "echo Linux",
	})
	if !probeCalled {
		t.Fatal("expected a separate OS probe")
	}
	if result.Stdout != "Linux\n" || result.OS != "macos" {
		t.Fatalf("result stdout=%q OS=%q, want user stdout preserved and OS from probe", result.Stdout, result.OS)
	}
}

func TestNormalizeOS(t *testing.T) {
	tests := map[string]string{
		"Linux\n":      "linux",
		"Darwin":       "macos",
		"FreeBSD":      "bsd",
		"MINGW64_NT":   "windows",
		"unknown-plan": "",
	}
	for input, want := range tests {
		if got := NormalizeOS(input); got != want {
			t.Fatalf("NormalizeOS(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestRunStreamingProcessWritesToProvidedWriters(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	result := runStreamingProcess(context.Background(), []string{"sh", "-c", "printf out; printf err >&2; exit 7"}, nil, &stdout, &stderr)

	if result.ExitCode != 7 || result.Err == nil {
		t.Fatalf("result = %#v", result)
	}
	if stdout.String() != "out" || stderr.String() != "err" {
		t.Fatalf("stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
}

// TestBuildSSHArgvNoRemoteInstall proves PRD §10 S4 at the seam that is testable
// without a real host: AgentSSH ships NOTHING to the remote — a run is exactly one
// `ssh <target> <cmd>` invocation, with no upload/install/bootstrap step and the
// remote command passed verbatim. (Real "no daemon installed" behavior is out of
// CI scope; this is the no-install contract.)
func TestBuildSSHArgvNoRemoteInstall(t *testing.T) {
	target := inventory.Target{
		Name: "web-1",
		Host: inventory.Host{Addr: "10.0.0.11", User: "deploy", Port: 22},
	}
	command := "systemctl status nginx"
	argv := BuildSSHArgv(target, command)

	if len(argv) != 3 {
		t.Fatalf("a default-port run must be exactly [ssh target cmd], got %#v", argv)
	}
	if argv[0] != "ssh" {
		t.Fatalf("argv[0] = %q, want ssh", argv[0])
	}
	if argv[len(argv)-1] != command {
		t.Fatalf("remote command not verbatim: %q", argv[len(argv)-1])
	}
	for _, a := range argv {
		switch a {
		case "scp", "rsync", "curl", "wget", "install", "bootstrap", "sftp":
			t.Fatalf("argv contains a transfer/install verb %q: %#v", a, argv)
		}
	}
}

func TestIsProcessExit(t *testing.T) {
	if !IsProcessExit(Result{ExitCode: 0}) {
		t.Fatal("nil error should be process exit")
	}
	if IsProcessExit(Result{Err: errors.New("connect failed")}) {
		t.Fatal("plain error should be ssh/connect error")
	}
}

func TestPrintArgvDemo(t *testing.T) {
	if testing.Short() {
		t.Skip("demo skipped in short mode")
	}

	runner := RunnerFunc(func(_ context.Context, argv []string, _ []byte) RunResult {
		fmt.Printf("argv=%#v\n", argv)
		return RunResult{ExitCode: 0}
	})
	exec := NewSSHExecutorWithOptions(runner, SSHOptions{DisableMultiplexing: true})
	result := exec.Run(context.Background(), Request{
		Target: inventory.Target{
			Name: "web-1",
			Host: inventory.Host{Addr: "10.0.0.11", User: "deploy"},
		},
		Command: `printf 'a|b;$(whoami)' | sed 's/a/x/'`,
	})
	if result.ExitCode != 0 {
		t.Fatalf("demo result = %#v", result)
	}
}

func sshOptionValue(t *testing.T, argv []string, name string) string {
	t.Helper()
	prefix := name + "="
	for i := 0; i+1 < len(argv); i++ {
		if argv[i] != "-o" {
			continue
		}
		if strings.HasPrefix(argv[i+1], prefix) {
			return strings.TrimPrefix(argv[i+1], prefix)
		}
	}
	return ""
}
