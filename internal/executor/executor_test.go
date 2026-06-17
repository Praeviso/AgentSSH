package executor

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"reflect"
	"testing"

	"github.com/Kritoooo/agentssh/internal/inventory"
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
	var captured []string
	runner := RunnerFunc(func(_ context.Context, argv []string) RunResult {
		captured = append([]string{}, argv...)
		return RunResult{Stdout: "ok\n", ExitCode: 0}
	})
	exec := NewSSHExecutor(runner)

	result := exec.Run(context.Background(), Request{
		Target: inventory.Target{
			Name: "web-1",
			Host: inventory.Host{Addr: "10.0.0.11", User: "deploy"},
		},
		Command: "echo ok",
	})

	wantArgv := []string{"ssh", "deploy@10.0.0.11", "echo ok"}
	if !reflect.DeepEqual(captured, wantArgv) {
		t.Fatalf("captured argv = %#v, want %#v", captured, wantArgv)
	}
	if !reflect.DeepEqual(result.Argv, wantArgv) {
		t.Fatalf("result argv = %#v, want %#v", result.Argv, wantArgv)
	}
	if result.Stdout != "ok\n" || result.ExitCode != 0 || result.Err != nil {
		t.Fatalf("result = %#v", result)
	}
}

func TestRunStreamingProcessWritesToProvidedWriters(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	result := runStreamingProcess(context.Background(), []string{"sh", "-c", "printf out; printf err >&2; exit 7"}, &stdout, &stderr)

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

	runner := RunnerFunc(func(_ context.Context, argv []string) RunResult {
		fmt.Printf("argv=%#v\n", argv)
		return RunResult{ExitCode: 0}
	})
	exec := NewSSHExecutor(runner)
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
