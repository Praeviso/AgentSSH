package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/Kritoooo/agentssh/internal/executor"
)

func TestExitCodeForResult(t *testing.T) {
	tests := []struct {
		name   string
		result executor.Result
		want   int
	}{
		{
			name:   "success",
			result: executor.Result{ExitCode: 0},
			want:   exitOK,
		},
		{
			name:   "remote non-zero",
			result: executor.Result{ExitCode: 3},
			want:   exitRemoteFailed,
		},
		{
			name:   "ssh error",
			result: executor.Result{ExitCode: -1, Err: errors.New("connect failed")},
			want:   exitSSHError,
		},
		{
			name: "ssh exit 255",
			result: executor.Result{
				ExitCode: 255,
				Argv:     []string{"ssh", "deploy@10.0.0.11", "uptime"},
			},
			want: exitSSHError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := exitCodeForResult(tt.result); got != tt.want {
				t.Fatalf("exitCodeForResult = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestStatusForResultSSHExit255(t *testing.T) {
	result := executor.Result{
		ExitCode: 255,
		Argv:     []string{"ssh", "deploy@10.0.0.11", "uptime"},
	}
	if got := statusForResult(result); got != "ssh_error" {
		t.Fatalf("statusForResult = %q, want ssh_error", got)
	}
}

func TestPrintSSHExit255MappingDemo(t *testing.T) {
	result := executor.Result{
		ExitCode: 255,
		Argv:     []string{"ssh", "deploy@10.0.0.11", "uptime"},
	}
	fmt.Printf("exit_code=%d status=%q mapped_exit=%d\n", result.ExitCode, statusForResult(result), exitCodeForResult(result))
}

func TestMergeExitCode(t *testing.T) {
	if got := mergeExitCode(exitOK, exitRemoteFailed); got != exitRemoteFailed {
		t.Fatalf("merge success+remote = %d, want %d", got, exitRemoteFailed)
	}
	if got := mergeExitCode(exitRemoteFailed, exitSSHError); got != exitSSHError {
		t.Fatalf("merge remote+ssh = %d, want %d", got, exitSSHError)
	}
}

func TestRunJSONShapeHostObjectGroupArray(t *testing.T) {
	hostOut, _, groupOut, _ := runJSONShapeDemo(t)

	var hostValue map[string]any
	if err := json.Unmarshal([]byte(hostOut), &hostValue); err != nil {
		t.Fatalf("host JSON is not object: %v\n%s", err, hostOut)
	}
	if hostValue["host"] != "web-1" {
		t.Fatalf("host JSON host = %#v", hostValue["host"])
	}

	var groupValue []map[string]any
	if err := json.Unmarshal([]byte(groupOut), &groupValue); err != nil {
		t.Fatalf("group JSON is not array: %v\n%s", err, groupOut)
	}
	if len(groupValue) != 1 || groupValue[0]["host"] != "web-1" {
		t.Fatalf("group JSON = %#v", groupValue)
	}
}

func TestPrintRunJSONShapeDemo(t *testing.T) {
	hostOut, hostErr, groupOut, groupErr := runJSONShapeDemo(t)
	if hostErr != "" || groupErr != "" {
		t.Fatalf("unexpected stderr: host=%q group=%q", hostErr, groupErr)
	}
	fmt.Printf("host_json=%s", hostOut)
	fmt.Printf("group_json=%s", groupOut)
}

func runJSONShapeDemo(t *testing.T) (string, string, string, string) {
	t.Helper()
	home := t.TempDir()
	writeTestInventory(t, home)
	t.Setenv("AGENTSSH_HOME", home)

	restoreExecutor := newExecutor
	newExecutor = func() executor.Executor {
		return fakeExecutor{}
	}
	defer func() {
		newExecutor = restoreExecutor
	}()

	hostOut, hostErr := runCommandForTest(t, "run", "web-1", "--json", "--", "echo", "hi")
	groupOut, groupErr := runCommandForTest(t, "run", "solo", "--json", "--", "echo", "hi")
	return hostOut, hostErr, groupOut, groupErr
}

func runCommandForTest(t *testing.T, args ...string) (string, string) {
	t.Helper()
	root := newRootCommand()
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	root.SetOut(&stdout)
	root.SetErr(&stderr)
	root.SetArgs(args)
	if err := root.Execute(); err != nil {
		t.Fatalf("Execute(%v) error: %v; stderr=%s", args, err, stderr.String())
	}
	return stdout.String(), stderr.String()
}

func writeTestInventory(t *testing.T, home string) {
	t.Helper()
	data := []byte(`
version: 1
hosts:
  web-1:
    addr: 10.0.0.11
    user: deploy
    tags: [web, solo]
  web-2:
    addr: 10.0.0.12
    user: deploy
    tags: [web]
groups:
  web: { tags: [web] }
  solo: { tags: [solo] }
`)
	if err := os.WriteFile(filepath.Join(home, "inventory.yaml"), data, 0o600); err != nil {
		t.Fatalf("write inventory: %v", err)
	}
}

type fakeExecutor struct{}

func (fakeExecutor) Run(_ context.Context, request executor.Request) executor.Result {
	return executor.Result{
		Stdout:   "ok\n",
		ExitCode: 0,
		Argv:     []string{"ssh", request.Target.Name, request.Command},
	}
}

var _ executor.Executor = fakeExecutor{}
