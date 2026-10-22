package main

import (
	"bytes"
	"os/exec"
	"slices"
	"strings"
	"testing"

	"github.com/Praeviso/AgentSSH/internal/gateway"
	"github.com/Praeviso/AgentSSH/internal/remote"
)

func TestServeRequiresExplicitPublicHTTPSBase(t *testing.T) {
	cmd := newRootCommand()
	cmd.SetArgs([]string{"serve"})
	if err := cmd.Execute(); err == nil || !strings.Contains(err.Error(), "--public-url") {
		t.Fatalf("serve: %v", err)
	}
}

func TestDeviceTokenCreateNamesGatewayMode(t *testing.T) {
	old := gateway.ScryptWorkFactor
	gateway.ScryptWorkFactor = 10
	t.Cleanup(func() { gateway.ScryptWorkFactor = old })
	dir := t.TempDir()
	if err := gateway.Init(dir, "master"); err != nil {
		t.Fatal(err)
	}
	cmd := newRootCommand()
	var stdout, stderr bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	cmd.SetArgs([]string{"--data", dir, "device", "token", "create", "--name", "agent-vm", "--public-url", "https://gw.example/agentssh"})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	token, err := remote.ParseEnrollToken(stdout.String())
	if err != nil || token.ServerURL != "https://gw.example/agentssh" {
		t.Fatalf("token: %+v %v", token, err)
	}
	if !strings.Contains(stderr.String(), "--mode gateway") || strings.Contains(stderr.String(), token.Secret) {
		t.Fatalf("enroll hint: %q", stderr.String())
	}
}

// The signing and bundle handlers live only in internal/remoteserver; the
// gateway binary must not link that package at all.
func TestGatewayDoesNotLinkManagedSigning(t *testing.T) {
	gobin, err := exec.LookPath("go")
	if err != nil {
		t.Skip("go toolchain not on PATH")
	}
	out, err := exec.Command(gobin, "list", "-deps", "-f", "{{.ImportPath}}", ".").CombinedOutput()
	if err != nil {
		t.Fatalf("go list: %v\n%s", err, out)
	}
	deps := strings.Fields(string(out))
	if !slices.Contains(deps, "github.com/Praeviso/AgentSSH/internal/gateway") {
		t.Fatalf("go list returned an unexpected graph: %v", deps)
	}
	if slices.Contains(deps, "github.com/Praeviso/AgentSSH/internal/remoteserver") {
		t.Fatal("agentssh-gateway depends on internal/remoteserver")
	}
}
