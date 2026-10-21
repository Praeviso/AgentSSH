package main

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/Praeviso/AgentSSH/internal/remote"
	"github.com/Praeviso/AgentSSH/internal/remoteserver"
)

func TestHTTPOriginRequiresExplicitPublicHTTPSBase(t *testing.T) {
	cmd := newRootCommand()
	cmd.SetArgs([]string{"serve", "--http"})
	if err := cmd.Execute(); err == nil || !strings.Contains(err.Error(), "--public-url") {
		t.Fatalf("serve --http: %v", err)
	}
}

func TestDeviceTokenCreateForHostedHTTPS(t *testing.T) {
	old := remoteserver.ScryptWorkFactor
	remoteserver.ScryptWorkFactor = 10
	t.Cleanup(func() { remoteserver.ScryptWorkFactor = old })
	dir := t.TempDir()
	if err := remoteserver.Init(dir, "master", []string{"localhost"}, time.Now()); err != nil {
		t.Fatal(err)
	}
	cmd := newRootCommand()
	var stdout, stderr bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	cmd.SetArgs([]string{"--data", dir, "device", "token", "create", "--name", "laptop", "--public-url", "https://config.example/v1/plugins/agentssh"})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	token, err := remote.ParseHTTPSEnrollToken(stdout.String())
	if err != nil || token.ServerURL != "https://config.example/v1/plugins/agentssh" {
		t.Fatalf("token: %+v %v", token, err)
	}
	if strings.Contains(stderr.String(), token.Secret) {
		t.Fatal("token leaked to stderr")
	}
}
