package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Praeviso/AgentSSH/internal/controlplane"
	"github.com/Praeviso/AgentSSH/internal/gateway"
	"github.com/Praeviso/AgentSSH/internal/remote"
)

// enrolledDevice initializes a gateway data directory with one enrolled
// device and returns the directory and the device's ID.
func enrolledDevice(t *testing.T) (string, string) {
	t.Helper()
	old := gateway.ScryptWorkFactor
	gateway.ScryptWorkFactor = 10
	t.Cleanup(func() { gateway.ScryptWorkFactor = old })
	dir := t.TempDir()
	if err := gateway.Init(dir, "master"); err != nil {
		t.Fatal(err)
	}
	store, err := gateway.OpenStore(filepath.Join(dir, gateway.FileDatabase))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()
	pub, err := controlplane.LoadBundlePublicKey(dir)
	if err != nil {
		t.Fatal(err)
	}
	token, err := store.CreateEnrollToken("ci-runner", "https://gw.example/agentssh", remote.PublicKeyFingerprint(pub), time.Minute, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	key, _, _ := ed25519.GenerateKey(rand.Reader)
	device, err := store.RedeemEnrollToken(token.ID, token.Secret, "https://gw.example/agentssh", base64.StdEncoding.EncodeToString(key), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return dir, device.ID
}

func TestDeviceActivationCommands(t *testing.T) {
	dir, id := enrolledDevice(t)
	if out, err := runGatewayCLI(t, "--data", dir, "device", "ls"); err != nil || !strings.Contains(out, "ACTIVATION") || !strings.Contains(out, "inactive") {
		t.Fatalf("ls before activation: %v\n%s", err, out)
	}
	if _, err := runGatewayCLI(t, "--data", dir, "device", "activate", id); err == nil || !strings.Contains(err.Error(), `"for" not set`) {
		t.Fatalf("activate without --for: %v", err)
	}
	if _, err := runGatewayCLI(t, "--data", dir, "device", "activate", id, "--for", "48h"); err == nil || !strings.Contains(err.Error(), "at most 24h") {
		t.Fatalf("activate beyond the cap: %v", err)
	}
	out, err := runGatewayCLI(t, "--data", dir, "device", "activate", id, "--for", "2h", "--note", "deploy")
	if err != nil || !strings.HasPrefix(out, "Activated "+id+" until ") || !strings.HasSuffix(out, "(2h)\n") {
		t.Fatalf("activate: %v %q", err, out)
	}
	if out, err := runGatewayCLI(t, "--data", dir, "device", "ls"); err != nil || !strings.Contains(out, "left)") {
		t.Fatalf("ls while active: %v\n%s", err, out)
	}
	if out, err := runGatewayCLI(t, "--data", dir, "device", "deactivate", id); err != nil || out != "Deactivated "+id+"\n" {
		t.Fatalf("deactivate: %v %q", err, out)
	}
	if out, err := runGatewayCLI(t, "--data", dir, "device", "deactivate", id); err != nil || out != id+" was not active\n" {
		t.Fatalf("deactivate again: %v %q", err, out)
	}
	if _, err := runGatewayCLI(t, "--data", dir, "device", "revoke", id); err != nil {
		t.Fatal(err)
	}
	if _, err := runGatewayCLI(t, "--data", dir, "device", "activate", id, "--for", "1h"); err == nil || !strings.Contains(err.Error(), "revoked") {
		t.Fatalf("activate a revoked device: %v", err)
	}
	if out, err := runGatewayCLI(t, "--data", dir, "audit", "verify"); err != nil || out != "audit chain ok · records=3\n" {
		t.Fatalf("audit verify: %v %q (want activation, deactivation and revocation)", err, out)
	}
}

func TestTokenDeviceCommands(t *testing.T) {
	dir, signed := enrolledDevice(t)
	if _, err := runGatewayCLI(t, "--data", dir, "device", "create", "--name", "hosted-agent"); err == nil || !strings.Contains(err.Error(), `"kind" not set`) {
		t.Fatalf("create without --kind: %v", err)
	}
	if _, err := runGatewayCLI(t, "--data", dir, "device", "create", "--name", "hosted-agent", "--kind", "signed"); err == nil || !strings.Contains(err.Error(), "agentssh remote enroll") {
		t.Fatalf("create a signed device: %v", err)
	}
	first, err := runGatewayCLI(t, "--data", dir, "device", "create", "--name", "hosted-agent", "--kind", "token")
	if err != nil || !strings.HasPrefix(first, "agt_") {
		t.Fatalf("create: %v %q", err, first)
	}
	out, err := runGatewayCLI(t, "--data", dir, "device", "ls")
	if err != nil || !strings.Contains(out, "KIND") || !strings.Contains(out, "hosted-agent") {
		t.Fatalf("ls: %v\n%s", err, out)
	}
	var tokenID string
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) > 0 && strings.Contains(line, "hosted-agent") {
			tokenID = fields[0]
			if !strings.Contains(line, " token ") || !strings.HasSuffix(line, "inactive") {
				t.Fatalf("token device row: %q", line)
			}
		}
		if len(fields) > 0 && fields[0] == signed && !strings.Contains(line, " signed ") {
			t.Fatalf("signed device row: %q", line)
		}
	}
	second, err := runGatewayCLI(t, "--data", dir, "device", "rotate", tokenID)
	if err != nil || !strings.HasPrefix(second, "agt_") || second == first {
		t.Fatalf("rotate: %v %q", err, second)
	}
	if _, err := runGatewayCLI(t, "--data", dir, "device", "rotate", signed); err == nil || !strings.Contains(err.Error(), "signed device") {
		t.Fatalf("rotate a signed device: %v", err)
	}
	if out, err := runGatewayCLI(t, "--data", dir, "audit", "verify"); err != nil || out != "audit chain ok · records=3\n" {
		t.Fatalf("audit verify: %v %q (want issued, revoked, issued)", err, out)
	}
}
