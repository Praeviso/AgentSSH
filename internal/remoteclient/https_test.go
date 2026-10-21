package remoteclient_test

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Praeviso/AgentSSH/internal/executor"
	"github.com/Praeviso/AgentSSH/internal/managedmode"
	"github.com/Praeviso/AgentSSH/internal/remote"
	"github.com/Praeviso/AgentSSH/internal/remoteclient"
	"github.com/Praeviso/AgentSSH/internal/remoteserver"
)

func TestHTTPSRemoteSignedRunEndToEnd(t *testing.T) {
	cp := newControlPlaneWithProtocol(t, true)
	state, err := remoteclient.LoadState(cp.home)
	if err != nil || state.Protocol != remote.HTTPSProtocol || !strings.HasSuffix(state.ServerURL, "/v1/plugins/agentssh") {
		t.Fatalf("state=%+v err=%v", state, err)
	}
	for _, file := range []string{"ca.crt", "device.crt"} {
		if _, err := os.Stat(filepath.Join(managedmode.Dir(cp.home), file)); !os.IsNotExist(err) {
			t.Fatalf("v2 wrote %s: %v", file, err)
		}
	}
	info, err := os.Stat(filepath.Join(managedmode.Dir(cp.home), "device.key"))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("device key permissions: %v %v", info, err)
	}
	session := cp.open(t)
	exec := cp.executor(t, session)
	for range 2 {
		result := cp.run(exec, "echo https")
		if result.Err != nil || result.ExitCode != 0 || string(result.Stdout) != "https\n" || result.RemoteSignID == "" {
			t.Fatalf("run: %+v", result)
		}
	}
	entries, err := cp.store.SignLog(remoteserver.SignLogFilter{})
	if err != nil || len(entries) != 2 || entries[0].SignID == entries[1].SignID {
		t.Fatalf("sign log: %+v %v", entries, err)
	}
	if err := cp.store.RevokeDevice(cp.deviceID, time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := session.Client.Status(context.Background()); !remote.IsRevoked(err) {
		t.Fatalf("status after revoke: %v", err)
	}
	if _, err := remoteclient.Open(context.Background(), cp.home, remoteclient.OpenOptions{Refresh: true}); !remote.IsRevoked(err) {
		t.Fatalf("bundle after revoke used cache: %v", err)
	}
	if result := cp.run(exec, "echo forbidden"); result.Err == nil {
		t.Fatal("revoked device connected")
	}
}

func TestHTTPSIdentityDisableAndUnreachableFailClosed(t *testing.T) {
	cp := newControlPlaneWithProtocol(t, true)
	session := cp.open(t)
	exec := cp.executor(t, session)
	if err := cp.store.DisableIdentity("web", time.Now()); err != nil {
		t.Fatal(err)
	}
	if result := cp.run(exec, "echo forbidden"); result.Err == nil {
		t.Fatal("disabled identity connected")
	}
	cp.http.Close()
	if result := cp.run(exec, "echo offline"); result.Err == nil {
		t.Fatal("offline control plane connected")
	}
}

func TestHTTPSRevocationCancelsRunningCommand(t *testing.T) {
	old := remoteclient.WatchInterval
	remoteclient.WatchInterval = 20 * time.Millisecond
	t.Cleanup(func() { remoteclient.WatchInterval = old })
	cp := newControlPlaneWithProtocol(t, true)
	exec := cp.executor(t, cp.open(t))
	done := make(chan executor.Result, 1)
	go func() { done <- cp.run(exec, "block") }()
	cp.ssh.waitBlocked(t)
	if err := cp.store.RevokeDevice(cp.deviceID, time.Now()); err != nil {
		t.Fatal(err)
	}
	select {
	case result := <-done:
		if !errors.Is(result.Err, remoteclient.ErrRevokedDuringRun) {
			t.Fatalf("run: %v", result.Err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("running command not cancelled")
	}
}

func TestHTTPSEnrollmentPinsAndRedirects(t *testing.T) {
	cp := newControlPlaneWithProtocol(t, true)
	base := cp.http.URL + "/v1/plugins/agentssh"
	token, err := cp.store.CreateHTTPSEnrollToken("other", base, remote.PublicKeyFingerprint(cp.keys.BundleKey.Public().(ed25519.PublicKey)), time.Minute, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := remoteclient.Enroll(context.Background(), t.TempDir(), cp.http.URL, token.String(), time.Now()); err == nil {
		t.Fatal("wrong URL accepted")
	}
	wrongPin := token
	wrongPin.BundleFingerprint = strings.Repeat("0", 64)
	home := t.TempDir()
	if _, err := remoteclient.Enroll(context.Background(), home, base, wrongPin.String(), time.Now()); err == nil || !strings.Contains(err.Error(), "bundle public key") {
		t.Fatalf("wrong pin: %v", err)
	}
	if managedmode.Enrolled(home) {
		t.Fatal("pin failure activated remote mode")
	}
	if _, err := remoteclient.Enroll(context.Background(), t.TempDir(), base, token.String(), time.Now()); err == nil {
		t.Fatal("used token accepted")
	}

	requests := 0
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { requests++; w.WriteHeader(500) }))
	t.Cleanup(target.Close)
	ingress := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
	}))
	ingress.TLS = &tls.Config{Certificates: cp.http.TLS.Certificates, MinVersion: tls.VersionTLS13}
	ingress.StartTLS()
	t.Cleanup(ingress.Close)
	token.ServerURL = ingress.URL
	_, err = remoteclient.Enroll(context.Background(), t.TempDir(), ingress.URL, token.String(), time.Now())
	var apiErr *remote.APIError
	if !errors.As(err, &apiErr) || requests != 0 {
		t.Fatalf("redirect: %v; forwarded requests=%d", err, requests)
	}
}
