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

	"github.com/Praeviso/AgentSSH/internal/managedmode"
	"github.com/Praeviso/AgentSSH/internal/remote"
	"github.com/Praeviso/AgentSSH/internal/remoteclient"
	"gopkg.in/yaml.v3"
)

func TestEnrollmentStateIsMinimal(t *testing.T) {
	cp := newControlPlane(t)
	data, err := os.ReadFile(filepath.Join(managedmode.Dir(cp.home), managedmode.MarkerName))
	if err != nil {
		t.Fatal(err)
	}
	var state map[string]any
	if err := yaml.Unmarshal(data, &state); err != nil {
		t.Fatal(err)
	}
	if len(state) != 5 || state["mode"] != remote.ModeManaged {
		t.Fatalf("enrollment fields: %+v", state)
	}
	for _, field := range []string{"server_url", "device_id", "bundle_public_key", "enrolled_at", "mode"} {
		if _, ok := state[field]; !ok {
			t.Fatalf("missing %s", field)
		}
	}
	entries, err := os.ReadDir(managedmode.Dir(cp.home))
	if err != nil || len(entries) != 2 {
		t.Fatalf("enrollment files: %v %v", entries, err)
	}
	key, err := os.Stat(filepath.Join(managedmode.Dir(cp.home), "device.key"))
	if err != nil || key.Mode().Perm() != 0o600 {
		t.Fatalf("device key: %v %v", key, err)
	}
	path := filepath.Join(managedmode.Dir(cp.home), managedmode.MarkerName)
	if err := os.WriteFile(path, append(data, []byte("unknown_field: retired\n")...), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := remoteclient.LoadState(cp.home); err == nil {
		t.Fatal("unexpected enrollment field accepted")
	}
}

func TestHTTPSEnrollmentPinsAndRedirects(t *testing.T) {
	cp := newControlPlane(t)
	base := cp.base
	token, err := cp.store.CreateEnrollToken("other", base, remote.PublicKeyFingerprint(cp.keys.BundleKey.Public().(ed25519.PublicKey)), time.Minute, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := remoteclient.Enroll(context.Background(), t.TempDir(), cp.http.URL, token.String(), remote.ModeManaged, time.Now()); err == nil {
		t.Fatal("wrong URL accepted")
	}
	wrongPin := token
	wrongPin.BundleFingerprint = strings.Repeat("0", 64)
	home := t.TempDir()
	if _, err := remoteclient.Enroll(context.Background(), home, base, wrongPin.String(), remote.ModeManaged, time.Now()); err == nil || !strings.Contains(err.Error(), "bundle public key") {
		t.Fatalf("wrong pin: %v", err)
	}
	if managedmode.Enrolled(home) {
		t.Fatal("pin failure activated remote mode")
	}
	if _, err := remoteclient.Enroll(context.Background(), t.TempDir(), base, token.String(), remote.ModeManaged, time.Now()); err == nil {
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
	_, err = remoteclient.Enroll(context.Background(), t.TempDir(), ingress.URL, token.String(), remote.ModeManaged, time.Now())
	var apiErr *remote.APIError
	if !errors.As(err, &apiErr) || requests != 0 {
		t.Fatalf("redirect: %v; forwarded requests=%d", err, requests)
	}
}
