package remoteclient_test

import (
	"context"
	"crypto/tls"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Praeviso/AgentSSH/internal/managedmode"
	"github.com/Praeviso/AgentSSH/internal/remote"
	"github.com/Praeviso/AgentSSH/internal/remoteclient"
)

func TestIngressFailureCacheBoundary(t *testing.T) {
	cp := newControlPlane(t)
	cached := cp.open(t)
	type gatewayResponse struct {
		status int
		body   string
	}
	var response atomic.Value
	ingress := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		value := response.Load().(gatewayResponse)
		w.WriteHeader(value.status)
		_, _ = w.Write([]byte(value.body))
	}))
	ingress.TLS = &tls.Config{Certificates: cp.http.TLS.Certificates, MinVersion: tls.VersionTLS13}
	ingress.StartTLS()
	defer ingress.Close()
	rewriteServerURL(t, cp.home, ingress.URL+"/plugins/agentssh")

	for _, tc := range []struct {
		name   string
		status int
		body   string
		grace  bool
	}{
		{"bad gateway", 502, "<html>backend down</html>", true},
		{"unavailable", 503, "", true},
		{"gateway timeout", 504, `{"message":"upstream timeout"}`, true},
		{"incomplete protocol body", 502, `{"code":"upstream_error"}`, true},
		{"protocol internal", 503, `{"code":"internal","error":"database unavailable"}`, false},
		{"revoked", 403, `{"code":"device_revoked","error":"revoked"}`, false},
		{"protocol at gateway status", 502, `{"code":"device_revoked","error":"revoked"}`, false},
		{"other server error", 500, "internal server error", false},
		{"bad success body", 200, "<html>not a bundle</html>", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			response.Store(gatewayResponse{tc.status, tc.body})
			session, err := remoteclient.Open(context.Background(), cp.home, remoteclient.OpenOptions{Refresh: true})
			if tc.grace {
				if err != nil || !session.Stale || session.Bundle.Version != cached.Bundle.Version {
					t.Fatalf("unexpired cache not used: %+v, %v", session, err)
				}
				_, err = remoteclient.Open(context.Background(), cp.home, remoteclient.OpenOptions{Refresh: true, Now: func() time.Time { return cached.Bundle.NotAfter }})
				var unreachable *remoteclient.UnreachableError
				if !errors.As(err, &unreachable) || !strings.Contains(err.Error(), "expired") {
					t.Fatalf("expired cache boundary: %v", err)
				}
			} else if err == nil || session != nil {
				t.Fatal("refusal or invalid response used cached configuration")
			}
		})
	}
}

func TestInvalidEnrollmentGivesCompleteRecovery(t *testing.T) {
	cp := newControlPlane(t)
	path := filepath.Join(managedmode.Dir(cp.home), managedmode.MarkerName)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, invalid := range [][]byte{
		append(append([]byte{}, data...), []byte("ca_fingerprint: retired\n")...),
		[]byte("server_url: http://invalid\n"),
		append(append([]byte{}, data...), []byte("---\n{}\n")...),
		[]byte(strings.Replace(string(data), cp.keys.BundlePublicKey(), "bad-key", 1)),
	} {
		if err := os.WriteFile(path, invalid, 0o600); err != nil {
			t.Fatal(err)
		}
		_, err := remoteclient.LoadState(cp.home)
		if err == nil || !strings.Contains(err.Error(), "agentssh remote leave") || !strings.Contains(err.Error(), "re-enroll") {
			t.Fatalf("incomplete recovery guidance: %v", err)
		}
	}
}

func TestClockSkewSurfacesSyncGuidance(t *testing.T) {
	cp := newControlPlane(t)
	cp.open(t)
	now := time.Now().Add(-35 * time.Second)
	cp.http.Close()
	cp.server.Now = func() time.Time { return now }
	mux := http.NewServeMux()
	ingress := httptest.NewUnstartedServer(mux)
	ingress.TLS = &tls.Config{Certificates: cp.http.TLS.Certificates, MinVersion: tls.VersionTLS13}
	ingress.StartTLS()
	defer ingress.Close()
	base := ingress.URL + "/plugins/agentssh"
	handler, err := cp.server.Handler(base)
	if err != nil {
		t.Fatal(err)
	}
	mux.Handle("/", handler)
	rewriteServerURL(t, cp.home, base)
	client, err := remoteclient.NewClient(cp.home)
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.Status(context.Background())
	var apiErr *remote.APIError
	if !errors.As(err, &apiErr) || apiErr.Code != "clock_skew" || !strings.Contains(err.Error(), "synchronize") || !strings.Contains(err.Error(), now.UTC().Format(time.RFC3339)) {
		t.Fatalf("clock diagnosis: %v", err)
	}
	if _, err := remoteclient.Open(context.Background(), cp.home, remoteclient.OpenOptions{Refresh: true}); err == nil {
		t.Fatal("clock refusal silently used cache")
	}
}
