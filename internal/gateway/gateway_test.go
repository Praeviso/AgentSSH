package gateway_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/Praeviso/AgentSSH/internal/controlplane"
	"github.com/Praeviso/AgentSSH/internal/gateway"
	"github.com/Praeviso/AgentSSH/internal/remote"
	"github.com/Praeviso/AgentSSH/internal/remoteclient"
)

func init() {
	gateway.ScryptWorkFactor = 10
}

type fixture struct {
	dir    string
	store  *controlplane.Store
	keys   *controlplane.Keys
	server *gateway.Server
	client *remoteclient.Client
}

// enrolledGateway runs an in-process gateway behind a TLS ingress and enrolls
// one device home against it with the real client.
func enrolledGateway(t *testing.T) *fixture {
	t.Helper()
	dir := t.TempDir()
	if err := gateway.Init(dir, "master"); err != nil {
		t.Fatalf("init: %v", err)
	}
	store, err := gateway.OpenStore(filepath.Join(dir, gateway.FileDatabase))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	keys, err := controlplane.Unlock(dir, "master")
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	ingress := httptest.NewUnstartedServer(mux)
	// Like admin.Serve's per-request timeouts, scaled down: a streaming
	// execution must outlive them.
	ingress.Config.ReadTimeout = time.Second
	ingress.Config.WriteTimeout = time.Second
	ingress.StartTLS()
	t.Cleanup(ingress.Close)
	base := ingress.URL + "/agentssh"
	server := gateway.NewServer(dir, store, keys)
	handler, err := server.Handler(base)
	if err != nil {
		t.Fatal(err)
	}
	mux.Handle("/", handler)
	original := http.DefaultTransport
	transport := original.(*http.Transport).Clone()
	pool := x509.NewCertPool()
	pool.AddCert(ingress.Certificate())
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: pool}
	http.DefaultTransport = transport
	t.Cleanup(func() { http.DefaultTransport = original; transport.CloseIdleConnections() })

	pub, err := controlplane.LoadBundlePublicKey(dir)
	if err != nil {
		t.Fatal(err)
	}
	token, err := store.CreateEnrollToken("agent-vm", base, remote.PublicKeyFingerprint(pub), time.Minute, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	home := t.TempDir()
	if _, err := remoteclient.Enroll(context.Background(), home, base, token.String(), time.Now()); err != nil {
		t.Fatalf("enroll: %v", err)
	}
	client, err := remoteclient.NewClient(home)
	if err != nil {
		t.Fatal(err)
	}
	return &fixture{dir: dir, store: store, keys: keys, server: server, client: client}
}

func TestEnrolledDeviceIsRefusedAfterRevocation(t *testing.T) {
	f := enrolledGateway(t)
	store, client := f.store, f.client
	status, err := client.Status(context.Background())
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	if status.DeviceID != client.State.DeviceID || status.Status != remote.DeviceActive || status.Mode != remote.ModeGateway {
		t.Fatalf("status = %+v, want active device %s in gateway mode", status, client.State.DeviceID)
	}
	if err := store.RevokeDevice(client.State.DeviceID, time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Status(context.Background()); !remote.IsRevoked(err) {
		t.Fatalf("status after revoke: %v, want device_revoked", err)
	}
}

func TestSigningAndBundleEndpointsDoNotExist(t *testing.T) {
	client := enrolledGateway(t).client
	_, signErr := client.Sign(context.Background(), "web-1", []byte("userauth"))
	_, bundleErr := client.FetchBundle(context.Background())
	for name, err := range map[string]error{"sign": signErr, "bundle": bundleErr} {
		var apiErr *remote.APIError
		if !errors.As(err, &apiErr) || apiErr.Status != http.StatusNotFound {
			t.Errorf("%s: %v, want HTTP 404", name, err)
		}
	}
}
