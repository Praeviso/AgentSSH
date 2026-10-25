package gateway_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
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
	base    string
	ingress *httptest.Server
	handler *atomic.Pointer[http.Handler]
	// down makes the ingress answer 503, like a gateway that is unreachable.
	down *atomic.Bool
	// dropNextExec lets the gateway handle the next /exec but loses its
	// whole response, as if the connection died right after the request.
	dropNextExec *atomic.Bool
	dir          string
	store        *controlplane.Store
	keys         *controlplane.Keys
	server       *gateway.Server
	client       *remoteclient.Client
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
	first, err := server.Handler(base)
	if err != nil {
		t.Fatal(err)
	}
	current := new(atomic.Pointer[http.Handler])
	current.Store(&first)
	down, dropNextExec := new(atomic.Bool), new(atomic.Bool)
	mux.Handle("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handler := *current.Load()
		if down.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		if strings.HasSuffix(r.URL.Path, remote.PathExec) && dropNextExec.CompareAndSwap(true, false) {
			body, _ := io.ReadAll(r.Body)
			if conn, _, err := http.NewResponseController(w).Hijack(); err == nil {
				_ = conn.Close()
			}
			r = r.WithContext(context.Background())
			r.Body = io.NopCloser(bytes.NewReader(body))
			handler.ServeHTTP(httptest.NewRecorder(), r)
			return
		}
		handler.ServeHTTP(w, r)
	}))
	original := http.DefaultTransport
	transport := original.(*http.Transport).Clone()
	pool := x509.NewCertPool()
	pool.AddCert(ingress.Certificate())
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: pool}
	http.DefaultTransport = transport
	t.Cleanup(func() { http.DefaultTransport = original; transport.CloseIdleConnections() })

	f := &fixture{base: base, ingress: ingress, handler: current, down: down, dropNextExec: dropNextExec, dir: dir, store: store, keys: keys, server: server}
	f.client = f.enroll(t, "agent-vm")
	return f
}

// restart replaces the gateway with a new process over the same data
// directory: nothing in memory survives, the old process's runs are left to
// finish on their own.
func (f *fixture) restart(t *testing.T) {
	t.Helper()
	f.server = gateway.NewServer(f.dir, f.store, f.keys)
	handler, err := f.server.Handler(f.base)
	if err != nil {
		t.Fatal(err)
	}
	f.handler.Store(&handler)
}

// enroll enrolls another device home with the real client.
func (f *fixture) enroll(t *testing.T, name string) *remoteclient.Client {
	t.Helper()
	client, err := remoteclient.NewClient(f.enrollHome(t, name))
	if err != nil {
		t.Fatal(err)
	}
	return client
}

// enrollHome enrolls another device, activates it, and returns its home.
func (f *fixture) enrollHome(t *testing.T, name string) string {
	t.Helper()
	home := f.enrollInactive(t, name)
	state, err := remoteclient.LoadState(home)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := gateway.ActivateDevice(f.dir, f.store, state.DeviceID, gateway.MaxActivation, "local:test", "", time.Now()); err != nil {
		t.Fatalf("activate: %v", err)
	}
	return home
}

// enrollInactive enrolls another device, leaving it inactive as enrollment
// does, and returns its home.
func (f *fixture) enrollInactive(t *testing.T, name string) string {
	t.Helper()
	pub, err := controlplane.LoadBundlePublicKey(f.dir)
	if err != nil {
		t.Fatal(err)
	}
	token, err := f.store.CreateEnrollToken(name, f.base, remote.PublicKeyFingerprint(pub), time.Minute, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	home := t.TempDir()
	if _, err := remoteclient.Enroll(context.Background(), home, f.base, token.String(), remote.ModeGateway, time.Now()); err != nil {
		t.Fatalf("enroll: %v", err)
	}
	return home
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

// A device that expects a managed control plane is refused before /enroll,
// so its token still enrolls the device in gateway mode.
func TestManagedEnrollmentIsRefusedBeforeSpendingTheToken(t *testing.T) {
	f := enrolledGateway(t)
	pub, err := controlplane.LoadBundlePublicKey(f.dir)
	if err != nil {
		t.Fatal(err)
	}
	token, err := f.store.CreateEnrollToken("laptop", f.base, remote.PublicKeyFingerprint(pub), time.Minute, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	home := t.TempDir()
	_, err = remoteclient.Enroll(context.Background(), home, f.base, token.String(), remote.ModeManaged, time.Now())
	var mismatch *remoteclient.ModeMismatchError
	if !errors.As(err, &mismatch) || mismatch.Got != remote.ModeGateway {
		t.Fatalf("managed enrollment against a gateway: %v", err)
	}
	if _, err := remoteclient.Enroll(context.Background(), home, f.base, token.String(), remote.ModeGateway, time.Now()); err != nil {
		t.Fatalf("the refused enrollment spent the token: %v", err)
	}
}

// A gateway answers the device's hosts from its pushed inventory, and request
// status only from that device's own audit.
func TestHostsAndRequestStatusAreTheDevicesOwn(t *testing.T) {
	f, _ := execGateway(t)
	hosts, err := f.client.Hosts(context.Background())
	if err != nil || len(hosts.Hosts) != 1 || hosts.Hosts[0].Name != "web-1" {
		t.Fatalf("hosts = %+v, %v", hosts, err)
	}
	result, err := f.client.Exec(context.Background(), execReq("uptime"), io.Discard, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	reqID := result.Responses[0].ReqID
	status, err := f.client.RequestStatus(context.Background(), reqID)
	if err != nil || status.ReqID != reqID || status.Status != "completed" || status.Host != "web-1" {
		t.Fatalf("status = %+v, %v", status, err)
	}
	other := f.enroll(t, "other-vm")
	_, err = other.RequestStatus(context.Background(), reqID)
	var apiErr *remote.APIError
	if !errors.As(err, &apiErr) || apiErr.Code != remote.CodeRequestNotFound {
		t.Fatalf("another device read the request: %v", err)
	}
	if _, err := other.Hosts(context.Background()); !errors.As(err, &apiErr) || apiErr.Code != remote.CodeNoConfig {
		t.Fatalf("hosts without a configuration: %v", err)
	}
}

// A single-host run names its request before its output, on /exec and on
// every reattach, and says it ran on a host.
func TestRunFrameNamesTheRequestBeforeOutput(t *testing.T) {
	f, _ := execGateway(t)
	var seen []string
	req := execReq("uptime")
	req.Stream = true
	result, err := f.client.ExecNotify(context.Background(), req, func(run remote.ExecRun) { seen = append(seen, run.ReqID) }, io.Discard, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if len(seen) != 1 || seen[0] == "" || seen[0] != result.Responses[0].ReqID || result.TargetKind != "host" {
		t.Fatalf("run frames named %v; result %+v", seen, result)
	}
	replayed, err := f.client.Attach(context.Background(), result.RunID, io.Discard, io.Discard)
	if err != nil || replayed.TargetKind != "host" || replayed.Responses[0].ReqID != seen[0] {
		t.Fatalf("replay = %+v, %v", replayed, err)
	}
}
