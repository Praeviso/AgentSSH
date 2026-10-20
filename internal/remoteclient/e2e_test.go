package remoteclient_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Praeviso/AgentSSH/internal/config"
	"github.com/Praeviso/AgentSSH/internal/executor"
	"github.com/Praeviso/AgentSSH/internal/inventory"
	"github.com/Praeviso/AgentSSH/internal/managedmode"
	"github.com/Praeviso/AgentSSH/internal/policy"
	"github.com/Praeviso/AgentSSH/internal/remote"
	"github.com/Praeviso/AgentSSH/internal/remoteclient"
	"github.com/Praeviso/AgentSSH/internal/remoteserver"
	"golang.org/x/crypto/ssh"
)

func init() {
	remoteserver.ScryptWorkFactor = 10
}

// controlPlane is an in-process agentssh-server plus one enrolled client home.
type controlPlane struct {
	dir      string
	store    *remoteserver.Store
	keys     *remoteserver.Keys
	server   *remoteserver.Server
	http     *httptest.Server
	identity ssh.PublicKey
	home     string
	deviceID string
	ssh      *sshServer
}

func newControlPlane(t *testing.T) *controlPlane {
	t.Helper()
	cp := &controlPlane{dir: t.TempDir()}
	now := time.Now()
	if err := remoteserver.Init(cp.dir, "master", []string{"127.0.0.1"}, now); err != nil {
		t.Fatalf("server init: %v", err)
	}
	store, err := remoteserver.OpenStore(filepath.Join(cp.dir, remoteserver.FileDatabase))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	keys, err := remoteserver.Unlock(cp.dir, "master")
	if err != nil {
		t.Fatalf("unlock: %v", err)
	}
	cp.store, cp.keys = store, keys
	cp.server = remoteserver.NewServer(store, keys)
	cp.http = httptest.NewUnstartedServer(cp.server.Handler())
	cp.http.TLS = cp.server.TLSConfig()
	cp.http.Config.ErrorLog = log.New(io.Discard, "", 0)
	cp.http.StartTLS()
	t.Cleanup(cp.http.Close)

	recipient, err := remoteserver.LoadRecipient(cp.dir)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := remoteserver.NewIdentity("web", recipient, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.CreateIdentity(identity); err != nil {
		t.Fatal(err)
	}
	cp.identity, _, _, _, err = ssh.ParseAuthorizedKey([]byte(identity.PublicKey))
	if err != nil {
		t.Fatal(err)
	}

	cp.home = t.TempDir()
	state, err := remoteclient.Enroll(context.Background(), cp.home, cp.http.URL, cp.token(t), now)
	if err != nil {
		t.Fatalf("enroll: %v", err)
	}
	cp.deviceID = state.DeviceID

	cp.ssh = newSSHServer(t, cp.identity)
	cp.push(t, "deploy", "web")
	return cp
}

func (cp *controlPlane) token(t *testing.T) string {
	t.Helper()
	id, secret, err := cp.store.CreateEnrollToken("laptop", time.Minute, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return remote.EnrollToken{ID: id, Secret: secret, CAFingerprint: cp.keys.CAFingerprint()}.String()
}

func (cp *controlPlane) push(t *testing.T, user string, identity string) {
	t.Helper()
	inv := fmt.Sprintf("host_key_policy: accept-new\nhosts:\n  web-1: {addr: 127.0.0.1, port: %d, user: %s, identity: %s, tags: [web]}\n", cp.ssh.port(), user, identity)
	pol := "version: 1\nrules:\n  - {name: allow-echo, match: {cmd_regex: '^echo '}, action: allow}\n"
	if _, err := remoteserver.PushConfig(cp.store, cp.deviceID, inv, pol, time.Now()); err != nil {
		t.Fatalf("push config: %v", err)
	}
}

func (cp *controlPlane) executor(t *testing.T, session *remoteclient.Session) executor.Executor {
	t.Helper()
	options := executor.NativeOptions{KnownHostsPath: filepath.Join(cp.home, "known_hosts")}
	session.ApplyNativeOptions(&options)
	exec := session.WrapExecutor(executor.NewNativeExecutor(options))
	t.Cleanup(func() { _ = exec.Close() })
	return exec
}

func (cp *controlPlane) open(t *testing.T) *remoteclient.Session {
	t.Helper()
	session, err := remoteclient.Open(context.Background(), cp.home, remoteclient.OpenOptions{Refresh: true})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	return session
}

func (cp *controlPlane) run(exec executor.Executor, command string) executor.Result {
	target := inventory.Target{Name: "web-1", Host: inventory.Host{Addr: "127.0.0.1", Port: cp.ssh.port(), User: "deploy", Identity: "web"}}
	return exec.Run(context.Background(), executor.Request{Target: target, Command: command})
}

func TestRemoteSignedRunEndToEnd(t *testing.T) {
	cp := newControlPlane(t)
	session := cp.open(t)
	if session.Bundle.Version != 1 || len(session.Inventory.Hosts) != 1 {
		t.Fatalf("bundle = v%d with %d hosts", session.Bundle.Version, len(session.Inventory.Hosts))
	}
	exec := cp.executor(t, session)

	result := cp.run(exec, "echo hello")
	if result.Err != nil || result.ExitCode != 0 || result.Stdout != "hello\n" {
		t.Fatalf("run = %+v (err %v)", result, result.Err)
	}
	if !strings.HasPrefix(result.RemoteSignID, "sg_") {
		t.Fatalf("RemoteSignID = %q, want a signing-log id", result.RemoteSignID)
	}
	entries, err := cp.store.SignLog(remoteserver.SignLogFilter{DeviceID: cp.deviceID})
	if err != nil {
		t.Fatal(err)
	}
	last := entries[len(entries)-1]
	if last.SignID != result.RemoteSignID || last.Result != remoteserver.SignOK || last.User != "deploy" || last.Identity != "web" {
		t.Fatalf("sign log = %+v", last)
	}

	// No connection reuse: every command is a fresh login with a fresh signature.
	second := cp.run(exec, "echo again")
	if second.Err != nil || second.RemoteSignID == "" || second.RemoteSignID == result.RemoteSignID {
		t.Fatalf("second run should be signed anew, got %+v (err %v)", second, second.Err)
	}
}

// A login the control plane signed but the target then refused still carries
// the signing-log id, so the failed run reconciles with the signing log.
func TestFailedLoginAfterSigningKeepsSignID(t *testing.T) {
	cp := newControlPlane(t)
	cp.ssh = startSSHServer(t, cp.identity, true)
	cp.push(t, "deploy", "web")
	exec := cp.executor(t, cp.open(t))

	result := cp.run(exec, "echo hello")
	if result.Err == nil {
		t.Fatalf("run against a refusing server succeeded: %+v", result)
	}
	if !strings.HasPrefix(result.RemoteSignID, "sg_") {
		t.Fatalf("RemoteSignID = %q after a signed but refused login, want the signing-log id (err %v)", result.RemoteSignID, result.Err)
	}
	entries, err := cp.store.SignLog(remoteserver.SignLogFilter{DeviceID: cp.deviceID})
	if err != nil {
		t.Fatal(err)
	}
	if last := entries[len(entries)-1]; last.SignID != result.RemoteSignID || last.Result != remoteserver.SignOK {
		t.Fatalf("sign log = %+v, want the signed entry %s", last, result.RemoteSignID)
	}
}

func TestRevokedDeviceCannotLogInOrRefresh(t *testing.T) {
	cp := newControlPlane(t)
	session := cp.open(t)
	exec := cp.executor(t, session)
	if r := cp.run(exec, "echo ok"); r.Err != nil {
		t.Fatalf("pre-revoke run: %v", r.Err)
	}
	if err := cp.store.RevokeDevice(cp.deviceID, time.Now()); err != nil {
		t.Fatal(err)
	}

	result := cp.run(exec, "echo ok")
	if result.Err == nil {
		t.Fatal("revoked device still logged in")
	}
	if hint := executor.ConnectHint(result.Err); !strings.Contains(hint, "revoked") {
		t.Fatalf("hint = %q, want revocation guidance", hint)
	}
	entries, _ := cp.store.SignLog(remoteserver.SignLogFilter{DeviceID: cp.deviceID})
	if last := entries[len(entries)-1]; last.Result != remoteserver.SignRejected || last.Reason != "device revoked" || last.Host != "web-1" {
		t.Fatalf("sign log = %+v, want the revoked attempt recorded", last)
	}
	_, err := remoteclient.Open(context.Background(), cp.home, remoteclient.OpenOptions{Refresh: true})
	if !remote.IsRevoked(err) {
		t.Fatalf("refresh after revoke = %v, want a revocation refusal", err)
	}
}

func TestDisabledIdentityStopsSigning(t *testing.T) {
	cp := newControlPlane(t)
	exec := cp.executor(t, cp.open(t))
	if err := cp.store.DisableIdentity("web", time.Now()); err != nil {
		t.Fatal(err)
	}
	if result := cp.run(exec, "echo ok"); result.Err == nil {
		t.Fatal("disabled identity still signed a login")
	}
	entries, _ := cp.store.SignLog(remoteserver.SignLogFilter{DeviceID: cp.deviceID})
	last := entries[len(entries)-1]
	if last.Result != remoteserver.SignRejected || !strings.Contains(last.Reason, "disabled") {
		t.Fatalf("sign log = %+v, want a logged rejection", last)
	}
}

func TestSigningEndpointOnlySignsMatchingUserauth(t *testing.T) {
	cp := newControlPlane(t)
	client, err := remoteclient.NewClient(cp.home)
	if err != nil {
		t.Fatal(err)
	}
	userauth := func(user string, pub []byte) []byte {
		return ssh.Marshal(struct {
			Session []byte
			Type    byte
			User    string
			Service string
			Method  string
			Sign    bool
			Algo    string
			PubKey  []byte
		}{[]byte("0123456789abcdef0123456789abcdef"), 50, user, "ssh-connection", "publickey", true, ssh.KeyAlgoED25519, pub})
	}
	otherPub, _, _ := ed25519.GenerateKey(rand.Reader)
	otherSSH, _ := ssh.NewPublicKey(otherPub)
	cases := map[string]struct {
		host string
		data []byte
	}{
		"arbitrary data":  {"web-1", []byte("sign me")},
		"wrong user":      {"web-1", userauth("root", cp.identity.Marshal())},
		"wrong key":       {"web-1", userauth("deploy", otherSSH.Marshal())},
		"unassigned host": {"db-1", userauth("deploy", cp.identity.Marshal())},
	}
	for name, tc := range cases {
		_, err := client.Sign(context.Background(), tc.host, tc.data)
		var apiErr *remote.APIError
		if !errors.As(err, &apiErr) {
			t.Errorf("%s: Sign = %v, want a control-plane refusal", name, err)
		}
	}
	resp, err := client.Sign(context.Background(), "web-1", userauth("deploy", cp.identity.Marshal()))
	if err != nil || resp.SignID == "" {
		t.Fatalf("valid userauth refused: %v", err)
	}
}

func TestUnreachableControlPlaneFailsClosed(t *testing.T) {
	cp := newControlPlane(t)
	session := cp.open(t)
	exec := cp.executor(t, session)
	cp.http.Close()

	result := cp.run(exec, "echo ok")
	if result.Err == nil {
		t.Fatal("login succeeded without the control plane")
	}
	if hint := executor.ConnectHint(result.Err); !strings.Contains(hint, "unreachable") {
		t.Fatalf("hint = %q, want an unreachable control plane hint", hint)
	}

	// Inside the bundle's validity window the cached config is still usable...
	later := time.Now().Add(2 * time.Minute)
	stale, err := remoteclient.Open(context.Background(), cp.home, remoteclient.OpenOptions{Now: func() time.Time { return later }})
	if err != nil || !stale.Stale {
		t.Fatalf("open within validity = %+v, %v; want a stale cached session", stale, err)
	}
	// ...but not after it expires.
	expired := session.Bundle.NotAfter.Add(time.Second)
	if _, err := remoteclient.Open(context.Background(), cp.home, remoteclient.OpenOptions{Now: func() time.Time { return expired }}); err == nil {
		t.Fatal("expired cached configuration was used while the control plane was unreachable")
	}
}

func TestBundleRollbackAndForeignBundlesAreRejected(t *testing.T) {
	cp := newControlPlane(t)
	cp.open(t)

	// Raise the rollback floor above what the server will serve.
	cachePath := filepath.Join(managedmode.Dir(cp.home), "bundle.cache.json")
	var cache map[string]any
	data, _ := os.ReadFile(cachePath)
	_ = json.Unmarshal(data, &cache)
	cache["max_version"] = 99
	data, _ = json.Marshal(cache)
	if err := os.WriteFile(cachePath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := remoteclient.Open(context.Background(), cp.home, remoteclient.OpenOptions{Refresh: true}); err == nil || !strings.Contains(err.Error(), "rollback") {
		t.Fatalf("older bundle accepted: %v", err)
	}

	// A correctly signed bundle for another device is refused.
	forged := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != remote.PathBundle {
			cp.server.Handler().ServeHTTP(w, r)
			return
		}
		raw, sig, _ := remote.SignBundle(remote.Bundle{Version: 100, DeviceID: "dev_someone_else", NotAfter: time.Now().Add(time.Minute)}, cp.keys.BundleKey)
		_ = json.NewEncoder(w).Encode(remote.BundleResponse{Bundle: raw, Signature: sig})
	}))
	forged.TLS = cp.server.TLSConfig()
	forged.StartTLS()
	defer forged.Close()
	rewriteServerURL(t, cp.home, forged.URL)
	if _, err := remoteclient.Open(context.Background(), cp.home, remoteclient.OpenOptions{Refresh: true}); err == nil || !strings.Contains(err.Error(), "not this device") {
		t.Fatalf("foreign bundle accepted: %v", err)
	}
}

func rewriteServerURL(t *testing.T, home string, url string) {
	t.Helper()
	path := filepath.Join(managedmode.Dir(home), managedmode.MarkerName)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	state, err := remoteclient.LoadState(home)
	if err != nil {
		t.Fatal(err)
	}
	data = []byte(strings.Replace(string(data), state.ServerURL, url, 1))
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestEnrollmentTokenChecks(t *testing.T) {
	cp := newControlPlane(t)
	token := cp.token(t)
	if _, err := remoteclient.Enroll(context.Background(), t.TempDir(), cp.http.URL, token, time.Now()); err != nil {
		t.Fatalf("first enroll: %v", err)
	}
	if _, err := remoteclient.Enroll(context.Background(), t.TempDir(), cp.http.URL, token, time.Now()); err == nil {
		t.Fatal("enrollment token was accepted twice")
	}
	if _, err := remoteclient.Enroll(context.Background(), cp.home, cp.http.URL, cp.token(t), time.Now()); err == nil {
		t.Fatal("an already enrolled home enrolled again")
	}
	parsed, _ := remote.ParseEnrollToken(cp.token(t))
	parsed.CAFingerprint = strings.Repeat("00", 32)
	home := t.TempDir()
	if _, err := remoteclient.Enroll(context.Background(), home, cp.http.URL, parsed.String(), time.Now()); err == nil {
		t.Fatal("enrollment trusted a server whose CA does not match the token")
	}
	if managedmode.Enrolled(home) {
		t.Fatal("a failed enrollment left the home in remote mode")
	}
}

func TestRevocationCancelsRunningCommand(t *testing.T) {
	old := remoteclient.WatchInterval
	remoteclient.WatchInterval = 20 * time.Millisecond
	defer func() { remoteclient.WatchInterval = old }()

	cp := newControlPlane(t)
	exec := cp.executor(t, cp.open(t))
	done := make(chan executor.Result, 1)
	go func() { done <- cp.run(exec, "block") }()
	cp.ssh.waitBlocked(t)
	if err := cp.store.RevokeDevice(cp.deviceID, time.Now()); err != nil {
		t.Fatal(err)
	}
	select {
	case result := <-done:
		if !errors.Is(result.Err, remoteclient.ErrRevokedDuringRun) || result.ExitCode != -1 {
			t.Fatalf("result = %+v (err %v), want revocation cancel", result, result.Err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("running command was not cancelled after revocation")
	}
}

func TestEnrolledHomeUsesRemoteConfigAndRefusesLocalWrites(t *testing.T) {
	cp := newControlPlane(t)
	t.Setenv(config.EnvStateDir, "")
	local := "version: 1\nrules:\n  - {name: no-echo-secret, match: {cmd_regex: '^echo secret'}, action: deny}\n  - {name: allow-all, match: {cmd_regex: '.*'}, action: allow}\n"
	if err := os.WriteFile(filepath.Join(cp.home, "policy.yaml"), []byte(local), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cp.home, "inventory.yaml"), []byte("hosts:\n  local-only: {addr: 10.9.9.9}\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := config.LoadHome(cp.home)
	if err != nil {
		t.Fatalf("LoadHome: %v", err)
	}
	if cfg.Remote == nil {
		t.Fatal("enrolled home loaded in local mode")
	}
	if _, ok := cfg.Inventory.Hosts["local-only"]; ok || len(cfg.Inventory.Hosts) != 1 {
		t.Fatalf("inventory = %v, want only the managed host", cfg.Inventory.Hosts)
	}
	engine, err := policy.NewEngine(cfg.Policy, cfg.Inventory)
	if err != nil {
		t.Fatal(err)
	}
	if d, _ := engine.Evaluate("web-1", "echo secret"); d.Action != policy.ActionDeny {
		t.Fatalf("local deny overlay not applied: %+v", d)
	}
	if d, _ := engine.Evaluate("web-1", "uptime"); d.Action != policy.ActionDeny || d.Rule != policy.RuleDefaultDeny {
		t.Fatalf("local allow loosened the remote policy: %+v", d)
	}
	if d, _ := engine.Evaluate("web-1", "echo hi"); d.Action != policy.ActionAllow {
		t.Fatalf("remote allow lost: %+v", d)
	}

	if err := inventory.Save(cfg.Paths.InventoryFile, inventory.Inventory{}); !errors.Is(err, managedmode.ErrManaged) {
		t.Fatalf("inventory.Save = %v, want ErrManaged", err)
	}
	if err := policy.Save(cfg.Paths.PolicyFile, policy.Config{}); !errors.Is(err, managedmode.ErrManaged) {
		t.Fatalf("policy.Save = %v, want ErrManaged", err)
	}

	if err := remoteclient.Leave(cp.home); err != nil {
		t.Fatal(err)
	}
	cfg, err = config.LoadHome(cp.home)
	if err != nil || cfg.Remote != nil {
		t.Fatalf("after leave: remote=%v err=%v", cfg != nil && cfg.Remote != nil, err)
	}
	if _, ok := cfg.Inventory.Hosts["local-only"]; !ok {
		t.Fatal("local inventory not restored after leave")
	}
}

// sshServer accepts exactly one public key and runs "echo ..." and "block".
type sshServer struct {
	listener net.Listener
	hostKey  ssh.Signer
	allowed  ssh.PublicKey
	// rejectSigned fails the login only after the signature has been checked,
	// like a server that accepts the key offer but then refuses the user.
	rejectSigned bool
	wg           sync.WaitGroup
	blocked      chan struct{}
	once         sync.Once
}

func newSSHServer(t *testing.T, allowed ssh.PublicKey) *sshServer {
	t.Helper()
	return startSSHServer(t, allowed, false)
}

func startSSHServer(t *testing.T, allowed ssh.PublicKey, rejectSigned bool) *sshServer {
	t.Helper()
	_, hostPriv, _ := ed25519.GenerateKey(rand.Reader)
	hostKey, err := ssh.NewSignerFromKey(hostPriv)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &sshServer{listener: ln, hostKey: hostKey, allowed: allowed, rejectSigned: rejectSigned, blocked: make(chan struct{})}
	s.wg.Add(1)
	go s.accept()
	t.Cleanup(func() {
		_ = ln.Close()
		s.wg.Wait()
	})
	return s
}

func (s *sshServer) port() int {
	return s.listener.Addr().(*net.TCPAddr).Port
}

func (s *sshServer) waitBlocked(t *testing.T) {
	t.Helper()
	select {
	case <-s.blocked:
	case <-time.After(5 * time.Second):
		t.Fatal("blocking command never started")
	}
}

func (s *sshServer) accept() {
	defer s.wg.Done()
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			return
		}
		s.wg.Add(1)
		go s.handle(conn)
	}
}

func (s *sshServer) handle(conn net.Conn) {
	defer s.wg.Done()
	cfg := &ssh.ServerConfig{PublicKeyCallback: func(_ ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
		if string(key.Marshal()) == string(s.allowed.Marshal()) {
			return nil, nil
		}
		return nil, errors.New("unknown key")
	}}
	if s.rejectSigned {
		cfg.VerifiedPublicKeyCallback = func(ssh.ConnMetadata, ssh.PublicKey, *ssh.Permissions, string) (*ssh.Permissions, error) {
			return nil, errors.New("user refused")
		}
	}
	cfg.AddHostKey(s.hostKey)
	sshConn, chans, reqs, err := ssh.NewServerConn(conn, cfg)
	if err != nil {
		_ = conn.Close()
		return
	}
	defer func() { _ = sshConn.Close() }()
	closed := make(chan struct{})
	go func() {
		_ = sshConn.Wait()
		close(closed)
	}()
	go ssh.DiscardRequests(reqs)
	for ch := range chans {
		channel, requests, err := ch.Accept()
		if err != nil {
			continue
		}
		go s.session(channel, requests, closed)
	}
}

func (s *sshServer) session(channel ssh.Channel, requests <-chan *ssh.Request, closed <-chan struct{}) {
	defer func() { _ = channel.Close() }()
	for req := range requests {
		if req.Type != "exec" {
			_ = req.Reply(false, nil)
			continue
		}
		var payload struct{ Command string }
		_ = ssh.Unmarshal(req.Payload, &payload)
		_ = req.Reply(true, nil)
		switch {
		case payload.Command == "block":
			s.once.Do(func() { close(s.blocked) })
			<-closed // until the client hangs up
			return
		case strings.HasPrefix(payload.Command, "echo "):
			_, _ = channel.Write([]byte(strings.TrimPrefix(payload.Command, "echo ") + "\n"))
		case payload.Command == executor.OSProbeCommand:
			_, _ = channel.Write([]byte("Linux\n"))
		}
		_, _ = channel.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))
		return
	}
}
