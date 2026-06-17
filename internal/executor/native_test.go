package executor

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/Praeviso/AgentSSH/internal/inventory"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

func TestNativeExecutorExecSuccessAndRemoteNonZero(t *testing.T) {
	home := t.TempDir()
	clientSigner := writeClientKey(t, home)
	server := newTestSSHServer(t, clientSigner.PublicKey())
	defer server.Close()

	writeKnownHosts(t, home, server.Addr(), server.HostSigner.PublicKey())

	exec := NewNativeExecutor(NativeOptions{
		KnownHostsPath: filepath.Join(home, ".ssh", "known_hosts"),
		ConfigPath:     filepath.Join(home, ".ssh", "config"),
	})
	target := inventory.Target{Name: "test", Host: inventory.Host{Addr: server.Host(), Port: server.Port(), User: "test"}}

	result := exec.Run(context.Background(), Request{Target: target, Command: "ok"})
	if result.Err != nil || result.ExitCode != 0 || result.Stdout != "ok\n" {
		t.Fatalf("success result = %#v err=%v", result, result.Err)
	}
	if len(result.Argv) == 0 || result.Argv[0] != nativeArgv0 {
		t.Fatalf("native argv = %#v", result.Argv)
	}
	t.Logf("native exec command=ok exit_code=%d err_nil=%t stdout=%q argv0=%q", result.ExitCode, result.Err == nil, result.Stdout, result.Argv[0])

	result = exec.Run(context.Background(), Request{Target: target, Command: "exit7"})
	if result.Err != nil || result.ExitCode != 7 {
		t.Fatalf("exit7 result = %#v err=%v", result, result.Err)
	}
	t.Logf("native exec command=exit7 exit_code=%d err_nil=%t stderr=%q", result.ExitCode, result.Err == nil, result.Stderr)
}

func TestNativeExecutorRunStreaming(t *testing.T) {
	home := t.TempDir()
	clientSigner := writeClientKey(t, home)
	server := newTestSSHServer(t, clientSigner.PublicKey())
	defer server.Close()

	writeKnownHosts(t, home, server.Addr(), server.HostSigner.PublicKey())

	exec := NewNativeExecutor(NativeOptions{
		KnownHostsPath: filepath.Join(home, ".ssh", "known_hosts"),
		ConfigPath:     filepath.Join(home, ".ssh", "config"),
	})
	target := inventory.Target{Name: "test", Host: inventory.Host{Addr: server.Host(), Port: server.Port(), User: "test"}}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	result := exec.RunStreaming(context.Background(), Request{Target: target, Command: "stream-secret"}, &stdout, &stderr)
	if result.Err != nil || result.ExitCode != 0 {
		t.Fatalf("stream result = %#v err=%v", result, result.Err)
	}
	if result.Stdout != "" || result.Stderr != "" {
		t.Fatalf("stream result carries buffered output: %#v", result)
	}
	if stdout.String() != "line1\npassword=secret123\nline3\n" || stderr.String() != "warn=secret\n" {
		t.Fatalf("stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
	t.Logf("native streaming stdout=%q stderr=%q exit_code=%d", stdout.String(), stderr.String(), result.ExitCode)
}

func TestNativeExecutorHostKeyRejected(t *testing.T) {
	home := t.TempDir()
	clientSigner := writeClientKey(t, home)
	server := newTestSSHServer(t, clientSigner.PublicKey())
	defer server.Close()

	wrongKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate wrong key: %v", err)
	}
	wrongSigner, err := ssh.NewSignerFromKey(wrongKey)
	if err != nil {
		t.Fatalf("wrong signer: %v", err)
	}
	writeKnownHosts(t, home, server.Addr(), wrongSigner.PublicKey())

	exec := NewNativeExecutor(NativeOptions{
		KnownHostsPath: filepath.Join(home, ".ssh", "known_hosts"),
		ConfigPath:     filepath.Join(home, ".ssh", "config"),
	})
	target := inventory.Target{Name: "test", Host: inventory.Host{Addr: server.Host(), Port: server.Port(), User: "test"}}
	result := exec.Run(context.Background(), Request{Target: target, Command: "ok"})
	if result.Err == nil || result.ExitCode != -1 {
		t.Fatalf("hostkey rejection result = %#v err=%v", result, result.Err)
	}
	t.Logf("native hostkey_rejected exit_code=%d err_nil=%t argv0=%q", result.ExitCode, result.Err == nil, result.Argv[0])
}

func TestNativeExecutorAcceptNewTrustsUnknownHost(t *testing.T) {
	home := t.TempDir()
	clientSigner := writeClientKey(t, home)
	server := newTestSSHServer(t, clientSigner.PublicKey())
	defer server.Close()

	knownHostsPath := filepath.Join(home, ".ssh", "known_hosts")
	exec := NewNativeExecutor(NativeOptions{
		KnownHostsPath: knownHostsPath,
		ConfigPath:     filepath.Join(home, ".ssh", "config"),
		HostKeyPolicy:  "accept-new",
	})
	target := inventory.Target{Name: "test", Host: inventory.Host{Addr: server.Host(), Port: server.Port(), User: "test"}}
	result := exec.Run(context.Background(), Request{Target: target, Command: "ok"})
	if result.Err != nil || result.ExitCode != 0 {
		t.Fatalf("accept-new result = %#v err=%v", result, result.Err)
	}

	data, err := os.ReadFile(knownHostsPath)
	if err != nil {
		t.Fatalf("read known_hosts: %v", err)
	}
	if len(data) == 0 {
		t.Fatal("known_hosts was not updated")
	}

	strictExec := NewNativeExecutor(NativeOptions{
		KnownHostsPath: knownHostsPath,
		ConfigPath:     filepath.Join(home, ".ssh", "config"),
	})
	result = strictExec.Run(context.Background(), Request{Target: target, Command: "ok"})
	if result.Err != nil || result.ExitCode != 0 {
		t.Fatalf("strict result after accept-new = %#v err=%v", result, result.Err)
	}
	t.Logf("native accept_new wrote_known_hosts=%t strict_reconnect_exit_code=%d", len(data) > 0, result.ExitCode)
}

func TestResolveAliasFromSSHConfig(t *testing.T) {
	home := t.TempDir()
	configPath := filepath.Join(home, "config")
	if err := os.WriteFile(configPath, []byte(`
Host prod-web
  HostName 10.0.0.11
  User deploy
  Port 2222
  IdentityFile ~/keys/prod_ed25519
  ProxyJump jump@bastion:2200
`), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	t.Setenv("HOME", home)
	exec := NewNativeExecutor(NativeOptions{ConfigPath: configPath})
	target, err := exec.resolveTarget(inventory.Target{Name: "web-1", Host: inventory.Host{SSHConfigAlias: "prod-web", Addr: "ignored", User: "ignored", Port: 99}})
	if err != nil {
		t.Fatalf("resolve alias: %v", err)
	}
	if target.HostName != "10.0.0.11" || target.User != "deploy" || target.Port != 2222 || target.ProxyJump != "jump@bastion:2200" {
		t.Fatalf("target = %#v", target)
	}
	wantIdentity := filepath.Join(home, "keys", "prod_ed25519")
	if len(target.IdentityFiles) != 1 || target.IdentityFiles[0] != wantIdentity {
		t.Fatalf("identity files = %#v, want %s", target.IdentityFiles, wantIdentity)
	}
}

type testSSHServer struct {
	Listener   net.Listener
	HostSigner ssh.Signer
	wg         sync.WaitGroup
	allowedKey ssh.PublicKey
}

func newTestSSHServer(t *testing.T, allowedKey ssh.PublicKey) *testSSHServer {
	t.Helper()
	hostKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate host key: %v", err)
	}
	hostSigner, err := ssh.NewSignerFromKey(hostKey)
	if err != nil {
		t.Fatalf("host signer: %v", err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	server := &testSSHServer{Listener: ln, HostSigner: hostSigner, allowedKey: allowedKey}
	server.wg.Add(1)
	go server.accept()
	return server
}

func (s *testSSHServer) Addr() string { return s.Listener.Addr().String() }

func (s *testSSHServer) Host() string {
	host, _, _ := net.SplitHostPort(s.Addr())
	return host
}

func (s *testSSHServer) Port() int {
	_, portValue, _ := net.SplitHostPort(s.Addr())
	var port int
	_, _ = fmt.Sscanf(portValue, "%d", &port)
	return port
}

func (s *testSSHServer) Close() {
	_ = s.Listener.Close()
	s.wg.Wait()
}

func (s *testSSHServer) accept() {
	defer s.wg.Done()
	for {
		conn, err := s.Listener.Accept()
		if err != nil {
			return
		}
		s.wg.Add(1)
		go s.handle(conn)
	}
}

func (s *testSSHServer) handle(conn net.Conn) {
	defer s.wg.Done()
	cfg := &ssh.ServerConfig{
		PublicKeyCallback: func(_ ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			if string(key.Marshal()) == string(s.allowedKey.Marshal()) {
				return nil, nil
			}
			return nil, fmt.Errorf("unexpected public key")
		},
	}
	cfg.AddHostKey(s.HostSigner)
	sshConn, chans, reqs, err := ssh.NewServerConn(conn, cfg)
	if err != nil {
		_ = conn.Close()
		return
	}
	defer func() { _ = sshConn.Close() }()
	go ssh.DiscardRequests(reqs)
	for ch := range chans {
		if ch.ChannelType() != "session" {
			_ = ch.Reject(ssh.UnknownChannelType, "session only")
			continue
		}
		channel, requests, err := ch.Accept()
		if err != nil {
			continue
		}
		go handleSession(channel, requests)
	}
}

func handleSession(channel ssh.Channel, requests <-chan *ssh.Request) {
	defer func() { _ = channel.Close() }()
	for req := range requests {
		if req.Type != "exec" {
			_ = req.Reply(false, nil)
			continue
		}
		var payload struct{ Command string }
		_ = ssh.Unmarshal(req.Payload, &payload)
		_ = req.Reply(true, nil)
		code := uint32(0)
		if strings.Contains(payload.Command, "stream-secret") {
			_, _ = channel.Write([]byte("line1\n"))
			_, _ = channel.Write([]byte("password="))
			_, _ = channel.Write([]byte("secret123\nline3\n"))
			_, _ = channel.Stderr().Write([]byte("warn=secret\n"))
		} else if strings.Contains(payload.Command, "exit7") {
			code = 7
			_, _ = channel.Stderr().Write([]byte("failed\n"))
		} else {
			_, _ = channel.Write([]byte("ok\n"))
		}
		_, _ = channel.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{Status: code}))
		return
	}
}

func writeClientKey(t *testing.T, home string) ssh.Signer {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate client key: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		t.Fatalf("client signer: %v", err)
	}
	dir := filepath.Join(home, ".ssh")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("mkdir .ssh: %v", err)
	}
	data := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	if err := os.WriteFile(filepath.Join(dir, "id_rsa"), data, 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	t.Setenv("HOME", home)
	t.Setenv("SSH_AUTH_SOCK", "")
	return signer
}

func writeKnownHosts(t *testing.T, home string, addr string, key ssh.PublicKey) {
	t.Helper()
	dir := filepath.Join(home, ".ssh")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("mkdir .ssh: %v", err)
	}
	line := knownhosts.Line([]string{addr}, key)
	if err := os.WriteFile(filepath.Join(dir, "known_hosts"), []byte(line+"\n"), 0o600); err != nil {
		t.Fatalf("write known_hosts: %v", err)
	}
}
