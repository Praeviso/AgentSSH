package executor

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

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
	defer func() { _ = exec.Close() }()
	target := inventory.Target{Name: "test", Host: inventory.Host{Addr: server.Host(), Port: server.Port(), User: "test"}}

	result := exec.Run(context.Background(), Request{Target: target, Command: "ok"})
	if result.Err != nil || result.ExitCode != 0 || result.Stdout != "ok\n" {
		t.Fatalf("success result = %#v err=%v", result, result.Err)
	}
	if result.OS != "linux" {
		t.Fatalf("success OS = %q, want linux", result.OS)
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
	defer func() { _ = exec.Close() }()
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

func TestNativeExecutorReusesPooledConnection(t *testing.T) {
	home := t.TempDir()
	clientSigner := writeClientKey(t, home)
	server := newTestSSHServer(t, clientSigner.PublicKey())
	defer server.Close()

	writeKnownHosts(t, home, server.Addr(), server.HostSigner.PublicKey())

	exec := NewNativeExecutor(NativeOptions{
		KnownHostsPath:    filepath.Join(home, ".ssh", "known_hosts"),
		ConfigPath:        filepath.Join(home, ".ssh", "config"),
		KeepAliveInterval: -1,
	})
	defer func() { _ = exec.Close() }()
	target := inventory.Target{Name: "test", Host: inventory.Host{Addr: server.Host(), Port: server.Port(), User: "test"}}

	for _, command := range []string{"ok", "exit7"} {
		result := exec.Run(context.Background(), Request{Target: target, Command: command})
		if result.Err != nil {
			t.Fatalf("%s result err = %v", command, result.Err)
		}
	}
	if got := atomic.LoadInt32(&server.accepted); got != 1 {
		t.Fatalf("accepted connections = %d, want 1 pooled connection", got)
	}
}

func TestNativeExecutorCachesOSPerPooledConnection(t *testing.T) {
	home := t.TempDir()
	clientSigner := writeClientKey(t, home)
	server := newTestSSHServer(t, clientSigner.PublicKey())
	defer server.Close()

	writeKnownHosts(t, home, server.Addr(), server.HostSigner.PublicKey())

	exec := NewNativeExecutor(NativeOptions{
		KnownHostsPath:    filepath.Join(home, ".ssh", "known_hosts"),
		ConfigPath:        filepath.Join(home, ".ssh", "config"),
		KeepAliveInterval: -1,
	})
	defer func() { _ = exec.Close() }()
	target := inventory.Target{Name: "test", Host: inventory.Host{Addr: server.Host(), Port: server.Port(), User: "test"}}

	for i := 0; i < 2; i++ {
		result := exec.Run(context.Background(), Request{Target: target, Command: "ok"})
		if result.Err != nil || result.OS != "linux" {
			t.Fatalf("run %d result = %#v err=%v", i, result, result.Err)
		}
	}
	if got := atomic.LoadInt32(&server.osProbes); got != 1 {
		t.Fatalf("OS probes = %d, want 1 cached probe", got)
	}
}

func TestNativeExecutorPoolSingleFlightsConcurrentDial(t *testing.T) {
	home := t.TempDir()
	clientSigner := writeClientKey(t, home)
	server := newTestSSHServer(t, clientSigner.PublicKey())
	defer server.Close()

	writeKnownHosts(t, home, server.Addr(), server.HostSigner.PublicKey())

	exec := NewNativeExecutor(NativeOptions{
		KnownHostsPath:    filepath.Join(home, ".ssh", "known_hosts"),
		ConfigPath:        filepath.Join(home, ".ssh", "config"),
		KeepAliveInterval: -1,
	})
	defer func() { _ = exec.Close() }()
	target := inventory.Target{Name: "test", Host: inventory.Host{Addr: server.Host(), Port: server.Port(), User: "test"}}

	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			result := exec.Run(context.Background(), Request{Target: target, Command: "ok"})
			if result.Err != nil || result.ExitCode != 0 || result.Stdout != "ok\n" {
				errs <- fmt.Errorf("result = %#v err=%v", result, result.Err)
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	if got := atomic.LoadInt32(&server.accepted); got != 1 {
		t.Fatalf("accepted connections = %d, want 1 pooled connection", got)
	}
}

func TestNativeClientPoolBroadcastsDialErrorToWaiters(t *testing.T) {
	pool := newNativeClientPool(-1)
	wantErr := errors.New("dial failed")
	dialEntered := make(chan struct{})
	releaseDial := make(chan struct{})
	var dials int32
	dial := func(context.Context) (*nativeClient, error) {
		if atomic.AddInt32(&dials, 1) == 1 {
			close(dialEntered)
		}
		<-releaseDial
		return nil, wantErr
	}

	errs := make(chan error, 6)
	go func() {
		_, _, err := pool.get(context.Background(), "web-1", dial)
		errs <- err
	}()
	<-dialEntered
	for i := 0; i < 5; i++ {
		go func() {
			_, _, err := pool.get(context.Background(), "web-1", dial)
			errs <- err
		}()
	}
	time.Sleep(20 * time.Millisecond)
	close(releaseDial)

	for i := 0; i < 6; i++ {
		if err := <-errs; !errors.Is(err, wantErr) {
			t.Fatalf("waiter %d err = %v, want %v", i, err, wantErr)
		}
	}
	if got := atomic.LoadInt32(&dials); got != 1 {
		t.Fatalf("dials = %d, want one broadcast failed dial", got)
	}
}

func TestNativeClientPoolDepoolDefersCloseUntilInFlightDrains(t *testing.T) {
	pool := newNativeClientPool(-1)
	var closes int32
	entry := &nativePoolEntry{
		client: &nativeClient{closers: []io.Closer{
			closerFunc(func() error {
				atomic.AddInt32(&closes, 1)
				return nil
			}),
		}},
		stop:     make(chan struct{}),
		inFlight: 2,
	}
	pool.entries["web-1"] = entry

	pool.depoolWhenIdle("web-1", entry, entry.client)
	if _, ok := pool.entries["web-1"]; ok {
		t.Fatal("entry still pooled after suspicious run error")
	}
	if got := atomic.LoadInt32(&closes); got != 0 {
		t.Fatalf("close count after depool = %d, want 0 while sessions are in flight", got)
	}
	pool.release(entry)
	if got := atomic.LoadInt32(&closes); got != 0 {
		t.Fatalf("close count after first release = %d, want 0", got)
	}
	pool.release(entry)
	if got := atomic.LoadInt32(&closes); got != 1 {
		t.Fatalf("close count after final release = %d, want 1", got)
	}
}

func TestNativeExecutorReconnectsWhenPooledClientDies(t *testing.T) {
	home := t.TempDir()
	clientSigner := writeClientKey(t, home)
	server := newTestSSHServer(t, clientSigner.PublicKey())
	defer server.Close()

	writeKnownHosts(t, home, server.Addr(), server.HostSigner.PublicKey())

	exec := NewNativeExecutor(NativeOptions{
		KnownHostsPath:    filepath.Join(home, ".ssh", "known_hosts"),
		ConfigPath:        filepath.Join(home, ".ssh", "config"),
		KeepAliveInterval: -1,
	})
	defer func() { _ = exec.Close() }()
	target := inventory.Target{Name: "test", Host: inventory.Host{Addr: server.Host(), Port: server.Port(), User: "test"}}

	result := exec.Run(context.Background(), Request{Target: target, Command: "close-connection"})
	if result.Err != nil || result.ExitCode != 0 {
		t.Fatalf("close-connection result = %#v err=%v", result, result.Err)
	}
	waitForAtomic(t, &server.closed, 1)

	result = exec.Run(context.Background(), Request{Target: target, Command: "ok"})
	if result.Err != nil || result.ExitCode != 0 || result.Stdout != "ok\n" {
		t.Fatalf("reconnected result = %#v err=%v", result, result.Err)
	}
	if got := atomic.LoadInt32(&server.accepted); got != 2 {
		t.Fatalf("accepted connections = %d, want reconnect to dial once", got)
	}
}

func TestNativeExecutorFallsBackToUnpooledWhenMaxSessionsRejects(t *testing.T) {
	home := t.TempDir()
	clientSigner := writeClientKey(t, home)
	server := newTestSSHServer(t, clientSigner.PublicKey())
	server.maxSessions = 1
	server.blockCh = make(chan struct{})
	defer server.Close()

	writeKnownHosts(t, home, server.Addr(), server.HostSigner.PublicKey())

	exec := NewNativeExecutor(NativeOptions{
		KnownHostsPath:    filepath.Join(home, ".ssh", "known_hosts"),
		ConfigPath:        filepath.Join(home, ".ssh", "config"),
		KeepAliveInterval: -1,
	})
	defer func() { _ = exec.Close() }()
	target := inventory.Target{Name: "test", Host: inventory.Host{Addr: server.Host(), Port: server.Port(), User: "test"}}

	firstDone := make(chan Result, 1)
	go func() {
		firstDone <- exec.Run(context.Background(), Request{Target: target, Command: "block"})
	}()
	waitForAtomic(t, &server.activeSessions, 1)

	second := exec.Run(context.Background(), Request{Target: target, Command: "ok"})
	if second.Err != nil || second.ExitCode != 0 || second.Stdout != "ok\n" {
		t.Fatalf("fallback result = %#v err=%v", second, second.Err)
	}
	if got := atomic.LoadInt32(&server.sessionRejects); got == 0 {
		t.Fatal("pooled channel-open was not rejected by the session cap")
	}

	close(server.blockCh)
	first := <-firstDone
	if first.Err != nil || first.ExitCode != 0 {
		t.Fatalf("first pooled result = %#v err=%v", first, first.Err)
	}
	third := exec.Run(context.Background(), Request{Target: target, Command: "ok"})
	if third.Err != nil || third.ExitCode != 0 {
		t.Fatalf("third pooled result = %#v err=%v", third, third.Err)
	}
	if got := atomic.LoadInt32(&server.accepted); got != 2 {
		t.Fatalf("accepted connections = %d, want pooled connection plus one unpooled fallback", got)
	}
}

func TestNativeExecutorNewSessionTimesOutAndClosesPooledClient(t *testing.T) {
	home := t.TempDir()
	clientSigner := writeClientKey(t, home)
	server := newTestSSHServer(t, clientSigner.PublicKey())
	server.hangChannels = make(chan struct{})
	defer server.Close()

	writeKnownHosts(t, home, server.Addr(), server.HostSigner.PublicKey())

	exec := NewNativeExecutor(NativeOptions{
		KnownHostsPath:    filepath.Join(home, ".ssh", "known_hosts"),
		ConfigPath:        filepath.Join(home, ".ssh", "config"),
		ConnectTimeout:    30 * time.Millisecond,
		KeepAliveInterval: -1,
	})
	defer func() { _ = exec.Close() }()
	target := inventory.Target{Name: "test", Host: inventory.Host{Addr: server.Host(), Port: server.Port(), User: "test"}}

	start := time.Now()
	result := exec.Run(context.Background(), Request{Target: target, Command: "ok"})
	close(server.hangChannels)
	if !errors.Is(result.Err, context.DeadlineExceeded) {
		t.Fatalf("result err = %v, want context deadline exceeded", result.Err)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("NewSession timeout took %s", elapsed)
	}
	waitForAtomic(t, &server.closed, 1)
}

func TestNativeExecutorRunHonorsContextWithoutRunTimeout(t *testing.T) {
	home := t.TempDir()
	clientSigner := writeClientKey(t, home)
	server := newTestSSHServer(t, clientSigner.PublicKey())
	server.blockCh = make(chan struct{})
	defer server.Close()

	writeKnownHosts(t, home, server.Addr(), server.HostSigner.PublicKey())

	exec := NewNativeExecutor(NativeOptions{
		KnownHostsPath:    filepath.Join(home, ".ssh", "known_hosts"),
		ConfigPath:        filepath.Join(home, ".ssh", "config"),
		KeepAliveInterval: -1,
	})
	defer func() { _ = exec.Close() }()
	target := inventory.Target{Name: "test", Host: inventory.Host{Addr: server.Host(), Port: server.Port(), User: "test"}}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()

	result := exec.Run(ctx, Request{Target: target, Command: "block"})
	close(server.blockCh)
	if !errors.Is(result.Err, context.DeadlineExceeded) {
		t.Fatalf("result err = %v, want context deadline exceeded", result.Err)
	}
	waitForAtomic(t, &server.closed, 1)
}

func TestNativeExecutorKeepAliveAndClose(t *testing.T) {
	home := t.TempDir()
	clientSigner := writeClientKey(t, home)
	server := newTestSSHServer(t, clientSigner.PublicKey())
	defer server.Close()

	writeKnownHosts(t, home, server.Addr(), server.HostSigner.PublicKey())

	exec := NewNativeExecutor(NativeOptions{
		KnownHostsPath:    filepath.Join(home, ".ssh", "known_hosts"),
		ConfigPath:        filepath.Join(home, ".ssh", "config"),
		KeepAliveInterval: 5 * time.Millisecond,
	})
	target := inventory.Target{Name: "test", Host: inventory.Host{Addr: server.Host(), Port: server.Port(), User: "test"}}

	result := exec.Run(context.Background(), Request{Target: target, Command: "ok"})
	if result.Err != nil || result.ExitCode != 0 {
		t.Fatalf("run result = %#v err=%v", result, result.Err)
	}
	waitForAtomic(t, &server.globalRequests, 1)

	if err := exec.Close(); err != nil {
		t.Fatalf("close executor: %v", err)
	}
	waitForAtomic(t, &server.closed, 1)
}

func TestNativeExecutorKeepAliveTimeoutEvictsAndCloses(t *testing.T) {
	home := t.TempDir()
	clientSigner := writeClientKey(t, home)
	server := newTestSSHServer(t, clientSigner.PublicKey())
	server.hangGlobalRequests = make(chan struct{})
	defer server.Close()

	writeKnownHosts(t, home, server.Addr(), server.HostSigner.PublicKey())

	oldTimeout := nativeKeepAliveTimeout
	nativeKeepAliveTimeout = 20 * time.Millisecond
	defer func() { nativeKeepAliveTimeout = oldTimeout }()

	exec := NewNativeExecutor(NativeOptions{
		KnownHostsPath:    filepath.Join(home, ".ssh", "known_hosts"),
		ConfigPath:        filepath.Join(home, ".ssh", "config"),
		KeepAliveInterval: 10 * time.Millisecond,
	})
	defer func() { _ = exec.Close() }()
	target := inventory.Target{Name: "test", Host: inventory.Host{Addr: server.Host(), Port: server.Port(), User: "test"}}

	result := exec.Run(context.Background(), Request{Target: target, Command: "ok"})
	if result.Err != nil || result.ExitCode != 0 {
		t.Fatalf("run result = %#v err=%v", result, result.Err)
	}
	waitForAtomic(t, &server.globalRequests, 1)
	waitForAtomic(t, &server.closed, 1)
	close(server.hangGlobalRequests)
}

func TestNativeClientPoolCloseClosesCloserChain(t *testing.T) {
	pool := newNativeClientPool(-1)
	var first int32
	var second int32
	pool.entries["web-1"] = &nativePoolEntry{
		client: &nativeClient{closers: []io.Closer{
			closerFunc(func() error {
				atomic.AddInt32(&first, 1)
				return nil
			}),
			closerFunc(func() error {
				atomic.AddInt32(&second, 1)
				return nil
			}),
		}},
		stop: make(chan struct{}),
	}

	if err := pool.Close(); err != nil {
		t.Fatalf("pool close: %v", err)
	}
	if atomic.LoadInt32(&first) != 1 || atomic.LoadInt32(&second) != 1 {
		t.Fatalf("closer counts first=%d second=%d", first, second)
	}
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
	defer func() { _ = exec.Close() }()
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
	defer func() { _ = exec.Close() }()
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
	defer func() { _ = strictExec.Close() }()
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

func TestResolveTargetAddsPerHostIdentityFile(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	exec := NewNativeExecutor(NativeOptions{})
	target, err := exec.resolveTarget(inventory.Target{
		Name: "web-1",
		Host: inventory.Host{Addr: "10.0.0.11", User: "deploy", IdentityFile: "~/keys/web-1"},
	})
	if err != nil {
		t.Fatalf("resolve target: %v", err)
	}
	want := filepath.Join(home, "keys", "web-1")
	if len(target.IdentityFiles) != 1 || target.IdentityFiles[0] != want {
		t.Fatalf("identity files = %#v, want %s", target.IdentityFiles, want)
	}
}

func TestNativeExecutorUsesPerHostIdentityBeforeDefault(t *testing.T) {
	home := t.TempDir()
	defaultSigner := writeClientKey(t, home)
	perHostSigner := writePrivateKey(t, filepath.Join(home, "keys", "web-1"))
	server := newTestSSHServer(t, perHostSigner.PublicKey())
	defer server.Close()

	writeKnownHosts(t, home, server.Addr(), server.HostSigner.PublicKey())
	exec := NewNativeExecutor(NativeOptions{
		KnownHostsPath: filepath.Join(home, ".ssh", "known_hosts"),
		ConfigPath:     filepath.Join(home, ".ssh", "config"),
	})
	defer func() { _ = exec.Close() }()
	target := inventory.Target{Name: "test", Host: inventory.Host{Addr: server.Host(), Port: server.Port(), User: "test", IdentityFile: "~/keys/web-1"}}
	result := exec.Run(context.Background(), Request{Target: target, Command: "ok"})
	if result.Err != nil || result.ExitCode != 0 {
		t.Fatalf("per-host identity result = %#v err=%v", result, result.Err)
	}
	if string(defaultSigner.PublicKey().Marshal()) == string(perHostSigner.PublicKey().Marshal()) {
		t.Fatal("test signers unexpectedly match")
	}
}

func TestNativeExecutorPasswordSourceAppendedOnlyWhenPresent(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("SSH_AUTH_SOCK", "")
	exec := NewNativeExecutor(NativeOptions{})
	target := nativeTarget{Name: "web-1", User: "test"}
	methods, closer, err := exec.authMethods(target)
	if err != nil {
		t.Fatalf("authMethods without password: %v", err)
	}
	if closer != nil {
		_ = closer.Close()
	}
	if len(methods) != 0 {
		t.Fatalf("auth methods without keys/password = %d, want 0", len(methods))
	}

	var seen []string
	exec = NewNativeExecutor(NativeOptions{PasswordSource: func(host string) (string, bool) {
		seen = append(seen, host)
		return "pw", true
	}})
	methods, closer, err = exec.authMethods(target)
	if err != nil {
		t.Fatalf("authMethods with password: %v", err)
	}
	if closer != nil {
		_ = closer.Close()
	}
	if len(methods) != 1 || len(seen) != 1 || seen[0] != "web-1" {
		t.Fatalf("methods=%d seen=%#v", len(methods), seen)
	}

	writePrivateKey(t, filepath.Join(home, ".ssh", "id_rsa"))
	methods, closer, err = exec.authMethods(target)
	if err != nil {
		t.Fatalf("authMethods with key+password: %v", err)
	}
	if closer != nil {
		_ = closer.Close()
	}
	if len(methods) != 2 {
		t.Fatalf("methods with key+password = %d, want 2", len(methods))
	}
}

func TestNativeExecutorPasswordAuthEndToEnd(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("SSH_AUTH_SOCK", "")
	server := newPasswordTestSSHServer(t, nil, "secretpw")
	defer server.Close()

	writeKnownHosts(t, home, server.Addr(), server.HostSigner.PublicKey())
	exec := NewNativeExecutor(NativeOptions{
		KnownHostsPath: filepath.Join(home, ".ssh", "known_hosts"),
		ConfigPath:     filepath.Join(home, ".ssh", "config"),
		PasswordSource: func(host string) (string, bool) {
			if host != "web-1" {
				t.Fatalf("password source host = %q", host)
			}
			return "secretpw", true
		},
	})
	defer func() { _ = exec.Close() }()
	target := inventory.Target{Name: "web-1", Host: inventory.Host{Addr: server.Host(), Port: server.Port(), User: "test"}}
	result := exec.Run(context.Background(), Request{Target: target, Command: "ok"})
	if result.Err != nil || result.ExitCode != 0 || result.Stdout != "ok\n" {
		t.Fatalf("password auth result = %#v err=%v", result, result.Err)
	}
	if got := atomic.LoadInt32(&server.passwordAttempts); got != 1 {
		t.Fatalf("password attempts = %d, want 1", got)
	}
}

func TestNativeExecutorPrefersKeyAuthBeforePassword(t *testing.T) {
	home := t.TempDir()
	clientSigner := writeClientKey(t, home)
	server := newPasswordTestSSHServer(t, clientSigner.PublicKey(), "secretpw")
	defer server.Close()

	writeKnownHosts(t, home, server.Addr(), server.HostSigner.PublicKey())
	exec := NewNativeExecutor(NativeOptions{
		KnownHostsPath: filepath.Join(home, ".ssh", "known_hosts"),
		ConfigPath:     filepath.Join(home, ".ssh", "config"),
		PasswordSource: func(string) (string, bool) { return "secretpw", true },
	})
	defer func() { _ = exec.Close() }()
	target := inventory.Target{Name: "web-1", Host: inventory.Host{Addr: server.Host(), Port: server.Port(), User: "test"}}
	result := exec.Run(context.Background(), Request{Target: target, Command: "ok"})
	if result.Err != nil || result.ExitCode != 0 {
		t.Fatalf("key preferred result = %#v err=%v", result, result.Err)
	}
	if got := atomic.LoadInt32(&server.publicKeyAttempts); got == 0 {
		t.Fatal("public key was not attempted")
	}
	if got := atomic.LoadInt32(&server.passwordAttempts); got != 0 {
		t.Fatalf("password attempts = %d, want 0 when key succeeds", got)
	}
}

func TestConnectHintMapping(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want string
	}{
		{name: "no auth", err: errors.New("no SSH auth methods available"), want: "identity_file"},
		{name: "auth failed", err: errors.New("ssh: handshake failed: ssh: unable to authenticate, attempted methods [none publickey]"), want: "AgentSSH never changes the remote host"},
		{name: "unknown host", err: &knownhosts.KeyError{}, want: "unknown host key"},
		{name: "changed host", err: &knownhosts.KeyError{Want: []knownhosts.KnownKey{{}}}, want: "possible MITM"},
		{name: "refused", err: errors.New("dial tcp 127.0.0.1:22: connect: connection refused"), want: "addr, port"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ConnectHint(tt.err); !strings.Contains(got, tt.want) {
				t.Fatalf("ConnectHint(%v) = %q, want contains %q", tt.err, got, tt.want)
			}
		})
	}
}

type testSSHServer struct {
	Listener           net.Listener
	HostSigner         ssh.Signer
	wg                 sync.WaitGroup
	allowedKey         ssh.PublicKey
	accepted           int32
	closed             int32
	globalRequests     int32
	osProbes           int32
	activeSessions     int32
	sessionRejects     int32
	maxSessions        int32
	blockCh            chan struct{}
	hangChannels       chan struct{}
	hangGlobalRequests chan struct{}
}

type closerFunc func() error

func (fn closerFunc) Close() error {
	return fn()
}

type passwordTestSSHServer struct {
	Listener          net.Listener
	HostSigner        ssh.Signer
	wg                sync.WaitGroup
	allowedKey        ssh.PublicKey
	password          string
	publicKeyAttempts int32
	passwordAttempts  int32
}

func newPasswordTestSSHServer(t *testing.T, allowedKey ssh.PublicKey, password string) *passwordTestSSHServer {
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
	server := &passwordTestSSHServer{Listener: ln, HostSigner: hostSigner, allowedKey: allowedKey, password: password}
	server.wg.Add(1)
	go server.accept()
	return server
}

func (s *passwordTestSSHServer) Addr() string { return s.Listener.Addr().String() }

func (s *passwordTestSSHServer) Host() string {
	host, _, _ := net.SplitHostPort(s.Addr())
	return host
}

func (s *passwordTestSSHServer) Port() int {
	_, portValue, _ := net.SplitHostPort(s.Addr())
	var port int
	_, _ = fmt.Sscanf(portValue, "%d", &port)
	return port
}

func (s *passwordTestSSHServer) Close() {
	_ = s.Listener.Close()
	s.wg.Wait()
}

func (s *passwordTestSSHServer) accept() {
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

func (s *passwordTestSSHServer) handle(conn net.Conn) {
	defer s.wg.Done()
	cfg := &ssh.ServerConfig{
		PublicKeyCallback: func(_ ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			atomic.AddInt32(&s.publicKeyAttempts, 1)
			if s.allowedKey != nil && string(key.Marshal()) == string(s.allowedKey.Marshal()) {
				return nil, nil
			}
			return nil, fmt.Errorf("unexpected public key")
		},
		PasswordCallback: func(_ ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
			atomic.AddInt32(&s.passwordAttempts, 1)
			if string(password) == s.password {
				return nil, nil
			}
			return nil, fmt.Errorf("unexpected password")
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
		go handleSession(sshConn, channel, requests, nil)
	}
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
	atomic.AddInt32(&s.accepted, 1)
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
	defer func() {
		atomic.AddInt32(&s.closed, 1)
		_ = sshConn.Close()
	}()
	go s.handleGlobalRequests(reqs)
	var connectionSessions int32
	for ch := range chans {
		if s.hangChannels != nil {
			<-s.hangChannels
		}
		if ch.ChannelType() != "session" {
			_ = ch.Reject(ssh.UnknownChannelType, "session only")
			continue
		}
		if maxSessions := atomic.LoadInt32(&s.maxSessions); maxSessions > 0 && atomic.LoadInt32(&connectionSessions) >= maxSessions {
			atomic.AddInt32(&s.sessionRejects, 1)
			_ = ch.Reject(ssh.Prohibited, "session limit reached")
			continue
		}
		channel, requests, err := ch.Accept()
		if err != nil {
			continue
		}
		atomic.AddInt32(&connectionSessions, 1)
		atomic.AddInt32(&s.activeSessions, 1)
		go func() {
			defer func() {
				atomic.AddInt32(&connectionSessions, -1)
				atomic.AddInt32(&s.activeSessions, -1)
			}()
			handleSession(sshConn, channel, requests, s)
		}()
	}
}

func (s *testSSHServer) handleGlobalRequests(requests <-chan *ssh.Request) {
	for req := range requests {
		atomic.AddInt32(&s.globalRequests, 1)
		if s.hangGlobalRequests != nil {
			<-s.hangGlobalRequests
		}
		if req.WantReply {
			_ = req.Reply(true, nil)
		}
	}
}

func waitForAtomic(t *testing.T, value *int32, want int32) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if got := atomic.LoadInt32(value); got >= want {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("atomic value = %d, want at least %d", atomic.LoadInt32(value), want)
}

func handleSession(conn *ssh.ServerConn, channel ssh.Channel, requests <-chan *ssh.Request, server *testSSHServer) {
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
		if payload.Command == OSProbeCommand {
			if server != nil {
				atomic.AddInt32(&server.osProbes, 1)
			}
			_, _ = channel.Write([]byte("Linux\n"))
		} else if strings.Contains(payload.Command, "block") {
			if server != nil && server.blockCh != nil {
				<-server.blockCh
			}
			_, _ = channel.Write([]byte("ok\n"))
		} else if strings.Contains(payload.Command, "stream-secret") {
			_, _ = channel.Write([]byte("line1\n"))
			_, _ = channel.Write([]byte("password="))
			_, _ = channel.Write([]byte("secret123\nline3\n"))
			_, _ = channel.Stderr().Write([]byte("warn=secret\n"))
		} else if strings.Contains(payload.Command, "close-connection") {
			_, _ = channel.Write([]byte("ok\n"))
			_, _ = channel.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{Status: code}))
			if conn != nil {
				go func() { _ = conn.Close() }()
			}
			return
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
	signer := writePrivateKey(t, filepath.Join(home, ".ssh", "id_rsa"))
	t.Setenv("HOME", home)
	t.Setenv("SSH_AUTH_SOCK", "")
	return signer
}

func writePrivateKey(t *testing.T, path string) ssh.Signer {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate client key: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		t.Fatalf("client signer: %v", err)
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("mkdir key dir: %v", err)
	}
	data := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
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

func TestKnownHostKeyAlgorithmsPrefersStoredType(t *testing.T) {
	edPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate ed25519: %v", err)
	}
	edKey, err := ssh.NewPublicKey(edPub)
	if err != nil {
		t.Fatalf("ssh public key: %v", err)
	}
	khPath := filepath.Join(t.TempDir(), "known_hosts")
	line := knownhosts.Line([]string{"example.com:22"}, edKey)
	if err := os.WriteFile(khPath, []byte(line+"\n"), 0o600); err != nil {
		t.Fatalf("write known_hosts: %v", err)
	}

	e := NewNativeExecutor(NativeOptions{KnownHostsPath: khPath})

	// A host with only an ed25519 entry must constrain negotiation to ed25519, so
	// a server also offering ecdsa/rsa isn't negotiated onto an untrusted type and
	// falsely flagged as a key mismatch.
	if got := e.knownHostKeyAlgorithms("example.com:22"); !reflect.DeepEqual(got, []string{ssh.KeyAlgoED25519}) {
		t.Fatalf("known ed25519 host: got %v, want [%s]", got, ssh.KeyAlgoED25519)
	}

	// Unknown host: return nil so the caller leaves HostKeyAlgorithms unset and
	// default negotiation applies (needed for first-time / accept-new connects).
	if got := e.knownHostKeyAlgorithms("unknown.example.com:22"); got != nil {
		t.Fatalf("unknown host: got %v, want nil", got)
	}
}

func TestKnownHostKeyAlgorithmsExpandsRSA(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa: %v", err)
	}
	pub, err := ssh.NewPublicKey(&rsaKey.PublicKey)
	if err != nil {
		t.Fatalf("ssh public key: %v", err)
	}
	khPath := filepath.Join(t.TempDir(), "known_hosts")
	line := knownhosts.Line([]string{"rsa.example.com:22"}, pub)
	if err := os.WriteFile(khPath, []byte(line+"\n"), 0o600); err != nil {
		t.Fatalf("write known_hosts: %v", err)
	}

	e := NewNativeExecutor(NativeOptions{KnownHostsPath: khPath})
	got := e.knownHostKeyAlgorithms("rsa.example.com:22")
	want := []string{ssh.KeyAlgoRSASHA512, ssh.KeyAlgoRSASHA256, ssh.KeyAlgoRSA}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("rsa host: got %v, want %v", got, want)
	}
}

func TestScrubbedEnvRemovesMasterPassword(t *testing.T) {
	t.Setenv("AGENTSSH_MASTER_PASSWORD", "supersecret")
	t.Setenv("SSH_AUTH_SOCK", "/tmp/agent.sock")
	env := scrubbedEnv()
	for _, kv := range env {
		if strings.HasPrefix(kv, "AGENTSSH_MASTER_PASSWORD=") {
			t.Fatalf("scrubbedEnv leaked the master password into the subprocess env")
		}
	}
	found := false
	for _, kv := range env {
		if kv == "SSH_AUTH_SOCK=/tmp/agent.sock" {
			found = true
		}
	}
	if !found {
		t.Fatal("scrubbedEnv dropped SSH_AUTH_SOCK, which key/agent auth needs")
	}
}
