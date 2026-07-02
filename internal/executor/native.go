package executor

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/Praeviso/AgentSSH/internal/inventory"
	sshconfig "github.com/kevinburke/ssh_config"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/crypto/ssh/knownhosts"
	"golang.org/x/term"
)

const (
	TransportShell  = "ssh"
	TransportNative = "native"
	nativeArgv0     = "native-ssh"
)

const defaultNativeKeepAliveInterval = 30 * time.Second

var nativeKeepAliveTimeout = 5 * time.Second

// ProbeTimeout bounds connectivity probes (inventory test, discover --probe, the
// TUI t/probe actions). It matches the default Run connect budget so a probe
// fails only when a real run would: a shorter cap produced false "cannot reach
// SSH" reports for legitimate but distant / high-latency hosts whose handshake
// takes several seconds.
const ProbeTimeout = 10 * time.Second

// NativeOptions configures the native Go SSH executor.
type NativeOptions struct {
	ConfigPath     string
	KnownHostsPath string
	ConnectTimeout time.Duration
	// DisableConnectionReuse preserves the old one-dial-per-command behavior.
	DisableConnectionReuse bool
	// KeepAliveInterval controls pooled-connection heartbeats. Zero uses the
	// default; a negative value disables keepalives for tests and diagnostics.
	KeepAliveInterval time.Duration
	HostKeyPolicy     string // strict | accept-new
	PasswordSource    func(host string) (string, bool)
}

// NativeExecutor executes commands using golang.org/x/crypto/ssh.
type NativeExecutor struct {
	Options NativeOptions
	pool    *nativeClientPool
}

// NewNativeExecutor returns a native SSH executor.
func NewNativeExecutor(options NativeOptions) NativeExecutor {
	if options.ConnectTimeout == 0 {
		options.ConnectTimeout = 10 * time.Second
	}
	if options.HostKeyPolicy == "" {
		options.HostKeyPolicy = "strict"
	}
	var pool *nativeClientPool
	if !options.DisableConnectionReuse {
		pool = newNativeClientPool(options.KeepAliveInterval)
	}
	return NativeExecutor{
		Options: options,
		pool:    pool,
	}
}

// Close releases every pooled SSH connection held by this executor, including
// ProxyJump tunnel and jump-client closers owned by each connection.
func (e NativeExecutor) Close() error {
	if e.pool == nil {
		return nil
	}
	return e.pool.Close()
}

func (e NativeExecutor) Run(ctx context.Context, request Request) Result {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	result := e.runSession(ctx, request, &stdout, &stderr, true)
	result.Stdout = stdout.String()
	result.Stderr = stderr.String()
	return result
}

func (e NativeExecutor) RunStreaming(ctx context.Context, request Request, stdout io.Writer, stderr io.Writer) Result {
	return e.runSession(ctx, request, stdout, stderr, true)
}

func (e NativeExecutor) runSession(ctx context.Context, request Request, stdout io.Writer, stderr io.Writer, usePool bool) Result {
	start := time.Now()
	target, err := e.resolveTarget(request.Target)
	targetDisplay := target.display()
	if targetDisplay == "" {
		targetDisplay = request.Target.Name
	}
	argv := []string{nativeArgv0, targetDisplay, request.Command}
	if err != nil {
		return Result{ExitCode: -1, Duration: time.Since(start), Err: err, Argv: argv}
	}

	client, poolKey, poolEntry, pooled, err := e.client(ctx, target, usePool)
	if err != nil {
		return Result{ExitCode: -1, Duration: time.Since(start), Err: err, Argv: argv}
	}
	closeClient := !pooled
	poolReleased := false
	releasePool := func() {
		if pooled && poolEntry != nil && !poolReleased {
			e.pool.release(poolEntry)
			poolReleased = true
		}
	}
	defer func() {
		releasePool()
		if closeClient && client != nil {
			_ = client.Close()
		}
	}()

	closeCurrentClient := func() {
		if pooled && poolEntry != nil {
			e.pool.evictNow(poolKey, poolEntry, client)
			return
		}
		_ = client.Close()
	}
	session, err := e.newSession(ctx, client, e.connectTimeout(), closeCurrentClient)
	if err != nil && pooled && isSessionCapacityError(err) {
		releasePool()
		client, _, _, pooled, err = e.client(ctx, target, false)
		closeClient = true
		poolEntry = nil
		poolKey = ""
		poolReleased = false
		closeCurrentClient = func() { _ = client.Close() }
		if err == nil {
			session, err = e.newSession(ctx, client, e.connectTimeout(), closeCurrentClient)
		}
	}
	if err != nil && pooled && e.shouldReconnect(poolKey, poolEntry, client, err) {
		e.pool.evictNow(poolKey, poolEntry, client)
		releasePool()
		client, poolKey, poolEntry, pooled, err = e.client(ctx, target, usePool)
		closeClient = !pooled
		poolReleased = false
		closeCurrentClient = func() {
			if pooled && poolEntry != nil {
				e.pool.evictNow(poolKey, poolEntry, client)
				return
			}
			_ = client.Close()
		}
		if err == nil {
			session, err = e.newSession(ctx, client, e.connectTimeout(), closeCurrentClient)
		}
	}
	if err != nil {
		return Result{ExitCode: -1, Duration: time.Since(start), Err: err, Argv: argv}
	}
	defer func() {
		_ = session.Close()
	}()

	session.Stdout = stdout
	session.Stderr = stderr

	runErr := runSSHSession(ctx, session, request.Command, closeCurrentClient)
	exitCode, err := nativeExitCode(runErr)
	if err != nil {
		if pooled && isBrokenSSHClientError(err) {
			e.pool.depoolWhenIdle(poolKey, poolEntry, client)
		}
		return Result{ExitCode: -1, Duration: time.Since(start), Err: err, Argv: argv}
	}
	osName := ""
	if request.Command == OSProbeCommand {
		if buffer, ok := stdout.(*bytes.Buffer); ok {
			osName = NormalizeOS(buffer.String())
		}
	}
	if osName == "" {
		if pooled {
			osName = e.pool.cachedOS(poolEntry)
		}
		if osName == "" {
			osName = e.detectOS(ctx, client, closeCurrentClient)
		}
	}
	if pooled && osName != "" {
		e.pool.setOS(poolEntry, osName)
	}
	return Result{ExitCode: exitCode, Duration: time.Since(start), Argv: argv, OS: osName}
}

func (e NativeExecutor) client(ctx context.Context, target nativeTarget, usePool bool) (*nativeClient, string, *nativePoolEntry, bool, error) {
	if e.pool == nil || !usePool {
		client, err := e.dial(ctx, target)
		return client, "", nil, false, err
	}
	key := target.poolKey()
	client, entry, err := e.pool.get(ctx, key, func(context.Context) (*nativeClient, error) {
		return e.dial(ctx, target)
	})
	return client, key, entry, true, err
}

func (e NativeExecutor) shouldReconnect(key string, entry *nativePoolEntry, client *nativeClient, err error) bool {
	if e.pool == nil {
		return false
	}
	return e.pool.isDead(key, entry, client) || isBrokenSSHClientError(err)
}

func (e NativeExecutor) detectOS(ctx context.Context, client *nativeClient, closeClient func()) string {
	probeCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	session, err := e.newSession(probeCtx, client, 5*time.Second, closeClient)
	if err != nil {
		return ""
	}
	defer func() {
		_ = session.Close()
	}()
	var stdout bytes.Buffer
	session.Stdout = &stdout
	if err := runSSHSession(probeCtx, session, OSProbeCommand, func() {
		if closeClient != nil {
			closeClient()
		}
		_ = session.Close()
	}); err != nil {
		return ""
	}
	return NormalizeOS(stdout.String())
}

func (e NativeExecutor) connectTimeout() time.Duration {
	if e.Options.ConnectTimeout != 0 {
		return e.Options.ConnectTimeout
	}
	return 10 * time.Second
}

func (e NativeExecutor) newSession(ctx context.Context, client *nativeClient, timeout time.Duration, closeClient func()) (*ssh.Session, error) {
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	sessionCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	type sessionResult struct {
		session *ssh.Session
		err     error
	}
	done := make(chan sessionResult)
	go func() {
		session, err := client.NewSession()
		select {
		case done <- sessionResult{session: session, err: err}:
		case <-sessionCtx.Done():
			if session != nil {
				_ = session.Close()
			}
		}
	}()
	select {
	case result := <-done:
		return result.session, result.err
	case <-sessionCtx.Done():
		if closeClient != nil {
			closeClient()
		}
		return nil, sessionCtx.Err()
	}
}

func runSSHSession(ctx context.Context, session *ssh.Session, command string, closeClient func()) error {
	done := make(chan error, 1)
	go func() {
		done <- session.Run(command)
	}()
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		if closeClient != nil {
			closeClient()
		} else {
			_ = session.Close()
		}
		// Closing the transport unblocks session.Run, and Run does not return
		// until its stdout/stderr copies finish. Wait for it so the caller can
		// read the output buffers without racing those copies.
		<-done
		return ctx.Err()
	}
}

type nativeTarget struct {
	Name          string
	HostName      string
	Port          int
	User          string
	IdentityFiles []string
	ProxyJump     string
}

// ProbeStatus is the coarse connection outcome used by discovery and tests.
type ProbeStatus string

const (
	ProbeConnectable  ProbeStatus = "connectable"
	ProbeAuthFailed   ProbeStatus = "auth-failed"
	ProbeHostKeyIssue ProbeStatus = "host-key-issue"
	ProbeUnreachable  ProbeStatus = "unreachable"
)

func (t nativeTarget) address() string {
	return net.JoinHostPort(t.HostName, strconv.Itoa(t.Port))
}

func (t nativeTarget) display() string {
	if t.User == "" {
		return t.address()
	}
	return t.User + "@" + t.address()
}

func (t nativeTarget) poolKey() string {
	parts := []string{
		strings.ToLower(t.HostName),
		strconv.Itoa(t.Port),
		t.User,
		strings.TrimSpace(t.ProxyJump),
	}
	parts = append(parts, t.IdentityFiles...)
	return strings.Join(parts, "\x00")
}

func (e NativeExecutor) resolveTarget(target inventory.Target) (nativeTarget, error) {
	host := target.Host
	if host.SSHConfigAlias != "" {
		return e.resolveAlias(target.Name, host.SSHConfigAlias)
	}
	if host.Addr == "" {
		return nativeTarget{Name: target.Name}, fmt.Errorf("host %q has no addr", target.Name)
	}
	userName := host.User
	if userName == "" {
		userName = currentUserName()
	}
	if host.Port == 0 {
		host.Port = 22
	}
	var identityFiles []string
	if host.IdentityFile != "" {
		identityFiles = append(identityFiles, expandHome(host.IdentityFile))
	}
	return nativeTarget{Name: target.Name, HostName: host.Addr, Port: host.Port, User: userName, IdentityFiles: identityFiles}, nil
}

func (e NativeExecutor) resolveAlias(name string, alias string) (nativeTarget, error) {
	settings, err := e.userSettings()
	if err != nil {
		return nativeTarget{}, err
	}
	hostName, err := settings.GetStrict(alias, "HostName")
	if err != nil {
		return nativeTarget{}, fmt.Errorf("ssh_config %s HostName: %w", alias, err)
	}
	if hostName == "" {
		hostName = alias
	}
	userName, err := settings.GetStrict(alias, "User")
	if err != nil {
		return nativeTarget{}, fmt.Errorf("ssh_config %s User: %w", alias, err)
	}
	if userName == "" {
		userName = currentUserName()
	}
	portValue, err := settings.GetStrict(alias, "Port")
	if err != nil {
		return nativeTarget{}, fmt.Errorf("ssh_config %s Port: %w", alias, err)
	}
	port := 22
	if portValue != "" {
		parsed, err := strconv.Atoi(portValue)
		if err != nil {
			return nativeTarget{}, fmt.Errorf("ssh_config %s invalid Port %q: %w", alias, portValue, err)
		}
		port = parsed
	}
	identityFiles, err := settings.GetAllStrict(alias, "IdentityFile")
	if err != nil {
		return nativeTarget{}, fmt.Errorf("ssh_config %s IdentityFile: %w", alias, err)
	}
	for i := range identityFiles {
		identityFiles[i] = expandHome(identityFiles[i])
	}
	proxyJump, err := settings.GetStrict(alias, "ProxyJump")
	if err != nil {
		return nativeTarget{}, fmt.Errorf("ssh_config %s ProxyJump: %w", alias, err)
	}
	return nativeTarget{Name: name, HostName: hostName, Port: port, User: userName, IdentityFiles: identityFiles, ProxyJump: proxyJump}, nil
}

func (e NativeExecutor) userSettings() (*sshconfig.UserSettings, error) {
	path := e.Options.ConfigPath
	if path == "" {
		path = expandHome("~/.ssh/config")
	}
	settings := &sshconfig.UserSettings{}
	settings.ConfigFinder(func() string { return path })
	return settings, nil
}

func (e NativeExecutor) dial(ctx context.Context, target nativeTarget) (*nativeClient, error) {
	cfg, agentCloser, err := e.clientConfig(target)
	if err != nil {
		return nil, err
	}
	if agentCloser != nil {
		defer func() { _ = agentCloser.Close() }()
	}
	hostKeyCallback, err := e.hostKeyCallback()
	if err != nil {
		return nil, err
	}
	cfg.HostKeyCallback = hostKeyCallback
	if algos := e.knownHostKeyAlgorithms(target.address()); len(algos) > 0 {
		cfg.HostKeyAlgorithms = algos
	}
	return e.dialWithConfig(ctx, target, cfg)
}

func (e NativeExecutor) dialWithConfig(ctx context.Context, target nativeTarget, cfg *ssh.ClientConfig) (*nativeClient, error) {
	if strings.TrimSpace(target.ProxyJump) == "" || strings.TrimSpace(target.ProxyJump) == "none" {
		conn, err := e.dialTCP(ctx, target.address())
		if err != nil {
			return nil, err
		}
		client, err := e.newClientOnConn(conn, target.address(), cfg)
		if err != nil {
			return nil, err
		}
		return &nativeClient{Client: client, closers: []io.Closer{client}}, nil
	}

	jumps := strings.Split(target.ProxyJump, ",")
	firstJump, err := e.parseJump(strings.TrimSpace(jumps[0]))
	if err != nil {
		return nil, err
	}
	if len(jumps) > 1 {
		firstJump.ProxyJump = strings.Join(jumps[1:], ",")
	}
	jumpCfg, jumpCloser, err := e.clientConfig(firstJump)
	if err != nil {
		return nil, err
	}
	if jumpCloser != nil {
		defer func() { _ = jumpCloser.Close() }()
	}
	jumpCfg.HostKeyCallback = cfg.HostKeyCallback
	if algos := e.knownHostKeyAlgorithms(firstJump.address()); len(algos) > 0 {
		jumpCfg.HostKeyAlgorithms = algos
	}
	jumpClient, err := e.dialWithConfig(ctx, firstJump, jumpCfg)
	if err != nil {
		return nil, fmt.Errorf("proxyjump %s: %w", firstJump.display(), err)
	}
	tunnel, err := jumpClient.DialContext(ctx, "tcp", target.address())
	if err != nil {
		_ = jumpClient.Close()
		return nil, fmt.Errorf("proxyjump tunnel to %s: %w", target.address(), err)
	}
	client, err := e.newClientOnConn(tunnel, target.address(), cfg)
	if err != nil {
		_ = tunnel.Close()
		_ = jumpClient.Close()
		return nil, err
	}
	return &nativeClient{Client: client, closers: []io.Closer{client, tunnel, jumpClient}}, nil
}

type nativeClient struct {
	*ssh.Client
	closers []io.Closer
}

func (c *nativeClient) Close() error {
	var err error
	for _, closer := range c.closers {
		if closeErr := closer.Close(); closeErr != nil && err == nil {
			err = closeErr
		}
	}
	return err
}

type nativeClientPool struct {
	mu                sync.Mutex
	entries           map[string]*nativePoolEntry
	keepAliveInterval time.Duration
	closed            bool
}

type nativePoolEntry struct {
	client        *nativeClient
	dialing       bool
	ready         chan struct{}
	readyOnce     sync.Once
	stop          chan struct{}
	stopOnce      sync.Once
	dialErr       error
	inFlight      int
	removed       bool
	closeWhenIdle bool
	forceClosed   bool
	osName        string
}

func (e *nativePoolEntry) closeReady() {
	e.readyOnce.Do(func() {
		if e.ready != nil {
			close(e.ready)
		}
	})
}

func (e *nativePoolEntry) closeStop() {
	e.stopOnce.Do(func() {
		if e.stop != nil {
			close(e.stop)
		}
	})
}

func newNativeClientPool(keepAliveInterval time.Duration) *nativeClientPool {
	if keepAliveInterval == 0 {
		keepAliveInterval = defaultNativeKeepAliveInterval
	}
	return &nativeClientPool{
		entries:           map[string]*nativePoolEntry{},
		keepAliveInterval: keepAliveInterval,
	}
}

func (p *nativeClientPool) get(ctx context.Context, key string, dial func(context.Context) (*nativeClient, error)) (*nativeClient, *nativePoolEntry, error) {
	for {
		p.mu.Lock()
		if p.closed {
			p.mu.Unlock()
			return nil, nil, errors.New("native SSH executor is closed")
		}
		entry := p.entries[key]
		if entry == nil {
			entry = &nativePoolEntry{dialing: true, ready: make(chan struct{})}
			p.entries[key] = entry
			p.mu.Unlock()
			return p.dialEntry(ctx, key, entry, dial)
		}
		if entry.client != nil {
			client := entry.client
			entry.inFlight++
			p.mu.Unlock()
			return client, entry, nil
		}
		if entry.dialing {
			ready := entry.ready
			p.mu.Unlock()
			select {
			case <-ready:
				p.mu.Lock()
				dialErr := entry.dialErr
				p.mu.Unlock()
				if dialErr != nil {
					return nil, nil, dialErr
				}
				continue
			case <-ctx.Done():
				return nil, nil, ctx.Err()
			}
		}
		p.mu.Unlock()
	}
}

func (p *nativeClientPool) dialEntry(ctx context.Context, key string, entry *nativePoolEntry, dial func(context.Context) (*nativeClient, error)) (*nativeClient, *nativePoolEntry, error) {
	client, err := dial(ctx)

	p.mu.Lock()
	defer p.mu.Unlock()
	current := p.entries[key]
	if current != entry {
		if client != nil {
			_ = client.Close()
		}
		if err != nil {
			return nil, nil, err
		}
		return nil, nil, errors.New("native SSH pooled connection was replaced while dialing")
	}
	entry.dialing = false
	if err != nil {
		entry.dialErr = err
		delete(p.entries, key)
		entry.closeReady()
		return nil, nil, err
	}
	if p.closed {
		delete(p.entries, key)
		entry.closeReady()
		_ = client.Close()
		return nil, nil, errors.New("native SSH executor is closed")
	}
	entry.client = client
	entry.inFlight = 1
	entry.stop = make(chan struct{})
	entry.closeReady()
	p.startKeepAliveLocked(key, entry)
	return client, entry, nil
}

func (p *nativeClientPool) startKeepAliveLocked(key string, entry *nativePoolEntry) {
	if p.keepAliveInterval < 0 || entry.client == nil || entry.stop == nil {
		return
	}
	client := entry.client
	stop := entry.stop
	interval := p.keepAliveInterval
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				if err := sendKeepAlive(client, nativeKeepAliveTimeout); err != nil {
					p.evictNow(key, entry, client)
					return
				}
			case <-stop:
				return
			}
		}
	}()
}

func (p *nativeClientPool) isDead(key string, entry *nativePoolEntry, client *nativeClient) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	current := p.entries[key]
	return current != entry || entry == nil || entry.client != client || entry.forceClosed
}

func (p *nativeClientPool) release(entry *nativePoolEntry) {
	var closeClient *nativeClient
	var closeStop *nativePoolEntry

	p.mu.Lock()
	if entry != nil && entry.inFlight > 0 {
		entry.inFlight--
		if entry.inFlight == 0 && entry.closeWhenIdle && !entry.forceClosed {
			closeClient = entry.client
			closeStop = entry
			entry.forceClosed = true
		}
	}
	p.mu.Unlock()

	if closeStop != nil {
		closeStop.closeStop()
	}
	if closeClient != nil {
		_ = closeClient.Close()
	}
}

func (p *nativeClientPool) cachedOS(entry *nativePoolEntry) string {
	p.mu.Lock()
	defer p.mu.Unlock()
	if entry == nil || entry.forceClosed {
		return ""
	}
	return entry.osName
}

func (p *nativeClientPool) setOS(entry *nativePoolEntry, osName string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if entry != nil && !entry.forceClosed {
		entry.osName = osName
	}
}

func (p *nativeClientPool) depoolWhenIdle(key string, entry *nativePoolEntry, client *nativeClient) {
	var closeClient *nativeClient
	var closeStop *nativePoolEntry

	p.mu.Lock()
	if entry != nil && entry.client == client && !entry.forceClosed {
		if p.entries[key] == entry {
			delete(p.entries, key)
		}
		entry.removed = true
		entry.closeWhenIdle = true
		if entry.inFlight == 0 {
			closeClient = entry.client
			closeStop = entry
			entry.forceClosed = true
		}
	}
	p.mu.Unlock()

	if closeStop != nil {
		closeStop.closeStop()
	}
	if closeClient != nil {
		_ = closeClient.Close()
	}
}

func (p *nativeClientPool) evictNow(key string, entry *nativePoolEntry, client *nativeClient) {
	var closeClient *nativeClient
	var closeStop *nativePoolEntry

	p.mu.Lock()
	if entry != nil && entry.client == client && !entry.forceClosed {
		if p.entries[key] == entry {
			delete(p.entries, key)
		}
		entry.removed = true
		entry.closeWhenIdle = true
		entry.forceClosed = true
		closeClient = entry.client
		closeStop = entry
	}
	p.mu.Unlock()

	if closeStop != nil {
		closeStop.closeStop()
	}
	if closeClient != nil {
		_ = closeClient.Close()
	}
}

func sendKeepAlive(client *nativeClient, timeout time.Duration) error {
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	done := make(chan error, 1)
	go func() {
		_, _, err := client.SendRequest("keepalive@openssh.com", true, nil)
		done <- err
	}()
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case err := <-done:
		return err
	case <-timer.C:
		return context.DeadlineExceeded
	}
}

func (p *nativeClientPool) Close() error {
	if p == nil {
		return nil
	}

	var clients []*nativeClient
	var stops []*nativePoolEntry
	var ready []*nativePoolEntry

	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil
	}
	p.closed = true
	for key, entry := range p.entries {
		delete(p.entries, key)
		if entry.stop != nil {
			stops = append(stops, entry)
		}
		if entry.dialing && entry.ready != nil {
			ready = append(ready, entry)
		}
		if entry.client != nil {
			clients = append(clients, entry.client)
		}
	}
	p.mu.Unlock()

	for _, entry := range stops {
		entry.closeStop()
	}
	for _, entry := range ready {
		entry.closeReady()
	}
	var err error
	for _, client := range clients {
		if closeErr := client.Close(); closeErr != nil && err == nil {
			err = closeErr
		}
	}
	return err
}

func (e NativeExecutor) dialTCP(ctx context.Context, addr string) (net.Conn, error) {
	timeout := e.Options.ConnectTimeout
	if timeout == 0 {
		timeout = 10 * time.Second
	}
	dialer := net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	deadline := time.Now().Add(timeout)
	if err := conn.SetDeadline(deadline); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return conn, nil
}

func (e NativeExecutor) newClientOnConn(conn net.Conn, addr string, cfg *ssh.ClientConfig) (*ssh.Client, error) {
	clientConn, chans, reqs, err := ssh.NewClientConn(conn, addr, cfg)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	_ = conn.SetDeadline(time.Time{})
	return ssh.NewClient(clientConn, chans, reqs), nil
}

func (e NativeExecutor) parseJump(value string) (nativeTarget, error) {
	if value == "" || value == "none" {
		return nativeTarget{}, fmt.Errorf("empty ProxyJump")
	}
	userName := currentUserName()
	hostPort := value
	if before, after, ok := strings.Cut(value, "@"); ok {
		userName = before
		hostPort = after
	}
	hostName, portValue, err := net.SplitHostPort(hostPort)
	if err != nil {
		hostName = hostPort
		portValue = "22"
	}
	port, err := strconv.Atoi(portValue)
	if err != nil {
		return nativeTarget{}, fmt.Errorf("invalid ProxyJump port %q: %w", portValue, err)
	}
	return nativeTarget{Name: value, HostName: hostName, Port: port, User: userName}, nil
}

func (e NativeExecutor) clientConfig(target nativeTarget) (*ssh.ClientConfig, io.Closer, error) {
	authMethods, closer, err := e.authMethods(target)
	if err != nil {
		return nil, nil, err
	}
	if len(authMethods) == 0 {
		return nil, closer, errors.New("no SSH auth methods available (set identity_file, start ssh-agent, load a key with ssh-add, or register a password with agentssh secret set)")
	}
	timeout := e.Options.ConnectTimeout
	if timeout == 0 {
		timeout = 10 * time.Second
	}
	return &ssh.ClientConfig{User: target.User, Auth: authMethods, Timeout: timeout}, closer, nil
}

// Probe opens a native SSH session and runs a no-op command. It is intended for
// explicit operator diagnostics; callers must gate it behind a user action.
func (e NativeExecutor) Probe(ctx context.Context, target inventory.Target) Result {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	result := e.runSession(ctx, Request{Target: target, Command: OSProbeCommand}, &stdout, &stderr, false)
	result.Stdout = stdout.String()
	result.Stderr = stderr.String()
	return result
}

// ProbeStatusForError maps a transport error into the probe status vocabulary.
func ProbeStatusForError(err error) ProbeStatus {
	if err == nil {
		return ProbeConnectable
	}
	var keyErr *knownhosts.KeyError
	if errors.As(err, &keyErr) {
		return ProbeHostKeyIssue
	}
	message := strings.ToLower(err.Error())
	if strings.Contains(message, "authenticate") || strings.Contains(message, "auth methods") {
		return ProbeAuthFailed
	}
	return ProbeUnreachable
}

// ConnectHint maps connection failures to credential-free operator guidance.
func ConnectHint(err error) string {
	if err == nil {
		return ""
	}
	var keyErr *knownhosts.KeyError
	if errors.As(err, &keyErr) {
		if len(keyErr.Want) == 0 {
			return "hint: unknown host key; connect once with ssh to trust this host, or set host_key_policy: accept-new."
		}
		return "hint: host key changed; possible MITM. Verify the fingerprint before trusting this host."
	}
	if isConnectionRefused(err) || isTimeout(err) {
		return "hint: cannot reach SSH; check addr, port, network route, and firewall rules."
	}
	message := strings.ToLower(err.Error())
	if strings.Contains(message, "no ssh auth methods available") || strings.Contains(message, "no auth methods available") {
		return "hint: no SSH credentials available; set identity_file for this host, load a key with ssh-add, or register a password with agentssh secret set <host>."
	}
	if strings.Contains(message, "unable to authenticate") || strings.Contains(message, "attempted methods") || strings.Contains(message, "authenticate") {
		return "hint: SSH authentication failed; set identity_file, load a key with ssh-add, or register a password with agentssh secret set <host>. Ensure the remote account and authorized_keys are already configured; AgentSSH never changes the remote host."
	}
	return "hint: SSH connection failed; check addr, port, network, host key trust, and available SSH keys."
}

func isTimeout(err error) bool {
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

func isConnectionRefused(err error) bool {
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		var syscallErr *os.SyscallError
		if errors.As(opErr.Err, &syscallErr) {
			return errors.Is(syscallErr.Err, syscall.ECONNREFUSED)
		}
	}
	return errors.Is(err, syscall.ECONNREFUSED) || strings.Contains(strings.ToLower(err.Error()), "connection refused")
}

func isBrokenSSHClientError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) || errors.Is(err, syscall.EPIPE) || errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.ECONNABORTED) {
		return true
	}
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "use of closed network connection") ||
		strings.Contains(message, "broken pipe") ||
		strings.Contains(message, "connection reset") ||
		strings.Contains(message, "connection closed") ||
		strings.Contains(message, "unexpected packet in response to channel open: <nil>")
}

func isSessionCapacityError(err error) bool {
	var openErr *ssh.OpenChannelError
	if errors.As(err, &openErr) {
		return openErr.Reason == ssh.Prohibited || openErr.Reason == ssh.ResourceShortage
	}
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "administratively prohibited") || strings.Contains(message, "resource shortage")
}

func (e NativeExecutor) authMethods(target nativeTarget) ([]ssh.AuthMethod, io.Closer, error) {
	var methods []ssh.AuthMethod
	var agentConn io.Closer
	if sock := os.Getenv("SSH_AUTH_SOCK"); sock != "" {
		conn, err := net.Dial("unix", sock)
		if err == nil {
			agentConn = conn
			ag := agent.NewClient(conn)
			methods = append(methods, ssh.PublicKeysCallback(ag.Signers))
		}
	}

	files := append([]string{}, target.IdentityFiles...)
	files = append(files, defaultIdentityFiles()...)
	signers, err := signersFromFiles(files)
	if err != nil {
		return nil, agentConn, err
	}
	if len(signers) > 0 {
		methods = append(methods, ssh.PublicKeys(signers...))
	}
	if e.Options.PasswordSource != nil {
		if password, ok := e.Options.PasswordSource(target.Name); ok {
			methods = append(methods, ssh.Password(password))
		}
	}
	return methods, agentConn, nil
}

func signersFromFiles(files []string) ([]ssh.Signer, error) {
	var signers []ssh.Signer
	for _, path := range files {
		data, err := os.ReadFile(expandHome(path))
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("read identity file %s: %w", path, err)
		}
		signer, err := ssh.ParsePrivateKey(data)
		if err != nil {
			var passphraseErr *ssh.PassphraseMissingError
			if errors.As(err, &passphraseErr) {
				passphrase, ok, readErr := readPassphrase(path)
				if readErr != nil {
					return nil, readErr
				}
				if !ok {
					continue
				}
				signer, err = ssh.ParsePrivateKeyWithPassphrase(data, passphrase)
				if err != nil {
					return nil, fmt.Errorf("parse encrypted identity file %s: %w", path, err)
				}
				signers = append(signers, signer)
				continue
			}
			return nil, fmt.Errorf("parse identity file %s: %w", path, err)
		}
		signers = append(signers, signer)
	}
	return signers, nil
}

func readPassphrase(path string) ([]byte, bool, error) {
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return nil, false, nil
	}
	_, _ = fmt.Fprintf(os.Stderr, "Enter passphrase for %s: ", path)
	passphrase, err := term.ReadPassword(int(os.Stdin.Fd()))
	_, _ = fmt.Fprintln(os.Stderr)
	if err != nil {
		return nil, false, fmt.Errorf("read passphrase for %s: %w", path, err)
	}
	return passphrase, true, nil
}

func defaultIdentityFiles() []string {
	return []string{"~/.ssh/id_ed25519", "~/.ssh/id_ecdsa", "~/.ssh/id_rsa"}
}

func (e NativeExecutor) hostKeyCallback() (ssh.HostKeyCallback, error) {
	path := e.Options.KnownHostsPath
	if path == "" {
		path = expandHome("~/.ssh/known_hosts")
	}
	if err := ensureKnownHosts(path); err != nil {
		return nil, err
	}
	strict, err := knownhosts.New(path)
	if err != nil {
		return nil, fmt.Errorf("load known_hosts %s: %w", path, err)
	}
	if e.Options.HostKeyPolicy != "accept-new" {
		return strict, nil
	}
	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		err := strict(hostname, remote, key)
		if err == nil {
			return nil
		}
		var keyErr *knownhosts.KeyError
		if errors.As(err, &keyErr) && len(keyErr.Want) == 0 {
			return appendKnownHost(path, hostname, remote, key)
		}
		return err
	}, nil
}

// knownHostKeyAlgorithms returns the host-key algorithms already recorded for
// addr in known_hosts, in client-preference order, so the handshake negotiates a
// key type we actually trust. Without this, a server offering several host-key
// types (e.g. ecdsa + ed25519) can get negotiated onto a type absent from
// known_hosts and be falsely reported as a key mismatch — OpenSSH avoids this by
// preferring algorithms it already has a key for, and so do we.
//
// It returns nil when the host is unknown (no recorded keys) so the caller leaves
// ClientConfig.HostKeyAlgorithms unset and default negotiation applies, which is
// what first-time / accept-new connections need. It probes a fresh strict
// callback (never the accept-new wrapper) so the probe can never append a key.
func (e NativeExecutor) knownHostKeyAlgorithms(addr string) []string {
	path := e.Options.KnownHostsPath
	if path == "" {
		path = expandHome("~/.ssh/known_hosts")
	}
	strict, err := knownhosts.New(path)
	if err != nil {
		return nil
	}
	// An all-zero ed25519 key is a valid placeholder for marshaling; it will not
	// equal any real stored key, so the callback returns a KeyError whose Want
	// lists every host key recorded for addr.
	fakeKey, err := ssh.NewPublicKey(ed25519.PublicKey(make([]byte, ed25519.PublicKeySize)))
	if err != nil {
		return nil
	}
	probeErr := strict(addr, &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 22}, fakeKey)
	var keyErr *knownhosts.KeyError
	if !errors.As(probeErr, &keyErr) || len(keyErr.Want) == 0 {
		return nil
	}

	seen := map[string]bool{}
	var algos []string
	add := func(a string) {
		if a == "" || seen[a] {
			return
		}
		seen[a] = true
		algos = append(algos, a)
	}
	for _, want := range keyErr.Want {
		switch want.Key.Type() {
		case ssh.KeyAlgoRSA:
			// Servers sign with the SHA-2 variants now; offer them ahead of the
			// legacy ssh-rsa name, which shares the same stored key.
			add(ssh.KeyAlgoRSASHA512)
			add(ssh.KeyAlgoRSASHA256)
			add(ssh.KeyAlgoRSA)
		default:
			add(want.Key.Type())
		}
	}
	return algos
}

func ensureKnownHosts(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create known_hosts directory: %w", err)
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return fmt.Errorf("open known_hosts %s: %w", path, err)
	}
	return file.Close()
}

func appendKnownHost(path string, hostname string, remote net.Addr, key ssh.PublicKey) error {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return fmt.Errorf("open known_hosts for append: %w", err)
	}
	defer func() { _ = file.Close() }()
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX); err != nil {
		return fmt.Errorf("lock known_hosts: %w", err)
	}
	defer func() { _ = syscall.Flock(int(file.Fd()), syscall.LOCK_UN) }()

	names := []string{hostname}
	if remote.String() != hostname {
		names = append(names, remote.String())
	}
	line := knownhosts.Line(names, key)
	if _, err := file.WriteString(line + "\n"); err != nil {
		return fmt.Errorf("append known_hosts: %w", err)
	}
	return nil
}

func nativeExitCode(err error) (int, error) {
	if err == nil {
		return 0, nil
	}
	var exitErr *ssh.ExitError
	if errors.As(err, &exitErr) {
		return exitErr.ExitStatus(), nil
	}
	var missing *ssh.ExitMissingError
	if errors.As(err, &missing) {
		return -1, err
	}
	return -1, err
}

func currentUserName() string {
	if env := os.Getenv("USER"); env != "" {
		return env
	}
	if u, err := user.Current(); err == nil && u.Username != "" {
		return u.Username
	}
	return ""
}

func expandHome(path string) string {
	if path == "~" {
		if home, err := os.UserHomeDir(); err == nil {
			return home
		}
	}
	if strings.HasPrefix(path, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, path[2:])
		}
	}
	return path
}
