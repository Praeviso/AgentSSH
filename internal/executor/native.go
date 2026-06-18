package executor

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
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

// NativeOptions configures the native Go SSH executor.
type NativeOptions struct {
	ConfigPath     string
	KnownHostsPath string
	ConnectTimeout time.Duration
	HostKeyPolicy  string // strict | accept-new
	PasswordSource func(host string) (string, bool)
}

// NativeExecutor executes commands using golang.org/x/crypto/ssh.
type NativeExecutor struct {
	Options NativeOptions
}

// NewNativeExecutor returns a native SSH executor.
func NewNativeExecutor(options NativeOptions) NativeExecutor {
	if options.ConnectTimeout == 0 {
		options.ConnectTimeout = 10 * time.Second
	}
	if options.HostKeyPolicy == "" {
		options.HostKeyPolicy = "strict"
	}
	return NativeExecutor{Options: options}
}

func (e NativeExecutor) Run(ctx context.Context, request Request) Result {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	result := e.runSession(ctx, request, &stdout, &stderr)
	result.Stdout = stdout.String()
	result.Stderr = stderr.String()
	return result
}

func (e NativeExecutor) RunStreaming(ctx context.Context, request Request, stdout io.Writer, stderr io.Writer) Result {
	return e.runSession(ctx, request, stdout, stderr)
}

func (e NativeExecutor) runSession(ctx context.Context, request Request, stdout io.Writer, stderr io.Writer) Result {
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

	client, err := e.dial(ctx, target)
	if err != nil {
		return Result{ExitCode: -1, Duration: time.Since(start), Err: err, Argv: argv}
	}
	defer func() {
		_ = client.Close()
	}()

	session, err := client.NewSession()
	if err != nil {
		return Result{ExitCode: -1, Duration: time.Since(start), Err: err, Argv: argv}
	}
	defer func() {
		_ = session.Close()
	}()

	session.Stdout = stdout
	session.Stderr = stderr

	runErr := session.Run(request.Command)
	exitCode, err := nativeExitCode(runErr)
	if err != nil {
		return Result{ExitCode: -1, Duration: time.Since(start), Err: err, Argv: argv}
	}
	return Result{ExitCode: exitCode, Duration: time.Since(start), Argv: argv}
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
	return e.Run(ctx, Request{Target: target, Command: "true"})
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
