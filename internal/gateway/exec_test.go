package gateway_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Praeviso/AgentSSH/internal/audit"
	"github.com/Praeviso/AgentSSH/internal/controlplane"
	"github.com/Praeviso/AgentSSH/internal/gateway"
	"github.com/Praeviso/AgentSSH/internal/remote"
	"golang.org/x/crypto/ssh"
)

const testPolicy = `version: 1
approval:
  enabled: true
rules:
  - {name: deny-reboot, match: {cmd_regex: '^reboot$'}, action: deny}
  - {name: allow-test, match: {cmd_regex: '^(stream|cat|secret|sleep|uptime|flood)$'}, action: allow}
output:
  redact: ['hunter2']
`

// targetHost is an in-process sshd that accepts only one public key and runs
// a handful of scripted commands.
type targetHost struct {
	listener net.Listener
	hostKey  ssh.Signer
	allowed  ssh.PublicKey
	release  chan struct{}
	events   chan string
	wg       sync.WaitGroup
}

func newTargetHost(t *testing.T, allowed ssh.PublicKey) *targetHost {
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
	h := &targetHost{listener: ln, hostKey: hostKey, allowed: allowed, release: make(chan struct{}), events: make(chan string, 32)}
	h.wg.Add(1)
	go h.accept()
	t.Cleanup(func() {
		_ = ln.Close()
		h.wg.Wait()
	})
	return h
}

func (h *targetHost) port() int { return h.listener.Addr().(*net.TCPAddr).Port }

func (h *targetHost) event(name string) { h.events <- name }

func (h *targetHost) waitEvent(t *testing.T, want string) {
	t.Helper()
	deadline := time.After(10 * time.Second)
	for {
		select {
		case got := <-h.events:
			if got == want {
				return
			}
		case <-deadline:
			t.Fatalf("target host never saw %q", want)
		}
	}
}

func (h *targetHost) accept() {
	defer h.wg.Done()
	for {
		conn, err := h.listener.Accept()
		if err != nil {
			return
		}
		h.wg.Add(1)
		go h.serve(conn)
	}
}

func (h *targetHost) serve(conn net.Conn) {
	defer h.wg.Done()
	cfg := &ssh.ServerConfig{PublicKeyCallback: func(_ ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
		if bytes.Equal(key.Marshal(), h.allowed.Marshal()) {
			return nil, nil
		}
		return nil, errors.New("unknown key")
	}}
	cfg.AddHostKey(h.hostKey)
	sshConn, chans, reqs, err := ssh.NewServerConn(conn, cfg)
	if err != nil {
		_ = conn.Close()
		return
	}
	defer func() { _ = sshConn.Close() }()
	go ssh.DiscardRequests(reqs)
	var sessions sync.WaitGroup
	for ch := range chans {
		channel, requests, err := ch.Accept()
		if err != nil {
			continue
		}
		sessions.Add(1)
		go func() {
			defer sessions.Done()
			h.session(channel, requests)
		}()
	}
	sessions.Wait()
}

func (h *targetHost) session(channel ssh.Channel, requests <-chan *ssh.Request) {
	defer func() { _ = channel.Close() }()
	signals := make(chan string, 1)
	done := make(chan struct{})
	defer close(done)
	for req := range requests {
		switch req.Type {
		case "exec":
			var payload struct{ Command string }
			_ = ssh.Unmarshal(req.Payload, &payload)
			_ = req.Reply(true, nil)
			go func() {
				// Drain the remaining requests (signals) while the command runs.
				for req := range requests {
					if req.Type == "signal" {
						var sig struct{ Signal string }
						_ = ssh.Unmarshal(req.Payload, &sig)
						h.event("signal:" + sig.Signal)
						signals <- sig.Signal
					}
					if req.WantReply {
						_ = req.Reply(false, nil)
					}
				}
			}()
			status := h.run(channel, payload.Command, signals)
			_, _ = channel.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{status}))
			return
		default:
			if req.WantReply {
				_ = req.Reply(false, nil)
			}
		}
	}
}

func (h *targetHost) run(channel ssh.Channel, command string, signals <-chan string) uint32 {
	switch command {
	case "uname -s":
		_, _ = io.WriteString(channel, "Linux\n")
	case "uptime":
		_, _ = io.WriteString(channel, "up 3 days\n")
	case "secret":
		_, _ = io.WriteString(channel, "token=hunter2\n")
	case "flood":
		// Three times the gateway's output cap, in a byte JSON must escape.
		_, _ = channel.Write(bytes.Repeat([]byte("<"), 3*remote.MaxExecOutputBytes))
	case "stream":
		_, _ = io.WriteString(channel, "chunk-1\n")
		<-h.release
		_, _ = io.WriteString(channel, "chunk-2\n")
	case "cat":
		data, _ := io.ReadAll(channel)
		_, _ = channel.Write(data)
	case "sleep":
		h.event("sleep-started")
		<-signals
		return 143
	default:
		_, _ = io.WriteString(channel.Stderr(), "unexpected command\n")
		return 127
	}
	return 0
}

// execGateway is an enrolled gateway with a target host and pushed config.
func execGateway(t *testing.T) (*fixture, *targetHost) {
	t.Helper()
	f := enrolledGateway(t)
	recipient, err := controlplane.LoadRecipient(f.dir)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := controlplane.NewIdentity("web", recipient, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := f.store.CreateIdentity(identity); err != nil {
		t.Fatal(err)
	}
	pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(identity.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	host := newTargetHost(t, pub)
	inv := fmt.Sprintf("host_key_policy: accept-new\nhosts:\n  web-1: {addr: 127.0.0.1, port: %d, user: deploy, identity: web}\n", host.port())
	if _, err := controlplane.PushConfig(f.store, f.client.State.DeviceID, inv, testPolicy, time.Now()); err != nil {
		t.Fatal(err)
	}
	return f, host
}

func execReq(cmd string) remote.ExecRequest {
	return remote.ExecRequest{Host: "web-1", Cmd: cmd, Session: "s_test"}
}

// chunkWriter publishes every write so a test can observe output while the
// command is still running.
type chunkWriter struct {
	mu     sync.Mutex
	chunks chan string
	buf    bytes.Buffer
}

func (w *chunkWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	w.buf.Write(p)
	w.mu.Unlock()
	w.chunks <- string(p)
	return len(p), nil
}

func auditRecords(t *testing.T, f *fixture) []audit.Record {
	t.Helper()
	records, err := audit.NewStore(filepath.Join(f.dir, gateway.FileAudit)).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	return records
}

func TestExecStreamsAllowedOutputChunkByChunk(t *testing.T) {
	f, host := execGateway(t)
	stdout := &chunkWriter{chunks: make(chan string, 8)}
	type outcome struct {
		result remote.ExecResult
		err    error
	}
	done := make(chan outcome, 1)
	go func() {
		req := execReq("stream")
		req.Stream = true
		result, err := f.client.Exec(context.Background(), req, stdout, io.Discard)
		done <- outcome{result, err}
	}()
	select {
	case chunk := <-stdout.chunks:
		if chunk != "chunk-1\n" {
			t.Fatalf("first chunk = %q", chunk)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("no output streamed while the command was running")
	}
	// Outlast the ingress read/write timeouts before the command finishes.
	time.Sleep(1500 * time.Millisecond)
	select {
	case chunk := <-stdout.chunks:
		t.Fatalf("output %q arrived before the command produced it", chunk)
	default:
	}
	close(host.release)
	got := <-done
	if got.err != nil {
		t.Fatalf("exec: %v", got.err)
	}
	if got.result.ExitCode != 0 || len(got.result.Responses) != 1 || got.result.Responses[0].Status != "completed" {
		t.Fatalf("result = %+v", got.result)
	}
	if stdout.buf.String() != "chunk-1\nchunk-2\n" {
		t.Fatalf("streamed stdout = %q", stdout.buf.String())
	}
}

func TestExecFeedsStdinByteForByte(t *testing.T) {
	f, _ := execGateway(t)
	stdin := []byte("line one\nzweite Zeile — ü\n\ttabbed\n")
	req := execReq("cat")
	req.Stdin = stdin
	result, err := f.client.Exec(context.Background(), req, io.Discard, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(stdin)
	got := result.Responses[0]
	if got.Stdout != string(stdin) || got.StdinSHA256 != hex.EncodeToString(sum[:]) || got.StdinBytes != int64(len(stdin)) {
		t.Fatalf("stdin round trip: stdout=%q sha=%s bytes=%d", got.Stdout, got.StdinSHA256, got.StdinBytes)
	}
}

func TestExecRedactsOutputOnTheGateway(t *testing.T) {
	f, _ := execGateway(t)
	stdout := &chunkWriter{chunks: make(chan string, 8)}
	req := execReq("secret")
	req.Stream = true
	result, err := f.client.Exec(context.Background(), req, stdout, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(stdout.buf.String(), "hunter2") || strings.Contains(result.Responses[0].Stdout, "hunter2") || result.Responses[0].Redactions != 1 {
		t.Fatalf("secret reached the device: stream=%q result=%+v", stdout.buf.String(), result.Responses[0])
	}
}

func TestExecPolicyDenyAndGrayZone(t *testing.T) {
	f, _ := execGateway(t)
	denied, err := f.client.Exec(context.Background(), execReq("reboot"), io.Discard, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if denied.ExitCode != 6 || denied.Responses[0].Status != "denied" || denied.Responses[0].PolicyRule != "rules:deny-reboot" {
		t.Fatalf("deny = %+v", denied)
	}
	pending, err := f.client.Exec(context.Background(), execReq("ls -la /etc"), io.Discard, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	got := pending.Responses[0]
	if pending.ExitCode != 7 || got.Status != "approval_pending" || got.ApprovalID == "" || got.NextAction != "wait_for_approval" {
		t.Fatalf("gray zone = %+v", pending)
	}
	files, err := os.ReadDir(filepath.Join(f.dir, "devices", f.client.State.DeviceID, "approval", "pending"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no pending request stored for the device: %v", err)
	}
}

func TestExecCancellationTerminatesRemoteCommand(t *testing.T) {
	f, host := execGateway(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := f.client.Exec(ctx, execReq("sleep"), io.Discard, io.Discard)
		done <- err
	}()
	host.waitEvent(t, "sleep-started")
	cancel()
	if err := <-done; err == nil {
		t.Fatal("cancelled execution reported a result")
	}
	host.waitEvent(t, "signal:TERM")
	deadline := time.Now().Add(10 * time.Second)
	for {
		records := auditRecords(t, f)
		if n := len(records); n > 0 && records[n-1].Event == audit.EventFailed {
			last := records[n-1]
			if last.Error != "cancelled" || last.DeviceID != f.client.State.DeviceID {
				t.Fatalf("cancellation audit = %+v", last)
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("no cancellation audit record: %+v", records)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestExecTimeoutEndsTheCommand(t *testing.T) {
	f, host := execGateway(t)
	f.server.ExecTimeout = 300 * time.Millisecond
	result, err := f.client.Exec(context.Background(), execReq("sleep"), io.Discard, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if result.ExitCode != 9 || result.Responses[0].Status != "ssh_error" {
		t.Fatalf("timed out run = %+v", result)
	}
	host.waitEvent(t, "signal:TERM")
	if records := auditRecords(t, f); records[len(records)-1].Error != "timed out" {
		t.Fatalf("timeout audit = %+v", records[len(records)-1])
	}
}

func TestExecPerDeviceConcurrencyLimit(t *testing.T) {
	f, host := execGateway(t)
	f.server.MaxConcurrentPerDevice = 1
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = f.client.Exec(ctx, execReq("sleep"), io.Discard, io.Discard)
	}()
	host.waitEvent(t, "sleep-started")
	_, err := f.client.Exec(context.Background(), execReq("uptime"), io.Discard, io.Discard)
	var apiErr *remote.APIError
	if !errors.As(err, &apiErr) || apiErr.Status != 429 || apiErr.Code != remote.CodeBusy {
		t.Fatalf("second execution = %v, want 429 busy", err)
	}
	cancel()
	<-done
}

func TestExecUsageErrors(t *testing.T) {
	f, _ := execGateway(t)
	for name, req := range map[string]remote.ExecRequest{
		"unknown host": {Host: "db-9", Cmd: "uptime", Session: "s_test"},
		"no session":   {Host: "web-1", Cmd: "uptime"},
		"no command":   {Host: "web-1", Session: "s_test"},
	} {
		_, err := f.client.Exec(context.Background(), req, io.Discard, io.Discard)
		var apiErr *remote.APIError
		if !errors.As(err, &apiErr) || apiErr.Code != remote.CodeUsage {
			t.Errorf("%s: %v, want usage refusal", name, err)
		}
	}
	if records := auditRecords(t, f); len(records) != 0 {
		t.Fatalf("usage errors were audited as runs: %+v", records)
	}
}

func TestGatewayAuditChainBindsDevice(t *testing.T) {
	f, _ := execGateway(t)
	for _, cmd := range []string{"uptime", "reboot"} {
		if _, err := f.client.Exec(context.Background(), execReq(cmd), io.Discard, io.Discard); err != nil {
			t.Fatal(err)
		}
	}
	log := audit.NewStore(filepath.Join(f.dir, gateway.FileAudit))
	if result, err := log.Verify(); err != nil || !result.OK || result.Count != 3 {
		t.Fatalf("verify = %+v, %v (want started, completed, denied)", result, err)
	}
	for _, record := range auditRecords(t, f) {
		if record.DeviceID != f.client.State.DeviceID {
			t.Fatalf("record %d device = %q", record.Seq, record.DeviceID)
		}
	}
	data, err := os.ReadFile(log.Path)
	if err != nil {
		t.Fatal(err)
	}
	lines := bytes.Split(bytes.TrimSpace(data), []byte("\n"))
	var record map[string]any
	if err := json.Unmarshal(lines[1], &record); err != nil {
		t.Fatal(err)
	}
	record["device_id"] = "dev_0000000000000000"
	lines[1], _ = json.Marshal(record)
	if err := os.WriteFile(log.Path, append(bytes.Join(lines, []byte("\n")), '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	if result, err := log.Verify(); err != nil || result.OK || result.BrokenSeq != 1 {
		t.Fatalf("tampered device_id verified: %+v, %v", result, err)
	}
}

func TestDisabledIdentityStopsConnecting(t *testing.T) {
	f, _ := execGateway(t)
	if err := f.store.DisableIdentity("web", time.Now()); err != nil {
		t.Fatal(err)
	}
	result, err := f.client.Exec(context.Background(), execReq("uptime"), io.Discard, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if result.ExitCode != 9 || result.Responses[0].Status != "ssh_error" {
		t.Fatalf("disabled identity run = %+v", result)
	}
}

// An unauthenticated client must not get /exec's larger body cap or upload
// deadline: the refusal comes before the body is read. The request is written
// by hand so the headers reach the server while the body is still pending.
func TestExecRefusesUnauthenticatedUploadBeforeReadingIt(t *testing.T) {
	f, _ := execGateway(t)
	u, err := url.Parse(f.base + remote.PathExec)
	if err != nil {
		t.Fatal(err)
	}
	tlsConfig := http.DefaultTransport.(*http.Transport).TLSClientConfig.Clone()
	for name, tc := range map[string]struct {
		framing string
		status  int
	}{
		"unsigned stream":    {"Transfer-Encoding: chunked\r\n\r\n10\r\n{\"host\":\"web-1\",\r\n", 401},
		"declared too large": {"Content-Length: 67108864\r\n\r\n{\"host\":\"web-1\",", 413},
	} {
		t.Run(name, func(t *testing.T) {
			conn, err := tls.Dial("tcp", u.Host, tlsConfig)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = conn.Close() }()
			_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
			// Headers and the start of a body, then nothing more.
			if _, err := fmt.Fprintf(conn, "POST %s HTTP/1.1\r\nHost: %s\r\nContent-Type: application/json\r\n%s", u.Path, u.Host, tc.framing); err != nil {
				t.Fatal(err)
			}
			resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
			if err != nil {
				t.Fatalf("no refusal before the body was sent: %v", err)
			}
			_ = resp.Body.Close()
			if resp.StatusCode != tc.status {
				t.Fatalf("status = %d, want %d", resp.StatusCode, tc.status)
			}
		})
	}
}

// The audit reader caps one record at 8 MiB; a command at the request limit,
// in bytes JSON must escape, still leaves the chain readable.
func TestExecBoundsWhatReachesTheAudit(t *testing.T) {
	f, _ := execGateway(t)
	longest := execReq(strings.Repeat("<", remote.MaxExecCommandBytes))
	longest.SessionLabel = strings.Repeat("\x01", remote.MaxExecLabelBytes)
	result, err := f.client.Exec(context.Background(), longest, io.Discard, io.Discard)
	if err != nil || result.ExitCode != 7 {
		t.Fatalf("longest command: exit=%d err=%v, want approval pending", result.ExitCode, err)
	}
	for name, req := range map[string]remote.ExecRequest{
		"command": execReq(strings.Repeat("x", remote.MaxExecCommandBytes+1)),
		"label":   {Host: "web-1", Cmd: "uptime", Session: "s_test", SessionLabel: strings.Repeat("x", remote.MaxExecLabelBytes+1)},
		"step id": {Host: "web-1", Cmd: "uptime", Session: "s_test", StepID: strings.Repeat("x", remote.MaxExecFieldBytes+1)},
	} {
		_, err := f.client.Exec(context.Background(), req, io.Discard, io.Discard)
		var apiErr *remote.APIError
		if !errors.As(err, &apiErr) || apiErr.Code != remote.CodeUsage {
			t.Errorf("oversized %s: %v, want usage refusal", name, err)
		}
	}
	if _, err := f.client.Exec(context.Background(), execReq("uptime"), io.Discard, io.Discard); err != nil {
		t.Fatalf("run after the longest command: %v", err)
	}
	if result, err := audit.NewStore(filepath.Join(f.dir, gateway.FileAudit)).Verify(); err != nil || !result.OK || result.Count != 3 {
		t.Fatalf("audit = %+v, %v; want approval_requested, started, completed", result, err)
	}
}

// A policy without output.max_bytes must not let a group's output outgrow the
// stream: each target is capped and arrives in its own frame.
func TestExecCapsUnboundedGroupOutput(t *testing.T) {
	f, host := execGateway(t)
	inv := fmt.Sprintf(`host_key_policy: accept-new
hosts:
  web-1: {addr: 127.0.0.1, port: %d, user: deploy, identity: web, tags: [web]}
  web-2: {addr: 127.0.0.1, port: %d, user: deploy, identity: web, tags: [web]}
groups:
  web: {tags: [web]}
`, host.port(), host.port())
	if _, err := controlplane.PushConfig(f.store, f.client.State.DeviceID, inv, testPolicy, time.Now()); err != nil {
		t.Fatal(err)
	}
	result, err := f.client.Exec(context.Background(), remote.ExecRequest{Host: "web", Cmd: "flood", Session: "s_test"}, io.Discard, io.Discard)
	if err != nil {
		t.Fatalf("exec: %v", err)
	}
	if result.ExitCode != 0 || len(result.Responses) != 2 {
		t.Fatalf("result exit=%d responses=%d", result.ExitCode, len(result.Responses))
	}
	for _, got := range result.Responses {
		if len(got.Stdout) != remote.MaxExecOutputBytes || !got.OutputTruncated {
			t.Fatalf("%s: %d bytes, truncated=%v", got.Host, len(got.Stdout), got.OutputTruncated)
		}
	}
}
