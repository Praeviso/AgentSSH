package gateway_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Praeviso/AgentSSH/internal/audit"
	"github.com/Praeviso/AgentSSH/internal/controlplane"
	"github.com/Praeviso/AgentSSH/internal/gateway"
	"github.com/Praeviso/AgentSSH/internal/managedmode"
	"github.com/Praeviso/AgentSSH/internal/remote"
	"github.com/Praeviso/AgentSSH/internal/remoteclient"
)

type apiAnswer struct {
	status int
	body   remote.ErrorResponse
	raw    []byte
}

// bearer calls a token route with token as its bearer credential (none when
// empty).
func bearer(t *testing.T, f *fixture, path, token string) apiAnswer {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, f.base+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	return send(t, req)
}

// send makes one request, failing the test rather than hanging if no answer
// comes.
func send(t *testing.T, req *http.Request) apiAnswer {
	t.Helper()
	ctx, cancel := context.WithTimeout(req.Context(), 15*time.Second)
	defer cancel()
	resp, err := http.DefaultTransport.RoundTrip(req.WithContext(ctx))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(resp.Body)
	answer := apiAnswer{status: resp.StatusCode, raw: raw}
	_ = json.Unmarshal(raw, &answer.body)
	return answer
}

// signedGet sends a GET signed with key under keyID, as a device would.
func signedGet(t *testing.T, f *fixture, path, keyID string, key ed25519.PrivateKey) apiAnswer {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, f.base+path, http.NoBody)
	if err != nil {
		t.Fatal(err)
	}
	if err := remote.SignHTTPRequest(req, nil, keyID, remote.DeviceSignatureTag, key, time.Now()); err != nil {
		t.Fatal(err)
	}
	return send(t, req)
}

func deviceKey(t *testing.T, home string) ed25519.PrivateKey {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(managedmode.Dir(home), "device.key"))
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(data)
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return parsed.(ed25519.PrivateKey)
}

// tokenDevice creates a token device with the fixture inventory pushed, still
// inactive.
func tokenDevice(t *testing.T, f *fixture) gateway.IssuedToken {
	t.Helper()
	issued, err := gateway.CreateTokenDevice(f.dir, f.store, "hosted-agent", "local:alice", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := f.store.Config(f.client.State.DeviceID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := controlplane.PushConfig(f.store, issued.DeviceID, cfg.InventoryYAML, cfg.PolicyYAML, time.Now()); err != nil {
		t.Fatal(err)
	}
	return issued
}

// A token device starts inactive: its token reads its status but nothing
// else until an operator activates it, and is refused again once it is
// deactivated or revoked.
func TestATokenWorksOnlyWhileItsDeviceIsActive(t *testing.T) {
	f, _ := execGateway(t)
	issued := tokenDevice(t, f)
	if !strings.HasPrefix(issued.Token, "agt_"+issued.TokenID+"_") {
		t.Fatalf("token %q does not carry its ID %s", issued.Token, issued.TokenID)
	}
	status := bearer(t, f, remote.PathTokenStatus, issued.Token)
	var st remote.StatusResponse
	if err := json.Unmarshal(status.raw, &st); err != nil || status.status != http.StatusOK || st.DeviceID != issued.DeviceID || st.Activation == nil || st.Activation.State != remote.ActivationInactive {
		t.Fatalf("status while inactive: %d %s", status.status, status.raw)
	}
	if got := bearer(t, f, remote.PathTokenHosts, issued.Token); got.status != http.StatusForbidden || got.body.Code != remote.CodeDeviceInactive {
		t.Fatalf("hosts while inactive: %d %s", got.status, got.raw)
	}
	if _, err := gateway.ActivateDevice(f.dir, f.store, issued.DeviceID, time.Hour, "local:alice", "", time.Now()); err != nil {
		t.Fatal(err)
	}
	if got := bearer(t, f, remote.PathTokenHosts, issued.Token); got.status != http.StatusOK || !strings.Contains(string(got.raw), `"web-1"`) {
		t.Fatalf("hosts while active: %d %s", got.status, got.raw)
	}
	if _, err := gateway.DeactivateDevice(f.dir, f.store, issued.DeviceID, "local:alice", time.Now()); err != nil {
		t.Fatal(err)
	}
	if got := bearer(t, f, remote.PathTokenHosts, issued.Token); got.body.Code != remote.CodeDeviceInactive {
		t.Fatalf("hosts after deactivation: %d %s", got.status, got.raw)
	}
	if err := f.store.RevokeDevice(issued.DeviceID, time.Now()); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{remote.PathTokenStatus, remote.PathTokenHosts} {
		if got := bearer(t, f, path, issued.Token); got.status != http.StatusForbidden || got.body.Code != remote.CodeDeviceRevoked {
			t.Fatalf("%s after revocation: %d %s", path, got.status, got.raw)
		}
	}
	if _, err := gateway.RotateToken(f.dir, f.store, issued.DeviceID, "local:alice", time.Now()); err == nil {
		t.Fatal("a revoked device's token was rotated")
	}
}

// Rotating issues a new token and refuses the old one at once; both are in
// the audit chain with the device and token IDs.
func TestRotationRefusesTheOldTokenAtOnce(t *testing.T) {
	f, _ := execGateway(t)
	first := tokenDevice(t, f)
	second, err := gateway.RotateToken(f.dir, f.store, first.DeviceID, "local:bob", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if second.Token == first.Token || second.TokenID == first.TokenID || second.DeviceID != first.DeviceID {
		t.Fatalf("rotation: %+v after %+v", second, first)
	}
	if got := bearer(t, f, remote.PathTokenStatus, first.Token); got.status != http.StatusUnauthorized {
		t.Fatalf("old token after rotation: %d %s", got.status, got.raw)
	}
	if got := bearer(t, f, remote.PathTokenStatus, second.Token); got.status != http.StatusOK {
		t.Fatalf("new token: %d %s", got.status, got.raw)
	}
	if _, err := gateway.RotateToken(f.dir, f.store, f.client.State.DeviceID, "local:bob", time.Now()); err != gateway.ErrNotTokenDevice {
		t.Fatalf("rotating a signed device: %v", err)
	}
	records, err := audit.NewStore(filepath.Join(f.dir, gateway.FileAudit)).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	var tokens []string
	for _, r := range records {
		if r.Event == audit.EventTokenIssued || r.Event == audit.EventTokenRevoked {
			if r.DeviceID != first.DeviceID {
				t.Fatalf("token record for another device: %+v", r)
			}
			tokens = append(tokens, string(r.Event)+":"+r.TokenID+":"+r.Operator)
		}
	}
	want := []string{
		"device_token_issued:" + first.TokenID + ":local:alice",
		"device_token_revoked:" + first.TokenID + ":local:bob",
		"device_token_issued:" + second.TokenID + ":local:bob",
	}
	if strings.Join(tokens, " ") != strings.Join(want, " ") {
		t.Fatalf("token audit: %v, want %v", tokens, want)
	}
}

// Only the token's hash is stored: its secret appears nowhere in the
// gateway's data directory.
func TestATokenIsNotStoredInClear(t *testing.T) {
	f := enrolledGateway(t)
	issued, err := gateway.CreateTokenDevice(f.dir, f.store, "hosted-agent", "local:alice", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	// The secret's alphabet includes "_", so split on the two fixed separators.
	parts := strings.SplitN(issued.Token, "_", 3)
	if len(parts) != 3 || len(parts[2]) != 43 {
		t.Fatalf("token %q is not agt_<id>_<43-character secret>", issued.Token)
	}
	secret := parts[2]
	err = filepath.Walk(f.dir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if bytes.Contains(data, []byte(secret)) {
			t.Errorf("%s holds the token's secret", path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// A token never authenticates a signed route, a signature never
// authenticates a token route, and a token device cannot sign.
func TestTokensAndSignaturesNeverStandInForEachOther(t *testing.T) {
	f, _ := execGateway(t)
	issued := tokenDevice(t, f)
	if _, err := gateway.ActivateDevice(f.dir, f.store, issued.DeviceID, time.Hour, "local:alice", "", time.Now()); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{remote.PathStatus, remote.PathHosts} {
		if got := bearer(t, f, path, issued.Token); got.status != http.StatusUnauthorized {
			t.Fatalf("token on signed %s: %d %s", path, got.status, got.raw)
		}
	}
	// The signed device's own valid signature, on token routes.
	home := f.enrollHome(t, "signer")
	state, err := remoteclient.LoadState(home)
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{remote.PathTokenStatus, remote.PathTokenHosts} {
		if got := signedGet(t, f, path, state.DeviceID, deviceKey(t, home)); got.status != http.StatusUnauthorized {
			t.Fatalf("signature on token %s: %d %s", path, got.status, got.raw)
		}
	}
	// A signature claiming to be the token device, which has no key.
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	if got := signedGet(t, f, remote.PathStatus, issued.DeviceID, key); got.status != http.StatusUnauthorized {
		t.Fatalf("signature as the token device: %d %s", got.status, got.raw)
	}
}

// Malformed, unknown and guessed tokens get one answer that says nothing
// about which part was wrong, and a token is never accepted in a URL.
func TestBadTokensAreRefusedAlike(t *testing.T) {
	f := enrolledGateway(t)
	issued, err := gateway.CreateTokenDevice(f.dir, f.store, "hosted-agent", "local:alice", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	guess := issued.Token[:len(issued.Token)-1] + "A"
	if guess == issued.Token {
		guess = issued.Token[:len(issued.Token)-1] + "B"
	}
	unknown := "agt_0123456789abcdef_" + strings.Repeat("A", 43)
	for name, token := range map[string]string{
		"none": "", "garbage": "nonsense", "wrong prefix": "xyz" + issued.Token[3:], "unknown id": unknown, "wrong secret": guess,
	} {
		got := bearer(t, f, remote.PathTokenStatus, token)
		if got.status != http.StatusUnauthorized || got.body.Error != "invalid bearer token" {
			t.Errorf("%s: %d %s", name, got.status, got.raw)
		}
	}
	req, _ := http.NewRequest(http.MethodGet, f.base+remote.PathTokenStatus+"?token="+issued.Token, nil)
	if got := send(t, req); got.status != http.StatusBadRequest {
		t.Fatalf("token in the URL: %d %s", got.status, got.raw)
	}
}
