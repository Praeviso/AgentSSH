package gateway_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/Praeviso/AgentSSH/internal/audit"
	"github.com/Praeviso/AgentSSH/internal/controlplane"
	"github.com/Praeviso/AgentSSH/internal/gateway"
	"github.com/Praeviso/AgentSSH/internal/remote"
)

const testWebOrigin = "https://ops.example"

// oauthGateway is an exec gateway that knows its Web UI's origin, so it is
// also an OAuth authorization server.
func oauthGateway(t *testing.T) (*fixture, gateway.OAuth) {
	t.Helper()
	f, _ := execGateway(t)
	f.server.WebOrigin = testWebOrigin
	handler, err := f.server.Handler(f.base)
	if err != nil {
		t.Fatal(err)
	}
	f.handler.Store(&handler)
	o, err := gateway.NewOAuth(f.base, testWebOrigin)
	if err != nil {
		t.Fatal(err)
	}
	return f, o
}

type oauthAnswer struct {
	status int
	header http.Header
	raw    []byte
	body   map[string]any
}

func roundTrip(t *testing.T, req *http.Request) oauthAnswer {
	t.Helper()
	ctx, cancel := context.WithTimeout(req.Context(), 15*time.Second)
	defer cancel()
	resp, err := http.DefaultTransport.RoundTrip(req.WithContext(ctx))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(resp.Body)
	answer := oauthAnswer{status: resp.StatusCode, header: resp.Header, raw: raw}
	_ = json.Unmarshal(raw, &answer.body)
	return answer
}

func fetch(t *testing.T, rawURL string) oauthAnswer {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	return roundTrip(t, req)
}

// register registers a client as an MCP client would, failing unless it is
// accepted.
func register(t *testing.T, f *fixture, meta map[string]any) map[string]any {
	t.Helper()
	got := registration(t, f, meta)
	if got.status != http.StatusCreated {
		t.Fatalf("register %v: %d %s", meta, got.status, got.raw)
	}
	return got.body
}

func registration(t *testing.T, f *fixture, meta map[string]any) oauthAnswer {
	t.Helper()
	data, _ := json.Marshal(meta)
	req, err := http.NewRequest(http.MethodPost, f.base+remote.PathOAuthRegister, bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	return roundTrip(t, req)
}

func publicClient(t *testing.T, f *fixture) string {
	t.Helper()
	return register(t, f, map[string]any{
		"client_name": "Hosted agent", "redirect_uris": []string{"https://agent.example/callback"},
		"token_endpoint_auth_method": "none", "grant_types": []string{"authorization_code", "refresh_token"},
	})["client_id"].(string)
}

// tokenRequest posts form to the token endpoint, with Basic client
// credentials when basic names them (id, secret).
func tokenRequest(t *testing.T, f *fixture, form url.Values, basic ...string) oauthAnswer {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, f.base+remote.PathOAuthToken, strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if len(basic) == 2 {
		req.SetBasicAuth(url.QueryEscape(basic[0]), url.QueryEscape(basic[1]))
	}
	return roundTrip(t, req)
}

func pkce(seed string) (verifier, challenge string) {
	verifier = strings.Repeat(seed, 50)[:64]
	sum := sha256.Sum256([]byte(verifier))
	return verifier, base64.RawURLEncoding.EncodeToString(sum[:])
}

// authorizationQuery is the authorization request an MCP client sends the
// operator's browser with.
func authorizationQuery(o gateway.OAuth, clientID, redirectURI, challenge string) url.Values {
	return url.Values{
		"response_type": {"code"}, "client_id": {clientID}, "redirect_uri": {redirectURI},
		"code_challenge": {challenge}, "code_challenge_method": {"S256"},
		"state": {"st-1"}, "scope": {remote.OAuthScope}, "resource": {o.Resource},
	}
}

// consent takes an authorization request through the operator's consent to
// deviceID and returns the code its redirect hands the client.
func consent(t *testing.T, f *fixture, o gateway.OAuth, clientID, challenge, deviceID string) (string, gateway.Grant) {
	t.Helper()
	req, err := gateway.ParseAuthorization(f.store, o, authorizationQuery(o, clientID, "https://agent.example/callback", challenge))
	if err != nil {
		t.Fatal(err)
	}
	if req.ClientName != "Hosted agent" {
		t.Fatalf("the request names its client %q", req.ClientName)
	}
	redirect, grant, err := gateway.Authorize(f.dir, f.store, o, req, deviceID, "web:alice", f.server.Now())
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(redirect)
	if err != nil || u.Scheme+"://"+u.Host+u.Path != "https://agent.example/callback" {
		t.Fatalf("redirect %q", redirect)
	}
	if q := u.Query(); q.Get("state") != "st-1" || q.Get("iss") != o.Issuer || q.Get("code") == "" {
		t.Fatalf("redirect %q", redirect)
	}
	return u.Query().Get("code"), grant
}

type tokens struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
	Scope        string `json:"scope"`
}

func issued(t *testing.T, got oauthAnswer) tokens {
	t.Helper()
	var tk tokens
	if got.status != http.StatusOK || json.Unmarshal(got.raw, &tk) != nil || tk.AccessToken == "" || tk.RefreshToken == "" {
		t.Fatalf("token answer: %d %s", got.status, got.raw)
	}
	if tk.TokenType != "Bearer" || tk.Scope != remote.OAuthScope || tk.ExpiresIn < 1 || tk.ExpiresIn > 3600 {
		t.Fatalf("token answer: %s", got.raw)
	}
	return tk
}

func exchange(clientID, code, verifier string) url.Values {
	return url.Values{"grant_type": {"authorization_code"}, "client_id": {clientID}, "code": {code}, "code_verifier": {verifier}, "redirect_uri": {"https://agent.example/callback"}}
}

func refreshWith(clientID, refresh string) url.Values {
	return url.Values{"grant_type": {"refresh_token"}, "client_id": {clientID}, "refresh_token": {refresh}}
}

// refused checks a token endpoint refusal's OAuth error and description.
func refused(t *testing.T, got oauthAnswer, code, description string) {
	t.Helper()
	if got.status/100 != 4 || got.body["error"] != code || !strings.Contains(fmt.Sprint(got.body["error_description"]), description) {
		t.Fatalf("want %s (%s): %d %s", code, description, got.status, got.raw)
	}
}

func oauthEvents(t *testing.T, f *fixture) []audit.Record {
	t.Helper()
	var out []audit.Record
	for _, r := range auditRecords(t, f) {
		switch r.Event {
		case audit.EventOAuthGrantCreated, audit.EventOAuthRefreshRefused, audit.EventOAuthGrantRevoked:
			out = append(out, r)
		}
	}
	return out
}

func mcpInit(c *mcpClient) mcpReply {
	return c.request("initialize", map[string]any{"protocolVersion": "2025-11-25", "capabilities": map[string]any{}, "clientInfo": map[string]any{"name": "test", "version": "1"}})
}

// An MCP client finds everything it needs to start the flow from the 401
// its first request gets: the resource metadata the challenge names, the
// authorization server it lists, and that server's metadata at the
// well-known URI with the issuer's path inserted.
func TestOAuthDiscovery(t *testing.T) {
	f, o := oauthGateway(t)
	req, _ := http.NewRequest(http.MethodPost, f.base+remote.PathMCP, strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"initialize"}`))
	first := roundTrip(t, req)
	challenge := first.header.Get("WWW-Authenticate")
	m := regexp.MustCompile(`^Bearer resource_metadata="([^"]+)", scope="agentssh"$`).FindStringSubmatch(challenge)
	if first.status != http.StatusUnauthorized || m == nil {
		t.Fatalf("first request: %d %q", first.status, challenge)
	}
	origin := strings.TrimSuffix(f.base, "/agentssh")
	if m[1] != origin+"/.well-known/oauth-protected-resource/agentssh/mcp" {
		t.Fatalf("resource metadata at %s", m[1])
	}
	resource := fetch(t, m[1])
	if resource.status != http.StatusOK || resource.body["resource"] != f.base+"/mcp" ||
		fmt.Sprint(resource.body["authorization_servers"]) != "["+f.base+"]" || fmt.Sprint(resource.body["scopes_supported"]) != "[agentssh]" {
		t.Fatalf("resource metadata: %d %s", resource.status, resource.raw)
	}
	issuer := resource.body["authorization_servers"].([]any)[0].(string)
	issuerURL, _ := url.Parse(issuer)
	server := fetch(t, origin+"/.well-known/oauth-authorization-server"+issuerURL.Path)
	want := map[string]string{
		"issuer":                                         issuer,
		"authorization_endpoint":                         testWebOrigin + "/oauth/authorize",
		"token_endpoint":                                 f.base + "/oauth/token",
		"registration_endpoint":                          f.base + "/oauth/register",
		"code_challenge_methods_supported":               "[S256]",
		"response_types_supported":                       "[code]",
		"grant_types_supported":                          "[authorization_code refresh_token]",
		"token_endpoint_auth_methods_supported":          "[none client_secret_basic client_secret_post]",
		"authorization_response_iss_parameter_supported": "true",
	}
	for field, value := range want {
		if fmt.Sprint(server.body[field]) != value {
			t.Errorf("server metadata %s = %v, want %s", field, server.body[field], value)
		}
	}
	if o.Issuer != issuer || o.Resource != resource.body["resource"] {
		t.Fatalf("configuration %+v", o)
	}
	// A token that is wrong says so, so the client refreshes or starts over.
	req, _ = http.NewRequest(http.MethodPost, f.base+remote.PathMCP, strings.NewReader(`{}`))
	req.Header.Set("Authorization", "Bearer ago_0123456789abcdef_"+strings.Repeat("A", 43))
	if got := roundTrip(t, req); got.status != http.StatusUnauthorized || !strings.HasSuffix(got.header.Get("WWW-Authenticate"), `error="invalid_token"`) {
		t.Fatalf("a wrong token: %d %q", got.status, got.header.Get("WWW-Authenticate"))
	}
	// A device token still works on /mcp.
	device := activeTokenDevice(t, f)
	if r := mcpInit(&mcpClient{t: t, f: f, token: device.Token}); r.status != http.StatusOK {
		t.Fatalf("a device token: %d %s", r.status, r.raw)
	}

	// Without the Web UI's origin there is no authorization server.
	plain, _ := execGateway(t)
	req, _ = http.NewRequest(http.MethodPost, plain.base+remote.PathMCP, strings.NewReader(`{}`))
	if got := roundTrip(t, req); got.status != http.StatusUnauthorized || strings.Contains(got.header.Get("WWW-Authenticate"), "resource_metadata") {
		t.Fatalf("without OAuth: %d %q", got.status, got.header.Get("WWW-Authenticate"))
	}
	plainOrigin := strings.TrimSuffix(plain.base, "/agentssh")
	for _, path := range []string{"/.well-known/oauth-protected-resource/agentssh/mcp", "/.well-known/oauth-authorization-server/agentssh"} {
		if got := fetch(t, plainOrigin+path); got.status != http.StatusNotFound {
			t.Errorf("%s without OAuth: %d", path, got.status)
		}
	}
	if got := tokenRequest(t, plain, url.Values{"grant_type": {"refresh_token"}}); got.status != http.StatusNotFound {
		t.Errorf("token endpoint without OAuth: %d", got.status)
	}
}

// The authorization code flow with PKCE: the operator's consent binds the
// client to the device, the code is redeemed once with its verifier, and the
// access token runs the device's tools on /mcp only. A code redeemed twice
// revokes the grant.
func TestOAuthCodeFlow(t *testing.T) {
	f, o := oauthGateway(t)
	device := activeTokenDevice(t, f)
	client := publicClient(t, f)
	other := publicClient(t, f)
	verifier, challenge := pkce("a1b2")
	code, grant := consent(t, f, o, client, challenge, device.DeviceID)
	if grant.DeviceID != device.DeviceID || grant.ClientID != client || grant.CreatedBy != "web:alice" {
		t.Fatalf("grant %+v", grant)
	}

	wrongVerifier, _ := pkce("zz")
	refused(t, tokenRequest(t, f, exchange(client, code, wrongVerifier)), "invalid_grant", "code_verifier")
	refused(t, tokenRequest(t, f, exchange(other, code, verifier)), "invalid_grant", "another client")
	wrongRedirect := exchange(client, code, verifier)
	wrongRedirect.Set("redirect_uri", "https://agent.example/other")
	refused(t, tokenRequest(t, f, wrongRedirect), "invalid_grant", "redirect_uri")
	wrongResource := exchange(client, code, verifier)
	wrongResource.Set("resource", "https://elsewhere.example/mcp")
	refused(t, tokenRequest(t, f, wrongResource), "invalid_target", "only for")
	refused(t, tokenRequest(t, f, url.Values{"grant_type": {"password"}, "client_id": {client}}), "unsupported_grant_type", "")
	if got := tokenRequest(t, f, exchange("oc_unknown", code, verifier)); got.status != http.StatusUnauthorized || got.body["error"] != "invalid_client" {
		t.Fatalf("an unknown client: %d %s", got.status, got.raw)
	}
	// The resource may be named with a trailing slash or another case.
	good := exchange(client, code, verifier)
	good.Set("resource", strings.Replace(o.Resource, "https://", "HTTPS://", 1)+"/")
	tk := issued(t, tokenRequest(t, f, good))

	c := &mcpClient{t: t, f: f, token: tk.AccessToken}
	if r := mcpInit(c); r.status != http.StatusOK || r.Error != nil {
		t.Fatalf("initialize with the access token: %d %s", r.status, r.raw)
	}
	if run := c.call("run", map[string]any{"host": "web-1", "command": "uptime", "session": "s_oauth"}); run.Structured["result"] != "ok" {
		t.Fatalf("run with the access token: %+v", run)
	}
	var grantRecords int
	for _, r := range auditRecords(t, f) {
		if r.DeviceID == device.DeviceID && r.Event == audit.EventCompleted {
			if r.GrantID != grant.ID || r.TokenID != "" {
				t.Fatalf("a run's record names %q and token %q", r.GrantID, r.TokenID)
			}
			grantRecords++
		}
	}
	if grantRecords != 1 {
		t.Fatalf("%d records of the run", grantRecords)
	}
	// Access tokens are for the MCP endpoint, not the API.
	if got := bearer(t, f, remote.PathTokenStatus, tk.AccessToken); got.status != http.StatusUnauthorized {
		t.Fatalf("the access token on /api/status: %d %s", got.status, got.raw)
	}

	// The used code without its verifier proves nothing (the code was in a
	// redirect URL) and changes nothing.
	refused(t, tokenRequest(t, f, exchange(client, code, wrongVerifier)), "invalid_grant", "code_verifier")
	refused(t, tokenRequest(t, f, exchange(client, code, "")), "invalid_grant", "code_verifier")
	if r := mcpInit(c); r.status != http.StatusOK {
		t.Fatalf("after a used code without its verifier: %d %s", r.status, r.raw)
	}
	// With it: someone else has both, so the grant goes.
	refused(t, tokenRequest(t, f, exchange(client, code, verifier)), "invalid_grant", "authorization code reused")
	if r := mcpInit(c); r.status != http.StatusUnauthorized {
		t.Fatalf("after the code was reused: %d %s", r.status, r.raw)
	}
	refused(t, tokenRequest(t, f, refreshWith(client, tk.RefreshToken)), "invalid_grant", "revoked")
	events := oauthEvents(t, f)
	if len(events) != 3 || events[0].Event != audit.EventOAuthGrantCreated || events[0].Operator != "web:alice" || events[0].ClientID != client || events[0].Note != "Hosted agent" ||
		events[1].Event != audit.EventOAuthGrantRevoked || events[1].Note != "authorization code reused" || events[1].Operator != "" ||
		events[2].Event != audit.EventOAuthRefreshRefused || events[2].Note != "the grant was revoked" {
		t.Fatalf("audit %+v", events)
	}
	for _, e := range events {
		if e.GrantID != grant.ID || e.DeviceID != device.DeviceID {
			t.Fatalf("audit record %+v", e)
		}
	}
}

// Each refresh replaces the refresh token; one used again revokes the grant
// and every token it issued.
func TestOAuthRefreshRotation(t *testing.T) {
	f, o := oauthGateway(t)
	device := activeTokenDevice(t, f)
	client := publicClient(t, f)
	verifier, challenge := pkce("r0t")
	code, grant := consent(t, f, o, client, challenge, device.DeviceID)
	first := issued(t, tokenRequest(t, f, exchange(client, code, verifier)))
	refused(t, tokenRequest(t, f, refreshWith(client, first.AccessToken)), "invalid_grant", "unknown refresh token")
	scoped := refreshWith(client, first.RefreshToken)
	scoped.Set("scope", "admin")
	refused(t, tokenRequest(t, f, scoped), "invalid_scope", "")
	second := issued(t, tokenRequest(t, f, refreshWith(client, first.RefreshToken)))
	if second.RefreshToken == first.RefreshToken || second.AccessToken == first.AccessToken {
		t.Fatal("refresh did not rotate")
	}
	third := issued(t, tokenRequest(t, f, refreshWith(client, second.RefreshToken)))
	if r := mcpInit(&mcpClient{t: t, f: f, token: third.AccessToken}); r.status != http.StatusOK {
		t.Fatalf("the newest access token: %d %s", r.status, r.raw)
	}

	refused(t, tokenRequest(t, f, refreshWith(client, first.RefreshToken)), "invalid_grant", "refresh token reused")
	for _, access := range []string{first.AccessToken, second.AccessToken, third.AccessToken} {
		if r := mcpInit(&mcpClient{t: t, f: f, token: access}); r.status != http.StatusUnauthorized {
			t.Fatalf("an access token after the reuse: %d %s", r.status, r.raw)
		}
	}
	refused(t, tokenRequest(t, f, refreshWith(client, third.RefreshToken)), "invalid_grant", "revoked")
	events := oauthEvents(t, f)
	if len(events) != 4 || events[1].Event != audit.EventOAuthRefreshRefused || events[1].Note != "refresh token reused" ||
		events[2].Event != audit.EventOAuthGrantRevoked || events[2].Note != "refresh token reused" || events[2].GrantID != grant.ID ||
		events[3].Event != audit.EventOAuthRefreshRefused {
		t.Fatalf("audit %+v", events)
	}
}

// Revoking the grant or the device ends the client's access on its next
// request.
func TestOAuthRevocation(t *testing.T) {
	f, o := oauthGateway(t)
	device := activeTokenDevice(t, f)
	client := publicClient(t, f)
	verifier, challenge := pkce("rev")
	code, grant := consent(t, f, o, client, challenge, device.DeviceID)
	tk := issued(t, tokenRequest(t, f, exchange(client, code, verifier)))
	c := &mcpClient{t: t, f: f, token: tk.AccessToken}
	if r := mcpInit(c); r.status != http.StatusOK {
		t.Fatalf("before revocation: %d %s", r.status, r.raw)
	}
	if revoked, err := gateway.RevokeGrant(f.dir, f.store, grant.ID, "local:alice", time.Now()); err != nil || !revoked {
		t.Fatalf("revoke: %v %v", revoked, err)
	}
	if again, err := gateway.RevokeGrant(f.dir, f.store, grant.ID, "local:alice", time.Now()); err != nil || again {
		t.Fatalf("revoke again: %v %v", again, err)
	}
	if _, err := gateway.RevokeGrant(f.dir, f.store, "og_missing", "local:alice", time.Now()); !errors.Is(err, controlplane.ErrNotFound) {
		t.Fatalf("revoke an unknown grant: %v", err)
	}
	if r := mcpInit(c); r.status != http.StatusUnauthorized {
		t.Fatalf("after the grant was revoked: %d %s", r.status, r.raw)
	}
	refused(t, tokenRequest(t, f, refreshWith(client, tk.RefreshToken)), "invalid_grant", "the grant was revoked")
	grants, err := gateway.Grants(f.store)
	if err != nil || len(grants) != 1 || grants[0].RevokedBy != "local:alice" || grants[0].RevokedAt.IsZero() || grants[0].ClientName != "Hosted agent" {
		t.Fatalf("grants %+v %v", grants, err)
	}
	events := oauthEvents(t, f)
	if len(events) != 3 || events[1].Event != audit.EventOAuthGrantRevoked || events[1].Operator != "local:alice" {
		t.Fatalf("audit %+v", events)
	}

	// A new grant, then the device is revoked.
	verifier, challenge = pkce("dev")
	code, _ = consent(t, f, o, client, challenge, device.DeviceID)
	tk = issued(t, tokenRequest(t, f, exchange(client, code, verifier)))
	if err := f.store.RevokeDevice(device.DeviceID, time.Now()); err != nil {
		t.Fatal(err)
	}
	c.token = tk.AccessToken
	if r := mcpInit(c); r.status != http.StatusForbidden || !strings.Contains(string(r.raw), remote.CodeDeviceRevoked) {
		t.Fatalf("after the device was revoked: %d %s", r.status, r.raw)
	}
	refused(t, tokenRequest(t, f, refreshWith(client, tk.RefreshToken)), "invalid_grant", "the device is revoked")
	if _, _, err := gateway.Authorize(f.dir, f.store, o, gateway.AuthorizationRequest{ClientID: client}, device.DeviceID, "web:alice", time.Now()); !errors.Is(err, controlplane.ErrDeviceRevoked) {
		t.Fatalf("consent to a revoked device: %v", err)
	}
}

// Outside the device's activation window no token is issued or accepted,
// and the code or refresh token refused is still good once an operator
// activates the device; an access token never outlives the window.
func TestOAuthRefusedWhileInactive(t *testing.T) {
	f, o := oauthGateway(t)
	device := tokenDevice(t, f)
	client := publicClient(t, f)
	verifier, challenge := pkce("in")
	code, _ := consent(t, f, o, client, challenge, device.DeviceID)
	refused(t, tokenRequest(t, f, exchange(client, code, verifier)), "invalid_grant", "not activated")
	if _, err := gateway.ActivateDevice(f.dir, f.store, device.DeviceID, 2*time.Minute, "local:alice", "", time.Now()); err != nil {
		t.Fatal(err)
	}
	tk := issued(t, tokenRequest(t, f, exchange(client, code, verifier)))
	if tk.ExpiresIn > 120 {
		t.Fatalf("an access token outlives the window: %d s", tk.ExpiresIn)
	}
	c := &mcpClient{t: t, f: f, token: tk.AccessToken}
	if r := mcpInit(c); r.status != http.StatusOK {
		t.Fatalf("while active: %d %s", r.status, r.raw)
	}
	if _, err := gateway.DeactivateDevice(f.dir, f.store, device.DeviceID, "local:alice", time.Now()); err != nil {
		t.Fatal(err)
	}
	if r := mcpInit(c); r.status != http.StatusForbidden || !strings.Contains(string(r.raw), remote.CodeDeviceInactive) {
		t.Fatalf("after deactivation: %d %s", r.status, r.raw)
	}
	refused(t, tokenRequest(t, f, refreshWith(client, tk.RefreshToken)), "invalid_grant", "not activated")
	if _, err := gateway.ActivateDevice(f.dir, f.store, device.DeviceID, time.Hour, "local:alice", "", time.Now()); err != nil {
		t.Fatal(err)
	}
	again := issued(t, tokenRequest(t, f, refreshWith(client, tk.RefreshToken)))
	if r := mcpInit(&mcpClient{t: t, f: f, token: again.AccessToken}); r.status != http.StatusOK {
		t.Fatalf("after activation: %d %s", r.status, r.raw)
	}
	events := oauthEvents(t, f)
	if len(events) != 2 || events[1].Event != audit.EventOAuthRefreshRefused || !strings.Contains(events[1].Note, "not activated") {
		t.Fatalf("audit %+v", events)
	}
}

// Codes and access tokens expire.
func TestOAuthExpiry(t *testing.T) {
	f, o := oauthGateway(t)
	now := &clock{now: time.Now()}
	f.server.Now = now.Now
	device := tokenDevice(t, f)
	if _, err := gateway.ActivateDevice(f.dir, f.store, device.DeviceID, 24*time.Hour, "local:alice", "", now.Now()); err != nil {
		t.Fatal(err)
	}
	client := publicClient(t, f)
	verifier, challenge := pkce("ex")
	code, _ := consent(t, f, o, client, challenge, device.DeviceID)
	now.Add(6 * time.Minute)
	refused(t, tokenRequest(t, f, exchange(client, code, verifier)), "invalid_grant", "expired")
	code, _ = consent(t, f, o, client, challenge, device.DeviceID)
	tk := issued(t, tokenRequest(t, f, exchange(client, code, verifier)))
	if tk.ExpiresIn != 3600 {
		t.Fatalf("expires_in %d", tk.ExpiresIn)
	}
	now.Add(61 * time.Minute)
	if r := mcpInit(&mcpClient{t: t, f: f, token: tk.AccessToken}); r.status != http.StatusUnauthorized {
		t.Fatalf("an expired access token: %d %s", r.status, r.raw)
	}
	issued(t, tokenRequest(t, f, refreshWith(client, tk.RefreshToken)))
}

// Registration takes HTTPS or loopback redirect URIs only; a confidential
// client gets a secret and must authenticate with it; clients awaiting
// consent are capped and age out.
func TestOAuthRegistration(t *testing.T) {
	f, o := oauthGateway(t)
	for _, uri := range []string{"http://agent.example/cb", "myapp://cb", "https://agent.example/cb#x", "https://user@agent.example/cb", "/cb", ""} {
		if got := registration(t, f, map[string]any{"redirect_uris": []string{uri}}); got.status != http.StatusBadRequest || got.body["error"] != "invalid_redirect_uri" {
			t.Errorf("redirect URI %q: %d %s", uri, got.status, got.raw)
		}
	}
	for _, meta := range []map[string]any{
		{"redirect_uris": []string{"https://a.example/cb"}, "grant_types": []string{"client_credentials"}},
		{"redirect_uris": []string{"https://a.example/cb"}, "response_types": []string{"token"}},
		{"redirect_uris": []string{"https://a.example/cb"}, "token_endpoint_auth_method": "private_key_jwt"},
	} {
		if got := registration(t, f, meta); got.status != http.StatusBadRequest || got.body["error"] != "invalid_client_metadata" {
			t.Errorf("%v: %d %s", meta, got.status, got.raw)
		}
	}

	// No method named means client_secret_basic, so a secret.
	confidential := register(t, f, map[string]any{"client_name": "Hosted agent", "redirect_uris": []string{"https://agent.example/callback"}, "logo_uri": "https://agent.example/logo.png"})
	id, secret := confidential["client_id"].(string), confidential["client_secret"].(string)
	if confidential["token_endpoint_auth_method"] != "client_secret_basic" || secret == "" {
		t.Fatalf("registration %v", confidential)
	}
	device := activeTokenDevice(t, f)
	verifier, challenge := pkce("cf")
	code, _ := consent(t, f, o, id, challenge, device.DeviceID)
	if got := tokenRequest(t, f, exchange(id, code, verifier)); got.status != http.StatusUnauthorized || got.body["error"] != "invalid_client" {
		t.Fatalf("no secret: %d %s", got.status, got.raw)
	}
	if got := tokenRequest(t, f, exchange(id, code, verifier), id, "wrong"); got.status != http.StatusUnauthorized || !strings.HasPrefix(got.header.Get("WWW-Authenticate"), "Basic") {
		t.Fatalf("wrong secret: %d %s", got.status, got.raw)
	}
	tk := issued(t, tokenRequest(t, f, exchange(id, code, verifier), id, secret))
	posted := refreshWith(id, tk.RefreshToken)
	posted.Set("client_secret", secret)
	issued(t, tokenRequest(t, f, posted))

	// A loopback redirect may name any port.
	native := register(t, f, map[string]any{"redirect_uris": []string{"http://127.0.0.1/callback"}, "token_endpoint_auth_method": "none"})["client_id"].(string)
	for uri, ok := range map[string]bool{"http://127.0.0.1:53111/callback": true, "http://127.0.0.1:53111/other": false, "http://localhost:53111/callback": false} {
		_, err := gateway.ParseAuthorization(f.store, o, authorizationQuery(o, native, uri, challenge))
		if (err == nil) != ok {
			t.Errorf("redirect %s: %v", uri, err)
		}
	}

	// Clients nobody consented to age out after an hour and are capped.
	now := &clock{now: time.Now()}
	f.server.Now = now.Now
	defer gateway.SetMaxPendingClients(3)()
	stale := publicClient(t, f)
	publicClient(t, f)
	if got := registration(t, f, map[string]any{"redirect_uris": []string{"https://a.example/cb"}}); got.status != http.StatusServiceUnavailable {
		t.Fatalf("over the cap: %d %s", got.status, got.raw)
	}
	now.Add(61 * time.Minute)
	publicClient(t, f)
	if _, err := gateway.ParseAuthorization(f.store, o, authorizationQuery(o, stale, "https://agent.example/callback", challenge)); err == nil {
		t.Fatal("a stale client was kept")
	}
	if _, err := gateway.ParseAuthorization(f.store, o, authorizationQuery(o, id, "https://agent.example/callback", challenge)); err != nil {
		t.Fatalf("a client with a grant aged out: %v", err)
	}
}

// An authorization request whose client or redirect URI is unknown is never
// sent anywhere; any other error goes back to the client's redirect URI with
// its state and the issuer.
func TestParseAuthorizationRefusals(t *testing.T) {
	f, o := oauthGateway(t)
	client := publicClient(t, f)
	_, challenge := pkce("pa")
	base := func() url.Values { return authorizationQuery(o, client, "https://agent.example/callback", challenge) }
	for name, edit := range map[string]func(url.Values){
		"unknown client":    func(q url.Values) { q.Set("client_id", "oc_nobody") },
		"no client":         func(q url.Values) { q.Del("client_id") },
		"other redirect":    func(q url.Values) { q.Set("redirect_uri", "https://evil.example/callback") },
		"repeated redirect": func(q url.Values) { q.Add("redirect_uri", "https://agent.example/callback") },
	} {
		q := base()
		edit(q)
		var refusal *gateway.AuthorizationError
		if _, err := gateway.ParseAuthorization(f.store, o, q); !errors.As(err, &refusal) || refusal.Redirect != "" {
			t.Errorf("%s: %v", name, err)
		}
	}
	for name, c := range map[string]struct {
		edit func(url.Values)
		code string
	}{
		"implicit":     {func(q url.Values) { q.Set("response_type", "token") }, "unsupported_response_type"},
		"no PKCE":      {func(q url.Values) { q.Del("code_challenge") }, "invalid_request"},
		"plain PKCE":   {func(q url.Values) { q.Set("code_challenge_method", "plain") }, "invalid_request"},
		"other scope":  {func(q url.Values) { q.Set("scope", "agentssh admin") }, "invalid_scope"},
		"other target": {func(q url.Values) { q.Set("resource", "https://elsewhere.example/mcp") }, "invalid_target"},
		"repeated":     {func(q url.Values) { q.Add("state", "again") }, "invalid_request"},
	} {
		q := base()
		c.edit(q)
		var refusal *gateway.AuthorizationError
		if _, err := gateway.ParseAuthorization(f.store, o, q); !errors.As(err, &refusal) || refusal.Code != c.code {
			t.Errorf("%s: %v", name, err)
			continue
		}
		u, err := url.Parse(refusal.Redirect)
		if err != nil || !strings.HasPrefix(refusal.Redirect, "https://agent.example/callback?") || u.Query().Get("error") != c.code || u.Query().Get("iss") != o.Issuer {
			t.Errorf("%s redirects to %q", name, refusal.Redirect)
		}
		if name != "repeated" && u.Query().Get("state") != "st-1" {
			t.Errorf("%s loses the state: %q", name, refusal.Redirect)
		}
	}
	// No scope means the one there is; the operator can refuse.
	q := base()
	q.Del("scope")
	q.Del("resource")
	req, err := gateway.ParseAuthorization(f.store, o, q)
	if err != nil || req.Scope != remote.OAuthScope {
		t.Fatalf("a request without scope or resource: %+v %v", req, err)
	}
	denied, _ := url.Parse(gateway.Deny(o, req))
	if denied.Query().Get("error") != "access_denied" || denied.Query().Get("state") != "st-1" {
		t.Fatalf("deny redirects to %s", denied)
	}
	// Consent binds a token device only.
	if _, _, err := gateway.Authorize(f.dir, f.store, o, req, f.client.State.DeviceID, "web:alice", time.Now()); !errors.Is(err, gateway.ErrNotTokenDevice) {
		t.Fatalf("consent to a signed device: %v", err)
	}
}
