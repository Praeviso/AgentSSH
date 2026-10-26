package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Praeviso/AgentSSH/internal/gateway"
)

// grantedClient registers an OAuth client with the gateway in dir and
// records an operator's consent binding it to a new token device.
func grantedClient(t *testing.T, dir string) gateway.Grant {
	t.Helper()
	store, err := gateway.OpenStore(filepath.Join(dir, gateway.FileDatabase))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()
	server := gateway.NewServer(dir, store, nil)
	server.WebOrigin = "https://ops.example"
	handler, err := server.Handler("https://gw.example/agentssh")
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "https://gw.example/agentssh/oauth/register",
		strings.NewReader(`{"client_name":"Hosted agent","redirect_uris":["https://agent.example/cb"],"token_endpoint_auth_method":"none"}`)))
	var client struct {
		ID string `json:"client_id"`
	}
	if rec.Code != http.StatusCreated || json.Unmarshal(rec.Body.Bytes(), &client) != nil {
		t.Fatalf("register: %d %s", rec.Code, rec.Body)
	}
	issued, err := gateway.CreateTokenDevice(dir, store, "hosted-agent", "local:alice", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	o, err := gateway.NewOAuth("https://gw.example/agentssh", "https://ops.example")
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(strings.Repeat("v", 50)))
	req, err := gateway.ParseAuthorization(store, o, url.Values{
		"response_type": {"code"}, "client_id": {client.ID}, "redirect_uri": {"https://agent.example/cb"},
		"code_challenge": {base64.RawURLEncoding.EncodeToString(sum[:])}, "code_challenge_method": {"S256"},
	})
	if err != nil {
		t.Fatal(err)
	}
	_, grant, err := gateway.Authorize(dir, store, o, req, issued.DeviceID, "web:alice", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return grant
}

func TestOAuthCommands(t *testing.T) {
	dir, _ := enrolledDevice(t)
	grant := grantedClient(t, dir)
	out, err := runGatewayCLI(t, "--data", dir, "oauth", "ls")
	if err != nil || !strings.HasPrefix(out, "GRANT") || !strings.Contains(out, grant.ID+"  Hosted agent  "+grant.DeviceID) || !strings.Contains(out, "web:alice  active") {
		t.Fatalf("ls: %v\n%s", err, out)
	}
	if out, err := runGatewayCLI(t, "--data", dir, "oauth", "revoke", grant.ID); err != nil || out != "Revoked "+grant.ID+"\n" {
		t.Fatalf("revoke: %v %q", err, out)
	}
	if out, err := runGatewayCLI(t, "--data", dir, "oauth", "revoke", grant.ID); err != nil || out != grant.ID+" was already revoked\n" {
		t.Fatalf("revoke again: %v %q", err, out)
	}
	if _, err := runGatewayCLI(t, "--data", dir, "oauth", "revoke", "og_missing"); err == nil || !strings.Contains(err.Error(), "no such grant") {
		t.Fatalf("revoke an unknown grant: %v", err)
	}
	if out, err := runGatewayCLI(t, "--data", dir, "oauth", "ls"); err != nil || strings.Contains(out, grant.ID) {
		t.Fatalf("ls after revoke: %v\n%s", err, out)
	}
	if out, err := runGatewayCLI(t, "--data", dir, "oauth", "ls", "--all"); err != nil || !strings.Contains(out, "revoked ") {
		t.Fatalf("ls --all: %v\n%s", err, out)
	}
	store, err := gateway.OpenStore(filepath.Join(dir, gateway.FileDatabase))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()
	grants, err := gateway.Grants(store)
	if err != nil || len(grants) != 1 || !strings.HasPrefix(grants[0].RevokedBy, "local:") {
		t.Fatalf("grants %+v %v", grants, err)
	}
}
