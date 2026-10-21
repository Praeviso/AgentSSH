package remote

import (
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"
	"time"

	"github.com/Praeviso/AgentSSH/internal/inventory"
	"golang.org/x/crypto/ssh"
)

// userAuthData builds the exact RFC 4252 §7 payload an SSH client signs.
func userAuthData(sessionID []byte, msgType byte, user, service, method string, sign bool, algo string, pub []byte) []byte {
	return ssh.Marshal(struct {
		Session []byte
		Type    byte
		User    string
		Service string
		Method  string
		Sign    bool
		Algo    string
		PubKey  []byte
	}{sessionID, msgType, user, service, method, sign, algo, pub})
}

func TestParseUserAuthAcceptsPublickeyRequest(t *testing.T) {
	pub := []byte("public-key-blob")
	data := userAuthData([]byte("0123456789abcdef0123456789abcdef"), 50, "deploy", "ssh-connection", "publickey", true, "ssh-ed25519", pub)
	got, err := ParseUserAuth(data)
	if err != nil {
		t.Fatalf("ParseUserAuth: %v", err)
	}
	if got.User != "deploy" || got.Algorithm != "ssh-ed25519" || string(got.PublicKey) != string(pub) {
		t.Fatalf("parsed = %+v", got)
	}
}

func TestParseUserAuthRejectsAnythingElse(t *testing.T) {
	sid := []byte("0123456789abcdef0123456789abcdef")
	pub := []byte("public-key-blob")
	valid := userAuthData(sid, 50, "deploy", "ssh-connection", "publickey", true, "ssh-ed25519", pub)
	cases := map[string][]byte{
		"arbitrary bytes":    []byte("please sign this"),
		"empty":              nil,
		"wrong message type": userAuthData(sid, 51, "deploy", "ssh-connection", "publickey", true, "ssh-ed25519", pub),
		"wrong service":      userAuthData(sid, 50, "deploy", "ssh-userauth", "publickey", true, "ssh-ed25519", pub),
		"wrong method":       userAuthData(sid, 50, "deploy", "ssh-connection", "hostbased", true, "ssh-ed25519", pub),
		"query not sign":     userAuthData(sid, 50, "deploy", "ssh-connection", "publickey", false, "ssh-ed25519", pub),
		"empty session id":   userAuthData(nil, 50, "deploy", "ssh-connection", "publickey", true, "ssh-ed25519", pub),
		"oversized session":  userAuthData(make([]byte, 65), 50, "deploy", "ssh-connection", "publickey", true, "ssh-ed25519", pub),
		"empty user":         userAuthData(sid, 50, "", "ssh-connection", "publickey", true, "ssh-ed25519", pub),
		"trailing bytes":     append(append([]byte(nil), valid...), 0),
		"truncated":          valid[:len(valid)-3],
	}
	for name, data := range cases {
		if _, err := ParseUserAuth(data); err == nil {
			t.Errorf("%s: ParseUserAuth accepted invalid data", name)
		}
	}
}

func TestBundleSignatureBindsBytesAndKey(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	otherPub, _, _ := ed25519.GenerateKey(rand.Reader)
	raw, sig, err := SignBundle(Bundle{Version: 3, DeviceID: "dev_1", NotAfter: time.Now().Add(time.Minute)}, priv)
	if err != nil {
		t.Fatalf("SignBundle: %v", err)
	}
	got, err := VerifyBundle(raw, sig, pub)
	if err != nil || got.Version != 3 || got.DeviceID != "dev_1" {
		t.Fatalf("VerifyBundle = %+v, %v", got, err)
	}
	tampered := []byte(strings.Replace(string(raw), `"version":3`, `"version":4`, 1))
	if _, err := VerifyBundle(tampered, sig, pub); err == nil {
		t.Fatal("tampered bundle verified")
	}
	if _, err := VerifyBundle(raw, sig, otherPub); err == nil {
		t.Fatal("bundle verified under the wrong key")
	}
	// A bare ed25519 signature over the JSON (no domain separation) must not verify.
	if _, err := VerifyBundle(raw, ed25519.Sign(priv, raw), pub); err == nil {
		t.Fatal("signature without the bundle context verified")
	}
}

func TestValidateManagedInventory(t *testing.T) {
	known := func(name string) bool { return name == "web" }
	ok := inventory.Host{Addr: "10.0.0.1", User: "deploy", Identity: "web"}
	if err := ValidateManagedInventory(inventory.Inventory{Hosts: map[string]inventory.Host{"a": ok}}, known); err != nil {
		t.Fatalf("valid inventory rejected: %v", err)
	}
	cases := map[string]inventory.Inventory{
		"alias":            {Hosts: map[string]inventory.Host{"a": {Addr: "x", User: "u", Identity: "web", SSHConfigAlias: "x"}}},
		"identity file":    {Hosts: map[string]inventory.Host{"a": {Addr: "x", User: "u", Identity: "web", IdentityFile: "~/.ssh/id"}}},
		"no addr":          {Hosts: map[string]inventory.Host{"a": {User: "u", Identity: "web"}}},
		"no user":          {Hosts: map[string]inventory.Host{"a": {Addr: "x", Identity: "web"}}},
		"no identity":      {Hosts: map[string]inventory.Host{"a": {Addr: "x", User: "u"}}},
		"unknown identity": {Hosts: map[string]inventory.Host{"a": {Addr: "x", User: "u", Identity: "db"}}},
		"shell transport":  {Transport: "ssh", Hosts: map[string]inventory.Host{"a": ok}},
	}
	for name, inv := range cases {
		if err := ValidateManagedInventory(inv, known); err == nil {
			t.Errorf("%s: invalid managed inventory accepted", name)
		}
	}
}
