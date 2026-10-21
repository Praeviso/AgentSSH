package remote

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func TestHTTPSTokenAndCanonicalBase(t *testing.T) {
	token := EnrollToken{ID: "et_fixture", Secret: base64.RawURLEncoding.EncodeToString(make([]byte, 32)), BundleFingerprint: strings.Repeat("ab", 32), ServerURL: "https://config.example/plugins/agentssh"}
	got, err := ParseEnrollToken(token.String())
	if err != nil || got != token {
		t.Fatalf("round trip: %+v %v", got, err)
	}
	for _, base := range []string{"http://example.com", "https://u:p@example.com", "https://example.com?a=1", "https://example.com#x", "https://example.com/a/../b", "https://example.com/a//b", "https://example.com/a%2fb", "https://example.com/{wildcard}"} {
		if _, err := HTTPSBaseURL(base); err == nil {
			t.Errorf("accepted %q", base)
		}
	}

}

func TestHTTPSRequestCoverageAndClockBounds(t *testing.T) {
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Unix(1700000000, 0)
	body := []byte(`{"host":"web-1"}`)
	target := "https://config.example/plugin/sign"
	r := httptest.NewRequest("POST", target, strings.NewReader(string(body)))
	if err := SignHTTPRequest(r, body, "dev_fixture", DeviceSignatureTag, key, now); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyHTTPRequest(r, body, target, "dev_fixture", DeviceSignatureTag, pub, now); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, target, id, tag string
		body                  []byte
		now                   time.Time
	}{
		{"origin", "https://other.example/plugin/sign", "dev_fixture", DeviceSignatureTag, body, now},
		{"prefix", "https://config.example/other/sign", "dev_fixture", DeviceSignatureTag, body, now},
		{"id", target, "dev_other", DeviceSignatureTag, body, now},
		{"tag", target, "dev_fixture", EnrollSignatureTag, body, now},
		{"body", target, "dev_fixture", DeviceSignatureTag, []byte(`{}`), now},
		{"expired", target, "dev_fixture", DeviceSignatureTag, body, now.Add(RequestLifetime)},
		{"future", target, "dev_fixture", DeviceSignatureTag, body, now.Add(-RequestClockSkew - time.Second)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := VerifyHTTPRequest(r, tc.body, tc.target, tc.id, tc.tag, pub, tc.now); err == nil {
				t.Fatal("invalid proof accepted")
			}
		})
	}
}

func TestHTTPSIndependentWebCryptoVectors(t *testing.T) {
	raw, err := os.ReadFile("testdata/https.json")
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		PublicKey, Target, Method, Body, ContentDigest, SignatureInput, Signature, Bundle, BundleSignature, SSHUserauth, SSHSignature, SSHPublicKey string
		Created                                                                                                                                     int64
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	decode := func(s string) []byte {
		t.Helper()
		b, err := base64.StdEncoding.DecodeString(s)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	r := httptest.NewRequest(v.Method, v.Target, strings.NewReader(v.Body))
	r.Header.Set("Content-Digest", v.ContentDigest)
	r.Header.Set("Signature-Input", v.SignatureInput)
	r.Header.Set("Signature", v.Signature)
	if _, err := VerifyHTTPRequest(r, []byte(v.Body), v.Target, "dev_fixture", DeviceSignatureTag, ed25519.PublicKey(decode(v.PublicKey)), time.Unix(v.Created, 0)); err != nil {
		t.Fatalf("Web Crypto request: %v", err)
	}
	if _, err := VerifyBundle([]byte(v.Bundle), decode(v.BundleSignature), ed25519.PublicKey(decode(v.PublicKey))); err != nil {
		t.Fatalf("Web Crypto bundle: %v", err)
	}
	pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(v.SSHPublicKey))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseUserAuth(decode(v.SSHUserauth)); err != nil {
		t.Fatal(err)
	}
	if err := pub.Verify(decode(v.SSHUserauth), &ssh.Signature{Format: ssh.KeyAlgoED25519, Blob: decode(v.SSHSignature)}); err != nil {
		t.Fatalf("Web Crypto SSH signature: %v", err)
	}
}
