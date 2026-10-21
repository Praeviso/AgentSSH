package remote

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	RequestLifetime    = 60 * time.Second
	RequestClockSkew   = 30 * time.Second
	DeviceSignatureTag = "agentssh-device-v2"
	EnrollSignatureTag = "agentssh-enroll-v2"
)

// This is a deliberately narrow RFC 9421 profile, not a general Structured
// Fields parser. The exact covered components and parameter order are required.
const coveredComponents = `("@method" "@target-uri" "content-digest")`

var signatureInputPattern = regexp.MustCompile(`^agentssh=\("@method" "@target-uri" "content-digest"\);created=([0-9]{1,12});expires=([0-9]{1,12});nonce="([A-Za-z0-9_-]{43})";keyid="([A-Za-z0-9_-]{1,80})";alg="ed25519";tag="(agentssh-device-v2|agentssh-enroll-v2)"$`)

type RequestProof struct {
	KeyID   string
	Nonce   string
	Expires int64
}

func validKeyID(value string) bool {
	if len(value) < 1 || len(value) > 80 {
		return false
	}
	for _, c := range value {
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '_', c == '-':
		default:
			return false
		}
	}
	return true
}

func contentDigest(body []byte) string {
	sum := sha256.Sum256(body)
	return "sha-256=:" + base64.StdEncoding.EncodeToString(sum[:]) + ":"
}

func signatureBase(method, target, digest, params string) []byte {
	return []byte(fmt.Sprintf("\"@method\": %s\n\"@target-uri\": %s\n\"content-digest\": %s\n\"@signature-params\": %s", method, target, digest, params))
}

// SignHTTPRequest adds a fresh, body-bound proof. HTTPS and redirect policy are the
// caller's responsibility. The nonce must be consumed durably by the verifier.
func SignHTTPRequest(req *http.Request, body []byte, keyID, tag string, key ed25519.PrivateKey, now time.Time) error {
	if !validKeyID(keyID) || len(key) != ed25519.PrivateKeySize || (tag != DeviceSignatureTag && tag != EnrollSignatureTag) {
		return errors.New("invalid request signing parameters")
	}
	random := make([]byte, 32)
	if _, err := rand.Read(random); err != nil {
		return err
	}
	nonce := base64.RawURLEncoding.EncodeToString(random)
	params := fmt.Sprintf(`%s;created=%d;expires=%d;nonce="%s";keyid="%s";alg="ed25519";tag="%s"`, coveredComponents,
		now.Unix(), now.Add(RequestLifetime).Unix(), nonce, keyID, tag)
	digest := contentDigest(body)
	sig := ed25519.Sign(key, signatureBase(req.Method, req.URL.String(), digest, params))
	req.Header.Set("Content-Digest", digest)
	req.Header.Set("Signature-Input", "agentssh="+params)
	req.Header.Set("Signature", "agentssh=:"+base64.StdEncoding.EncodeToString(sig)+":")
	return nil
}

// RequestKeyID is untrusted until VerifyHTTPRequest succeeds.
func RequestKeyID(req *http.Request) string {
	parts := signatureInputPattern.FindStringSubmatch(req.Header.Get("Signature-Input"))
	if parts == nil {
		return ""
	}
	return parts[4]
}

// VerifyHTTPRequest authenticates exact bytes and the externally configured target
// URI. A terminating proxy must not derive that URI from untrusted forwarding
// headers. Replay protection is a separate mandatory durable operation.
func VerifyHTTPRequest(req *http.Request, body []byte, target, keyID, tag string, key ed25519.PublicKey, now time.Time) (RequestProof, error) {
	fail := errors.New("invalid or expired request signature")
	if len(key) != ed25519.PublicKeySize {
		return RequestProof{}, fail
	}
	for _, h := range []string{"Content-Digest", "Signature-Input", "Signature"} {
		if len(req.Header.Values(h)) != 1 {
			return RequestProof{}, fail
		}
	}
	input := req.Header.Get("Signature-Input")
	parts := signatureInputPattern.FindStringSubmatch(input)
	if parts == nil || parts[4] != keyID || parts[5] != tag {
		return RequestProof{}, fail
	}
	created, _ := strconv.ParseInt(parts[1], 10, 64)
	expires, _ := strconv.ParseInt(parts[2], 10, 64)
	if expires <= created || expires-created > int64(RequestLifetime/time.Second) || now.Unix() >= expires || created > now.Add(RequestClockSkew).Unix() {
		return RequestProof{}, fail
	}
	nonce, err := base64.RawURLEncoding.Strict().DecodeString(parts[3])
	if err != nil || len(nonce) != 32 || req.Header.Get("Content-Digest") != contentDigest(body) {
		return RequestProof{}, fail
	}
	rawSig := req.Header.Get("Signature")
	if !strings.HasPrefix(rawSig, "agentssh=:") || !strings.HasSuffix(rawSig, ":") {
		return RequestProof{}, fail
	}
	sig, err := base64.StdEncoding.Strict().DecodeString(strings.TrimSuffix(strings.TrimPrefix(rawSig, "agentssh=:"), ":"))
	if err != nil || !ed25519.Verify(key, signatureBase(req.Method, target, contentDigest(body), strings.TrimPrefix(input, "agentssh=")), sig) {
		return RequestProof{}, fail
	}
	return RequestProof{KeyID: keyID, Nonce: parts[3], Expires: expires}, nil
}
