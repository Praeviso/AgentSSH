package remote

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/url"
	"strings"
)

const tokenPrefix = "agentssh-enroll."

// HTTPSBaseURL validates a canonical, prefix-bearing public HTTPS base. Reject
// ambiguous encodings instead of letting a proxy and the verifier disagree.
func HTTPSBaseURL(value string) (string, error) {
	u, err := url.Parse(value)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil ||
		u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" || u.RawPath != "" ||
		strings.ContainsAny(u.Path, "\\\r\n\t ") {
		return "", errors.New("control plane base must be an absolute HTTPS URL without credentials, query, fragment or escaped path")
	}
	for _, segment := range strings.Split(u.Path, "/") {
		if segment == "." || segment == ".." {
			return "", errors.New("control plane base must not contain dot path segments")
		}
	}
	for _, c := range u.Path {
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9', strings.ContainsRune("/._~-", c):
		default:
			return "", errors.New("control plane path must contain only unreserved ASCII characters and slashes")
		}
	}
	u.Path = strings.TrimRight(u.Path, "/")
	if strings.Contains(u.Path, "//") {
		return "", errors.New("control plane base must not contain empty path segments")
	}
	return u.String(), nil
}

// PublicKeyFingerprint pins the exact raw 32-byte Ed25519 bundle public key.
func PublicKeyFingerprint(key ed25519.PublicKey) string {
	sum := sha256.Sum256(key)
	return hex.EncodeToString(sum[:])
}

// EnrollToken carries an HTTPS base and a bundle-key pin, not a private CA.
// Only Secret is confidential. Servers persist its SHA-256, never the token.
type EnrollToken struct {
	ID                string
	Secret            string
	BundleFingerprint string
	ServerURL         string
}

func (t EnrollToken) String() string {
	return tokenPrefix + strings.Join([]string{t.ID, t.Secret, t.BundleFingerprint,
		base64.RawURLEncoding.EncodeToString([]byte(t.ServerURL))}, ".")
}

func ParseEnrollToken(value string) (EnrollToken, error) {
	rest, ok := strings.CutPrefix(strings.TrimSpace(value), tokenPrefix)
	parts := strings.Split(rest, ".")
	if !ok || len(parts) != 4 || !validKeyID(parts[0]) {
		return EnrollToken{}, errors.New("invalid HTTPS enrollment token")
	}
	secret, err := base64.RawURLEncoding.Strict().DecodeString(parts[1])
	if err != nil || len(secret) != 32 || base64.RawURLEncoding.EncodeToString(secret) != parts[1] {
		return EnrollToken{}, errors.New("invalid HTTPS enrollment token secret")
	}
	fp, err := hex.DecodeString(parts[2])
	if err != nil || len(fp) != sha256.Size || strings.ToLower(parts[2]) != parts[2] {
		return EnrollToken{}, errors.New("invalid bundle public-key fingerprint")
	}
	rawURL, err := base64.RawURLEncoding.Strict().DecodeString(parts[3])
	if err != nil || base64.RawURLEncoding.EncodeToString(rawURL) != parts[3] {
		return EnrollToken{}, errors.New("invalid HTTPS enrollment URL")
	}
	base, err := HTTPSBaseURL(string(rawURL))
	if err != nil || base != string(rawURL) {
		return EnrollToken{}, errors.New("invalid HTTPS enrollment URL")
	}
	return EnrollToken{ID: parts[0], Secret: parts[1], BundleFingerprint: parts[2], ServerURL: base}, nil
}

// EnrollRequest is signed using PublicKey, with the token ID as keyid.
type EnrollRequest struct {
	TokenID     string `json:"token_id"`
	TokenSecret string `json:"token_secret"`
	PublicKey   string `json:"public_key"`
}

type EnrollResponse struct {
	DeviceID        string `json:"device_id"`
	BundlePublicKey string `json:"bundle_public_key"`
}

func DecodePublicKey(value string) (ed25519.PublicKey, error) {
	key, err := base64.StdEncoding.Strict().DecodeString(value)
	if err != nil || len(key) != ed25519.PublicKeySize || base64.StdEncoding.EncodeToString(key) != value {
		return nil, errors.New("invalid Ed25519 public key")
	}
	return ed25519.PublicKey(key), nil
}
