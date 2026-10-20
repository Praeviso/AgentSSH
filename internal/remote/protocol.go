package remote

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

// API endpoints. Every endpoint except PathEnroll requires a device client
// certificate (mTLS) issued at enrollment.
const (
	PathEnroll = "/v1/enroll"
	PathStatus = "/v1/status"
	PathBundle = "/v1/bundle"
	PathSign   = "/v1/sign"
)

// Device status values.
const (
	DeviceActive  = "active"
	DeviceRevoked = "revoked"
)

// Error codes carried in ErrorResponse.Code.
const (
	CodeBadRequest       = "bad_request"
	CodeUnauthenticated  = "unauthenticated"
	CodeDeviceRevoked    = "device_revoked"
	CodeTokenInvalid     = "token_invalid"
	CodeNoConfig         = "no_config"
	CodeUnknownHost      = "unknown_host"
	CodeIdentityDisabled = "identity_disabled"
	CodeSignRejected     = "sign_rejected"
	CodeInternal         = "internal"
)

// EnrollRequest redeems a one-time enrollment token for a device certificate.
type EnrollRequest struct {
	TokenID     string `json:"token_id"`
	TokenSecret string `json:"token_secret"`
	CSRPEM      string `json:"csr_pem"`
}

// EnrollResponse returns the device identity and the keys the client pins.
type EnrollResponse struct {
	DeviceID        string `json:"device_id"`
	CertPEM         string `json:"cert_pem"`
	CAPEM           string `json:"ca_pem"`
	BundlePublicKey string `json:"bundle_public_key"`
}

// StatusResponse reports the calling device's standing.
type StatusResponse struct {
	DeviceID string `json:"device_id"`
	Status   string `json:"status"`
}

// BundleResponse carries the raw signed bundle bytes and their signature.
type BundleResponse struct {
	Bundle    []byte `json:"bundle"`
	Signature []byte `json:"signature"`
}

// SignRequest asks the control plane to sign SSH user-authentication data for
// an inventory host. The server picks the identity from the device's inventory.
type SignRequest struct {
	Host string `json:"host"`
	Data []byte `json:"data"`
}

// SignResponse returns an SSH signature and the server's signing-log id.
type SignResponse struct {
	SignID string `json:"sign_id"`
	Format string `json:"format"`
	Blob   []byte `json:"blob"`
}

// ErrorResponse is the JSON body of every non-2xx API response.
type ErrorResponse struct {
	Code  string `json:"code"`
	Error string `json:"error"`
}

// APIError is a structured control-plane refusal (as opposed to a network
// failure). Clients must never fall back to cached state on an APIError.
type APIError struct {
	Status  int
	Code    string
	Message string
}

func (e *APIError) Error() string {
	if e.Message == "" {
		return fmt.Sprintf("control plane refused the request (%s)", e.Code)
	}
	return fmt.Sprintf("control plane refused the request: %s", e.Message)
}

// IsRevoked reports whether err is a control-plane refusal because the device
// was revoked.
func IsRevoked(err error) bool {
	var apiErr *APIError
	return errors.As(err, &apiErr) && apiErr.Code == CodeDeviceRevoked
}

const tokenPrefix = "agentssh-enroll.v1"

// EnrollToken is the one-time secret an administrator hands to a new device.
// It also carries the control plane CA fingerprint so the first TLS connection
// is pinned without trusting system roots.
type EnrollToken struct {
	ID            string
	Secret        string
	CAFingerprint string
}

// String encodes the token for copy/paste.
func (t EnrollToken) String() string {
	return strings.Join([]string{tokenPrefix, t.ID, t.Secret, t.CAFingerprint}, ".")
}

// ParseEnrollToken decodes a token produced by EnrollToken.String.
func ParseEnrollToken(value string) (EnrollToken, error) {
	value = strings.TrimSpace(value)
	rest, ok := strings.CutPrefix(value, tokenPrefix+".")
	if !ok {
		return EnrollToken{}, errors.New("enrollment token has an unknown format")
	}
	parts := strings.Split(rest, ".")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" {
		return EnrollToken{}, errors.New("enrollment token is malformed")
	}
	if _, err := base64.RawURLEncoding.DecodeString(parts[1]); err != nil {
		return EnrollToken{}, errors.New("enrollment token secret is malformed")
	}
	if fp, err := hex.DecodeString(parts[2]); err != nil || len(fp) != sha256.Size {
		return EnrollToken{}, errors.New("enrollment token CA fingerprint is malformed")
	}
	return EnrollToken{ID: parts[0], Secret: parts[1], CAFingerprint: strings.ToLower(parts[2])}, nil
}

// CertFingerprint is the lowercase hex SHA-256 of a DER certificate.
func CertFingerprint(der []byte) string {
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:])
}
