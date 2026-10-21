package remote

import (
	"errors"
	"fmt"
)

// API endpoints are relative to the configured public HTTPS base.
const (
	PathEnroll = "/enroll"
	PathStatus = "/status"
	PathBundle = "/bundle"
	PathSign   = "/sign"
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
	CodeClockSkew        = "clock_skew"
	CodeDeviceRevoked    = "device_revoked"
	CodeTokenInvalid     = "token_invalid"
	CodeNoConfig         = "no_config"
	CodeUnknownHost      = "unknown_host"
	CodeIdentityDisabled = "identity_disabled"
	CodeSignRejected     = "sign_rejected"
	CodeInternal         = "internal"
)

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
