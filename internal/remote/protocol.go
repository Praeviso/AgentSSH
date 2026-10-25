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

// Control-plane modes reported by /status. A control plane runs exactly one.
const (
	// ModeManaged hands devices signed configuration bundles and SSH
	// signatures; the device enforces policy (agentssh-server).
	ModeManaged = "managed"
	// ModeGateway keeps inventory, policy, identities and SSH on the control
	// plane; the device only forwards commands (agentssh-gateway).
	ModeGateway = "gateway"
)

// HeaderMode carries the control plane's mode on every response, including
// refusals of unauthenticated requests, so a client checks it before spending
// an enrollment token and on every request after. A response without it comes
// from a managed control plane that predates the header.
const HeaderMode = "AgentSSH-Mode"

// ResponseMode is the mode a response's HeaderMode value names.
func ResponseMode(header string) string {
	if header == "" {
		return ModeManaged
	}
	return header
}

// Device status values.
const (
	DeviceActive  = "active"
	DeviceRevoked = "revoked"
)

// Error codes carried in ErrorResponse.Code.
const (
	CodeBadRequest      = "bad_request"
	CodeUnauthenticated = "unauthenticated"
	CodeClockSkew       = "clock_skew"
	CodeDeviceRevoked   = "device_revoked"
	// CodeDeviceInactive refuses a gateway device outside its activation
	// window: an operator must activate it.
	CodeDeviceInactive   = "device_inactive"
	CodeTokenInvalid     = "token_invalid"
	CodeNoConfig         = "no_config"
	CodeUnknownHost      = "unknown_host"
	CodeIdentityDisabled = "identity_disabled"
	CodeSignRejected     = "sign_rejected"
	CodeInternal         = "internal"
	// CodeUsage rejects an execution request the CLI would reject as a usage
	// error (exit 2): no session, unknown host, invalid policy.
	CodeUsage = "usage"
	// CodeBusy means the device already has the maximum number of executions
	// running.
	CodeBusy = "busy"
)

// StatusResponse reports the calling device's standing and the control
// plane's mode.
type StatusResponse struct {
	DeviceID string `json:"device_id"`
	Status   string `json:"status"`
	Mode     string `json:"mode,omitempty"`
	// Activation is a gateway device's activation window; a managed control
	// plane omits it.
	Activation *Activation `json:"activation,omitempty"`
}

// Activation states of a gateway device.
const (
	ActivationActive   = "active"
	ActivationInactive = "inactive"
)

// Activation reports whether a gateway device may use the gateway now, and
// until when (RFC 3339, set only while active).
type Activation struct {
	State string `json:"state"`
	Until string `json:"until,omitempty"`
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

// IsInactive reports whether err is a gateway's refusal because the device is
// outside its activation window.
func IsInactive(err error) bool {
	var apiErr *APIError
	return errors.As(err, &apiErr) && apiErr.Code == CodeDeviceInactive
}

// IsRevoked reports whether err is a control-plane refusal because the device
// was revoked.
func IsRevoked(err error) bool {
	var apiErr *APIError
	return errors.As(err, &apiErr) && apiErr.Code == CodeDeviceRevoked
}
