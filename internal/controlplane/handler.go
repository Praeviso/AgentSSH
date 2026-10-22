package controlplane

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"

	"github.com/Praeviso/AgentSSH/internal/remote"
)

const maxRequestBytes = 64 << 10

// DeviceHandler serves a request whose device signature, standing and nonce
// have been verified.
type DeviceHandler func(w http.ResponseWriter, r *http.Request, device Device, body []byte)

// Route is one mode-specific device endpoint.
type Route struct {
	Method, Path string
	Handler      DeviceHandler
	// Revoked, if set, runs when a revoked device's request authenticates,
	// before the refusal is sent. A non-nil error turns the refusal into a 500
	// carrying the error's message.
	Revoked func(deviceID string, body []byte, now time.Time) error
}

// API is the HTTP surface every control plane shares: enrollment, signed
// device requests, and /status. Store, Keys and Now are read on each request.
type API struct {
	// Mode is reported by /status.
	Mode  string
	Store func() *Store
	Keys  func() *Keys
	Now   func() time.Time
}

// Handler serves enrollment, /status, and routes under the configured public
// base. publicURL is trusted deployment configuration (including a possible
// plugin path prefix), never a forwarded header. It can sit behind a TLS
// terminator without client certificates. HTTP origins must be reachable only
// through that trusted HTTPS ingress.
func (a API) Handler(publicURL string, routes ...Route) (http.Handler, error) {
	base, err := remote.HTTPSBaseURL(publicURL)
	if err != nil {
		return nil, err
	}
	u, _ := url.Parse(base)
	mux := http.NewServeMux()
	mux.HandleFunc("POST "+u.Path+remote.PathEnroll, func(w http.ResponseWriter, r *http.Request) { a.handleEnroll(w, r, base) })
	routes = append([]Route{{Method: "GET", Path: remote.PathStatus, Handler: a.handleStatus}}, routes...)
	for _, route := range routes {
		mux.HandleFunc(route.Method+" "+u.Path+route.Path, a.device(base, route))
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		// Refuse alternate path spellings and redirects before routing; signatures
		// authenticate the externally configured URI's exact path bytes.
		if r.URL.RawQuery != "" || r.URL.ForceQuery || r.URL.EscapedPath() != r.URL.Path ||
			strings.Contains(r.URL.Path, "//") || path.Clean(r.URL.Path) != r.URL.Path {
			WriteError(w, 400, remote.CodeBadRequest, "noncanonical request target")
			return
		}
		mux.ServeHTTP(w, r)
	}), nil
}

// WriteJSON writes value as the response body.
func WriteJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

// WriteError writes a remote.ErrorResponse.
func WriteError(w http.ResponseWriter, status int, code string, message string) {
	WriteJSON(w, status, remote.ErrorResponse{Code: code, Error: message})
}

// DecodeBody strictly decodes exactly one JSON value with no unknown fields.
func DecodeBody(data []byte, value any) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(value); err != nil {
		return err
	}
	if err := dec.Decode(new(any)); err != io.EOF {
		return errors.New("request must contain exactly one JSON value")
	}
	return nil
}

func requestBytes(r *http.Request) ([]byte, error) {
	body, err := io.ReadAll(io.LimitReader(r.Body, maxRequestBytes+1))
	if err != nil {
		return nil, err
	}
	if len(body) > maxRequestBytes {
		return nil, errors.New("request body too large")
	}
	return body, nil
}

func (a API) handleStatus(w http.ResponseWriter, _ *http.Request, device Device, _ []byte) {
	WriteJSON(w, http.StatusOK, remote.StatusResponse{DeviceID: device.ID, Status: device.Status, Mode: a.Mode})
}

func (a API) handleEnroll(w http.ResponseWriter, r *http.Request, base string) {
	body, err := requestBytes(r)
	if err != nil {
		WriteError(w, 400, remote.CodeBadRequest, "malformed enrollment request")
		return
	}
	var req remote.EnrollRequest
	if DecodeBody(body, &req) != nil {
		WriteError(w, 400, remote.CodeBadRequest, "malformed enrollment request")
		return
	}
	key, err := remote.DecodePublicKey(req.PublicKey)
	if err != nil {
		WriteError(w, 400, remote.CodeBadRequest, "invalid device public key")
		return
	}
	now := a.Now()
	if _, err := remote.VerifyHTTPRequest(r, body, base+remote.PathEnroll, req.TokenID, remote.EnrollSignatureTag, key, now); err != nil {
		writeProofError(w, err, now)
		return
	}
	d, err := a.Store().RedeemEnrollToken(req.TokenID, req.TokenSecret, base, req.PublicKey, a.Now())
	if errors.Is(err, ErrTokenInvalid) {
		WriteError(w, 403, remote.CodeTokenInvalid, "enrollment token is invalid, expired, or already used")
		return
	}
	if err != nil {
		WriteError(w, 500, remote.CodeInternal, "enrollment failed")
		return
	}
	WriteJSON(w, 200, remote.EnrollResponse{DeviceID: d.ID, BundlePublicKey: a.Keys().BundlePublicKey()})
}

func (a API) device(base string, route Route) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, err := requestBytes(r)
		if err != nil {
			WriteError(w, 400, remote.CodeBadRequest, "request body too large or unreadable")
			return
		}
		store := a.Store()
		id := remote.RequestKeyID(r)
		device, err := store.Device(id)
		if errors.Is(err, ErrNotFound) {
			WriteError(w, 401, remote.CodeUnauthenticated, "unknown device key")
			return
		}
		if err != nil {
			WriteError(w, 500, remote.CodeInternal, "device lookup failed")
			return
		}
		key, err := remote.DecodePublicKey(device.PublicKey)
		if err != nil {
			WriteError(w, 500, remote.CodeInternal, "device key unavailable")
			return
		}
		now := a.Now()
		proof, err := remote.VerifyHTTPRequest(r, body, base+route.Path, id, remote.DeviceSignatureTag, key, now)
		if err != nil {
			writeProofError(w, err, now)
			return
		}
		err = store.consumeNonce(id, proof.Nonce, proof.Expires, a.Now)
		switch {
		case errors.Is(err, ErrDeviceRevoked):
			if route.Revoked != nil {
				if err := route.Revoked(id, body, now); err != nil {
					WriteError(w, 500, remote.CodeInternal, err.Error())
					return
				}
			}
			WriteError(w, 403, remote.CodeDeviceRevoked, "this device has been revoked by the control plane")
			return
		case errors.Is(err, ErrRequestReplayed):
			WriteError(w, 403, remote.CodeUnauthenticated, "request replayed")
			return
		case errors.Is(err, remote.ErrRequestTime):
			writeProofError(w, err, a.Now())
			return
		case err != nil:
			WriteError(w, 500, remote.CodeInternal, "replay protection unavailable")
			return
		}
		route.Handler(w, r, device, body)
	}
}

func writeProofError(w http.ResponseWriter, err error, now time.Time) {
	if errors.Is(err, remote.ErrRequestTime) {
		WriteError(w, 401, remote.CodeClockSkew, "request time outside accepted window; synchronize this machine's clock; server UTC time: "+now.UTC().Format(time.RFC3339))
		return
	}
	WriteError(w, 401, remote.CodeUnauthenticated, "invalid request signature")
}
