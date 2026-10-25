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

// streamingBodyTimeout bounds how long a streaming route may take to upload
// its (larger) body.
const streamingBodyTimeout = 5 * time.Minute

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
	// MaxBody caps the request body; zero means 64 KiB.
	MaxBody int64
	// Streaming routes get streamingBodyTimeout to upload their body once the
	// request headers authenticate, and no read or write deadline after
	// authentication, so a long-running response is not cut off by the
	// server's per-request timeouts.
	Streaming bool
}

// API is the HTTP surface every control plane shares: enrollment, signed
// device requests, and /status. Store, Keys and Now are read on each request.
type API struct {
	// Mode is reported by /status.
	Mode  string
	Store func() *Store
	Keys  func() *Keys
	Now   func() time.Time
	// DescribeStatus, if set, adds a mode's own standing to /status.
	DescribeStatus func(device Device, status *remote.StatusResponse)
	// Open are routes that authenticate requests themselves (the gateway's
	// bearer-token API). They share the canonical-target checks and response
	// headers, never the device signature check, and a signature never
	// authenticates them.
	Open []OpenRoute
}

// OpenRoute is a route that authenticates its own requests. The body reaching
// Handler is bounded by MaxBody (zero means 64 KiB).
type OpenRoute struct {
	Method, Path string
	MaxBody      int64
	Handler      func(w http.ResponseWriter, r *http.Request, body []byte)
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
	for _, route := range a.Open {
		mux.HandleFunc(route.Method+" "+u.Path+route.Path, open(route))
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set(remote.HeaderMode, a.Mode)
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
	return requestBytesLimit(r, maxRequestBytes)
}

func requestBytesLimit(r *http.Request, limit int64) ([]byte, error) {
	body, err := io.ReadAll(io.LimitReader(r.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > limit {
		return nil, errors.New("request body too large")
	}
	return body, nil
}

func (a API) handleStatus(w http.ResponseWriter, _ *http.Request, device Device, _ []byte) {
	status := remote.StatusResponse{DeviceID: device.ID, Status: device.Status, Mode: a.Mode}
	if a.DescribeStatus != nil {
		a.DescribeStatus(device, &status)
	}
	WriteJSON(w, http.StatusOK, status)
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
	limit := route.MaxBody
	if limit <= 0 {
		limit = maxRequestBytes
	}
	// A route that admits more than the default body authenticates the
	// request headers first, so unauthenticated clients cannot hold its larger
	// body cap or upload deadline.
	large := limit > maxRequestBytes
	return func(w http.ResponseWriter, r *http.Request) {
		rc := http.NewResponseController(w)
		var body []byte
		var err error
		if large {
			// Until the headers authenticate, a refusal closes the connection
			// instead of draining the unread body first.
			w.Header().Set("Connection", "close")
			if r.ContentLength > limit {
				WriteError(w, http.StatusRequestEntityTooLarge, remote.CodeBadRequest, "request body too large")
				return
			}
		} else if body, err = requestBytesLimit(r, limit); err != nil {
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
		if device.PublicKey == "" {
			// A device without a key (a gateway token device) never signs.
			WriteError(w, 401, remote.CodeUnauthenticated, "unknown device key")
			return
		}
		key, err := remote.DecodePublicKey(device.PublicKey)
		if err != nil {
			WriteError(w, 500, remote.CodeInternal, "device key unavailable")
			return
		}
		now := a.Now()
		var proof remote.RequestProof
		if large {
			proof, err = remote.VerifyHTTPRequestHeaders(r, base+route.Path, id, remote.DeviceSignatureTag, key, now)
			if err != nil {
				writeProofError(w, err, now)
				return
			}
			w.Header().Del("Connection")
			if route.Streaming {
				_ = rc.SetReadDeadline(time.Now().Add(streamingBodyTimeout))
			}
			if body, err = requestBytesLimit(r, limit); err != nil {
				WriteError(w, 400, remote.CodeBadRequest, "request body too large or unreadable")
				return
			}
			if !remote.ContentDigestMatches(r, body) {
				writeProofError(w, errors.New("content digest mismatch"), now)
				return
			}
		} else {
			proof, err = remote.VerifyHTTPRequest(r, body, base+route.Path, id, remote.DeviceSignatureTag, key, now)
			if err != nil {
				writeProofError(w, err, now)
				return
			}
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
		if route.Streaming {
			// The body is consumed; keep the connection's background read free
			// of a deadline so it does not cancel the request mid-stream.
			_ = rc.SetReadDeadline(time.Time{})
			_ = rc.SetWriteDeadline(time.Time{})
		}
		route.Handler(w, r, device, body)
	}
}

// open reads a bounded body for a route that authenticates itself.
func open(route OpenRoute) http.HandlerFunc {
	limit := route.MaxBody
	if limit <= 0 {
		limit = maxRequestBytes
	}
	return func(w http.ResponseWriter, r *http.Request) {
		body, err := requestBytesLimit(r, limit)
		if err != nil {
			WriteError(w, http.StatusRequestEntityTooLarge, remote.CodeBadRequest, "request body too large or unreadable")
			return
		}
		route.Handler(w, r, body)
	}
}

func writeProofError(w http.ResponseWriter, err error, now time.Time) {
	if errors.Is(err, remote.ErrRequestTime) {
		WriteError(w, 401, remote.CodeClockSkew, "request time outside accepted window; synchronize this machine's clock; server UTC time: "+now.UTC().Format(time.RFC3339))
		return
	}
	WriteError(w, 401, remote.CodeUnauthenticated, "invalid request signature")
}
