package remoteserver

import (
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

// Handler is the control-plane API. publicURL is trusted deployment
// configuration (including a possible plugin path prefix), never a forwarded
// header. It can sit behind a TLS terminator without client certificates.
// HTTP origins must be reachable only through that trusted HTTPS ingress.
func (s *Server) Handler(publicURL string) (http.Handler, error) {
	base, err := remote.HTTPSBaseURL(publicURL)
	if err != nil {
		return nil, err
	}
	u, _ := url.Parse(base)
	mux := http.NewServeMux()
	mux.HandleFunc("POST "+u.Path+remote.PathEnroll, func(w http.ResponseWriter, r *http.Request) { s.handleEnroll(w, r, base) })
	for _, route := range []struct {
		method, path string
		handler      deviceHandler
	}{
		{"GET", remote.PathStatus, s.handleStatus}, {"GET", remote.PathBundle, s.handleBundle}, {"POST", remote.PathSign, s.handleSign},
	} {
		mux.HandleFunc(route.method+" "+u.Path+route.path, s.device(base, route.path, route.handler))
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		// Refuse alternate path spellings and redirects before routing; signatures
		// authenticate the externally configured URI's exact path bytes.
		if r.URL.RawQuery != "" || r.URL.ForceQuery || r.URL.EscapedPath() != r.URL.Path ||
			strings.Contains(r.URL.Path, "//") || path.Clean(r.URL.Path) != r.URL.Path {
			writeError(w, 400, remote.CodeBadRequest, "noncanonical request target")
			return
		}
		mux.ServeHTTP(w, r)
	}), nil
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

func (s *Server) handleEnroll(w http.ResponseWriter, r *http.Request, base string) {
	body, err := requestBytes(r)
	if err != nil {
		writeError(w, 400, remote.CodeBadRequest, "malformed enrollment request")
		return
	}
	var req remote.EnrollRequest
	if decodeBody(body, &req) != nil {
		writeError(w, 400, remote.CodeBadRequest, "malformed enrollment request")
		return
	}
	key, err := remote.DecodePublicKey(req.PublicKey)
	if err != nil {
		writeError(w, 400, remote.CodeBadRequest, "invalid device public key")
		return
	}
	now := s.now()
	if _, err := remote.VerifyHTTPRequest(r, body, base+remote.PathEnroll, req.TokenID, remote.EnrollSignatureTag, key, now); err != nil {
		writeProofError(w, err, now)
		return
	}
	d, err := s.Store.RedeemEnrollToken(req.TokenID, req.TokenSecret, base, req.PublicKey, s.now())
	if errors.Is(err, ErrTokenInvalid) {
		writeError(w, 403, remote.CodeTokenInvalid, "enrollment token is invalid, expired, or already used")
		return
	}
	if err != nil {
		writeError(w, 500, remote.CodeInternal, "enrollment failed")
		return
	}
	writeJSON(w, 200, remote.EnrollResponse{DeviceID: d.ID, BundlePublicKey: s.Keys.BundlePublicKey()})
}

func (s *Server) device(base, path string, next deviceHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, err := requestBytes(r)
		if err != nil {
			writeError(w, 400, remote.CodeBadRequest, "request body too large or unreadable")
			return
		}
		id := remote.RequestKeyID(r)
		device, err := s.Store.Device(id)
		if errors.Is(err, ErrNotFound) {
			writeError(w, 401, remote.CodeUnauthenticated, "unknown device key")
			return
		}
		if err != nil {
			writeError(w, 500, remote.CodeInternal, "device lookup failed")
			return
		}
		key, err := remote.DecodePublicKey(device.PublicKey)
		if err != nil {
			writeError(w, 500, remote.CodeInternal, "device key unavailable")
			return
		}
		now := s.now()
		proof, err := remote.VerifyHTTPRequest(r, body, base+path, id, remote.DeviceSignatureTag, key, now)
		if err != nil {
			writeProofError(w, err, now)
			return
		}
		err = s.Store.consumeNonce(id, proof.Nonce, proof.Expires, s.now)
		switch {
		case errors.Is(err, ErrDeviceRevoked):
			if path == remote.PathSign {
				var req remote.SignRequest
				_ = json.Unmarshal(body, &req)
				if err := s.Store.AppendSign(SignEntry{SignID: "sg_" + randomHex(8), TS: now, DeviceID: id, Host: req.Host, Result: SignRejected, Reason: "device revoked"}); err != nil {
					writeError(w, 500, remote.CodeInternal, "signing log unavailable")
					return
				}
			}
			writeError(w, 403, remote.CodeDeviceRevoked, "this device has been revoked by the control plane")
			return
		case errors.Is(err, ErrRequestReplayed):
			writeError(w, 403, remote.CodeUnauthenticated, "request replayed")
			return
		case errors.Is(err, remote.ErrRequestTime):
			writeProofError(w, err, s.now())
			return
		case err != nil:
			writeError(w, 500, remote.CodeInternal, "replay protection unavailable")
			return
		}
		next(w, r, device, body)
	}
}

func writeProofError(w http.ResponseWriter, err error, now time.Time) {
	if errors.Is(err, remote.ErrRequestTime) {
		writeError(w, 401, remote.CodeClockSkew, "request time outside accepted window; synchronize this machine's clock; server UTC time: "+now.UTC().Format(time.RFC3339))
		return
	}
	writeError(w, 401, remote.CodeUnauthenticated, "invalid request signature")
}
