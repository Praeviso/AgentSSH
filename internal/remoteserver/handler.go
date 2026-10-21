package remoteserver

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"path"
	"strings"

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
	r.Body = io.NopCloser(bytes.NewReader(body))
	var req remote.EnrollRequest
	if decodeBody(r, &req) != nil {
		writeError(w, 400, remote.CodeBadRequest, "malformed enrollment request")
		return
	}
	key, err := remote.DecodeDevicePublicKey(req.PublicKey)
	if err != nil {
		writeError(w, 400, remote.CodeBadRequest, "invalid device public key")
		return
	}
	if _, err := remote.VerifyHTTPRequest(r, body, base+remote.PathEnroll, req.TokenID, remote.EnrollSignatureTag, key, s.now()); err != nil {
		writeError(w, 401, remote.CodeUnauthenticated, "invalid enrollment proof")
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
		key, err := remote.DecodeDevicePublicKey(device.PublicKey)
		if err != nil {
			writeError(w, 500, remote.CodeInternal, "device key unavailable")
			return
		}
		proof, err := remote.VerifyHTTPRequest(r, body, base+path, id, remote.DeviceSignatureTag, key, s.now())
		if err != nil {
			writeError(w, 401, remote.CodeUnauthenticated, "invalid request signature")
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
		if device.Status != remote.DeviceActive {
			if path == remote.PathSign {
				var req remote.SignRequest
				_ = json.Unmarshal(body, &req)
				if err := s.Store.AppendSign(SignEntry{SignID: "sg_" + randomHex(8), TS: s.now(), DeviceID: id, Host: req.Host, Result: SignRejected, Reason: "device revoked"}); err != nil {
					writeError(w, 500, remote.CodeInternal, "signing log unavailable")
					return
				}
			}
			writeError(w, 403, remote.CodeDeviceRevoked, "this device has been revoked by the control plane")
			return
		}
		ok, err := s.Store.consumeNonce(id, proof.Nonce, proof.Expires, s.now().Unix())
		if err != nil {
			writeError(w, 500, remote.CodeInternal, "replay protection unavailable")
			return
		}
		if !ok {
			writeError(w, 403, remote.CodeUnauthenticated, "request replayed or device no longer active")
			return
		}
		next(w, r, device)
	}
}
