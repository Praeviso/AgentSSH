package remoteserver

import (
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/Praeviso/AgentSSH/internal/inventory"
	"github.com/Praeviso/AgentSSH/internal/remote"
	"golang.org/x/crypto/ssh"
	"gopkg.in/yaml.v3"
)

// DefaultBundleTTL bounds how long a device may act on configuration it can no
// longer refresh.
const DefaultBundleTTL = 10 * time.Minute

const maxRequestBytes = 64 << 10

// Server is the control plane HTTP API.
type Server struct {
	Store     *Store
	Keys      *Keys
	BundleTTL time.Duration
	Now       func() time.Time

	mu      sync.Mutex
	signers map[string]ssh.Signer
}

// NewServer wires a store and unlocked keys into an API server.
func NewServer(store *Store, keys *Keys) *Server {
	return &Server{Store: store, Keys: keys, BundleTTL: DefaultBundleTTL, Now: time.Now, signers: map[string]ssh.Signer{}}
}

// TLSConfig requires TLS 1.3 and verifies device certificates when presented.
// Enrollment is the only endpoint reachable without one.
func (s *Server) TLSConfig() *tls.Config {
	pool := x509.NewCertPool()
	pool.AddCert(s.Keys.CACert)
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{s.Keys.TLSCert},
		ClientAuth:   tls.VerifyClientCertIfGiven,
		ClientCAs:    pool,
	}
}

// Handler returns the API routes.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST "+remote.PathEnroll, s.handleEnroll)
	mux.HandleFunc("GET "+remote.PathStatus, s.device(s.handleStatus))
	mux.HandleFunc("GET "+remote.PathBundle, s.device(s.handleBundle))
	mux.HandleFunc("POST "+remote.PathSign, s.device(s.handleSign))
	return mux
}

func (s *Server) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeError(w http.ResponseWriter, status int, code string, message string) {
	writeJSON(w, status, remote.ErrorResponse{Code: code, Error: message})
}

func decodeBody(r *http.Request, value any) error {
	data, err := io.ReadAll(io.LimitReader(r.Body, maxRequestBytes+1))
	if err != nil {
		return err
	}
	if len(data) > maxRequestBytes {
		return errors.New("request body too large")
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	return dec.Decode(value)
}

func (s *Server) handleEnroll(w http.ResponseWriter, r *http.Request) {
	var req remote.EnrollRequest
	if err := decodeBody(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, remote.CodeBadRequest, "malformed enrollment request")
		return
	}
	now := s.now()
	// Validate the CSR before burning the token so a malformed request can be retried.
	csr, err := ParseCSR(req.CSRPEM)
	if err != nil {
		writeError(w, http.StatusBadRequest, remote.CodeBadRequest, err.Error())
		return
	}
	device, err := s.Store.RedeemEnrollToken(req.TokenID, req.TokenSecret, now)
	if errors.Is(err, ErrTokenInvalid) {
		writeError(w, http.StatusForbidden, remote.CodeTokenInvalid, err.Error())
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, remote.CodeInternal, "enrollment failed")
		return
	}
	certPEM, err := s.Keys.IssueDeviceCert(csr, device.ID, now)
	if err != nil {
		writeError(w, http.StatusInternalServerError, remote.CodeInternal, "issue device certificate failed")
		return
	}
	writeJSON(w, http.StatusOK, remote.EnrollResponse{
		DeviceID:        device.ID,
		CertPEM:         string(certPEM),
		CAPEM:           string(pemBlock("CERTIFICATE", s.Keys.CACert.Raw)),
		BundlePublicKey: s.Keys.BundlePublicKey(),
	})
}

type deviceHandler func(http.ResponseWriter, *http.Request, Device)

// device authenticates the mTLS client certificate and re-checks the device's
// status on every request, which is what makes revocation immediate.
func (s *Server) device(next deviceHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 || len(r.TLS.VerifiedChains[0]) == 0 {
			writeError(w, http.StatusUnauthorized, remote.CodeUnauthenticated, "a device certificate is required")
			return
		}
		id := r.TLS.VerifiedChains[0][0].Subject.CommonName
		device, err := s.Store.Device(id)
		if errors.Is(err, ErrNotFound) {
			writeError(w, http.StatusUnauthorized, remote.CodeUnauthenticated, "unknown device")
			return
		}
		if err != nil {
			writeError(w, http.StatusInternalServerError, remote.CodeInternal, "device lookup failed")
			return
		}
		if device.Status != remote.DeviceActive {
			if r.URL.Path == remote.PathSign {
				// Refused logins belong in the signing log too: an attempt from a
				// revoked device is exactly what an administrator needs to see.
				var req remote.SignRequest
				_ = decodeBody(r, &req)
				entry := SignEntry{SignID: "sg_" + randomHex(8), TS: s.now(), DeviceID: device.ID, Host: req.Host, Result: SignRejected, Reason: "device revoked"}
				if err := s.Store.AppendSign(entry); err != nil {
					writeError(w, http.StatusInternalServerError, remote.CodeInternal, "signing log unavailable")
					return
				}
			}
			writeError(w, http.StatusForbidden, remote.CodeDeviceRevoked, "this device has been revoked by the control plane")
			return
		}
		next(w, r, device)
	}
}

func (s *Server) handleStatus(w http.ResponseWriter, _ *http.Request, device Device) {
	writeJSON(w, http.StatusOK, remote.StatusResponse{DeviceID: device.ID, Status: device.Status})
}

func (s *Server) handleBundle(w http.ResponseWriter, _ *http.Request, device Device) {
	cfg, err := s.Store.Config(device.ID)
	if errors.Is(err, ErrNotFound) {
		writeError(w, http.StatusNotFound, remote.CodeNoConfig, "no configuration has been pushed for this device")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, remote.CodeInternal, "configuration lookup failed")
		return
	}
	inv, err := decodeInventory(cfg.InventoryYAML)
	if err != nil {
		writeError(w, http.StatusInternalServerError, remote.CodeInternal, "stored inventory is unreadable")
		return
	}
	identities := map[string]string{}
	for _, host := range inv.Hosts {
		if host.Identity == "" {
			continue
		}
		if _, done := identities[host.Identity]; done {
			continue
		}
		id, err := s.Store.Identity(host.Identity)
		if err != nil {
			writeError(w, http.StatusInternalServerError, remote.CodeInternal, "identity lookup failed")
			return
		}
		identities[id.Name] = id.PublicKey
	}
	now := s.now()
	ttl := s.BundleTTL
	if ttl <= 0 {
		ttl = DefaultBundleTTL
	}
	raw, sig, err := remote.SignBundle(remote.Bundle{
		Version:       cfg.Version,
		DeviceID:      device.ID,
		IssuedAt:      now.UTC(),
		NotAfter:      now.Add(ttl).UTC(),
		InventoryYAML: cfg.InventoryYAML,
		PolicyYAML:    cfg.PolicyYAML,
		Identities:    identities,
	}, s.Keys.BundleKey)
	if err != nil {
		writeError(w, http.StatusInternalServerError, remote.CodeInternal, "sign bundle failed")
		return
	}
	writeJSON(w, http.StatusOK, remote.BundleResponse{Bundle: raw, Signature: sig})
}

func (s *Server) handleSign(w http.ResponseWriter, r *http.Request, device Device) {
	var req remote.SignRequest
	if err := decodeBody(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, remote.CodeBadRequest, "malformed sign request")
		return
	}
	entry := SignEntry{SignID: "sg_" + randomHex(8), TS: s.now(), DeviceID: device.ID, Host: req.Host}
	reject := func(status int, code string, reason string) {
		entry.Result, entry.Reason = SignRejected, reason
		if err := s.Store.AppendSign(entry); err != nil {
			writeError(w, http.StatusInternalServerError, remote.CodeInternal, "signing log unavailable")
			return
		}
		writeError(w, status, code, reason)
	}

	cfg, err := s.Store.Config(device.ID)
	if errors.Is(err, ErrNotFound) {
		reject(http.StatusNotFound, remote.CodeNoConfig, "no configuration has been pushed for this device")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, remote.CodeInternal, "configuration lookup failed")
		return
	}
	inv, err := decodeInventory(cfg.InventoryYAML)
	if err != nil {
		writeError(w, http.StatusInternalServerError, remote.CodeInternal, "stored inventory is unreadable")
		return
	}
	host, ok := inv.Hosts[req.Host]
	if !ok {
		reject(http.StatusNotFound, remote.CodeUnknownHost, fmt.Sprintf("host %q is not in this device's inventory", req.Host))
		return
	}
	entry.Identity, entry.User = host.Identity, host.User
	identity, err := s.Store.Identity(host.Identity)
	if errors.Is(err, ErrNotFound) {
		reject(http.StatusForbidden, remote.CodeIdentityDisabled, fmt.Sprintf("identity %q does not exist", host.Identity))
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, remote.CodeInternal, "identity lookup failed")
		return
	}
	if identity.Status != IdentityActive {
		reject(http.StatusForbidden, remote.CodeIdentityDisabled, fmt.Sprintf("identity %q is disabled", identity.Name))
		return
	}
	auth, err := remote.ParseUserAuth(req.Data)
	if err != nil {
		reject(http.StatusForbidden, remote.CodeSignRejected, err.Error())
		return
	}
	signer, err := s.identitySigner(identity)
	if err != nil {
		writeError(w, http.StatusInternalServerError, remote.CodeInternal, "identity key unavailable")
		return
	}
	switch {
	case auth.User != host.User:
		reject(http.StatusForbidden, remote.CodeSignRejected, fmt.Sprintf("login user %q does not match inventory user %q", auth.User, host.User))
		return
	case auth.Algorithm != ssh.KeyAlgoED25519:
		reject(http.StatusForbidden, remote.CodeSignRejected, fmt.Sprintf("signature algorithm %q is not allowed", auth.Algorithm))
		return
	case !bytes.Equal(auth.PublicKey, signer.PublicKey().Marshal()):
		reject(http.StatusForbidden, remote.CodeSignRejected, "public key does not match the host's identity")
		return
	}
	sig, err := signer.Sign(rand.Reader, req.Data)
	if err != nil {
		writeError(w, http.StatusInternalServerError, remote.CodeInternal, "signing failed")
		return
	}
	entry.Result = SignOK
	if err := s.Store.AppendSign(entry); err != nil {
		// No log entry, no signature: the server-side audit trail is the one
		// record a device cannot tamper with.
		writeError(w, http.StatusInternalServerError, remote.CodeInternal, "signing log unavailable")
		return
	}
	writeJSON(w, http.StatusOK, remote.SignResponse{SignID: entry.SignID, Format: sig.Format, Blob: sig.Blob})
}

func (s *Server) identitySigner(identity Identity) (ssh.Signer, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.signers == nil {
		s.signers = map[string]ssh.Signer{}
	}
	if signer, ok := s.signers[identity.Name]; ok {
		return signer, nil
	}
	signer, err := s.Keys.DecryptIdentity(identity.PrivateKey)
	if err != nil {
		return nil, err
	}
	s.signers[identity.Name] = signer
	return signer, nil
}

func decodeInventory(data string) (inventory.Inventory, error) {
	var inv inventory.Inventory
	err := yaml.Unmarshal([]byte(data), &inv)
	return inv, err
}

// PushConfig validates and stores a device's managed inventory and policy.
func PushConfig(store *Store, deviceID string, inventoryYAML string, policyYAML string, now time.Time) (int64, error) {
	if _, err := store.Device(deviceID); err != nil {
		if errors.Is(err, ErrNotFound) {
			return 0, fmt.Errorf("unknown device %q", deviceID)
		}
		return 0, err
	}
	identityExists := func(name string) bool {
		_, err := store.Identity(name)
		return err == nil
	}
	if _, _, err := remote.ParseManaged(inventoryYAML, policyYAML, identityExists); err != nil {
		return 0, err
	}
	return store.PutConfig(deviceID, inventoryYAML, policyYAML, now)
}
