package remoteserver

import (
	"bytes"
	"crypto/rand"
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

func decodeBody(data []byte, value any) error {
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

type deviceHandler func(http.ResponseWriter, *http.Request, Device, []byte)

func (s *Server) handleStatus(w http.ResponseWriter, _ *http.Request, device Device, _ []byte) {
	writeJSON(w, http.StatusOK, remote.StatusResponse{DeviceID: device.ID, Status: device.Status})
}

func (s *Server) handleBundle(w http.ResponseWriter, _ *http.Request, device Device, _ []byte) {
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

func (s *Server) handleSign(w http.ResponseWriter, _ *http.Request, device Device, body []byte) {
	var req remote.SignRequest
	if err := decodeBody(body, &req); err != nil {
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
