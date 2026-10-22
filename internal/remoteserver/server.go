package remoteserver

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/Praeviso/AgentSSH/internal/controlplane"
	"github.com/Praeviso/AgentSSH/internal/inventory"
	"github.com/Praeviso/AgentSSH/internal/remote"
	"golang.org/x/crypto/ssh"
	"gopkg.in/yaml.v3"
)

// DefaultBundleTTL bounds how long a device may act on configuration it can no
// longer refresh.
const DefaultBundleTTL = 10 * time.Minute

// Server is the managed control plane HTTP API: the shared enrollment and
// device authentication, plus configuration bundles and remote SSH signing.
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

var (
	writeJSON  = controlplane.WriteJSON
	writeError = controlplane.WriteError
	decodeBody = controlplane.DecodeBody
)

func (s *Server) handleBundle(w http.ResponseWriter, _ *http.Request, device controlplane.Device, _ []byte) {
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

func (s *Server) handleSign(w http.ResponseWriter, _ *http.Request, device controlplane.Device, body []byte) {
	var req remote.SignRequest
	if err := decodeBody(body, &req); err != nil {
		writeError(w, http.StatusBadRequest, remote.CodeBadRequest, "malformed sign request")
		return
	}
	entry := SignEntry{SignID: "sg_" + controlplane.RandomHex(8), TS: s.now(), DeviceID: device.ID, Host: req.Host}
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
	return controlplane.PushConfig(store.Store, deviceID, inventoryYAML, policyYAML, now)
}
