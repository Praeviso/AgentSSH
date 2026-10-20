package remote

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// BundleFormat is the current bundle schema version.
const BundleFormat = 1

// bundleSigContext domain-separates bundle signatures from any other use of
// the bundle signing key.
const bundleSigContext = "agentssh-bundle-v1\x00"

// Bundle is the configuration a control plane grants one device. Inventory
// and policy travel as their YAML source so the client reuses its normal
// parsers; identities carry public keys only.
type Bundle struct {
	Format        int               `json:"format"`
	Version       int64             `json:"version"`
	DeviceID      string            `json:"device_id"`
	IssuedAt      time.Time         `json:"issued_at"`
	NotAfter      time.Time         `json:"not_after"`
	InventoryYAML string            `json:"inventory_yaml"`
	PolicyYAML    string            `json:"policy_yaml"`
	Identities    map[string]string `json:"identities"`
}

// SignBundle serializes b and signs the exact bytes.
func SignBundle(b Bundle, key ed25519.PrivateKey) ([]byte, []byte, error) {
	b.Format = BundleFormat
	raw, err := json.Marshal(b)
	if err != nil {
		return nil, nil, fmt.Errorf("marshal bundle: %w", err)
	}
	return raw, ed25519.Sign(key, append([]byte(bundleSigContext), raw...)), nil
}

// VerifyBundle checks sig over raw with the pinned bundle key and decodes it.
func VerifyBundle(raw []byte, sig []byte, pub ed25519.PublicKey) (Bundle, error) {
	if len(pub) != ed25519.PublicKeySize {
		return Bundle{}, errors.New("bundle public key is invalid")
	}
	if !ed25519.Verify(pub, append([]byte(bundleSigContext), raw...), sig) {
		return Bundle{}, errors.New("configuration bundle signature is invalid")
	}
	var b Bundle
	if err := json.Unmarshal(raw, &b); err != nil {
		return Bundle{}, fmt.Errorf("decode configuration bundle: %w", err)
	}
	if b.Format != BundleFormat {
		return Bundle{}, fmt.Errorf("configuration bundle format %d is not supported", b.Format)
	}
	return b, nil
}
