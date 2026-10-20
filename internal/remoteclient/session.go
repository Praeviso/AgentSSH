package remoteclient

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/Praeviso/AgentSSH/internal/executor"
	"github.com/Praeviso/AgentSSH/internal/fileutil"
	"github.com/Praeviso/AgentSSH/internal/inventory"
	"github.com/Praeviso/AgentSSH/internal/managedmode"
	"github.com/Praeviso/AgentSSH/internal/policy"
	"github.com/Praeviso/AgentSSH/internal/remote"
	"golang.org/x/crypto/ssh"
)

// CacheFreshness is how long a fetched bundle is reused without asking the
// control plane again.
var CacheFreshness = 60 * time.Second

// cacheFile is the single on-disk record of the last verified bundle. Keeping
// bundle, signature, and rollback floor in one atomically replaced file means a
// reader never sees a bundle paired with another bundle's signature.
type cacheFile struct {
	Bundle     []byte    `json:"bundle"`
	Signature  []byte    `json:"signature"`
	FetchedAt  time.Time `json:"fetched_at"`
	MaxVersion int64     `json:"max_version"`
}

// OpenOptions tunes Open.
type OpenOptions struct {
	// Refresh skips the freshness window and always asks the control plane.
	Refresh bool
	Now     func() time.Time
}

// Session is an enrolled home's verified, current remote configuration.
type Session struct {
	Home      string
	Client    *Client
	Bundle    remote.Bundle
	FetchedAt time.Time
	// Stale is true when the control plane was unreachable and a cached bundle
	// that is still inside its validity window was used instead.
	Stale     bool
	Inventory inventory.Inventory
	Policy    policy.Config
}

// Open loads the device's configuration bundle, fetching a new one when the
// cache is older than CacheFreshness. It fails closed: a control-plane refusal
// is never papered over with the cache, and an unreachable control plane is
// only tolerated while the cached bundle has not expired.
func Open(ctx context.Context, home string, opts OpenOptions) (*Session, error) {
	now := time.Now
	if opts.Now != nil {
		now = opts.Now
	}
	client, err := NewClient(home)
	if err != nil {
		return nil, err
	}
	pub, err := base64.StdEncoding.DecodeString(client.State.BundlePublicKey)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return nil, errors.New("pinned bundle public key is invalid; run agentssh remote leave and enroll again")
	}
	cachePath := filepath.Join(managedmode.Dir(home), fileCache)
	cache, cached, cacheErr := readCache(cachePath, pub, client.State.DeviceID)

	current := now()
	if cacheErr == nil && !opts.Refresh && current.Sub(cache.FetchedAt) < CacheFreshness && current.Before(cached.NotAfter) {
		return newSession(home, client, cached, cache.FetchedAt, false)
	}

	resp, err := client.FetchBundle(ctx)
	if err != nil {
		var unreachable *UnreachableError
		if errors.As(err, &unreachable) && cacheErr == nil && current.Before(cached.NotAfter) {
			return newSession(home, client, cached, cache.FetchedAt, true)
		}
		if errors.As(err, &unreachable) && cacheErr == nil {
			return nil, fmt.Errorf("%w; the cached configuration expired at %s", err, cached.NotAfter.Local().Format(time.RFC3339))
		}
		return nil, err
	}
	bundle, err := remote.VerifyBundle(resp.Bundle, resp.Signature, pub)
	if err != nil {
		return nil, err
	}
	if bundle.DeviceID != client.State.DeviceID {
		return nil, fmt.Errorf("configuration bundle is for device %s, not this device (%s)", bundle.DeviceID, client.State.DeviceID)
	}
	floor := int64(0)
	if cacheErr == nil {
		floor = cache.MaxVersion
	}
	if bundle.Version < floor {
		return nil, fmt.Errorf("configuration bundle version %d is older than version %d already seen; refusing rollback", bundle.Version, floor)
	}
	if !current.Before(bundle.NotAfter) {
		return nil, fmt.Errorf("configuration bundle expired at %s; check this machine's clock", bundle.NotAfter.Local().Format(time.RFC3339))
	}
	next := cacheFile{Bundle: resp.Bundle, Signature: resp.Signature, FetchedAt: current.UTC(), MaxVersion: max(floor, bundle.Version)}
	data, err := json.Marshal(next)
	if err != nil {
		return nil, err
	}
	if err := fileutil.WriteFileAtomic(cachePath, data, 0o600, fileCache+"-*"); err != nil {
		return nil, fmt.Errorf("write bundle cache: %w", err)
	}
	return newSession(home, client, bundle, next.FetchedAt, false)
}

func readCache(path string, pub ed25519.PublicKey, deviceID string) (cacheFile, remote.Bundle, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return cacheFile{}, remote.Bundle{}, err
	}
	var cache cacheFile
	if err := json.Unmarshal(data, &cache); err != nil {
		return cacheFile{}, remote.Bundle{}, err
	}
	bundle, err := remote.VerifyBundle(cache.Bundle, cache.Signature, pub)
	if err != nil {
		return cacheFile{}, remote.Bundle{}, err
	}
	if bundle.DeviceID != deviceID {
		return cacheFile{}, remote.Bundle{}, errors.New("cached bundle belongs to another device")
	}
	return cache, bundle, nil
}

// CachedBundle returns the last verified bundle without any network access.
func CachedBundle(home string) (remote.Bundle, time.Time, error) {
	state, err := LoadState(home)
	if err != nil {
		return remote.Bundle{}, time.Time{}, err
	}
	pub, err := base64.StdEncoding.DecodeString(state.BundlePublicKey)
	if err != nil {
		return remote.Bundle{}, time.Time{}, err
	}
	cache, bundle, err := readCache(filepath.Join(managedmode.Dir(home), fileCache), pub, state.DeviceID)
	if err != nil {
		return remote.Bundle{}, time.Time{}, err
	}
	return bundle, cache.FetchedAt, nil
}

func newSession(home string, client *Client, bundle remote.Bundle, fetchedAt time.Time, stale bool) (*Session, error) {
	inv, pol, err := remote.ParseManaged(bundle.InventoryYAML, bundle.PolicyYAML, func(name string) bool {
		_, ok := bundle.Identities[name]
		return ok
	})
	if err != nil {
		return nil, fmt.Errorf("configuration bundle v%d: %w", bundle.Version, err)
	}
	return &Session{Home: home, Client: client, Bundle: bundle, FetchedAt: fetchedAt, Stale: stale, Inventory: inv, Policy: pol}, nil
}

// Signer returns an ssh.Signer for host whose private key stays on the control
// plane. Each Sign call is one control-plane request.
func (s *Session) Signer(host string) (ssh.Signer, error) {
	entry, ok := s.Inventory.Hosts[host]
	if !ok {
		return nil, fmt.Errorf("host %q is not in the managed inventory", host)
	}
	line, ok := s.Bundle.Identities[entry.Identity]
	if !ok {
		return nil, fmt.Errorf("host %q uses identity %q missing from the configuration bundle", host, entry.Identity)
	}
	pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(line))
	if err != nil {
		return nil, fmt.Errorf("identity %q public key: %w", entry.Identity, err)
	}
	return &remoteSigner{client: s.Client, host: host, pub: pub}, nil
}

// ApplyNativeOptions switches a native executor to remote signing only: no
// ssh-agent, local keys, or passwords, and no connection reuse, so every
// command needs a fresh signature and revocation takes effect immediately.
func (s *Session) ApplyNativeOptions(options *executor.NativeOptions) {
	options.RemoteSigner = s.Signer
	options.PasswordSource = nil
	options.DisableConnectionReuse = true
	options.HostKeyPolicy = s.Inventory.HostKeyPolicy
}

type remoteSigner struct {
	client *Client
	host   string
	pub    ssh.PublicKey

	mu     sync.Mutex
	signID string
}

func (r *remoteSigner) PublicKey() ssh.PublicKey { return r.pub }

func (r *remoteSigner) Sign(_ io.Reader, data []byte) (*ssh.Signature, error) {
	resp, err := r.client.Sign(context.Background(), r.host, data)
	if err != nil {
		return nil, &SignError{Err: err}
	}
	sig := &ssh.Signature{Format: resp.Format, Blob: resp.Blob}
	// Never hand the SSH server a signature we cannot verify ourselves; a wrong
	// key here would otherwise surface as an opaque authentication failure.
	if err := r.pub.Verify(data, sig); err != nil {
		return nil, &SignError{Err: fmt.Errorf("control plane signature does not verify: %w", err)}
	}
	r.mu.Lock()
	r.signID = resp.SignID
	r.mu.Unlock()
	return sig, nil
}

// SignID returns the control-plane signing-log id of the last signature.
func (r *remoteSigner) SignID() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.signID
}

// SignError marks a failure to obtain a remote signature.
type SignError struct {
	Err error
}

func (e *SignError) Error() string {
	return fmt.Sprintf("remote signing failed: %v", e.Err)
}

func (e *SignError) Unwrap() error { return e.Err }
