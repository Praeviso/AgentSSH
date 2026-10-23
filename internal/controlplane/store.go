package controlplane

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"time"

	"github.com/Praeviso/AgentSSH/internal/remote"
	_ "modernc.org/sqlite" // database/sql driver "sqlite"
)

var (
	// ErrNotFound reports a missing device, identity, or configuration.
	ErrNotFound = errors.New("not found")
	// ErrTokenInvalid reports an unknown, expired, used, or mismatched token.
	ErrTokenInvalid = errors.New("enrollment token is invalid, expired, or already used")
	// ErrExists reports a duplicate identity name.
	ErrExists = errors.New("already exists")
	// ErrDeviceRevoked reports revocation at the request authorization boundary.
	ErrDeviceRevoked = errors.New("device revoked")
	// ErrRequestReplayed reports an already consumed request proof.
	ErrRequestReplayed = errors.New("request replayed")
)

const schema = `
CREATE TABLE IF NOT EXISTS devices (
	id TEXT PRIMARY KEY,
	name TEXT NOT NULL,
	public_key TEXT NOT NULL,
	status TEXT NOT NULL,
	created_at TEXT NOT NULL,
	revoked_at TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS enroll_tokens (
	id TEXT PRIMARY KEY,
	name TEXT NOT NULL,
	secret_sha256 TEXT NOT NULL,
	public_url TEXT NOT NULL,
	expires_at TEXT NOT NULL,
	used_at TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS identities (
	name TEXT PRIMARY KEY,
	public_key TEXT NOT NULL,
	private_key BLOB NOT NULL,
	status TEXT NOT NULL,
	created_at TEXT NOT NULL,
	disabled_at TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS configs (
	device_id TEXT PRIMARY KEY,
	version INTEGER NOT NULL,
	inventory_yaml TEXT NOT NULL,
	policy_yaml TEXT NOT NULL,
	updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS request_nonces (
 device_id TEXT NOT NULL REFERENCES devices(id), nonce TEXT NOT NULL,
 expires_at INTEGER NOT NULL, PRIMARY KEY(device_id,nonce)
);
CREATE INDEX IF NOT EXISTS request_nonces_expiry ON request_nonces(expires_at);
`

// Identity statuses.
const (
	IdentityActive   = "active"
	IdentityDisabled = "disabled"
)

// Store is the control plane's SQLite state.
type Store struct {
	db             *sql.DB
	nextNoncePrune atomic.Int64
}

// Device is one enrolled client.
type Device struct {
	ID        string
	Name      string
	PublicKey string
	Status    string
	CreatedAt time.Time
	RevokedAt time.Time
}

// Identity is one control-plane SSH key. PrivateKey is age-encrypted.
type Identity struct {
	Name       string
	PublicKey  string
	PrivateKey []byte
	Status     string
	CreatedAt  time.Time
}

// DeviceConfig is the inventory and policy assigned to a device.
type DeviceConfig struct {
	DeviceID      string
	Version       int64
	InventoryYAML string
	PolicyYAML    string
	UpdatedAt     time.Time
}

// OpenStore opens (creating if needed) the SQLite database at path. extraSchema
// holds a mode's own tables, created after the shared ones.
func OpenStore(path string, extraSchema string) (*Store, error) {
	// All explicit transactions mutate state. Acquire write intent before any
	// reads, rather than upgrading a stale WAL snapshot after another writer.
	dsn := "file:" + path + "?_txlock=immediate&_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open control plane database: %w", err)
	}
	if _, err := db.Exec(schema + extraSchema); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("initialize control plane database: %w", err)
	}
	rows, err := db.Query(`SELECT devices.public_key, enroll_tokens.public_url FROM devices, enroll_tokens LIMIT 0`)
	if err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("incompatible control-plane storage; initialize a fresh data directory: %w", err)
	}
	if err := rows.Close(); err != nil {
		_ = db.Close()
		return nil, err
	}
	return &Store{db: db}, nil
}

// Close releases the database.
func (s *Store) Close() error {
	return s.db.Close()
}

// DB exposes the database to a mode's own tables.
func (s *Store) DB() *sql.DB {
	return s.db
}

// FormatTime is the stored time encoding; the zero time is "".
func FormatTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339Nano)
}

// ParseTime decodes FormatTime; malformed values are the zero time.
func ParseTime(value string) time.Time {
	if value == "" {
		return time.Time{}
	}
	t, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return time.Time{}
	}
	return t
}

// RandomHex returns n random bytes, hex encoded.
func RandomHex(n int) string {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		panic(fmt.Sprintf("crypto/rand: %v", err))
	}
	return hex.EncodeToString(buf)
}

func secretDigest(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:])
}

// Device returns one device by id.
func (s *Store) Device(id string) (Device, error) {
	var d Device
	var created, revoked string
	err := s.db.QueryRow(`SELECT id, name, public_key, status, created_at, revoked_at FROM devices WHERE id = ?`, id).
		Scan(&d.ID, &d.Name, &d.PublicKey, &d.Status, &created, &revoked)
	if errors.Is(err, sql.ErrNoRows) {
		return Device{}, ErrNotFound
	}
	if err != nil {
		return Device{}, err
	}
	d.CreatedAt, d.RevokedAt = ParseTime(created), ParseTime(revoked)
	return d, nil
}

// Devices lists every device, oldest first.
func (s *Store) Devices() ([]Device, error) {
	rows, err := s.db.Query(`SELECT id, name, public_key, status, created_at, revoked_at FROM devices ORDER BY created_at, id`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []Device
	for rows.Next() {
		var d Device
		var created, revoked string
		if err := rows.Scan(&d.ID, &d.Name, &d.PublicKey, &d.Status, &created, &revoked); err != nil {
			return nil, err
		}
		d.CreatedAt, d.RevokedAt = ParseTime(created), ParseTime(revoked)
		out = append(out, d)
	}
	return out, rows.Err()
}

// RevokeDevice marks a device revoked. It is idempotent.
func (s *Store) RevokeDevice(id string, now time.Time) error {
	res, err := s.db.Exec(`UPDATE devices SET status = ?, revoked_at = CASE WHEN revoked_at = '' THEN ? ELSE revoked_at END WHERE id = ?`,
		remote.DeviceRevoked, FormatTime(now), id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// CreateIdentity stores a new identity.
func (s *Store) CreateIdentity(id Identity) error {
	_, err := s.db.Exec(`INSERT INTO identities (name, public_key, private_key, status, created_at) VALUES (?, ?, ?, ?, ?)`,
		id.Name, id.PublicKey, id.PrivateKey, IdentityActive, FormatTime(id.CreatedAt))
	if err != nil && strings.Contains(strings.ToLower(err.Error()), "unique") {
		return ErrExists
	}
	return err
}

// Identity returns one identity by name.
func (s *Store) Identity(name string) (Identity, error) {
	var id Identity
	var created string
	err := s.db.QueryRow(`SELECT name, public_key, private_key, status, created_at FROM identities WHERE name = ?`, name).
		Scan(&id.Name, &id.PublicKey, &id.PrivateKey, &id.Status, &created)
	if errors.Is(err, sql.ErrNoRows) {
		return Identity{}, ErrNotFound
	}
	if err != nil {
		return Identity{}, err
	}
	id.CreatedAt = ParseTime(created)
	return id, nil
}

// Identities lists identities without their encrypted private keys.
func (s *Store) Identities() ([]Identity, error) {
	rows, err := s.db.Query(`SELECT name, public_key, status, created_at FROM identities ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []Identity
	for rows.Next() {
		var id Identity
		var created string
		if err := rows.Scan(&id.Name, &id.PublicKey, &id.Status, &created); err != nil {
			return nil, err
		}
		id.CreatedAt = ParseTime(created)
		out = append(out, id)
	}
	return out, rows.Err()
}

// DisableIdentity stops an identity from being used. It is idempotent.
func (s *Store) DisableIdentity(name string, now time.Time) error {
	res, err := s.db.Exec(`UPDATE identities SET status = ?, disabled_at = CASE WHEN disabled_at = '' THEN ? ELSE disabled_at END WHERE name = ?`,
		IdentityDisabled, FormatTime(now), name)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// PutConfig replaces a device's configuration and bumps its version.
func (s *Store) PutConfig(deviceID string, inventoryYAML string, policyYAML string, now time.Time) (int64, error) {
	return s.putConfig(deviceID, -1, inventoryYAML, policyYAML, now)
}

// ErrConfigChanged refuses a configuration derived from a version that is no
// longer current.
var ErrConfigChanged = errors.New("the device's configuration changed meanwhile")

// putConfig stores the next version; with from >= 0 only if the current
// version is still from, so a change derived from it never overwrites a
// newer push.
func (s *Store) putConfig(deviceID string, from int64, inventoryYAML string, policyYAML string, now time.Time) (int64, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()
	var version int64
	err = tx.QueryRow(`SELECT version FROM configs WHERE device_id = ?`, deviceID).Scan(&version)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return 0, err
	}
	if from >= 0 && version != from {
		return 0, ErrConfigChanged
	}
	version++
	_, err = tx.Exec(`INSERT INTO configs (device_id, version, inventory_yaml, policy_yaml, updated_at) VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(device_id) DO UPDATE SET version = excluded.version, inventory_yaml = excluded.inventory_yaml,
		policy_yaml = excluded.policy_yaml, updated_at = excluded.updated_at`,
		deviceID, version, inventoryYAML, policyYAML, FormatTime(now))
	if err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return version, nil
}

// Config returns a device's configuration.
func (s *Store) Config(deviceID string) (DeviceConfig, error) {
	var c DeviceConfig
	var updated string
	err := s.db.QueryRow(`SELECT device_id, version, inventory_yaml, policy_yaml, updated_at FROM configs WHERE device_id = ?`, deviceID).
		Scan(&c.DeviceID, &c.Version, &c.InventoryYAML, &c.PolicyYAML, &updated)
	if errors.Is(err, sql.ErrNoRows) {
		return DeviceConfig{}, ErrNotFound
	}
	if err != nil {
		return DeviceConfig{}, err
	}
	c.UpdatedAt = ParseTime(updated)
	return c, nil
}
