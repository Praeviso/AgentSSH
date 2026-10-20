package remoteserver

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
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
)

const schema = `
CREATE TABLE IF NOT EXISTS devices (
	id TEXT PRIMARY KEY,
	name TEXT NOT NULL,
	status TEXT NOT NULL,
	created_at TEXT NOT NULL,
	revoked_at TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS enroll_tokens (
	id TEXT PRIMARY KEY,
	name TEXT NOT NULL,
	secret_sha256 TEXT NOT NULL,
	expires_at TEXT NOT NULL,
	used_at TEXT NOT NULL DEFAULT '',
	device_id TEXT NOT NULL DEFAULT ''
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
CREATE TABLE IF NOT EXISTS sign_log (
	seq INTEGER PRIMARY KEY AUTOINCREMENT,
	sign_id TEXT NOT NULL,
	ts TEXT NOT NULL,
	device_id TEXT NOT NULL,
	host TEXT NOT NULL,
	identity TEXT NOT NULL,
	user TEXT NOT NULL,
	result TEXT NOT NULL,
	reason TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS sign_log_device ON sign_log(device_id);
`

// Identity statuses.
const (
	IdentityActive   = "active"
	IdentityDisabled = "disabled"
)

// Sign log results.
const (
	SignOK       = "signed"
	SignRejected = "rejected"
)

// Store is the control plane's SQLite state.
type Store struct {
	db *sql.DB
}

// Device is one enrolled client.
type Device struct {
	ID        string
	Name      string
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

// SignEntry is one signing-log row.
type SignEntry struct {
	Seq      int64
	SignID   string
	TS       time.Time
	DeviceID string
	Host     string
	Identity string
	User     string
	Result   string
	Reason   string
}

// OpenStore opens (creating if needed) the SQLite database at path.
func OpenStore(path string) (*Store, error) {
	dsn := "file:" + path + "?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open control plane database: %w", err)
	}
	if _, err := db.Exec(schema); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("initialize control plane database: %w", err)
	}
	return &Store{db: db}, nil
}

// Close releases the database.
func (s *Store) Close() error {
	return s.db.Close()
}

func formatTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339Nano)
}

func parseTime(value string) time.Time {
	if value == "" {
		return time.Time{}
	}
	t, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return time.Time{}
	}
	return t
}

func randomHex(n int) string {
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

// CreateEnrollToken stores a one-time token and returns its id and secret.
func (s *Store) CreateEnrollToken(name string, ttl time.Duration, now time.Time) (string, string, error) {
	id := "et_" + randomHex(6)
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", "", err
	}
	secret := base64.RawURLEncoding.EncodeToString(raw)
	_, err := s.db.Exec(`INSERT INTO enroll_tokens (id, name, secret_sha256, expires_at) VALUES (?, ?, ?, ?)`,
		id, name, secretDigest(secret), formatTime(now.Add(ttl)))
	if err != nil {
		return "", "", fmt.Errorf("store enrollment token: %w", err)
	}
	return id, secret, nil
}

// RedeemEnrollToken atomically consumes a token and creates the device it names.
func (s *Store) RedeemEnrollToken(tokenID string, secret string, now time.Time) (Device, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return Device{}, err
	}
	defer func() { _ = tx.Rollback() }()
	var name, digest, expires, used string
	err = tx.QueryRow(`SELECT name, secret_sha256, expires_at, used_at FROM enroll_tokens WHERE id = ?`, tokenID).
		Scan(&name, &digest, &expires, &used)
	if errors.Is(err, sql.ErrNoRows) {
		return Device{}, ErrTokenInvalid
	}
	if err != nil {
		return Device{}, err
	}
	if used != "" || !now.Before(parseTime(expires)) ||
		subtle.ConstantTimeCompare([]byte(digest), []byte(secretDigest(secret))) != 1 {
		return Device{}, ErrTokenInvalid
	}
	device := Device{ID: "dev_" + randomHex(8), Name: name, Status: remote.DeviceActive, CreatedAt: now}
	res, err := tx.Exec(`UPDATE enroll_tokens SET used_at = ?, device_id = ? WHERE id = ? AND used_at = ''`,
		formatTime(now), device.ID, tokenID)
	if err != nil {
		return Device{}, err
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return Device{}, ErrTokenInvalid
	}
	if _, err := tx.Exec(`INSERT INTO devices (id, name, status, created_at) VALUES (?, ?, ?, ?)`,
		device.ID, device.Name, device.Status, formatTime(now)); err != nil {
		return Device{}, err
	}
	if err := tx.Commit(); err != nil {
		return Device{}, err
	}
	return device, nil
}

// Device returns one device by id.
func (s *Store) Device(id string) (Device, error) {
	var d Device
	var created, revoked string
	err := s.db.QueryRow(`SELECT id, name, status, created_at, revoked_at FROM devices WHERE id = ?`, id).
		Scan(&d.ID, &d.Name, &d.Status, &created, &revoked)
	if errors.Is(err, sql.ErrNoRows) {
		return Device{}, ErrNotFound
	}
	if err != nil {
		return Device{}, err
	}
	d.CreatedAt, d.RevokedAt = parseTime(created), parseTime(revoked)
	return d, nil
}

// Devices lists every device, oldest first.
func (s *Store) Devices() ([]Device, error) {
	rows, err := s.db.Query(`SELECT id, name, status, created_at, revoked_at FROM devices ORDER BY created_at, id`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []Device
	for rows.Next() {
		var d Device
		var created, revoked string
		if err := rows.Scan(&d.ID, &d.Name, &d.Status, &created, &revoked); err != nil {
			return nil, err
		}
		d.CreatedAt, d.RevokedAt = parseTime(created), parseTime(revoked)
		out = append(out, d)
	}
	return out, rows.Err()
}

// RevokeDevice marks a device revoked. It is idempotent.
func (s *Store) RevokeDevice(id string, now time.Time) error {
	res, err := s.db.Exec(`UPDATE devices SET status = ?, revoked_at = CASE WHEN revoked_at = '' THEN ? ELSE revoked_at END WHERE id = ?`,
		remote.DeviceRevoked, formatTime(now), id)
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
		id.Name, id.PublicKey, id.PrivateKey, IdentityActive, formatTime(id.CreatedAt))
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
	id.CreatedAt = parseTime(created)
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
		id.CreatedAt = parseTime(created)
		out = append(out, id)
	}
	return out, rows.Err()
}

// DisableIdentity stops an identity from signing. It is idempotent.
func (s *Store) DisableIdentity(name string, now time.Time) error {
	res, err := s.db.Exec(`UPDATE identities SET status = ?, disabled_at = CASE WHEN disabled_at = '' THEN ? ELSE disabled_at END WHERE name = ?`,
		IdentityDisabled, formatTime(now), name)
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
	version++
	_, err = tx.Exec(`INSERT INTO configs (device_id, version, inventory_yaml, policy_yaml, updated_at) VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(device_id) DO UPDATE SET version = excluded.version, inventory_yaml = excluded.inventory_yaml,
		policy_yaml = excluded.policy_yaml, updated_at = excluded.updated_at`,
		deviceID, version, inventoryYAML, policyYAML, formatTime(now))
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
	c.UpdatedAt = parseTime(updated)
	return c, nil
}

// AppendSign records one signing decision.
func (s *Store) AppendSign(e SignEntry) error {
	_, err := s.db.Exec(`INSERT INTO sign_log (sign_id, ts, device_id, host, identity, user, result, reason) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		e.SignID, formatTime(e.TS), e.DeviceID, e.Host, e.Identity, e.User, e.Result, e.Reason)
	return err
}

// SignLogFilter narrows SignLog.
type SignLogFilter struct {
	DeviceID string
	Host     string
	Limit    int
}

// SignLog returns the newest matching entries, newest last.
func (s *Store) SignLog(filter SignLogFilter) ([]SignEntry, error) {
	limit := filter.Limit
	if limit <= 0 {
		limit = 50
	}
	query := `SELECT seq, sign_id, ts, device_id, host, identity, user, result, reason FROM sign_log WHERE 1=1`
	var args []any
	if filter.DeviceID != "" {
		query += ` AND device_id = ?`
		args = append(args, filter.DeviceID)
	}
	if filter.Host != "" {
		query += ` AND host = ?`
		args = append(args, filter.Host)
	}
	query += ` ORDER BY seq DESC LIMIT ?`
	args = append(args, limit)
	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []SignEntry
	for rows.Next() {
		var e SignEntry
		var ts string
		if err := rows.Scan(&e.Seq, &e.SignID, &ts, &e.DeviceID, &e.Host, &e.Identity, &e.User, &e.Result, &e.Reason); err != nil {
			return nil, err
		}
		e.TS = parseTime(ts)
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out, nil
}
