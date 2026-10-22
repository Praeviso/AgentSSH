package remoteserver

import (
	"database/sql"
	"time"

	"github.com/Praeviso/AgentSSH/internal/controlplane"
)

var (
	// ErrNotFound reports a missing device, identity, or configuration.
	ErrNotFound = controlplane.ErrNotFound
	// ErrTokenInvalid reports an unknown, expired, used, or mismatched token.
	ErrTokenInvalid = controlplane.ErrTokenInvalid
	// ErrExists reports a duplicate identity name.
	ErrExists = controlplane.ErrExists
	// ErrDeviceRevoked reports revocation at the request authorization boundary.
	ErrDeviceRevoked = controlplane.ErrDeviceRevoked
	// ErrRequestReplayed reports an already consumed request proof.
	ErrRequestReplayed = controlplane.ErrRequestReplayed
)

// signSchema is the managed control plane's own table, beside the shared ones.
const signSchema = `
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
	IdentityActive   = controlplane.IdentityActive
	IdentityDisabled = controlplane.IdentityDisabled
)

// Sign log results.
const (
	SignOK       = "signed"
	SignRejected = "rejected"
)

// Store is the managed control plane's SQLite state: the shared device,
// identity and configuration tables plus the signing log.
type Store struct {
	*controlplane.Store
	db *sql.DB
}

type (
	// Device is one enrolled client.
	Device = controlplane.Device
	// Identity is one control-plane SSH key. PrivateKey is age-encrypted.
	Identity = controlplane.Identity
	// DeviceConfig is the inventory and policy assigned to a device.
	DeviceConfig = controlplane.DeviceConfig
)

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
	store, err := controlplane.OpenStore(path, signSchema)
	if err != nil {
		return nil, err
	}
	return &Store{Store: store, db: store.DB()}, nil
}

// AppendSign records one signing decision.
func (s *Store) AppendSign(e SignEntry) error {
	_, err := s.db.Exec(`INSERT INTO sign_log (sign_id, ts, device_id, host, identity, user, result, reason) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		e.SignID, controlplane.FormatTime(e.TS), e.DeviceID, e.Host, e.Identity, e.User, e.Result, e.Reason)
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
		e.TS = controlplane.ParseTime(ts)
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
