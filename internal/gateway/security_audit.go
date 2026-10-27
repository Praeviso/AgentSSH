package gateway

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/Praeviso/AgentSSH/internal/audit"
	"github.com/Praeviso/AgentSSH/internal/controlplane"
)

// State changes and their pending audit facts share a SQLite transaction.
// Repair publication holds no database transaction: the audit lock serializes
// deduplication, and completion is marked only after a successful append.
// Keeping completed rows preserves the first fact on a retried transition.
const securityAuditSchema = `
CREATE TABLE IF NOT EXISTS security_audit_events (
	seq INTEGER PRIMARY KEY AUTOINCREMENT,
	event_id TEXT NOT NULL UNIQUE,
	record TEXT NOT NULL,
	audited INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS security_audit_pending ON security_audit_events(seq) WHERE audited = 0;
`

// AuditPendingError means an access restriction is already effective and its
// audit fact is durable, but publication or its completion marker needs repair.
// It must never be interpreted as failure to apply the restriction.
type AuditPendingError struct {
	Action string
	Err    error
}

func (e *AuditPendingError) Error() string {
	return e.Action + ", but its audit record failed; audit repair is pending: " + e.Err.Error()
}

func (e *AuditPendingError) Unwrap() error { return e.Err }

func isAuditPending(err error) bool {
	var pending *AuditPendingError
	return errors.As(err, &pending)
}

func pendingAudit(action string, err error) error {
	if err == nil {
		return nil
	}
	return &AuditPendingError{Action: action, Err: err}
}

func securityEventID(key string) string {
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:])
}

// enqueueSecurityAudit is idempotent and retains the original event payload.
// The caller commits it with the state change, before attempting publication.
func enqueueSecurityAudit(tx *sql.Tx, key string, record audit.Record) (audit.Record, error) {
	record.EventID = securityEventID(key)
	data, err := json.Marshal(record)
	if err != nil {
		return audit.Record{}, err
	}
	if _, err := tx.Exec(`INSERT INTO security_audit_events (event_id, record) VALUES (?, ?) ON CONFLICT(event_id) DO NOTHING`, record.EventID, string(data)); err != nil {
		return audit.Record{}, err
	}
	var saved string
	if err := tx.QueryRow(`SELECT record FROM security_audit_events WHERE event_id = ?`, record.EventID).Scan(&saved); err != nil {
		return audit.Record{}, err
	}
	err = json.Unmarshal([]byte(saved), &record)
	return record, err
}

func publishSecurityAudit(dir string, store *controlplane.Store, key string) error {
	id := securityEventID(key)
	var data string
	var audited bool
	err := store.DB().QueryRow(`SELECT record, audited FROM security_audit_events WHERE event_id = ?`, id).Scan(&data, &audited)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil || audited {
		return err
	}
	var record audit.Record
	if err := json.Unmarshal([]byte(data), &record); err != nil {
		return err
	}
	return publishSecurityRecord(dir, store, record)
}

func publishSecurityRecord(dir string, store *controlplane.Store, record audit.Record) error {
	if err := appendSecurityRecord(dir, record); err != nil {
		return err
	}
	_, err := store.DB().Exec(`UPDATE security_audit_events SET audited = 1 WHERE event_id = ?`, record.EventID)
	return err
}

// Tests replace this file-publication boundary to inject write failures.
var appendSecurityRecord = func(dir string, record audit.Record) error {
	if _, _, err := activationAudit(dir).AppendUnless(record, func(existing audit.Record) bool {
		if record.EventID != "" && existing.EventID == record.EventID {
			return true
		}
		// An older binary may have appended an expiry but crashed before
		// marking end_recorded. Preserve that already-published fact too.
		return record.EventID != "" && existing.EventID == "" && record.Event == audit.EventDeviceActivationEnded &&
			existing.Event == record.Event && existing.DeviceID == record.DeviceID && existing.ActiveUntil == record.ActiveUntil
	}); err != nil {
		return err
	}
	return nil
}

// RecordPendingAudits repairs committed security audit facts, including those
// left by another process or a restart. A failed event stays pending; other
// events are still attempted. Run it independently of standing enforcement.
func RecordPendingAudits(dir string, store *controlplane.Store) error {
	rows, err := store.DB().Query(`SELECT record FROM security_audit_events WHERE audited = 0 ORDER BY seq`)
	if err != nil {
		return err
	}
	var records []audit.Record
	for rows.Next() {
		var data string
		if err := rows.Scan(&data); err != nil {
			_ = rows.Close()
			return err
		}
		var record audit.Record
		if err := json.Unmarshal([]byte(data), &record); err != nil {
			_ = rows.Close()
			return err
		}
		records = append(records, record)
	}
	err = rows.Err()
	closeErr := rows.Close()
	if err != nil || closeErr != nil {
		return errors.Join(err, closeErr)
	}
	var failed error
	for _, record := range records {
		if err := publishSecurityRecord(dir, store, record); err != nil {
			failed = errors.Join(failed, fmt.Errorf("event %s: %w", record.EventID, err))
		}
	}
	return failed
}
