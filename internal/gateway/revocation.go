package gateway

import (
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/Praeviso/AgentSSH/internal/audit"
	"github.com/Praeviso/AgentSSH/internal/controlplane"
	"github.com/Praeviso/AgentSSH/internal/remote"
)

// A revocation is terminal. Preserve its original actor/time in the same
// transaction as the device state, so audit failures and retries after a
// restart never leave a device usable or attribute the change to a retrier.
const revocationSchema = `
CREATE TABLE IF NOT EXISTS device_revocations (
	device_id TEXT PRIMARY KEY REFERENCES devices(id),
	revoked_at TEXT NOT NULL,
	revoked_by TEXT NOT NULL,
	audited INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS device_revocations_pending ON device_revocations(device_id) WHERE audited = 0;
`

// RevokeDevice permanently revokes a signed or token gateway device and
// records who did it. It is idempotent. An audit error leaves the device
// revoked; another call or serve's sweep retries the missing record.
func RevokeDevice(dir string, store *controlplane.Store, deviceID, operator string, now time.Time) error {
	tx, err := store.DB().Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	var status string
	err = tx.QueryRow(`SELECT status FROM devices WHERE id = ?`, deviceID).Scan(&status)
	if errors.Is(err, sql.ErrNoRows) {
		return controlplane.ErrNotFound
	}
	if err != nil {
		return err
	}
	if status != remote.DeviceRevoked {
		ts := controlplane.FormatTime(now)
		if _, err := tx.Exec(`UPDATE devices SET status = ?, revoked_at = ? WHERE id = ?`, remote.DeviceRevoked, ts, deviceID); err != nil {
			return err
		}
		if _, err := tx.Exec(`INSERT INTO device_revocations (device_id, revoked_at, revoked_by) VALUES (?, ?, ?)`, deviceID, ts, operator); err != nil {
			return err
		}
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	return recordDeviceRevocation(dir, store, deviceID)
}

func recordDeviceRevocation(dir string, store *controlplane.Store, deviceID string) error {
	var ts, operator string
	var audited bool
	err := store.DB().QueryRow(`SELECT revoked_at, revoked_by, audited FROM device_revocations WHERE device_id = ?`, deviceID).
		Scan(&ts, &operator, &audited)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil || audited {
		return err
	}
	if _, _, err := activationAudit(dir).AppendUnless(audit.Record{
		TS: ts, Event: audit.EventDeviceRevoked, DeviceID: deviceID, Operator: operator,
	}, func(existing audit.Record) bool {
		return existing.Event == audit.EventDeviceRevoked && existing.DeviceID == deviceID
	}); err != nil {
		return fmt.Errorf("the device is revoked, but its audit record failed; retry device revoke or let serve retry it: %w", err)
	}
	_, err = store.DB().Exec(`UPDATE device_revocations SET audited = 1 WHERE device_id = ?`, deviceID)
	if err != nil {
		return fmt.Errorf("the device is revoked and audited, but recording audit completion failed: %w", err)
	}
	return nil
}

// RecordDeviceRevocations repairs pending revocation audit records, including
// changes committed by another process. serve runs it with the standing sweep.
func RecordDeviceRevocations(dir string, store *controlplane.Store) error {
	rows, err := store.DB().Query(`SELECT device_id FROM device_revocations WHERE audited = 0 ORDER BY device_id`)
	if err != nil {
		return err
	}
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			_ = rows.Close()
			return err
		}
		ids = append(ids, id)
	}
	err = rows.Err()
	closeErr := rows.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	for _, id := range ids {
		if err := recordDeviceRevocation(dir, store, id); err != nil {
			return err
		}
	}
	return nil
}
