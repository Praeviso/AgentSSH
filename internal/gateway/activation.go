package gateway

import (
	"database/sql"
	"errors"
	"fmt"
	"log"
	"path/filepath"
	"time"

	"github.com/Praeviso/AgentSSH/internal/audit"
	"github.com/Praeviso/AgentSSH/internal/controlplane"
	"github.com/Praeviso/AgentSSH/internal/remote"
)

// A gateway device may use the gateway only inside an activation window an
// operator opens for a chosen duration. With no window, or after it ends, the
// device is inactive; revocation stays separate and terminal.
const activationSchema = `
CREATE TABLE IF NOT EXISTS device_activations (
	device_id TEXT PRIMARY KEY REFERENCES devices(id),
	active_until TEXT NOT NULL,
	set_by TEXT NOT NULL,
	note TEXT NOT NULL DEFAULT '',
	set_at TEXT NOT NULL,
	end_recorded INTEGER NOT NULL DEFAULT 0,
	deactivated_by TEXT NOT NULL DEFAULT ''
);
`

// MinActivation and MaxActivation bound one window. The store enforces them,
// so every way of activating shares one rule.
const (
	MinActivation = time.Minute
	MaxActivation = 24 * time.Hour
)

// ErrActivationDuration refuses a window shorter than MinActivation or longer
// than MaxActivation.
var ErrActivationDuration = fmt.Errorf("the activation must last at least %s and at most %s", formatWindow(MinActivation), formatWindow(MaxActivation))

// Activation is a device's current window. Until is zero when the device has
// never been activated.
type Activation struct {
	DeviceID string
	Until    time.Time
	SetBy    string
	Note     string
	SetAt    time.Time
	// DeactivatedBy names the operator who closed the window early; empty
	// while it is open or after it ended on its own.
	DeactivatedBy string
}

// Active reports whether the window is open at now.
func (a Activation) Active(now time.Time) bool {
	return !a.Until.IsZero() && now.Before(a.Until)
}

// DeviceActivation returns a device's window; a device never activated has
// an empty one.
func DeviceActivation(store *controlplane.Store, deviceID string) (Activation, error) {
	a, _, err := loadActivation(store.DB(), deviceID)
	return a, err
}

func loadActivation(db querier, deviceID string) (Activation, bool, error) {
	a := Activation{DeviceID: deviceID}
	var until, setAt string
	var recorded bool
	err := db.QueryRow(`SELECT active_until, set_by, note, set_at, end_recorded, deactivated_by FROM device_activations WHERE device_id = ?`, deviceID).
		Scan(&until, &a.SetBy, &a.Note, &setAt, &recorded, &a.DeactivatedBy)
	if errors.Is(err, sql.ErrNoRows) {
		return a, true, nil
	}
	if err != nil {
		return Activation{}, false, err
	}
	a.Until, a.SetAt = controlplane.ParseTime(until), controlplane.ParseTime(setAt)
	return a, recorded, nil
}

// ActivateDevice opens a window of length d from now. Opening access still
// requires successful audit publication. Replacing an expired window commits
// its audit fact in the same transaction, so that window cannot be forgotten.
func ActivateDevice(dir string, store *controlplane.Store, deviceID string, d time.Duration, operator, note string, now time.Time) (Activation, error) {
	if d < MinActivation || d > MaxActivation {
		return Activation{}, ErrActivationDuration
	}
	device, err := store.Device(deviceID)
	if err != nil {
		return Activation{}, err
	}
	if device.Status == remote.DeviceRevoked {
		return Activation{}, controlplane.ErrDeviceRevoked
	}
	previous, _, err := loadActivation(store.DB(), deviceID)
	if err != nil {
		return Activation{}, err
	}
	expired := !previous.Until.IsZero() && !previous.Active(now) && previous.DeactivatedBy == ""
	if expired {
		if err := recordActivationEnd(dir, store, previous, now); err != nil {
			return Activation{}, fmt.Errorf("record the end of the previous window: %w", err)
		}
	}
	a := Activation{DeviceID: deviceID, Until: now.Add(d), SetBy: operator, Note: note, SetAt: now}
	// Never hold SQLite's writer lock while waiting on audit-file I/O:
	// a stalled activation must not prevent another operator restricting access.
	if err := appendSecurityRecord(dir, audit.Record{
		TS: now.UTC().Format(time.RFC3339), Event: audit.EventDeviceActivated, DeviceID: deviceID,
		Operator: operator, ActiveUntil: a.Until.UTC().Format(time.RFC3339), Note: note,
	}); err != nil {
		return Activation{}, fmt.Errorf("audit the activation: %w", err)
	}
	tx, err := store.DB().Begin()
	if err != nil {
		return Activation{}, err
	}
	defer func() { _ = tx.Rollback() }()
	var status string
	if err := tx.QueryRow(`SELECT status FROM devices WHERE id = ?`, deviceID).Scan(&status); err != nil {
		return Activation{}, err
	}
	if status == remote.DeviceRevoked {
		return Activation{}, controlplane.ErrDeviceRevoked
	}
	current, _, err := loadActivation(tx, deviceID)
	if err != nil {
		return Activation{}, err
	}
	if current != previous {
		return Activation{}, errors.New("activation changed while its audit was being recorded; retry activation")
	}
	if expired {
		// Keep the old fact with the replacement too. enqueue is idempotent;
		// it retains the first observation and any publication completion.
		if _, err := enqueueActivationEnd(tx, previous, now); err != nil {
			return Activation{}, err
		}
	}
	_, err = tx.Exec(`INSERT INTO device_activations (device_id, active_until, set_by, note, set_at, end_recorded, deactivated_by) VALUES (?, ?, ?, ?, ?, 0, '')
		ON CONFLICT(device_id) DO UPDATE SET active_until = excluded.active_until, set_by = excluded.set_by,
		note = excluded.note, set_at = excluded.set_at, end_recorded = 0, deactivated_by = ''`,
		deviceID, controlplane.FormatTime(a.Until), operator, note, controlplane.FormatTime(now))
	if err != nil {
		return Activation{}, err
	}
	if err := tx.Commit(); err != nil {
		return Activation{}, err
	}
	return a, nil
}

// DeactivateDevice commits the closed window and its pending audit atomically.
// An AuditPendingError leaves it inactive; a retry or serve repairs the event.
func DeactivateDevice(dir string, store *controlplane.Store, deviceID string, operator string, now time.Time) (bool, error) {
	tx, err := store.DB().Begin()
	if err != nil {
		return false, err
	}
	defer func() { _ = tx.Rollback() }()
	var exists string
	if err := tx.QueryRow(`SELECT id FROM devices WHERE id = ?`, deviceID).Scan(&exists); errors.Is(err, sql.ErrNoRows) {
		return false, controlplane.ErrNotFound
	} else if err != nil {
		return false, err
	}
	a, _, err := loadActivation(tx, deviceID)
	if err != nil {
		return false, err
	}
	if !a.Active(now) {
		_ = tx.Rollback()
		if a.DeactivatedBy != "" {
			return false, pendingAudit("the device is inactive", publishSecurityAudit(dir, store, deactivationKey(a, a.Until)))
		}
		return false, nil
	}
	key := deactivationKey(a, now)
	if _, err := tx.Exec(`UPDATE device_activations SET active_until = ?, end_recorded = 1, deactivated_by = ? WHERE device_id = ?`,
		controlplane.FormatTime(now), operator, deviceID); err != nil {
		return false, err
	}
	if _, err := enqueueSecurityAudit(tx, key, audit.Record{
		TS: now.UTC().Format(time.RFC3339), Event: audit.EventDeviceDeactivated, DeviceID: deviceID,
		Operator: operator, ActiveUntil: a.Until.UTC().Format(time.RFC3339),
	}); err != nil {
		return false, err
	}
	if err := tx.Commit(); err != nil {
		return false, err
	}
	return true, pendingAudit("the device is inactive", publishSecurityAudit(dir, store, key))
}

func deactivationKey(a Activation, closedAt time.Time) string {
	return "deactivation/" + a.DeviceID + "/" + controlplane.FormatTime(a.SetAt) + "/" + controlplane.FormatTime(closedAt)
}

// deviceActive only evaluates authoritative state. An audit failure cannot
// turn a definitive inactive result into unknown standing.
func deviceActive(store *controlplane.Store, deviceID string, now time.Time) (Activation, bool, error) {
	a, _, err := loadActivation(store.DB(), deviceID)
	return a, a.Active(now), err
}

// checkActivation durably collects an observed expiry without audit-file I/O
// on the authorization path. Standing uses the read-only check above.
func (s *Server) checkActivation(deviceID string, now time.Time) (Activation, bool, error) {
	a, collected, err := loadActivation(s.Store.DB(), deviceID)
	active := a.Active(now)
	if err == nil && !collected && !active && !a.Until.IsZero() && a.DeactivatedBy == "" {
		if err := collectActivationEnd(s.Store, a, now); err != nil {
			log.Printf("agentssh-gateway: device %s is inactive; collect expiry audit: %v", deviceID, err)
		}
	}
	return a, active, err
}

// RecordEndedActivations durably collects expired windows even without device
// requests, then repairs pending audit events, including replaced windows.
func RecordEndedActivations(dir string, store *controlplane.Store, now time.Time) error {
	rows, err := store.DB().Query(`SELECT device_id FROM device_activations WHERE end_recorded = 0`)
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
	if err != nil || closeErr != nil {
		return errors.Join(err, closeErr)
	}
	var failed error
	for _, id := range ids {
		a, active, err := deviceActive(store, id, now)
		if err == nil && !active && !a.Until.IsZero() && a.DeactivatedBy == "" {
			err = recordActivationEnd(dir, store, a, now)
		}
		if err != nil {
			failed = errors.Join(failed, fmt.Errorf("device %s: %w", id, err))
		}
	}
	return errors.Join(failed, RecordPendingAudits(dir, store))
}

func activationEndKey(a Activation) string {
	return "expiry/" + a.DeviceID + "/" + controlplane.FormatTime(a.SetAt) + "/" + controlplane.FormatTime(a.Until)
}

func enqueueActivationEnd(tx *sql.Tx, a Activation, now time.Time) (audit.Record, error) {
	record, err := enqueueSecurityAudit(tx, activationEndKey(a), audit.Record{
		TS: now.UTC().Format(time.RFC3339), Event: audit.EventDeviceActivationEnded, DeviceID: a.DeviceID,
		Operator: a.SetBy, ActiveUntil: a.Until.UTC().Format(time.RFC3339), Note: a.Note,
	})
	if err != nil {
		return audit.Record{}, err
	}
	// end_recorded now means the fact is durable, not necessarily published.
	// A stale finder must not mark a newer window as collected.
	_, err = tx.Exec(`UPDATE device_activations SET end_recorded = 1 WHERE device_id = ? AND active_until = ? AND set_at = ?`,
		a.DeviceID, controlplane.FormatTime(a.Until), controlplane.FormatTime(a.SetAt))
	return record, err
}

func recordActivationEnd(dir string, store *controlplane.Store, a Activation, now time.Time) error {
	if err := collectActivationEnd(store, a, now); err != nil {
		return err
	}
	return pendingAudit("the activation ended", publishSecurityAudit(dir, store, activationEndKey(a)))
}

func collectActivationEnd(store *controlplane.Store, a Activation, now time.Time) error {
	tx, err := store.DB().Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := enqueueActivationEnd(tx, a, now); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	return nil
}

func activationAudit(dir string) audit.Store {
	return audit.NewStore(filepath.Join(dir, FileAudit))
}

// ActivationStatus is a device's window as /status reports it.
func ActivationStatus(a Activation, now time.Time) *remote.Activation {
	if !a.Active(now) {
		return &remote.Activation{State: remote.ActivationInactive}
	}
	return &remote.Activation{State: remote.ActivationActive, Until: a.Until.UTC().Format(time.RFC3339)}
}

// formatWindow renders a duration without trailing zero units: 24h, 1h30m.
func formatWindow(d time.Duration) string {
	s := d.Round(time.Second).String()
	for _, zero := range []string{"0s", "0m"} {
		if len(s) > len(zero) && s[len(s)-len(zero):] == zero && s[len(s)-len(zero)-1] >= 'a' {
			s = s[:len(s)-len(zero)]
		}
	}
	return s
}

// Remaining renders the time from now to until, to the minute: 45m, 2h,
// 1h30m, or "under 1m".
func Remaining(until, now time.Time) string {
	d := until.Sub(now).Round(time.Minute)
	if d < time.Minute {
		return "under 1m"
	}
	h, m := int(d.Hours()), int(d.Minutes())%60
	switch {
	case h == 0:
		return fmt.Sprintf("%dm", m)
	case m == 0:
		return fmt.Sprintf("%dh", h)
	}
	return fmt.Sprintf("%dh%dm", h, m)
}
