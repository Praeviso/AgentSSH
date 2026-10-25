package gateway

import (
	"database/sql"
	"errors"
	"fmt"
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
	end_recorded INTEGER NOT NULL DEFAULT 0
);
`

// MaxActivation is the longest window one activation opens. The store
// enforces it, so every way of activating shares one rule.
const MaxActivation = 24 * time.Hour

// ErrActivationDuration refuses a window that is not positive or longer than
// MaxActivation.
var ErrActivationDuration = fmt.Errorf("the activation must last more than zero and at most %s", formatWindow(MaxActivation))

// Activation is a device's current window. Until is zero when the device has
// never been activated.
type Activation struct {
	DeviceID string
	Until    time.Time
	SetBy    string
	Note     string
	SetAt    time.Time
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

func loadActivation(db *sql.DB, deviceID string) (Activation, bool, error) {
	a := Activation{DeviceID: deviceID}
	var until, setAt string
	var recorded bool
	err := db.QueryRow(`SELECT active_until, set_by, note, set_at, end_recorded FROM device_activations WHERE device_id = ?`, deviceID).
		Scan(&until, &a.SetBy, &a.Note, &setAt, &recorded)
	if errors.Is(err, sql.ErrNoRows) {
		return a, true, nil
	}
	if err != nil {
		return Activation{}, false, err
	}
	a.Until, a.SetAt = controlplane.ParseTime(until), controlplane.ParseTime(setAt)
	return a, recorded, nil
}

// ActivateDevice opens a window of length d from now, replacing any current
// one. The audit record is written first: if the window cannot be stored
// afterwards, the device stays inactive.
func ActivateDevice(dir string, store *controlplane.Store, deviceID string, d time.Duration, operator, note string, now time.Time) (Activation, error) {
	if d <= 0 || d > MaxActivation {
		return Activation{}, ErrActivationDuration
	}
	device, err := store.Device(deviceID)
	if err != nil {
		return Activation{}, err
	}
	if device.Status == remote.DeviceRevoked {
		return Activation{}, controlplane.ErrDeviceRevoked
	}
	a := Activation{DeviceID: deviceID, Until: now.Add(d), SetBy: operator, Note: note, SetAt: now}
	if _, err := activationAudit(dir).Append(audit.Record{
		TS: now.UTC().Format(time.RFC3339), Event: audit.EventDeviceActivated, DeviceID: deviceID,
		Operator: operator, ActiveUntil: a.Until.UTC().Format(time.RFC3339), Note: note,
	}); err != nil {
		return Activation{}, fmt.Errorf("audit the activation: %w", err)
	}
	_, err = store.DB().Exec(`INSERT INTO device_activations (device_id, active_until, set_by, note, set_at, end_recorded) VALUES (?, ?, ?, ?, ?, 0)
		ON CONFLICT(device_id) DO UPDATE SET active_until = excluded.active_until, set_by = excluded.set_by,
		note = excluded.note, set_at = excluded.set_at, end_recorded = 0`,
		deviceID, controlplane.FormatTime(a.Until), operator, note, controlplane.FormatTime(now))
	if err != nil {
		return Activation{}, err
	}
	return a, nil
}

// DeactivateDevice closes a device's window at once; it can be activated
// again. It reports whether a window was open. The window is closed before
// the audit record is written, so a failed audit never leaves it open.
func DeactivateDevice(dir string, store *controlplane.Store, deviceID string, operator string, now time.Time) (bool, error) {
	if _, err := store.Device(deviceID); err != nil {
		return false, err
	}
	a, _, err := loadActivation(store.DB(), deviceID)
	if err != nil || !a.Active(now) {
		return false, err
	}
	// Only the window read above is closed; a newer activation in between
	// stays open.
	res, err := store.DB().Exec(`UPDATE device_activations SET active_until = ?, end_recorded = 1 WHERE device_id = ? AND active_until = ?`,
		controlplane.FormatTime(now), deviceID, controlplane.FormatTime(a.Until))
	if err != nil {
		return false, err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return false, nil
	}
	if _, err := activationAudit(dir).Append(audit.Record{
		TS: now.UTC().Format(time.RFC3339), Event: audit.EventDeviceDeactivated, DeviceID: deviceID, Operator: operator,
	}); err != nil {
		return true, fmt.Errorf("the device is inactive, but its audit record failed: %w", err)
	}
	return true, nil
}

// deviceActive reports whether deviceID may use the gateway at now. A window
// found ended for the first time is recorded in the audit chain once.
func deviceActive(dir string, store *controlplane.Store, deviceID string, now time.Time) (Activation, bool, error) {
	a, recorded, err := loadActivation(store.DB(), deviceID)
	if err != nil {
		return Activation{}, false, err
	}
	if a.Active(now) {
		return a, true, nil
	}
	if !a.Until.IsZero() && !recorded {
		if err := recordActivationEnd(dir, store, a, now); err != nil {
			return Activation{}, false, err
		}
	}
	return a, false, nil
}

// RecordEndedActivations records every window that has ended without a record
// yet. serve runs it periodically, so an ended window is recorded even when
// the device sends nothing more.
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
	if err := rows.Close(); err != nil {
		return err
	}
	for _, id := range ids {
		if _, _, err := deviceActive(dir, store, id, now); err != nil {
			return err
		}
	}
	return nil
}

// recordActivationEnd appends the end of window a, found at now, claiming it
// first so that concurrent requests record it once. The record's time is when
// it was found; active_until says when the window ended.
func recordActivationEnd(dir string, store *controlplane.Store, a Activation, now time.Time) error {
	res, err := store.DB().Exec(`UPDATE device_activations SET end_recorded = 1 WHERE device_id = ? AND active_until = ? AND end_recorded = 0`,
		a.DeviceID, controlplane.FormatTime(a.Until))
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return nil
	}
	_, err = activationAudit(dir).Append(audit.Record{
		TS: now.UTC().Format(time.RFC3339), Event: audit.EventDeviceActivationEnded, DeviceID: a.DeviceID,
		Operator: a.SetBy, ActiveUntil: a.Until.UTC().Format(time.RFC3339), Note: a.Note,
	})
	return err
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
