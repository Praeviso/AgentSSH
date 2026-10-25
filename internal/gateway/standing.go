package gateway

import (
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/Praeviso/AgentSSH/internal/controlplane"
	"github.com/Praeviso/AgentSSH/internal/remote"
)

// StandingCheckEvery is how often serve records ended activation windows and
// stops runs whose device lost its standing, so a run stops within this
// interval of the change.
const StandingCheckEvery = 30 * time.Second

// CancelRunsWithoutStanding stops every live run whose device may no longer
// act, as /exec/cancel would (SIGTERM, then the connection closes): its
// device was revoked or deactivated, its activation window ended, or an
// identity it connects with was disabled. The reason goes into the run's
// record and its audit record. Standing is read from the store, which other
// processes (the CLI) change. Only a definitive answer stops a run: a store
// error is returned and leaves the run alone.
func (s *Server) CancelRunsWithoutStanding() error {
	now := s.now()
	s.mu.Lock()
	live := make([]*run, 0, len(s.runs))
	for _, rn := range s.runs {
		live = append(live, rn)
	}
	s.mu.Unlock()
	devices := map[string]lostStanding{}
	identities := map[string]bool{}
	var failed error
	for _, rn := range live {
		lost, known := devices[rn.deviceID]
		if !known {
			var err error
			if lost, err = s.deviceStanding(rn.deviceID, now); err != nil {
				failed = errors.Join(failed, fmt.Errorf("device %s: %w", rn.deviceID, err))
				continue
			}
			devices[rn.deviceID] = lost
		}
		for _, name := range rn.identities {
			if lost.reason != "" {
				break
			}
			disabled, known := identities[name]
			if !known {
				id, err := s.Store.Identity(name)
				if err != nil && !errors.Is(err, controlplane.ErrNotFound) {
					failed = errors.Join(failed, fmt.Errorf("identity %s: %w", name, err))
					continue
				}
				disabled = errors.Is(err, controlplane.ErrNotFound) || id.Status == controlplane.IdentityDisabled
				identities[name] = disabled
			}
			if disabled {
				lost = lostStanding{code: remote.CodeIdentityDisabled, reason: "identity " + name + " was disabled"}
			}
		}
		if lost.reason != "" && rn.stop(lost) {
			log.Printf("agentssh-gateway: device %s: run %s stopped: %s", rn.deviceID, rn.id, lost.reason)
		}
	}
	return failed
}

// lostStanding is why a run's device may no longer act: the refusal code the
// device gets and the reason recorded. The zero value means it may act.
type lostStanding struct {
	code, reason string
}

// deviceStanding says why deviceID may no longer act.
func (s *Server) deviceStanding(deviceID string, now time.Time) (lostStanding, error) {
	device, err := s.Store.Device(deviceID)
	if errors.Is(err, controlplane.ErrNotFound) {
		return lostStanding{remote.CodeDeviceRevoked, "the device no longer exists"}, nil
	}
	if err != nil {
		return lostStanding{}, err
	}
	if device.Status == remote.DeviceRevoked {
		return lostStanding{remote.CodeDeviceRevoked, "the device was revoked"}, nil
	}
	a, active, err := deviceActive(s.Dir, s.Store, deviceID, now)
	switch {
	case err != nil:
		return lostStanding{}, err
	case active:
		return lostStanding{}, nil
	case a.DeactivatedBy != "":
		return lostStanding{remote.CodeDeviceInactive, "the device was deactivated"}, nil
	}
	return lostStanding{remote.CodeDeviceInactive, "the device's activation ended"}, nil
}

// stop cancels a live run because its device lost standing, recording why
// first. It reports whether the run was still running.
func (r *run) stop(lost lostStanding) bool {
	r.mu.Lock()
	if r.done || r.cancel == nil {
		r.mu.Unlock()
		return false
	}
	if r.stopped.reason == "" {
		r.stopped = lost
		r.record.CancelReason = lost.reason
	}
	cancel := r.cancel
	r.mu.Unlock()
	cancel(errors.New(lost.reason))
	return true
}

// stoppedFor is why the gateway stopped the run, or the zero value.
func (r *run) stoppedFor() lostStanding {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.stopped
}
