package controlplane

import (
	"errors"
	"fmt"
	"time"

	"github.com/Praeviso/AgentSSH/internal/remote"
)

// PushConfig validates and stores a device's inventory and policy. Every host
// must be a direct addr/user/identity target with a known identity, because
// the control plane's identities authenticate to it in both modes.
func PushConfig(store *Store, deviceID string, inventoryYAML string, policyYAML string, now time.Time) (int64, error) {
	return pushConfig(store, deviceID, -1, inventoryYAML, policyYAML, now)
}

// ReplaceConfig is PushConfig for a configuration derived from version from:
// it fails with ErrConfigChanged if another push came first.
func ReplaceConfig(store *Store, deviceID string, from int64, inventoryYAML string, policyYAML string, now time.Time) (int64, error) {
	return pushConfig(store, deviceID, from, inventoryYAML, policyYAML, now)
}

func pushConfig(store *Store, deviceID string, from int64, inventoryYAML string, policyYAML string, now time.Time) (int64, error) {
	if _, err := store.Device(deviceID); err != nil {
		if errors.Is(err, ErrNotFound) {
			return 0, fmt.Errorf("unknown device %q", deviceID)
		}
		return 0, err
	}
	identityExists := func(name string) bool {
		_, err := store.Identity(name)
		return err == nil
	}
	if _, _, err := remote.ParseManaged(inventoryYAML, policyYAML, identityExists); err != nil {
		return 0, err
	}
	return store.putConfig(deviceID, from, inventoryYAML, policyYAML, now)
}
