package tui

import (
	"fmt"

	"github.com/Praeviso/AgentSSH/internal/config"
	"github.com/Praeviso/AgentSSH/internal/executor"
	"github.com/Praeviso/AgentSSH/internal/inventory"
	"github.com/Praeviso/AgentSSH/internal/managedmode"
	"github.com/Praeviso/AgentSSH/internal/policy"
)

// remoteManaged reports whether paths belongs to a home enrolled with a
// remote control plane.
func remoteManaged(paths config.Paths) bool {
	return paths.Home != "" && managedmode.Enrolled(paths.Home)
}

// loadRemote returns the effective control-plane inventory and policy (with
// the local deny overlay) for an enrolled home.
func loadRemote(paths config.Paths) (*config.Config, error) {
	return config.LoadHome(paths.Home)
}

// loadEffective returns what commands actually run against: the control-plane
// bundle in remote mode, the local YAML files otherwise.
func loadEffective(paths config.Paths) (inventory.Inventory, policy.Config, error) {
	if remoteManaged(paths) {
		cfg, err := loadRemote(paths)
		if err != nil {
			return inventory.Inventory{}, policy.Config{}, err
		}
		return cfg.Inventory, cfg.Policy, nil
	}
	inv, err := inventory.Load(paths.InventoryFile)
	if err != nil {
		return inventory.Inventory{}, policy.Config{}, err
	}
	pol, err := policy.Load(paths.PolicyFile)
	return inv, pol, err
}

// applyRemoteProbe switches probe options to remote signing in remote mode.
func applyRemoteProbe(paths config.Paths, options *executor.NativeOptions) error {
	if !remoteManaged(paths) {
		return nil
	}
	cfg, err := loadRemote(paths)
	if err != nil {
		return err
	}
	cfg.Remote.ApplyNativeOptions(options)
	return nil
}

// remoteBadge is the status-bar marker for a remote-managed home.
func remoteBadge(cfg *config.Config) string {
	if cfg == nil || cfg.Remote == nil {
		return ""
	}
	badge := fmt.Sprintf("managed v%d", cfg.Remote.Bundle.Version)
	if cfg.Remote.Stale {
		badge += " (offline)"
	}
	return badge
}
