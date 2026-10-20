package remote

import (
	"fmt"
	"sort"
	"strings"

	"github.com/Praeviso/AgentSSH/internal/inventory"
	"github.com/Praeviso/AgentSSH/internal/policy"
	"gopkg.in/yaml.v3"
)

// ParseManaged decodes control-plane inventory and policy YAML and enforces the
// remote-mode rules. identityExists reports whether a named identity is known.
func ParseManaged(inventoryYAML string, policyYAML string, identityExists func(string) bool) (inventory.Inventory, policy.Config, error) {
	var inv inventory.Inventory
	if err := yaml.Unmarshal([]byte(inventoryYAML), &inv); err != nil {
		return inventory.Inventory{}, policy.Config{}, fmt.Errorf("parse managed inventory: %w", err)
	}
	var pol policy.Config
	if err := yaml.Unmarshal([]byte(policyYAML), &pol); err != nil {
		return inventory.Inventory{}, policy.Config{}, fmt.Errorf("parse managed policy: %w", err)
	}
	if err := ValidateManagedInventory(inv, identityExists); err != nil {
		return inventory.Inventory{}, policy.Config{}, err
	}
	if _, err := policy.NewEngine(pol, inv); err != nil {
		return inventory.Inventory{}, policy.Config{}, fmt.Errorf("managed policy: %w", err)
	}
	return inv, pol, nil
}

// ValidateManagedInventory enforces what remote signing needs: every host is a
// direct addr/user/identity target. ssh_config aliases and local identity files
// are rejected because they would route or authenticate outside the control
// plane's view.
func ValidateManagedInventory(inv inventory.Inventory, identityExists func(string) bool) error {
	switch strings.TrimSpace(inv.Transport) {
	case "", "native":
	default:
		return fmt.Errorf("managed inventory transport must be native, got %q", inv.Transport)
	}
	names := make([]string, 0, len(inv.Hosts))
	for name := range inv.Hosts {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		host := inv.Hosts[name]
		switch {
		case strings.TrimSpace(host.SSHConfigAlias) != "":
			return fmt.Errorf("managed host %q must not use ssh_config_alias", name)
		case strings.TrimSpace(host.IdentityFile) != "":
			return fmt.Errorf("managed host %q must not use identity_file", name)
		case strings.TrimSpace(host.Addr) == "":
			return fmt.Errorf("managed host %q has no addr", name)
		case strings.TrimSpace(host.User) == "":
			return fmt.Errorf("managed host %q has no user", name)
		case strings.TrimSpace(host.Identity) == "":
			return fmt.Errorf("managed host %q has no identity", name)
		}
		if identityExists != nil && !identityExists(host.Identity) {
			return fmt.Errorf("managed host %q uses unknown identity %q", name, host.Identity)
		}
	}
	return nil
}
