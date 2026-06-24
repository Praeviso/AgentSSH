package inventory

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

var (
	// ErrHostExists reports an attempted duplicate inventory host insertion.
	ErrHostExists = errors.New("inventory host already exists")
	// ErrHostNotFound reports an attempted removal of a missing inventory host.
	ErrHostNotFound = errors.New("inventory host not found")
)

// Load decodes inventory.yaml. A missing file is treated as an empty inventory.
func Load(path string) (Inventory, error) {
	var inv Inventory
	file, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return inv, nil
	}
	if err != nil {
		return inv, err
	}
	defer func() {
		_ = file.Close()
	}()
	if err := yaml.NewDecoder(file).Decode(&inv); err != nil {
		return inv, err
	}
	return inv, nil
}

// Save writes inventory.yaml atomically with private file permissions.
func Save(path string, inv Inventory) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create inventory directory: %w", err)
	}
	data, err := yaml.Marshal(&inv)
	if err != nil {
		return fmt.Errorf("marshal inventory: %w", err)
	}
	file, err := os.CreateTemp(dir, "inventory-*.yaml")
	if err != nil {
		return fmt.Errorf("create temporary inventory file: %w", err)
	}
	tempName := file.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tempName)
		}
	}()
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		return fmt.Errorf("chmod temporary inventory file: %w", err)
	}
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		return fmt.Errorf("write temporary inventory file: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close temporary inventory file: %w", err)
	}
	if err := os.Rename(tempName, path); err != nil {
		return fmt.Errorf("replace inventory file: %w", err)
	}
	cleanup = false
	return nil
}

// AddHost returns a copy of inv with name inserted, initializing MVP defaults.
func AddHost(inv Inventory, name string, host Host) (Inventory, error) {
	next := inv
	next.Hosts = copyHosts(inv.Hosts)
	next.Groups = copyGroups(inv.Groups)
	if next.Hosts == nil {
		next.Hosts = map[string]Host{}
	}
	if next.Version == 0 {
		next.Version = 1
	}
	if _, ok := next.Hosts[name]; ok {
		return inv, ErrHostExists
	}
	next.Hosts[name] = host
	return next, nil
}

// RemoveHost returns a copy of inv without name.
func RemoveHost(inv Inventory, name string) (Inventory, error) {
	if _, ok := inv.Hosts[name]; !ok {
		return inv, ErrHostNotFound
	}
	next := inv
	next.Hosts = copyHosts(inv.Hosts)
	next.Groups = copyGroups(inv.Groups)
	delete(next.Hosts, name)
	return next, nil
}

// SetHostOS returns a copy of inv with the host OS metadata replaced.
func SetHostOS(inv Inventory, name string, osName string) (Inventory, error) {
	host, ok := inv.Hosts[name]
	if !ok {
		return inv, ErrHostNotFound
	}
	if host.OS == osName {
		return inv, nil
	}
	next := inv
	next.Hosts = copyHosts(inv.Hosts)
	host.OS = osName
	next.Hosts[name] = host
	return next, nil
}

// HostNames returns the inventory host names as a set.
func HostNames(inv Inventory) map[string]struct{} {
	names := make(map[string]struct{}, len(inv.Hosts))
	for name := range inv.Hosts {
		names[name] = struct{}{}
	}
	return names
}

func copyHosts(hosts map[string]Host) map[string]Host {
	if hosts == nil {
		return nil
	}
	copied := make(map[string]Host, len(hosts))
	for name, host := range hosts {
		copied[name] = host
	}
	return copied
}

func copyGroups(groups map[string]Group) map[string]Group {
	if groups == nil {
		return nil
	}
	copied := make(map[string]Group, len(groups))
	for name, group := range groups {
		copied[name] = group
	}
	return copied
}
