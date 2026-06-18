package inventory

import (
	"errors"
	"fmt"
	"sort"
	"strings"
)

// Inventory is the parsed inventory.yaml document.
type Inventory struct {
	Version       int              `yaml:"version,omitempty" json:"version"`
	Transport     string           `yaml:"transport,omitempty" json:"transport"`
	HostKeyPolicy string           `yaml:"host_key_policy,omitempty" json:"host_key_policy"`
	Hosts         map[string]Host  `yaml:"hosts,omitempty" json:"hosts"`
	Groups        map[string]Group `yaml:"groups,omitempty" json:"groups"`
}

// Host describes a named SSH target without storing private keys or passwords.
type Host struct {
	Addr           string   `yaml:"addr,omitempty" json:"addr"`
	User           string   `yaml:"user,omitempty" json:"user"`
	Port           int      `yaml:"port,omitempty" json:"port"`
	SSHConfigAlias string   `yaml:"ssh_config_alias,omitempty" json:"ssh_config_alias"`
	IdentityFile   string   `yaml:"identity_file,omitempty" json:"identity_file"`
	Tags           []string `yaml:"tags,omitempty" json:"tags"`
}

// Group selects hosts by tag.
type Group struct {
	Tags []string `yaml:"tags,omitempty" json:"tags"`
}

// Target is a resolved host ready for execution.
type Target struct {
	Name string
	Host Host
}

// TargetKind records whether a CLI target name matched a host or a group.
type TargetKind string

const (
	TargetKindHost  TargetKind = "host"
	TargetKindGroup TargetKind = "group"
)

// ResolvedTarget is the result of resolving one CLI target name.
type ResolvedTarget struct {
	Kind    TargetKind
	Targets []Target
}

// PublicHost is the credential-free host shape returned by hosts.
type PublicHost struct {
	Name string   `json:"name"`
	Tags []string `json:"tags,omitempty"`
}

// PublicGroup is the credential-free group shape returned by hosts.
type PublicGroup struct {
	Name string   `json:"name"`
	Tags []string `json:"tags,omitempty"`
}

// PublicInventory is safe to show to agents.
type PublicInventory struct {
	Hosts  []PublicHost  `json:"hosts"`
	Groups []PublicGroup `json:"groups"`
}

// UnknownTargetError reports a name that is neither a host nor a group.
type UnknownTargetError struct {
	Name       string
	Known      []string
	HostNames  []string
	GroupNames []string
}

func (e UnknownTargetError) Error() string {
	if len(e.Known) == 0 {
		return fmt.Sprintf("unknown host or group %q; inventory is empty", e.Name)
	}
	return fmt.Sprintf("unknown host or group %q; available: %s", e.Name, strings.Join(e.Known, ", "))
}

// EmptyGroupError reports a known group that matches no hosts.
type EmptyGroupError struct {
	Name string
}

func (e EmptyGroupError) Error() string {
	return fmt.Sprintf("group %q matches no hosts", e.Name)
}

// Resolver resolves host or group names into concrete SSH targets.
type Resolver interface {
	Resolve(name string) (ResolvedTarget, error)
	Public() PublicInventory
}

// NewResolver builds a resolver over a parsed inventory document.
func NewResolver(inv Inventory) Resolver {
	return staticResolver{inventory: inv}
}

type staticResolver struct {
	inventory Inventory
}

func (r staticResolver) Resolve(name string) (ResolvedTarget, error) {
	if host, ok := r.inventory.Hosts[name]; ok {
		return ResolvedTarget{
			Kind:    TargetKindHost,
			Targets: []Target{{Name: name, Host: normalizeHost(host)}},
		}, nil
	}

	group, ok := r.inventory.Groups[name]
	if !ok {
		hosts, groups := names(r.inventory)
		return ResolvedTarget{}, UnknownTargetError{
			Name:       name,
			Known:      append(append([]string{}, hosts...), groups...),
			HostNames:  hosts,
			GroupNames: groups,
		}
	}

	var targets []Target
	for _, hostName := range sortedHostNames(r.inventory.Hosts) {
		host := r.inventory.Hosts[hostName]
		if matchesTags(host.Tags, group.Tags) {
			targets = append(targets, Target{Name: hostName, Host: normalizeHost(host)})
		}
	}
	if len(targets) == 0 {
		return ResolvedTarget{}, EmptyGroupError{Name: name}
	}
	return ResolvedTarget{
		Kind:    TargetKindGroup,
		Targets: targets,
	}, nil
}

func (r staticResolver) Public() PublicInventory {
	public := PublicInventory{
		Hosts:  make([]PublicHost, 0, len(r.inventory.Hosts)),
		Groups: make([]PublicGroup, 0, len(r.inventory.Groups)),
	}

	for _, hostName := range sortedHostNames(r.inventory.Hosts) {
		host := r.inventory.Hosts[hostName]
		public.Hosts = append(public.Hosts, PublicHost{
			Name: hostName,
			Tags: sortedStrings(host.Tags),
		})
	}

	for _, groupName := range sortedGroupNames(r.inventory.Groups) {
		group := r.inventory.Groups[groupName]
		publicGroup := PublicGroup{
			Name: groupName,
			Tags: sortedStrings(group.Tags),
		}
		public.Groups = append(public.Groups, publicGroup)
	}

	return public
}

// IsUnknown reports whether err is an unknown target error.
func IsUnknown(err error) bool {
	var target UnknownTargetError
	return errors.As(err, &target)
}

func normalizeHost(host Host) Host {
	if host.Port == 0 {
		host.Port = 22
	}
	host.Tags = sortedStrings(host.Tags)
	return host
}

func matchesTags(hostTags []string, groupTags []string) bool {
	if len(groupTags) == 0 {
		return false
	}

	set := make(map[string]struct{}, len(hostTags))
	for _, tag := range hostTags {
		set[tag] = struct{}{}
	}
	for _, tag := range groupTags {
		if _, ok := set[tag]; !ok {
			return false
		}
	}
	return true
}

func names(inv Inventory) ([]string, []string) {
	return sortedHostNames(inv.Hosts), sortedGroupNames(inv.Groups)
}

func sortedHostNames(hosts map[string]Host) []string {
	result := make([]string, 0, len(hosts))
	for name := range hosts {
		result = append(result, name)
	}
	sort.Strings(result)
	return result
}

func sortedGroupNames(groups map[string]Group) []string {
	result := make([]string, 0, len(groups))
	for name := range groups {
		result = append(result, name)
	}
	sort.Strings(result)
	return result
}

func sortedStrings(values []string) []string {
	result := append([]string{}, values...)
	sort.Strings(result)
	return result
}
