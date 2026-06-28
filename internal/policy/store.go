package policy

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Praeviso/AgentSSH/internal/inventory"
	"gopkg.in/yaml.v3"
)

var (
	ErrRuleExists    = errors.New("policy rule already exists")
	ErrRuleNotFound  = errors.New("policy rule not found")
	ErrRuleAmbiguous = errors.New("policy rule name is ambiguous")
	ErrGroupExists   = errors.New("policy rule group already exists")
	ErrGroupNotFound = errors.New("policy rule group not found")
	ErrHostNotFound  = errors.New("policy host rules host not found")
	ErrNoHostRules   = errors.New("policy host has no rules")
)

// HostRuleSet bundles the policy rules owned by one concrete host. It is stored
// as host_overrides["host:<name>"] so group overrides remain unchanged while
// host-specific overrides can be distinguished reliably.
type HostRuleSet struct {
	Host      string
	Key       string
	Override  HostOverride
	Managed   bool
	Effective bool
}

// Bundle is the pair of config documents used by host rules helpers. Only the
// policy is mutated; inventory is used to validate and report whether a rule set
// currently targets an existing host.
type Bundle struct {
	Policy    Config
	Inventory inventory.Inventory
}

// Load decodes policy.yaml. A missing file is treated as an empty policy.
func Load(path string) (Config, error) {
	var cfg Config
	file, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return cfg, nil
	}
	if err != nil {
		return cfg, err
	}
	defer func() {
		_ = file.Close()
	}()
	if err := yaml.NewDecoder(file).Decode(&cfg); err != nil {
		return cfg, err
	}
	return cfg, nil
}

// Save writes policy.yaml atomically with private file permissions.
func Save(path string, cfg Config) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create policy directory: %w", err)
	}
	if cfg.Version == 0 {
		cfg.Version = 1
	}
	data, err := yaml.Marshal(&cfg)
	if err != nil {
		return fmt.Errorf("marshal policy: %w", err)
	}
	file, err := os.CreateTemp(dir, "policy-*.yaml")
	if err != nil {
		return fmt.Errorf("create temporary policy file: %w", err)
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
		return fmt.Errorf("chmod temporary policy file: %w", err)
	}
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		return fmt.Errorf("write temporary policy file: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close temporary policy file: %w", err)
	}
	if err := os.Rename(tempName, path); err != nil {
		return fmt.Errorf("replace policy file: %w", err)
	}
	cleanup = false
	return nil
}

// AddRule returns a copy of cfg with rule appended.
func AddRule(cfg Config, rule Rule) (Config, error) {
	if rule.Name == "" {
		return cfg, fmt.Errorf("policy rule name is required")
	}
	if _, err := ruleIndex(cfg.Rules, rule.Name); err == nil {
		return cfg, ErrRuleExists
	} else if errors.Is(err, ErrRuleAmbiguous) {
		return cfg, err
	}
	next := copyConfig(cfg)
	if next.Version == 0 {
		next.Version = 1
	}
	next.Rules = append(next.Rules, rule)
	return next, nil
}

// UpdateRule returns a copy of cfg with the named rule replaced.
func UpdateRule(cfg Config, name string, rule Rule) (Config, error) {
	index, err := ruleIndex(cfg.Rules, name)
	if err != nil {
		return cfg, err
	}
	if rule.Name == "" {
		return cfg, fmt.Errorf("policy rule name is required")
	}
	if rule.Name != name {
		if _, err := ruleIndex(cfg.Rules, rule.Name); err == nil {
			return cfg, ErrRuleExists
		} else if errors.Is(err, ErrRuleAmbiguous) {
			return cfg, err
		}
	}
	next := copyConfig(cfg)
	next.Rules[index] = rule
	return next, nil
}

// RemoveRule returns a copy of cfg without the named rule.
func RemoveRule(cfg Config, name string) (Config, error) {
	index, err := ruleIndex(cfg.Rules, name)
	if err != nil {
		return cfg, err
	}
	next := copyConfig(cfg)
	next.Rules = append(next.Rules[:index], next.Rules[index+1:]...)
	return next, nil
}

// HostRulesKey returns the managed policy override/group name for a host.
func HostRulesKey(host string) string {
	return "host:" + strings.TrimSpace(host)
}

// HostRuleSets returns all known host-scoped rule sets. Rule sets produced through
// these helpers are keyed by host:<name>. Effective is false if the host no
// longer exists in inventory.
func HostRuleSets(bundle Bundle) []HostRuleSet {
	names := map[string]struct{}{}
	for host := range bundle.Inventory.Hosts {
		names[host] = struct{}{}
	}
	for group := range bundle.Policy.HostOverrides {
		if host, ok := strings.CutPrefix(group, "host:"); ok && host != "" {
			names[host] = struct{}{}
		}
	}

	sorted := make([]string, 0, len(names))
	for name := range names {
		if _, ok := bundle.Policy.HostOverrides[HostRulesKey(name)]; ok {
			sorted = append(sorted, name)
		}
	}
	sort.Strings(sorted)

	ruleSets := make([]HostRuleSet, 0, len(sorted))
	for _, host := range sorted {
		key := HostRulesKey(host)
		override := bundle.Policy.HostOverrides[key]
		_, hostOK := bundle.Inventory.Hosts[host]
		ruleSets = append(ruleSets, HostRuleSet{
			Host:      host,
			Key:       key,
			Override:  override,
			Managed:   true,
			Effective: hostOK,
		})
	}
	return ruleSets
}

// LookupHostRules returns the host-scoped policy rules for host.
func LookupHostRules(bundle Bundle, host string) (HostRuleSet, bool) {
	host = strings.TrimSpace(host)
	if host == "" {
		return HostRuleSet{}, false
	}
	key := HostRulesKey(host)
	override, ok := bundle.Policy.HostOverrides[key]
	if !ok {
		return HostRuleSet{}, false
	}
	_, hostOK := bundle.Inventory.Hosts[host]
	return HostRuleSet{
		Host:      host,
		Key:       key,
		Override:  override,
		Managed:   true,
		Effective: hostOK,
	}, true
}

// SetHostRules returns a copy of bundle with host-specific policy rules.
func SetHostRules(bundle Bundle, host string, override HostOverride) (Bundle, error) {
	host = strings.TrimSpace(host)
	if host == "" {
		return bundle, fmt.Errorf("policy host name is required")
	}
	if _, ok := bundle.Inventory.Hosts[host]; !ok {
		return bundle, ErrHostNotFound
	}
	next := copyBundle(bundle)
	if next.Policy.Version == 0 {
		next.Policy.Version = 1
	}
	if next.Policy.HostOverrides == nil {
		next.Policy.HostOverrides = map[string]HostOverride{}
	}
	key := HostRulesKey(host)
	override.Rules = append([]Rule(nil), override.Rules...)
	next.Policy.HostOverrides[key] = override
	return next, nil
}

// ClearHostRules removes the host-scoped override and its AgentSSH-managed
// policy key.
func ClearHostRules(bundle Bundle, host string) (Bundle, error) {
	host = strings.TrimSpace(host)
	if host == "" {
		return bundle, fmt.Errorf("policy host name is required")
	}
	key := HostRulesKey(host)
	if _, ok := bundle.Policy.HostOverrides[key]; !ok {
		return bundle, ErrNoHostRules
	}
	next := copyBundle(bundle)
	delete(next.Policy.HostOverrides, key)
	return next, nil
}

// AddHostRule appends a rule to existing host rules, creating them if the host
// exists but does not yet have host-scoped rules.
func AddHostRule(bundle Bundle, host string, rule Rule) (Bundle, error) {
	host = strings.TrimSpace(host)
	if host == "" {
		return bundle, fmt.Errorf("policy host name is required")
	}
	if _, ok := bundle.Inventory.Hosts[host]; !ok {
		return bundle, ErrHostNotFound
	}
	override := HostOverride{}
	if ruleSet, ok := LookupHostRules(bundle, host); ok {
		override = ruleSet.Override
	}
	override.Rules = append(append([]Rule(nil), override.Rules...), rule)
	return SetHostRules(bundle, host, override)
}

// RemoveHostRule removes one host-scoped rule by zero-based index.
func RemoveHostRule(bundle Bundle, host string, index int) (Bundle, error) {
	ruleSet, ok := LookupHostRules(bundle, host)
	if !ok {
		return bundle, ErrNoHostRules
	}
	if index < 0 || index >= len(ruleSet.Override.Rules) {
		return bundle, fmt.Errorf("host rule index %d out of range", index)
	}
	override := ruleSet.Override
	override.Rules = append([]Rule(nil), override.Rules...)
	override.Rules = append(override.Rules[:index], override.Rules[index+1:]...)
	return SetHostRules(bundle, host, override)
}

// CreateGroup returns a copy of bundle with a new empty authoring rule group.
func CreateGroup(bundle Bundle, name string) (Bundle, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return bundle, fmt.Errorf("policy rule group name is required")
	}
	if _, ok := bundle.Policy.RuleGroups[name]; ok {
		return bundle, ErrGroupExists
	}
	next := copyBundle(bundle)
	if next.Policy.Version == 0 {
		next.Policy.Version = 1
	}
	if next.Policy.RuleGroups == nil {
		next.Policy.RuleGroups = map[string]RuleGroup{}
	}
	next.Policy.RuleGroups[name] = RuleGroup{}
	return next, nil
}

// DeleteGroup returns a copy of bundle without the named authoring rule group.
// Stamped host snapshots are intentionally left untouched.
func DeleteGroup(bundle Bundle, name string) (Bundle, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return bundle, fmt.Errorf("policy rule group name is required")
	}
	if _, ok := bundle.Policy.RuleGroups[name]; !ok {
		return bundle, ErrGroupNotFound
	}
	next := copyBundle(bundle)
	delete(next.Policy.RuleGroups, name)
	return next, nil
}

// AddGroupRule appends rule to an existing authoring rule group.
func AddGroupRule(bundle Bundle, group string, rule Rule) (Bundle, error) {
	group = strings.TrimSpace(group)
	current, ok := bundle.Policy.RuleGroups[group]
	if !ok {
		return bundle, ErrGroupNotFound
	}
	next := copyBundle(bundle)
	nextGroup := next.Policy.RuleGroups[group]
	nextGroup.Rules = append(copyRules(current.Rules), rule)
	next.Policy.RuleGroups[group] = nextGroup
	if next.Policy.Version == 0 {
		next.Policy.Version = 1
	}
	return next, nil
}

// UpdateGroupRule replaces one rule in an existing authoring rule group.
func UpdateGroupRule(bundle Bundle, group string, index int, rule Rule) (Bundle, error) {
	group = strings.TrimSpace(group)
	current, ok := bundle.Policy.RuleGroups[group]
	if !ok {
		return bundle, ErrGroupNotFound
	}
	if index < 0 || index >= len(current.Rules) {
		return bundle, fmt.Errorf("rule group %q rule index %d out of range", group, index)
	}
	next := copyBundle(bundle)
	nextGroup := next.Policy.RuleGroups[group]
	nextGroup.Rules[index] = rule
	next.Policy.RuleGroups[group] = nextGroup
	return next, nil
}

// RemoveGroupRule removes one rule from an existing authoring rule group.
func RemoveGroupRule(bundle Bundle, group string, index int) (Bundle, error) {
	group = strings.TrimSpace(group)
	current, ok := bundle.Policy.RuleGroups[group]
	if !ok {
		return bundle, ErrGroupNotFound
	}
	if index < 0 || index >= len(current.Rules) {
		return bundle, fmt.Errorf("rule group %q rule index %d out of range", group, index)
	}
	next := copyBundle(bundle)
	nextGroup := next.Policy.RuleGroups[group]
	nextGroup.Rules = append(nextGroup.Rules[:index], nextGroup.Rules[index+1:]...)
	next.Policy.RuleGroups[group] = nextGroup
	return next, nil
}

// StampGroupOntoHost snapshots every rule from groupName into the concrete
// host:<host> override, stamping provenance on each copy. Later group edits do
// not propagate to the host snapshot.
func StampGroupOntoHost(bundle Bundle, host string, groupName string) (Bundle, error) {
	host = strings.TrimSpace(host)
	groupName = strings.TrimSpace(groupName)
	if host == "" {
		return bundle, fmt.Errorf("policy host name is required")
	}
	if _, ok := bundle.Inventory.Hosts[host]; !ok {
		return bundle, ErrHostNotFound
	}
	group, ok := bundle.Policy.RuleGroups[groupName]
	if !ok {
		return bundle, ErrGroupNotFound
	}
	override := HostOverride{}
	if ruleSet, ok := LookupHostRules(bundle, host); ok {
		override = ruleSet.Override
	}
	override.Rules = copyRules(override.Rules)
	for _, rule := range group.Rules {
		copied := rule
		copied.Group = groupName
		override.Rules = append(override.Rules, copied)
	}
	return SetHostRules(bundle, host, override)
}

// RemoveHostGroup removes all host snapshot rules whose provenance group matches
// groupName. The authoring rule group itself is unchanged.
func RemoveHostGroup(bundle Bundle, host string, groupName string) (Bundle, error) {
	groupName = strings.TrimSpace(groupName)
	// An empty group name would match every ungrouped (manually-added) rule via
	// rule.Group == "", silently deleting host-specific allow/deny rules. Reject it.
	if groupName == "" {
		return bundle, fmt.Errorf("policy group name is required")
	}
	ruleSet, ok := LookupHostRules(bundle, host)
	if !ok {
		return bundle, ErrNoHostRules
	}
	override := HostOverride{Rules: make([]Rule, 0, len(ruleSet.Override.Rules))}
	for _, rule := range ruleSet.Override.Rules {
		if rule.Group == groupName {
			continue
		}
		override.Rules = append(override.Rules, rule)
	}
	return SetHostRules(bundle, host, override)
}

func ruleIndex(rules []Rule, name string) (int, error) {
	found := -1
	for i, rule := range rules {
		if rule.Name != name {
			continue
		}
		if found >= 0 {
			return -1, ErrRuleAmbiguous
		}
		found = i
	}
	if found < 0 {
		return -1, ErrRuleNotFound
	}
	return found, nil
}

func copyBundle(bundle Bundle) Bundle {
	return Bundle{
		Policy:    copyConfig(bundle.Policy),
		Inventory: copyInventory(bundle.Inventory),
	}
}

func copyInventory(inv inventory.Inventory) inventory.Inventory {
	next := inv
	if inv.Hosts != nil {
		next.Hosts = make(map[string]inventory.Host, len(inv.Hosts))
		for key, value := range inv.Hosts {
			value.Tags = append([]string(nil), value.Tags...)
			next.Hosts[key] = value
		}
	}
	if inv.Groups != nil {
		next.Groups = make(map[string]inventory.Group, len(inv.Groups))
		for key, value := range inv.Groups {
			value.Tags = append([]string(nil), value.Tags...)
			next.Groups[key] = value
		}
	}
	return next
}

func copyConfig(cfg Config) Config {
	next := cfg
	next.Rules = copyRules(cfg.Rules)
	next.hostOrder = append([]string(nil), cfg.hostOrder...)
	if cfg.RuleGroups != nil {
		next.RuleGroups = make(map[string]RuleGroup, len(cfg.RuleGroups))
		for key, value := range cfg.RuleGroups {
			value.Rules = copyRules(value.Rules)
			next.RuleGroups[key] = value
		}
	}
	if cfg.HostOverrides != nil {
		next.HostOverrides = make(map[string]HostOverride, len(cfg.HostOverrides))
		for key, value := range cfg.HostOverrides {
			value.Rules = copyRules(value.Rules)
			next.HostOverrides[key] = value
		}
	}
	next.Output.Redact = append([]string(nil), cfg.Output.Redact...)
	return next
}

func copyRules(rules []Rule) []Rule {
	return append([]Rule(nil), rules...)
}
