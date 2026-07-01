package policy

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/Praeviso/AgentSSH/internal/inventory"
	"gopkg.in/yaml.v3"
)

// Action is the binary policy action used by AgentSSH.
type Action string

const (
	ActionAllow Action = "allow"
	ActionDeny  Action = "deny"
)

const (
	// RuleDefaultDeny is the immutable fallback rule name returned when no rule
	// matches. Approval code uses this symbol to distinguish gray-area commands
	// from explicit deny rules.
	RuleDefaultDeny = "default-deny"
	// ApprovalGroup is the reserved provenance marker for generated approval
	// host rules. It is not a user-authorable rule group name.
	ApprovalGroup = "__agentssh_approval"
)

// Decision is the result of evaluating a command against policy.
type Decision struct {
	Action Action `json:"action"`
	Rule   string `json:"rule,omitempty"`
}

// EffectiveRule is a display/editing projection of rules in the same tier order
// the engine uses: host tier first, then global tier. Index is the file-order
// index inside Source.
type EffectiveRule struct {
	Scope  string
	Source string
	Index  int
	Rule   Rule
}

// Config is the parsed policy.yaml document.
type Config struct {
	Version       int                     `yaml:"version" json:"version"`
	Rules         []Rule                  `yaml:"rules" json:"rules"`
	RuleGroups    map[string]RuleGroup    `yaml:"rule_groups" json:"rule_groups"`
	HostOverrides map[string]HostOverride `yaml:"host_overrides" json:"host_overrides"`
	Output        Output                  `yaml:"output" json:"output"`
	Approval      Approval                `yaml:"approval,omitempty" json:"approval,omitempty"`
	hostOrder     []string
}

// Approval is the optional async approval policy block. Durations are stored as
// strings so policy.yaml stays operator-readable ("12h", "10m"); the approval
// package parses and defaults them at runtime.
type Approval struct {
	Enabled       bool   `yaml:"enabled,omitempty" json:"enabled,omitempty"`
	HostGrantMode string `yaml:"host_grant_mode,omitempty" json:"host_grant_mode,omitempty"`
	SessionTTL    string `yaml:"session_ttl,omitempty" json:"session_ttl,omitempty"`
	WaitTimeout   string `yaml:"wait_timeout,omitempty" json:"wait_timeout,omitempty"`
}

// RuleGroup is an authoring-only preset. The engine ignores it; callers stamp a
// snapshot copy onto a concrete host override when they want it to take effect.
type RuleGroup struct {
	Rules []Rule `yaml:"rules" json:"rules"`
}

// Rule is a named first-match policy rule.
type Rule struct {
	Name     string `yaml:"name,omitempty" json:"name,omitempty"`
	Priority int    `yaml:"priority,omitempty" json:"priority,omitempty"`
	Match    Match  `yaml:"match" json:"match"`
	Action   Action `yaml:"action" json:"action"`
	Group    string `yaml:"group,omitempty" json:"group,omitempty"`
}

// Match contains command matching criteria.
type Match struct {
	CmdRegex string `yaml:"cmd_regex" json:"cmd_regex"`
}

// HostOverride contains host- or group-scoped rules.
type HostOverride struct {
	Rules []Rule `yaml:"rules" json:"rules"`
}

// Output contains output filtering policy.
type Output struct {
	MaxBytes int      `yaml:"max_bytes" json:"max_bytes"`
	Redact   []string `yaml:"redact" json:"redact"`
}

// Engine evaluates commands against policy.
type Engine interface {
	Evaluate(host string, command string) (Decision, error)
}

// NewEngine compiles a policy config against an inventory.
func NewEngine(config Config, inv inventory.Inventory) (Engine, error) {
	compiled := &compiledEngine{
		config:    config.withMaps(),
		inventory: inv,
		hostRules: map[string][]compiledRule{},
	}
	for i, rule := range compiled.config.Rules {
		expr, err := compileRegex(rule.Match.CmdRegex, fmt.Sprintf("rules[%d]", i))
		if err != nil {
			return nil, err
		}
		action, err := validateAction(rule.Action, fmt.Sprintf("rules[%d]", i))
		if err != nil {
			return nil, err
		}
		source := fmt.Sprintf("rules[%d]", i)
		if rule.Name != "" {
			source = "rules:" + rule.Name
		}
		compiled.globalRules = append(compiled.globalRules, compiledRule{
			source:   source,
			priority: rule.Priority,
			action:   action,
			regex:    expr,
		})
	}
	sortRules(compiled.globalRules)

	for groupName, override := range compiled.config.HostOverrides {
		for i, rule := range override.Rules {
			source := fmt.Sprintf("%s/rules[%d]", groupName, i)
			expr, err := compileRegex(rule.Match.CmdRegex, source)
			if err != nil {
				return nil, err
			}
			action, err := validateAction(rule.Action, source)
			if err != nil {
				return nil, err
			}
			compiled.hostRules[groupName] = append(compiled.hostRules[groupName], compiledRule{
				source:   source,
				priority: rule.Priority,
				action:   action,
				regex:    expr,
			})
		}
	}
	return compiled, nil
}

func (c Config) withMaps() Config {
	if c.RuleGroups == nil {
		c.RuleGroups = map[string]RuleGroup{}
	}
	if c.HostOverrides == nil {
		c.HostOverrides = map[string]HostOverride{}
	}
	return c
}

// UnmarshalYAML decodes policy.yaml while preserving the file order of
// host_overrides. That order is only a tie-breaker before priority sorting; rule
// groups remain authoring-only and are not part of engine evaluation.
func (c *Config) UnmarshalYAML(value *yaml.Node) error {
	if err := rejectLegacySchemaKeys(value); err != nil {
		return err
	}
	type configYAML struct {
		Version       int                     `yaml:"version"`
		Rules         []Rule                  `yaml:"rules"`
		RuleGroups    map[string]RuleGroup    `yaml:"rule_groups"`
		HostOverrides map[string]HostOverride `yaml:"host_overrides"`
		Output        Output                  `yaml:"output"`
		Approval      Approval                `yaml:"approval"`
	}
	var raw configYAML
	if err := value.Decode(&raw); err != nil {
		return err
	}
	*c = Config{
		Version:       raw.Version,
		Rules:         raw.Rules,
		RuleGroups:    raw.RuleGroups,
		HostOverrides: raw.HostOverrides,
		Output:        raw.Output,
		Approval:      raw.Approval,
		hostOrder:     hostOverrideOrder(value),
	}
	return nil
}

func (c Config) MarshalYAML() (any, error) {
	c = c.withMaps()
	root := &yaml.Node{Kind: yaml.MappingNode}
	appendNode(root, "version", scalarNode(c.Version))
	appendNode(root, "rules", mustYAMLNode(c.Rules))
	appendNode(root, "rule_groups", mustYAMLNode(c.RuleGroups))
	appendNode(root, "host_overrides", c.hostOverridesNode())
	appendNode(root, "output", mustYAMLNode(c.Output))
	if !approvalZero(c.Approval) {
		appendNode(root, "approval", mustYAMLNode(c.Approval))
	}
	return root, nil
}

func approvalZero(value Approval) bool {
	return !value.Enabled && value.HostGrantMode == "" && value.SessionTTL == "" && value.WaitTimeout == ""
}

func appendNode(mapping *yaml.Node, key string, value *yaml.Node) {
	mapping.Content = append(mapping.Content, scalarNode(key), value)
}

func scalarNode(value any) *yaml.Node {
	var node yaml.Node
	if err := node.Encode(value); err != nil {
		panic(err)
	}
	return &node
}

func mustYAMLNode(value any) *yaml.Node {
	var node yaml.Node
	if err := node.Encode(value); err != nil {
		panic(err)
	}
	return &node
}

func (c Config) hostOverridesNode() *yaml.Node {
	node := &yaml.Node{Kind: yaml.MappingNode}
	seen := map[string]struct{}{}
	for _, key := range c.hostOrder {
		override, ok := c.HostOverrides[key]
		if !ok {
			continue
		}
		if _, ok := seen[key]; ok {
			continue
		}
		appendNode(node, key, mustYAMLNode(override))
		seen[key] = struct{}{}
	}
	var missing []string
	for key := range c.HostOverrides {
		if _, ok := seen[key]; !ok {
			missing = append(missing, key)
		}
	}
	sort.Strings(missing)
	for _, key := range missing {
		appendNode(node, key, mustYAMLNode(c.HostOverrides[key]))
	}
	return node
}

func rejectLegacySchemaKeys(value *yaml.Node) error {
	if value == nil || value.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(value.Content); i += 2 {
		key := value.Content[i].Value
		if key == "defaults" || key == "policy" || key == "allow_rules" {
			return legacySchemaError(key, key)
		}
		if key != "host_overrides" {
			continue
		}
		overrides := value.Content[i+1]
		if overrides == nil || overrides.Kind != yaml.MappingNode {
			continue
		}
		for j := 0; j+1 < len(overrides.Content); j += 2 {
			overrideName := overrides.Content[j].Value
			override := overrides.Content[j+1]
			if override == nil || override.Kind != yaml.MappingNode {
				continue
			}
			for k := 0; k+1 < len(override.Content); k += 2 {
				overrideKey := override.Content[k].Value
				if overrideKey == "policy" || overrideKey == "allow_rules" {
					return legacySchemaError(overrideKey, fmt.Sprintf("host_overrides.%s.%s", overrideName, overrideKey))
				}
			}
		}
	}
	return nil
}

func legacySchemaError(key string, path string) error {
	return fmt.Errorf("policy.yaml uses removed v0.5.1 key %q at %s; migrate to schema version 1 using top-level rules and host_overrides.<target>.rules with explicit action allow|deny", key, path)
}

func hostOverrideOrder(value *yaml.Node) []string {
	if value == nil || value.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(value.Content); i += 2 {
		if value.Content[i].Value != "host_overrides" {
			continue
		}
		node := value.Content[i+1]
		if node == nil || node.Kind != yaml.MappingNode {
			return nil
		}
		order := make([]string, 0, len(node.Content)/2)
		for j := 0; j+1 < len(node.Content); j += 2 {
			order = append(order, node.Content[j].Value)
		}
		return order
	}
	return nil
}

type compiledEngine struct {
	config      Config
	inventory   inventory.Inventory
	globalRules []compiledRule
	hostRules   map[string][]compiledRule
}

type compiledRule struct {
	source   string
	priority int
	action   Action
	regex    *regexp.Regexp
}

func (e *compiledEngine) Evaluate(host string, command string) (Decision, error) {
	for _, rule := range e.hostRulesFor(host) {
		if rule.regex.MatchString(command) {
			return Decision{Action: rule.action, Rule: rule.source}, nil
		}
	}

	for _, rule := range e.globalRules {
		if rule.regex.MatchString(command) {
			return Decision{Action: rule.action, Rule: rule.source}, nil
		}
	}

	return Decision{Action: ActionDeny, Rule: RuleDefaultDeny}, nil
}

func (e *compiledEngine) hostRulesFor(hostName string) []compiledRule {
	matches := map[string]struct{}{}
	if _, ok := e.config.HostOverrides[HostRulesKey(hostName)]; ok {
		matches[HostRulesKey(hostName)] = struct{}{}
	}
	if host, ok := e.inventory.Hosts[hostName]; ok {
		for groupName, group := range e.inventory.Groups {
			if _, hasOverride := e.config.HostOverrides[groupName]; hasOverride && hostHasAllTags(host.Tags, group.Tags) {
				matches[groupName] = struct{}{}
			}
		}
	}

	keys := e.config.orderedHostOverrideKeys(matches)
	rules := make([]compiledRule, 0)
	for _, key := range keys {
		rules = append(rules, e.hostRules[key]...)
	}
	sortRules(rules)
	return rules
}

// EffectiveRules returns the host/global rule projection in engine evaluation
// order. RuleGroups are intentionally ignored; stamped copies are visible only
// through HostOverrides with Rule.Group provenance.
func EffectiveRules(config Config, inv inventory.Inventory, hostName string) []EffectiveRule {
	config = config.withMaps()
	out := make([]EffectiveRule, 0)
	if strings.TrimSpace(hostName) != "" {
		matches := map[string]struct{}{}
		if _, ok := config.HostOverrides[HostRulesKey(hostName)]; ok {
			matches[HostRulesKey(hostName)] = struct{}{}
		}
		if host, ok := inv.Hosts[hostName]; ok {
			for groupName, group := range inv.Groups {
				if _, hasOverride := config.HostOverrides[groupName]; hasOverride && hostHasAllTags(host.Tags, group.Tags) {
					matches[groupName] = struct{}{}
				}
			}
		}
		hostRows := make([]EffectiveRule, 0)
		for _, source := range config.orderedHostOverrideKeys(matches) {
			override := config.HostOverrides[source]
			for i, rule := range override.Rules {
				hostRows = append(hostRows, EffectiveRule{
					Scope:  "host",
					Source: source,
					Index:  i,
					Rule:   rule,
				})
			}
		}
		sortEffectiveRules(hostRows)
		out = append(out, hostRows...)
	}

	globalRows := make([]EffectiveRule, 0, len(config.Rules))
	for i, rule := range config.Rules {
		globalRows = append(globalRows, EffectiveRule{
			Scope:  "global",
			Source: "global",
			Index:  i,
			Rule:   rule,
		})
	}
	sortEffectiveRules(globalRows)
	out = append(out, globalRows...)
	return out
}

func sortEffectiveRules(rules []EffectiveRule) {
	sort.SliceStable(rules, func(i, j int) bool {
		return rules[i].Rule.Priority > rules[j].Rule.Priority
	})
}

func (c Config) orderedHostOverrideKeys(filter map[string]struct{}) []string {
	seen := map[string]struct{}{}
	keys := make([]string, 0, len(filter))
	for _, key := range c.hostOrder {
		if _, ok := filter[key]; !ok {
			continue
		}
		if _, ok := seen[key]; ok {
			continue
		}
		keys = append(keys, key)
		seen[key] = struct{}{}
	}
	var missing []string
	for key := range filter {
		if _, ok := seen[key]; !ok {
			missing = append(missing, key)
		}
	}
	sort.Strings(missing)
	return append(keys, missing...)
}

func compileRegex(pattern string, source string) (*regexp.Regexp, error) {
	if pattern == "" {
		return nil, fmt.Errorf("policy %s has empty cmd_regex", source)
	}
	expr, err := regexp.Compile(pattern)
	if err != nil {
		return nil, fmt.Errorf("policy %s invalid cmd_regex %q: %w", source, pattern, err)
	}
	return expr, nil
}

func validateAction(action Action, source string) (Action, error) {
	switch action {
	case ActionAllow, ActionDeny:
		return action, nil
	case "":
		return ActionAllow, nil
	default:
		return "", fmt.Errorf("policy %s has invalid action %q", source, action)
	}
}

func sortRules(rules []compiledRule) {
	sort.SliceStable(rules, func(i, j int) bool {
		return rules[i].priority > rules[j].priority
	})
}

func hostHasAllTags(hostTags []string, groupTags []string) bool {
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
