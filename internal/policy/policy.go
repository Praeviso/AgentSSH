package policy

import (
	"fmt"
	"regexp"
	"sort"

	"github.com/Kritoooo/agentssh/internal/inventory"
)

// Action is the binary policy action used by AgentSSH.
type Action string

const (
	ActionAllow Action = "allow"
	ActionDeny  Action = "deny"
)

// Decision is the result of evaluating a command against policy.
type Decision struct {
	Action Action `json:"action"`
	Rule   string `json:"rule,omitempty"`
}

// Config is the parsed policy.yaml document.
type Config struct {
	Version       int                     `yaml:"version" json:"version"`
	Defaults      Defaults                `yaml:"defaults" json:"defaults"`
	Rules         []Rule                  `yaml:"rules" json:"rules"`
	HostOverrides map[string]HostOverride `yaml:"host_overrides" json:"host_overrides"`
	Output        Output                  `yaml:"output" json:"output"`
}

// Defaults contains the fallback policy action.
type Defaults struct {
	Policy Action `yaml:"policy" json:"policy"`
}

// Rule is a named first-match policy rule.
type Rule struct {
	Name   string `yaml:"name" json:"name"`
	Match  Match  `yaml:"match" json:"match"`
	Action Action `yaml:"action" json:"action"`
}

// Match contains command matching criteria.
type Match struct {
	CmdRegex string `yaml:"cmd_regex" json:"cmd_regex"`
}

// HostOverride contains group-specific default and allowlist rules.
type HostOverride struct {
	Policy     Action  `yaml:"policy" json:"policy"`
	AllowRules []Match `yaml:"allow_rules" json:"allow_rules"`
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
		config:    config.withDefaults(),
		inventory: inv,
	}
	for i, rule := range compiled.config.Rules {
		expr, err := compileRegex(rule.Match.CmdRegex, fmt.Sprintf("rules[%d]", i))
		if err != nil {
			return nil, err
		}
		compiled.rules = append(compiled.rules, compiledRule{
			name:   rule.Name,
			action: normalizeAction(rule.Action),
			regex:  expr,
		})
	}
	for groupName, override := range compiled.config.HostOverrides {
		for i, rule := range override.AllowRules {
			expr, err := compileRegex(rule.CmdRegex, fmt.Sprintf("%s/allow_rules[%d]", groupName, i))
			if err != nil {
				return nil, err
			}
			compiled.allowRules = append(compiled.allowRules, compiledAllowRule{
				group: groupName,
				index: i,
				regex: expr,
			})
		}
	}
	return compiled, nil
}

func (c Config) withDefaults() Config {
	if c.Defaults.Policy == "" {
		c.Defaults.Policy = ActionAllow
	}
	if c.HostOverrides == nil {
		c.HostOverrides = map[string]HostOverride{}
	}
	return c
}

type compiledEngine struct {
	config     Config
	inventory  inventory.Inventory
	rules      []compiledRule
	allowRules []compiledAllowRule
}

type compiledRule struct {
	name   string
	action Action
	regex  *regexp.Regexp
}

type compiledAllowRule struct {
	group string
	index int
	regex *regexp.Regexp
}

func (e *compiledEngine) Evaluate(host string, command string) (Decision, error) {
	groups := e.hostGroups(host)
	var allowlistRule string
	for _, groupName := range groups {
		override := e.config.HostOverrides[groupName]
		if normalizeAction(override.Policy) != ActionDeny {
			continue
		}
		if rule, ok := e.matchAllowRule(groupName, command); ok {
			if allowlistRule == "" {
				allowlistRule = rule
			}
			continue
		}
		return Decision{Action: ActionDeny, Rule: groupName + "/default_deny"}, nil
	}
	if allowlistRule != "" {
		return Decision{Action: ActionAllow, Rule: allowlistRule}, nil
	}

	for _, rule := range e.rules {
		if rule.regex.MatchString(command) {
			ruleName := rule.name
			if ruleName == "" {
				ruleName = rule.regex.String()
			}
			return Decision{Action: rule.action, Rule: "rules:" + ruleName}, nil
		}
	}

	return Decision{Action: normalizeAction(e.config.Defaults.Policy), Rule: "default"}, nil
}

func (e *compiledEngine) hostGroups(hostName string) []string {
	host, ok := e.inventory.Hosts[hostName]
	if !ok {
		return nil
	}
	var groups []string
	for groupName, group := range e.inventory.Groups {
		if hostHasAllTags(host.Tags, group.Tags) {
			groups = append(groups, groupName)
		}
	}
	sort.Strings(groups)
	return groups
}

func (e *compiledEngine) matchAllowRule(groupName string, command string) (string, bool) {
	for _, rule := range e.allowRules {
		if rule.group != groupName {
			continue
		}
		if rule.regex.MatchString(command) {
			return fmt.Sprintf("%s/allow_rules[%d]", groupName, rule.index), true
		}
	}
	return "", false
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

func normalizeAction(action Action) Action {
	if action == "" {
		return ActionAllow
	}
	return action
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
