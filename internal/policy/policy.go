package policy

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
