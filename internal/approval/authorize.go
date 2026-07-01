package approval

import (
	"errors"
	"fmt"
	"strings"

	"github.com/Praeviso/AgentSSH/internal/inventory"
	"github.com/Praeviso/AgentSSH/internal/policy"
)

type AuthorizationStatus string

const (
	AuthAllow         AuthorizationStatus = "allow"
	AuthAllowByGrant  AuthorizationStatus = "allow_by_grant"
	AuthHardDeny      AuthorizationStatus = "hard_deny"
	AuthNeedsApproval AuthorizationStatus = "needs_approval"
)

type Authorization struct {
	Status          AuthorizationStatus
	Decision        policy.Decision
	GrantScope      Scope
	GrantMatcher    string
	ApprovalMatcher Matcher
}

func Authorize(cfg policy.Config, inv inventory.Inventory, sessionStore SessionStore, runtime RuntimeConfig, sessionID string, host string, command string) (Authorization, error) {
	return authorize(cfg, inv, sessionStore, runtime, sessionID, host, command, true)
}

func PreflightAuthorize(cfg policy.Config, inv inventory.Inventory, sessionStore SessionStore, runtime RuntimeConfig, sessionID string, host string, command string) (Authorization, error) {
	return authorize(cfg, inv, sessionStore, runtime, sessionID, host, command, false)
}

func authorize(cfg policy.Config, inv inventory.Inventory, sessionStore SessionStore, runtime RuntimeConfig, sessionID string, host string, command string, consumeOnce bool) (Authorization, error) {
	if !runtime.Enabled {
		engine, err := policy.NewEngine(cfg, inv)
		if err != nil {
			return Authorization{}, err
		}
		decision, err := engine.Evaluate(host, command)
		if err != nil {
			return Authorization{}, err
		}
		if decision.Action == policy.ActionAllow {
			return Authorization{Status: AuthAllow, Decision: decision}, nil
		}
		if decision.Rule != policy.RuleDefaultDeny {
			return Authorization{Status: AuthHardDeny, Decision: decision}, nil
		}
		return Authorization{Status: AuthNeedsApproval, Decision: decision}, nil
	}

	clean, hostMatchers := splitPolicy(cfg, host)
	engine, err := policy.NewEngine(clean, inv)
	if err != nil {
		return Authorization{}, err
	}
	decision, err := engine.Evaluate(host, command)
	if err != nil {
		return Authorization{}, err
	}
	if decision.Action == policy.ActionAllow {
		return Authorization{Status: AuthAllow, Decision: decision}, nil
	}
	if decision.Rule != policy.RuleDefaultDeny {
		return Authorization{Status: AuthHardDeny, Decision: decision}, nil
	}
	var grant Grant
	var ok bool
	if consumeOnce {
		grant, ok, err = sessionStore.Match(sessionID, host, command)
	} else {
		grant, ok, err = sessionStore.Peek(sessionID, host, command)
	}
	if err != nil {
		return Authorization{}, err
	}
	if ok {
		return Authorization{
			Status:       AuthAllowByGrant,
			Decision:     policy.Decision{Action: policy.ActionAllow, Rule: "approval/session/" + grant.ApprovalID},
			GrantScope:   grant.Scope,
			GrantMatcher: grant.Regex,
		}, nil
	}
	for _, matcher := range hostMatchers {
		matches, err := matcher.Match(command)
		if err != nil {
			return Authorization{}, err
		}
		if matches {
			return Authorization{
				Status:       AuthAllowByGrant,
				Decision:     policy.Decision{Action: policy.ActionAllow, Rule: "approval/host/" + matcherSHA12(matcher)},
				GrantScope:   ScopeHost,
				GrantMatcher: matcher.Regex,
			}, nil
		}
	}
	matcher, err := Generalize(command, runtime.HostGrantMode)
	if errors.Is(err, ErrNULCommand) {
		return Authorization{Status: AuthHardDeny, Decision: decision}, nil
	}
	if err != nil {
		return Authorization{}, err
	}
	return Authorization{Status: AuthNeedsApproval, Decision: decision, ApprovalMatcher: matcher}, nil
}

func splitPolicy(cfg policy.Config, host string) (policy.Config, []Matcher) {
	clean := copyPolicyConfig(cfg)
	if clean.HostOverrides == nil {
		return clean, nil
	}
	var hostMatchers []Matcher
	for key, override := range cfg.HostOverrides {
		if !strings.HasPrefix(key, "host:") {
			continue
		}
		filtered := make([]policy.Rule, 0, len(override.Rules))
		for _, rule := range override.Rules {
			if rule.Group != policy.ApprovalGroup {
				filtered = append(filtered, rule)
				continue
			}
			if key == policy.HostRulesKey(host) {
				hostMatchers = append(hostMatchers, Matcher{
					Kind:       MatcherExact,
					Regex:      rule.Match.CmdRegex,
					Promotable: true,
				})
			}
		}
		if len(filtered) == len(override.Rules) {
			continue
		}
		nextOverride := clean.HostOverrides[key]
		nextOverride.Rules = filtered
		clean.HostOverrides[key] = nextOverride
	}
	return clean, hostMatchers
}

func copyPolicyConfig(cfg policy.Config) policy.Config {
	next := cfg
	next.Rules = append([]policy.Rule(nil), cfg.Rules...)
	if cfg.RuleGroups != nil {
		next.RuleGroups = make(map[string]policy.RuleGroup, len(cfg.RuleGroups))
		for key, value := range cfg.RuleGroups {
			value.Rules = append([]policy.Rule(nil), value.Rules...)
			next.RuleGroups[key] = value
		}
	}
	if cfg.HostOverrides != nil {
		next.HostOverrides = make(map[string]policy.HostOverride, len(cfg.HostOverrides))
		for key, value := range cfg.HostOverrides {
			value.Rules = append([]policy.Rule(nil), value.Rules...)
			next.HostOverrides[key] = value
		}
	}
	next.Output.Redact = append([]string(nil), cfg.Output.Redact...)
	return next
}

func CheckHostGrantRule(rule policy.Rule) error {
	if rule.Group != policy.ApprovalGroup {
		return fmt.Errorf("rule is not an approval host rule")
	}
	return validateMatcherInvariant(rule.Match.CmdRegex)
}
