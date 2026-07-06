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

// Authorize decides one run request. A matching once grant is claimed under
// reqID (two-phase consumption): the caller must settle the claim with
// SessionStore.Commit once the command reaches the remote, or
// SessionStore.Release if it verifiably never executed.
// stdinSHA256 is empty for runs without stdin; when set, grants must carry the
// same stdin hash, persistent host approval rules never match, and the
// candidate matcher is forced to exact and non-promotable.
func Authorize(cfg policy.Config, inv inventory.Inventory, sessionStore SessionStore, runtime RuntimeConfig, sessionID string, host string, command string, stdinSHA256 string, reqID string) (Authorization, error) {
	if reqID == "" {
		return Authorization{}, fmt.Errorf("authorize requires a request id")
	}
	return authorize(cfg, inv, sessionStore, runtime, sessionID, host, command, stdinSHA256, reqID)
}

// PreflightAuthorize is the side-effect-free variant used to preview a batch
// before executing any of it.
func PreflightAuthorize(cfg policy.Config, inv inventory.Inventory, sessionStore SessionStore, runtime RuntimeConfig, sessionID string, host string, command string, stdinSHA256 string) (Authorization, error) {
	return authorize(cfg, inv, sessionStore, runtime, sessionID, host, command, stdinSHA256, "")
}

func authorize(cfg policy.Config, inv inventory.Inventory, sessionStore SessionStore, runtime RuntimeConfig, sessionID string, host string, command string, stdinSHA256 string, claimReqID string) (Authorization, error) {
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
	if claimReqID != "" {
		grant, ok, err = sessionStore.Claim(sessionID, host, command, stdinSHA256, claimReqID)
	} else {
		grant, ok, err = sessionStore.Peek(sessionID, host, command, stdinSHA256)
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
	// Persistent host approval rules match the command text only; they cannot
	// vouch for an arbitrary stdin payload, so stdin runs skip them entirely.
	if stdinSHA256 == "" {
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
	}
	matcher, err := Generalize(command, runtime.HostGrantMode)
	if errors.Is(err, ErrNULCommand) {
		return Authorization{Status: AuthHardDeny, Decision: decision}, nil
	}
	if err != nil {
		return Authorization{}, err
	}
	if stdinSHA256 != "" {
		// The operator sees only the stdin hash and size, never the content, so
		// a stdin approval must stay pinned to this exact command + payload and
		// must never widen into a persistent host rule.
		matcher, err = Exact(command)
		if err != nil {
			return Authorization{}, err
		}
		matcher.Promotable = false
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
