package approval

import (
	"fmt"
	"strings"
	"time"

	"github.com/Praeviso/AgentSSH/internal/audit"
	"github.com/Praeviso/AgentSSH/internal/policy"
)

type ApplyOptions struct {
	Pending    PendingStore
	Sessions   SessionStore
	Audit      audit.Store
	Bundle     policy.Bundle
	PolicyPath string
	SessionTTL time.Duration
	Channel    string
	SavePolicy func(policy.Config) error
}

type ApplyResult struct {
	Request    PendingRequest `json:"request"`
	Resolution Resolution     `json:"resolution"`
	Grant      *Grant         `json:"grant,omitempty"`
	RuleName   string         `json:"rule_name,omitempty"`
}

func ApplyDecision(opts ApplyOptions, id string, verdict Verdict, scope Scope) (ApplyResult, error) {
	if opts.Channel == "" {
		opts.Channel = ChannelCLI
	}
	req, err := opts.Pending.Get(id)
	if err != nil {
		return ApplyResult{}, err
	}
	if _, exists, err := opts.Pending.readResolution(id); err != nil {
		return ApplyResult{}, err
	} else if exists {
		return ApplyResult{}, ErrAlreadyResolved
	}
	result := ApplyResult{Request: req}
	switch verdict {
	case VerdictApproved:
		if scope != ScopeOnce && scope != ScopeSession && scope != ScopeHost {
			return ApplyResult{}, fmt.Errorf("approval grant scope is required")
		}
		if scope == ScopeHost {
			if !req.Candidate.Promotable {
				return ApplyResult{}, fmt.Errorf("approval %s cannot be promoted to host scope", req.ID)
			}
			if err := validateMatcherInvariant(req.Candidate.Regex); err != nil {
				return ApplyResult{}, err
			}
		} else if _, err := Exact(req.Cmd); err != nil {
			return ApplyResult{}, err
		}
	case VerdictDenied:
		scope = ""
	default:
		return ApplyResult{}, fmt.Errorf("invalid approval verdict %q", verdict)
	}

	resolution, err := opts.Pending.Resolve(req, verdict, scope)
	if err != nil {
		return ApplyResult{}, err
	}
	result.Resolution = resolution

	switch verdict {
	case VerdictApproved:
		if scope == ScopeHost {
			ruleName, err := applyHostGrant(opts, req)
			if err != nil {
				return ApplyResult{}, err
			}
			result.RuleName = ruleName
		} else {
			grant, err := applySessionGrant(opts, req, scope)
			if err != nil {
				return ApplyResult{}, err
			}
			result.Grant = &grant
		}
	case VerdictDenied:
	}

	if err := appendApprovalAudit(opts, req, verdict, scope); err != nil {
		return ApplyResult{}, err
	}
	return result, nil
}

func applySessionGrant(opts ApplyOptions, req PendingRequest, scope Scope) (Grant, error) {
	matcher, err := Exact(req.Cmd)
	if err != nil {
		return Grant{}, err
	}
	ttl := opts.SessionTTL
	if ttl <= 0 {
		ttl = DefaultSessionTTL
	}
	return opts.Sessions.Grant(req.SessionID, req.Host, scope, matcher, req.StdinSHA256, req.ID, req.ReqID, ttl, opts.Channel)
}

func applyHostGrant(opts ApplyOptions, req PendingRequest) (string, error) {
	if !req.Candidate.Promotable {
		return "", fmt.Errorf("approval %s cannot be promoted to host scope", req.ID)
	}
	if err := validateMatcherInvariant(req.Candidate.Regex); err != nil {
		return "", err
	}
	next := opts.Bundle
	if next.Policy.HostOverrides == nil {
		next.Policy.HostOverrides = map[string]policy.HostOverride{}
	}
	key := policy.HostRulesKey(req.Host)
	existing := next.Policy.HostOverrides[key]
	ruleName := "approval/" + matcherSHA12(req.Candidate)
	for _, rule := range existing.Rules {
		if rule.Name == ruleName || rule.Match.CmdRegex == req.Candidate.Regex {
			return ruleName, nil
		}
	}
	rule := policy.Rule{
		Name:     ruleName,
		Priority: 0,
		Match:    policy.Match{CmdRegex: req.Candidate.Regex},
		Action:   policy.ActionAllow,
		Group:    policy.ApprovalGroup,
	}
	updated, err := policy.AddHostRule(next, req.Host, rule)
	if err != nil {
		return "", err
	}
	if _, err := policy.NewEngine(updated.Policy, updated.Inventory); err != nil {
		return "", err
	}
	if opts.SavePolicy != nil {
		if err := opts.SavePolicy(updated.Policy); err != nil {
			return "", err
		}
	} else {
		if strings.TrimSpace(opts.PolicyPath) == "" {
			return "", fmt.Errorf("policy path is required for host approval")
		}
		if err := policy.Save(opts.PolicyPath, updated.Policy); err != nil {
			return "", err
		}
	}
	return ruleName, nil
}

func appendApprovalAudit(opts ApplyOptions, req PendingRequest, verdict Verdict, scope Scope) error {
	if opts.Audit.Path == "" {
		return nil
	}
	event := audit.EventApprovalDenied
	action := string(policy.ActionDeny)
	if verdict == VerdictApproved {
		event = audit.EventApprovalGranted
		action = string(policy.ActionAllow)
	}
	record := audit.Record{
		ReqID:           req.ReqID,
		SessionID:       req.SessionID,
		Event:           event,
		Host:            req.Host,
		Cmd:             req.Cmd,
		PolicyAction:    action,
		PolicyRule:      policy.RuleDefaultDeny,
		ApprovalID:      req.ID,
		ApprovalScope:   string(scope),
		ApprovalMatcher: req.Candidate.Regex,
		ApprovalChannel: opts.Channel,
		StdinSHA256:     req.StdinSHA256,
		StdinBytes:      req.StdinBytes,
		PlanID:          req.PlanID,
	}
	_, err := opts.Audit.Append(record)
	return err
}
