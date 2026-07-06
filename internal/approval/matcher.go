package approval

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

type MatcherKind string

const (
	MatcherExact  MatcherKind = "exact"
	MatcherPrefix MatcherKind = "prefix"
)

type Scope string

const (
	ScopeOnce    Scope = "once"
	ScopeSession Scope = "session"
	ScopeHost    Scope = "host"
)

type Verdict string

const (
	VerdictApproved Verdict = "approved"
	VerdictDenied   Verdict = "denied"
)

const (
	ChannelCLI  = "cli"
	ChannelTUI  = "tui"
	ChannelExit = "exit"
	ChannelPlan = "plan"
)

// Matcher is the reusable command matcher that can be stored in session grants
// or generated host rules.
type Matcher struct {
	Kind       MatcherKind `json:"kind"`
	Regex      string      `json:"regex"`
	Prefix     []string    `json:"prefix,omitempty"`
	Promotable bool        `json:"promotable"`
	SourceCmd  string      `json:"source_cmd"`
}

func (m Matcher) Match(command string) (bool, error) {
	if err := validateMatcherInvariant(m.Regex); err != nil {
		return false, err
	}
	expr, err := regexp.Compile(m.Regex)
	if err != nil {
		return false, err
	}
	return expr.MatchString(command), nil
}

func (m Matcher) SHA256() string {
	sum := sha256.Sum256([]byte(string(m.Kind) + "\x00" + m.Regex + "\x00" + strings.Join(m.Prefix, "\x00") + "\x00" + m.SourceCmd + "\x00" + strconv.FormatBool(m.Promotable)))
	return hex.EncodeToString(sum[:])
}

func matcherSHA12(m Matcher) string {
	sum := m.SHA256()
	if len(sum) < 12 {
		return sum
	}
	return sum[:12]
}

func validateMatcherInvariant(pattern string) error {
	switch {
	case !strings.HasPrefix(pattern, `\A`):
		return fmt.Errorf("approval matcher is missing \\A anchor: %q", pattern)
	case !strings.HasSuffix(pattern, `\z`):
		return fmt.Errorf("approval matcher is missing \\z anchor: %q", pattern)
	case strings.Contains(pattern, `\s`):
		return fmt.Errorf("approval matcher must not contain \\s: %q", pattern)
	case strings.Contains(pattern, "\n") || strings.Contains(pattern, "\r"):
		return fmt.Errorf("approval matcher must not contain literal newlines: %q", pattern)
	case strings.Contains(pattern, ".*"):
		return fmt.Errorf("approval matcher must not contain .*: %q", pattern)
	default:
		return nil
	}
}

func mustValidateMatcher(m Matcher) Matcher {
	if err := validateMatcherInvariant(m.Regex); err != nil {
		panic(err)
	}
	return m
}
