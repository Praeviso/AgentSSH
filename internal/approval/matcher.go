package approval

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"regexp/syntax"
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
	expr, err := compileMatcher(m.Regex)
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

// looksLegacyEscaped reports whether a stored pattern was generated before '+'
// was escaped, i.e. it carries a bare '+' that acts as a quantifier. Such a
// pattern authorizes commands the operator never approved (an approved "a+b"
// also matches "ab" and "aab"), so callers must stop honoring it.
//
// Order matters: prefix matchers legitimately contain structural '+' in
// `[ \t]+` and in tailTokenClass's trailing quantifier. Those fixed fragments
// are stripped first, so only a generator-emitted bare '+' remains. Exact
// matchers contain none of the fragments, so the strip is a no-op for them.
func looksLegacyEscaped(pattern string) bool {
	stripped := pattern
	for _, fragment := range []string{
		`(?:[ \t]+` + tailTokenClass + `)*`,
		`[ \t]+`,
		`[ \t]*`,
		`\A`,
		`\z`,
	} {
		stripped = strings.ReplaceAll(stripped, fragment, "")
	}
	return strings.Contains(stripped, "+")
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

// compileMatcher enforces the string invariant and then compiles. Callers that
// only hold a stored pattern (no SourceCmd) use this; construction goes through
// newMatcher, which additionally proves the pattern against its source.
func compileMatcher(pattern string) (*regexp.Regexp, error) {
	if err := validateMatcherInvariant(pattern); err != nil {
		return nil, err
	}
	expr, err := regexp.Compile(pattern)
	if err != nil {
		return nil, fmt.Errorf("approval matcher does not compile: %w", err)
	}
	return expr, nil
}

// newMatcher is the single gate every generated matcher passes through. It
// proves three things a string-level invariant check cannot:
//
//  1. the pattern compiles — a generator bug that emits an invalid quantifier
//     is caught here rather than at match time, where the error would surface
//     against unrelated commands;
//  2. the pattern matches the command it was generated from — a matcher that
//     cannot authorize its own source is silently useless and forces the
//     operator to re-approve the same command forever;
//  3. for exact matchers, the pattern matches *nothing but* that command.
//     Self-match alone is not enough: a pattern can match its source and still
//     match more, which is authorization widening.
//
// Returns an error rather than panicking: this runs on the Authorize hot path
// over an agent-supplied command string, so a panic would be a denial of
// service reachable from untrusted input, and inside ApplyDecision it would
// land between the audit append and the grant write, destroying the operator's
// decision.
func newMatcher(m Matcher) (Matcher, error) {
	expr, err := compileMatcher(m.Regex)
	if err != nil {
		return Matcher{}, err
	}
	if !expr.MatchString(m.SourceCmd) {
		return Matcher{}, fmt.Errorf("approval matcher does not match the command it was generated from: %q", m.Regex)
	}
	if m.Kind == MatcherExact {
		if err := assertExactLiteral(m.Regex, m.SourceCmd); err != nil {
			return Matcher{}, err
		}
	}
	return m, nil
}

// assertExactLiteral proves an exact matcher is anchored around one literal
// equal to the source command, so it can match that command and nothing else.
// The parsed form of \A<escaped>\z is Concat[BeginText, Literal, EndText] —
// the parser folds adjacent escapes into a single literal run — degenerating
// to Concat[BeginText, EndText] for the empty command.
func assertExactLiteral(pattern string, source string) error {
	parsed, err := syntax.Parse(pattern, syntax.Perl)
	if err != nil {
		return fmt.Errorf("approval matcher does not parse: %w", err)
	}
	parsed = parsed.Simplify()
	widened := fmt.Errorf("exact approval matcher is not a single anchored literal (would match more than the approved command): %q", pattern)
	if parsed.Op != syntax.OpConcat || len(parsed.Sub) == 0 {
		return widened
	}
	if parsed.Sub[0].Op != syntax.OpBeginText || parsed.Sub[len(parsed.Sub)-1].Op != syntax.OpEndText {
		return widened
	}
	switch len(parsed.Sub) {
	case 2:
		if source != "" {
			return widened
		}
	case 3:
		if parsed.Sub[1].Op != syntax.OpLiteral || string(parsed.Sub[1].Rune) != source {
			return widened
		}
	default:
		return widened
	}
	return nil
}
