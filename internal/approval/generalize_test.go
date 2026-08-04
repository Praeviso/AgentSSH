package approval

import (
	"regexp"
	"strings"
	"testing"
)

func TestGeneralizeSafePrefixTable(t *testing.T) {
	tests := []struct {
		command string
		mode    HostGrantMode
		kind    MatcherKind
		prefix  []string
		promo   bool
	}{
		{"systemctl status nginx", HostGrantSafePrefix, MatcherPrefix, []string{"systemctl", "status"}, true},
		{"systemctl restart nginx", HostGrantSafePrefix, MatcherExact, nil, true},
		{"ls -la /var", HostGrantSafePrefix, MatcherPrefix, []string{"ls"}, true},
		{"git diff HEAD", HostGrantSafePrefix, MatcherPrefix, []string{"git", "diff", "HEAD"}, true},
		{"kubectl get pods", HostGrantSafePrefix, MatcherPrefix, []string{"kubectl", "get", "pods"}, true},
		{"journalctl -u nginx", HostGrantSafePrefix, MatcherExact, nil, true},
		{"cat /etc/passwd", HostGrantSafePrefix, MatcherExact, nil, true},
		{"sudo systemctl restart nginx", HostGrantSafePrefix, MatcherExact, nil, false},
		{"rm -rf /var/tmp/cache", HostGrantSafePrefix, MatcherExact, nil, true},
		{"systemctl restart nginx", HostGrantPrefix, MatcherPrefix, []string{"systemctl", "restart"}, true},
	}
	for _, tt := range tests {
		t.Run(tt.command, func(t *testing.T) {
			got, err := Generalize(tt.command, tt.mode)
			if err != nil {
				t.Fatalf("Generalize: %v", err)
			}
			if got.Kind != tt.kind || got.Promotable != tt.promo {
				t.Fatalf("matcher = %#v", got)
			}
			if strings.Join(got.Prefix, "\x00") != strings.Join(tt.prefix, "\x00") {
				t.Fatalf("prefix = %#v, want %#v", got.Prefix, tt.prefix)
			}
			assertMatcherInvariant(t, got.Regex)
			if matched, err := got.Match(tt.command); err != nil || !matched {
				t.Fatalf("matcher should match source command: matched=%v err=%v regex=%s", matched, err, got.Regex)
			}
		})
	}
}

func TestGeneralizeSafePrefixConfirmedEscalationsDoNotMatch(t *testing.T) {
	tests := []struct {
		name    string
		benign  string
		exploit string
	}{
		{
			name:    "journalctl destructive flag",
			benign:  "journalctl -u nginx",
			exploit: "journalctl --vacuum-time=1s",
		},
		{
			name:    "git output overwrite",
			benign:  "git diff HEAD",
			exploit: "git diff --output=/etc/cron.d/x HEAD",
		},
		{
			name:    "kubectl impersonated secret read",
			benign:  "kubectl get pods",
			exploit: "kubectl get secret --as=system:masters -o yaml",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			benign, err := Generalize(tt.benign, HostGrantSafePrefix)
			if err != nil {
				t.Fatalf("Generalize benign: %v", err)
			}
			assertMatcherInvariant(t, benign.Regex)
			matched, err := benign.Match(tt.exploit)
			if err != nil {
				t.Fatalf("Match exploit with benign matcher: %v", err)
			}
			if matched {
				t.Fatalf("benign matcher %s matched exploit %q", benign.Regex, tt.exploit)
			}

			exploit, err := Generalize(tt.exploit, HostGrantSafePrefix)
			if err != nil {
				t.Fatalf("Generalize exploit: %v", err)
			}
			if exploit.Kind != MatcherExact {
				t.Fatalf("exploit matcher kind = %s, want exact: %#v", exploit.Kind, exploit)
			}
			assertMatcherInvariant(t, exploit.Regex)
			matched, err = exploit.Match(tt.exploit)
			if err != nil || !matched {
				t.Fatalf("exploit exact matcher should match source: matched=%v err=%v regex=%s", matched, err, exploit.Regex)
			}
		})
	}
}

func TestGeneralizeInjectionCorpusForcesExactOrRejects(t *testing.T) {
	tests := []string{
		"ls\nrm -rf /",
		"ls\rrm -rf /",
		"ls\t-la",
		"ls\f-la",
		"ls\v-la",
		"ls\u00a0-la",
		"echo $(id)",
		"cat /etc/passwd | grep root",
		"echo hi \\",
		"echo 'hi'",
		`echo "hi"`,
		"ls *",
		"LD_PRELOAD=x ls",
	}
	for _, command := range tests {
		t.Run(command, func(t *testing.T) {
			matcher, err := Generalize(command, HostGrantSafePrefix)
			if err != nil {
				t.Fatalf("Generalize: %v", err)
			}
			if matcher.Kind != MatcherExact {
				t.Fatalf("matcher kind = %s, want exact: %#v", matcher.Kind, matcher)
			}
			assertMatcherInvariant(t, matcher.Regex)
			if matched, err := matcher.Match(command); err != nil || !matched {
				t.Fatalf("exact matcher should match source: matched=%v err=%v regex=%s", matched, err, matcher.Regex)
			}
		})
	}
}

func TestGeneralizeRejectsNUL(t *testing.T) {
	if _, err := Generalize("ls\x00id", HostGrantSafePrefix); err != ErrNULCommand {
		t.Fatalf("err = %v, want ErrNULCommand", err)
	}
}

// Go's regexp cannot express a single invalid byte: `\xF3` in a pattern means
// the rune U+00F3 (encoded C3 B3), not the byte 0xF3. A matcher built from an
// invalid-UTF-8 command would fail to match that command while matching a
// different one, so such commands are rejected instead of approved.
func TestGeneralizeRejectsInvalidUTF8(t *testing.T) {
	for _, command := range []string{"\xf3", "ls \xff", "echo \xc3(", "\xed\xa0\x80"} {
		t.Run(command, func(t *testing.T) {
			if _, err := Generalize(command, HostGrantSafePrefix); err != ErrInvalidUTF8Command {
				t.Fatalf("Generalize err = %v, want ErrInvalidUTF8Command", err)
			}
			if _, err := Exact(command); err != ErrInvalidUTF8Command {
				t.Fatalf("Exact err = %v, want ErrInvalidUTF8Command", err)
			}
		})
	}
	// Valid multibyte UTF-8 stays supported.
	matcher, err := Exact("echo 日志")
	if err != nil {
		t.Fatalf("Exact on valid UTF-8: %v", err)
	}
	if matched, err := matcher.Match("echo 日志"); err != nil || !matched {
		t.Fatalf("valid UTF-8 matcher should match its source: matched=%v err=%v", matched, err)
	}
}

func TestPrefixMatcherDoesNotMatchNewlineInjection(t *testing.T) {
	matcher, err := Generalize("ls /var", HostGrantSafePrefix)
	if err != nil {
		t.Fatalf("Generalize: %v", err)
	}
	if matcher.Kind != MatcherPrefix {
		t.Fatalf("kind = %s, want prefix", matcher.Kind)
	}
	for _, attack := range []string{"ls\nrm -rf /", "ls\rrm -rf /", "ls\t;rm", "ls $(id)", "ls | id"} {
		matched, err := matcher.Match(attack)
		if err != nil {
			t.Fatalf("Match attack %q: %v", attack, err)
		}
		if matched {
			t.Fatalf("prefix matcher %s matched attack %q", matcher.Regex, attack)
		}
	}
}

func TestMatcherInvariantRejectsUnsafeRegexes(t *testing.T) {
	for _, pattern := range []string{
		`^ls$`,
		`\Als\s+foo\z`,
		"\\Als\nfoo\\z",
		`\Als.*\z`,
		`\Als`,
	} {
		if err := validateMatcherInvariant(pattern); err == nil {
			t.Fatalf("validateMatcherInvariant(%q) = nil, want error", pattern)
		}
	}
}

// The bytes quoteBytesForRegexp emits verbatim are spliced into a pattern
// outside any character class, so any regex metacharacter among them silently
// rewrites the pattern's meaning. '+' used to be on this list and did exactly
// that. This test is what makes the narrow allowlist safe to keep.
func TestLiteralAllowlistContainsNoRegexMetachar(t *testing.T) {
	for i := 0; i < len(literalSafePunct); i++ {
		b := literalSafePunct[i]
		t.Run(string(rune(b)), func(t *testing.T) {
			if quoted := regexp.QuoteMeta(string(b)); quoted != string(b) {
				t.Fatalf("literalSafePunct contains regex metacharacter %q (QuoteMeta = %q); it must be escaped, not passed through", string(b), quoted)
			}
		})
	}
}

// Every printable byte must survive the round trip: the generated matcher has
// to match the command it came from, and must not match the command with that
// byte removed. The second half is the one that catches quantifiers — a
// quantifier makes the preceding byte optional or repeatable, so the pattern
// widens to commands the operator never approved.
func TestQuoteBytesForRegexpEscapesEveryPrintableByte(t *testing.T) {
	for b := byte(0x20); b <= 0x7E; b++ {
		command := "a" + string(rune(b)) + "b"
		t.Run(command, func(t *testing.T) {
			matcher, err := Exact(command)
			if err != nil {
				t.Fatalf("Exact(%q): %v", command, err)
			}
			assertMatcherInvariant(t, matcher.Regex)
			if matched, err := matcher.Match(command); err != nil || !matched {
				t.Fatalf("matcher must match its source command: matched=%v err=%v regex=%s", matched, err, matcher.Regex)
			}
			if matched, err := matcher.Match("ab"); err != nil || matched {
				t.Fatalf("matcher for %q widened to %q: matched=%v err=%v regex=%s", command, "ab", matched, err, matcher.Regex)
			}
		})
	}
}

// Regression detail for the '+' defect. Before the fix each of these matchers
// failed to match its own source (forcing endless re-approval) while matching
// a command the operator never saw.
func TestExactMatcherPlusEscalations(t *testing.T) {
	tests := []struct {
		name    string
		command string
		widened []string
	}{
		{
			name:    "single plus",
			command: "echo a+b",
			widened: []string{"echo ab", "echo aab", "echo aaaaab"},
		},
		{
			name:    "plus in a tag argument",
			command: "deploy --tag v1+build",
			widened: []string{"deploy --tag v1build", "deploy --tag v11build"},
		},
		{
			name:    "escaped dot followed by plus",
			command: "a.+b",
			widened: []string{"a..b", "a.b"},
		},
		{
			name:    "urlopen expression from the production incident",
			command: `python -c "g=lambda p:u.urlopen(b+p,timeout=30)"`,
			widened: []string{`python -c "g=lambda p:u.urlopen(bp,timeout=30)"`},
		},
		{
			// Nested quantifiers used to make the pattern fail to compile, and
			// it was stored anyway — surfacing only at match time, against
			// unrelated commands. Escaping '+' removes the failure mode
			// entirely: this is now an ordinary literal.
			name:    "double plus is a literal, not a nested quantifier",
			command: "x++",
			widened: []string{"x", "x+", "x+++"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matcher, err := Exact(tt.command)
			if err != nil {
				t.Fatalf("Exact(%q): %v", tt.command, err)
			}
			assertMatcherInvariant(t, matcher.Regex)
			if matched, err := matcher.Match(tt.command); err != nil || !matched {
				t.Fatalf("matcher must match its source command: matched=%v err=%v regex=%s", matched, err, matcher.Regex)
			}
			for _, widened := range tt.widened {
				if matched, err := matcher.Match(widened); err != nil || matched {
					t.Fatalf("matcher for %q authorized unapproved command %q: matched=%v err=%v regex=%s", tt.command, widened, matched, err, matcher.Regex)
				}
			}
		})
	}
}

func TestLooksLegacyEscapedDetectsBarePlusOnly(t *testing.T) {
	legacy, err := Generalize("ls -la /var", HostGrantSafePrefix)
	if err != nil {
		t.Fatalf("Generalize: %v", err)
	}
	if legacy.Kind != MatcherPrefix {
		t.Fatalf("kind = %s, want prefix (structural '+' must be present to test the strip)", legacy.Kind)
	}
	// A prefix matcher's structural '+' in `[ \t]+` and tailTokenClass is
	// legitimate and must not be mistaken for the legacy defect.
	if looksLegacyEscaped(legacy.Regex) {
		t.Fatalf("prefix matcher misreported as legacy: %s", legacy.Regex)
	}
	current, err := Exact("echo a+b")
	if err != nil {
		t.Fatalf("Exact: %v", err)
	}
	if looksLegacyEscaped(current.Regex) {
		t.Fatalf("current exact matcher misreported as legacy: %s", current.Regex)
	}
	if !looksLegacyEscaped(`\Aecho\x20a+b\z`) {
		t.Fatal("legacy pattern with a bare '+' was not detected")
	}
}

// splitASCIIWords drops leading spaces, so rebuilding a prefix pattern from
// tokens would lose them and the matcher would miss its own source command.
func TestGeneralizeLeadingSpaceForcesExact(t *testing.T) {
	for _, command := range []string{" ls -la /var", "  systemctl status nginx", " git diff HEAD"} {
		t.Run(command, func(t *testing.T) {
			matcher, err := Generalize(command, HostGrantSafePrefix)
			if err != nil {
				t.Fatalf("Generalize: %v", err)
			}
			if matcher.Kind != MatcherExact {
				t.Fatalf("kind = %s, want exact: %#v", matcher.Kind, matcher)
			}
			if matched, err := matcher.Match(command); err != nil || !matched {
				t.Fatalf("matcher must match its source command: matched=%v err=%v regex=%s", matched, err, matcher.Regex)
			}
			if matched, err := matcher.Match(strings.TrimLeft(command, " ")); err != nil || matched {
				t.Fatalf("matcher widened across leading whitespace: matched=%v err=%v regex=%s", matched, err, matcher.Regex)
			}
		})
	}
}

func TestSplitASCIIWordsDoesNotUseUnicodeWhitespace(t *testing.T) {
	got := splitASCIIWords("a\tb c\u00a0d  e")
	want := []string{"a\tb", "c\u00a0d", "e"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("splitASCIIWords = %#v, want %#v", got, want)
	}
}

func assertMatcherInvariant(t *testing.T, pattern string) {
	t.Helper()
	if err := validateMatcherInvariant(pattern); err != nil {
		t.Fatalf("unsafe matcher invariant: %v", err)
	}
	if _, err := regexp.Compile(pattern); err != nil {
		t.Fatalf("generated regex does not compile: %v pattern=%q", err, pattern)
	}
}
