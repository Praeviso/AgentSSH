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
