package approval

import (
	"regexp"
	"strings"
	"testing"
	"unicode/utf8"
)

// FuzzExactMatcherSelfMatch asserts the two properties an exact matcher must
// hold for any command: it matches the command it was generated from, and it
// matches nothing else. The '+' defect violated both at once — the generated
// pattern failed against its own source while matching shorter variants — and
// went unnoticed because the hand-written corpus happened to contain no '+'.
func FuzzExactMatcherSelfMatch(f *testing.F) {
	seeds := []string{
		"echo a+b",
		"x++",
		"a.+b",
		"deploy --tag v1+build",
		`docker exec c python -c "g=lambda p:u.urlopen(b+p,timeout=30)"`,
		"systemctl status nginx",
		"ls -la /var",
		"日志 --tail 20",
		"",
		" ",
	}
	// Every byte quoteBytesForRegexp may emit verbatim, so a future edit to the
	// allowlist is exercised here as well as in the table test.
	for i := 0; i < len(literalSafePunct); i++ {
		seeds = append(seeds, "a"+string(rune(literalSafePunct[i]))+"b")
	}
	for _, seed := range seeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, command string) {
		// NUL and invalid UTF-8 are rejected by contract (a matcher cannot
		// express a lone invalid byte), and long inputs only slow the mutation
		// sweep below without reaching new generator paths.
		if strings.ContainsRune(command, 0) || !utf8.ValidString(command) || len(command) > 256 {
			t.Skip()
		}
		matcher, err := Exact(command)
		if err != nil {
			t.Fatalf("Exact(%q): %v", command, err)
		}
		expr, err := regexp.Compile(matcher.Regex)
		if err != nil {
			t.Fatalf("generated regex does not compile: %v regex=%s", err, matcher.Regex)
		}
		if !expr.MatchString(command) {
			t.Fatalf("matcher does not match its source command %q: regex=%s", command, matcher.Regex)
		}
		// Exactness: no single-byte edit of the command may still match. Each
		// mutation changes the length by exactly one, so a mutant can never
		// coincide with the original and there are no false failures.
		limit := min(len(command), 64)
		for i := 0; i < limit; i++ {
			mutations := []string{
				command[:i] + command[i+1:],                // delete byte i
				command[:i] + command[i:i+1] + command[i:], // duplicate byte i
				command[:i] + "X" + command[i:],            // insert at i
			}
			for _, mutation := range mutations {
				if expr.MatchString(mutation) {
					t.Fatalf("matcher for %q also matched %q: regex=%s", command, mutation, matcher.Regex)
				}
			}
		}
	})
}

// FuzzGeneralizeNoWiden covers the prefix path, where a matcher legitimately
// matches more than its source: it must still never extend across a command
// separator into an unapproved command.
func FuzzGeneralizeNoWiden(f *testing.F) {
	for _, seed := range []string{
		"systemctl status nginx",
		"ls -la /var",
		"git diff HEAD",
		"kubectl get pods",
		"echo a+b",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, command string) {
		if strings.ContainsRune(command, 0) || !utf8.ValidString(command) || len(command) > 256 {
			t.Skip()
		}
		for _, mode := range []HostGrantMode{HostGrantExact, HostGrantSafePrefix, HostGrantPrefix} {
			matcher, err := Generalize(command, mode)
			if err != nil {
				t.Fatalf("Generalize(%q, %s): %v", command, mode, err)
			}
			matched, err := matcher.Match(command)
			if err != nil || !matched {
				t.Fatalf("matcher does not match its source command %q (mode %s): matched=%v err=%v regex=%s", command, mode, matched, err, matcher.Regex)
			}
			for _, suffix := range []string{"; rm -rf /", "\nid", " | id", " && id", "`id`"} {
				if matched, err := matcher.Match(command + suffix); err != nil || matched {
					t.Fatalf("matcher for %q (mode %s) reached across %q: matched=%v err=%v regex=%s", command, mode, suffix, matched, err, matcher.Regex)
				}
			}
		}
	})
}
