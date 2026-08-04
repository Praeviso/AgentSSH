package approval

import (
	"errors"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"
)

type HostGrantMode string

const (
	HostGrantExact      HostGrantMode = "exact"
	HostGrantSafePrefix HostGrantMode = "safe-prefix"
	HostGrantPrefix     HostGrantMode = "prefix"
)

var ErrNULCommand = errors.New("approval command contains NUL")

// ErrInvalidUTF8Command rejects commands that are not valid UTF-8. Go's regexp
// has no way to express a single invalid byte: `\xF3` in a pattern denotes the
// *rune* U+00F3 (encoded C3 B3), not the byte 0xF3. A matcher generated from
// such a command would therefore fail to match the approved command while
// matching a different one, so these commands are rejected outright rather
// than approved with a matcher that cannot mean what it says.
var ErrInvalidUTF8Command = errors.New("approval command is not valid UTF-8")

const tailTokenClass = `[A-Za-z0-9@%+=:,./_-]+`

// literalSafePunct lists the punctuation bytes quoteBytesForRegexp may emit
// verbatim into a regex. Every byte here MUST be a regex non-metacharacter:
// the output is spliced into a pattern outside any character class, so a
// quantifier ('+', '*', '?') would silently rewrite the pattern's meaning.
// '+' used to live here and did exactly that — an approved "a+b" produced
// \Aa+b\z, which failed to match its own source yet matched "ab" and "aab",
// authorizing commands the operator never approved.
// TestLiteralAllowlistContainsNoRegexMetachar enforces this invariant.
// Note: tailTokenClass above is a character class, where '+' is literal and
// the trailing '+' is a deliberate quantifier — that one is correct as-is.
const literalSafePunct = `@%=:,/_-`

var interpreterOrEscapable = map[string]struct{}{
	"sh": {}, "bash": {}, "dash": {}, "zsh": {}, "ksh": {}, "env": {}, "find": {}, "xargs": {},
	"awk": {}, "gawk": {}, "sed": {}, "perl": {}, "ruby": {}, "node": {}, "php": {},
	"vi": {}, "vim": {}, "nano": {}, "emacs": {}, "less": {}, "more": {}, "man": {},
	"tar": {}, "zip": {}, "unzip": {}, "ssh": {}, "scp": {}, "rsync": {}, "nc": {}, "socat": {},
	"tee": {}, "watch": {}, "flock": {}, "setsid": {}, "ionice": {}, "nohup": {},
}

var privilegedCommands = map[string]struct{}{
	"sudo": {}, "su": {}, "doas": {},
}

var destructiveLeafCommands = map[string]struct{}{
	"rm": {}, "rmdir": {}, "dd": {}, "shred": {}, "shutdown": {}, "reboot": {}, "halt": {},
	"poweroff": {}, "kill": {}, "pkill": {}, "killall": {}, "chmod": {}, "chown": {}, "mv": {},
	"truncate": {}, "fdisk": {}, "parted": {},
}

var safeReadonlyLeaf = map[string]struct{}{
	"ls": {}, "df": {}, "free": {}, "uptime": {}, "uname": {}, "hostname": {}, "ps": {},
	"whoami": {}, "id": {}, "date": {},
}

var safeReadonlySubcommands = map[string]map[string]struct{}{
	"systemctl": {"status": {}, "is-active": {}, "is-enabled": {}, "show": {}, "cat": {}, "list-units": {}},
	"git":       {"status": {}, "log": {}, "diff": {}, "show": {}},
	"kubectl":   {"get": {}, "describe": {}, "logs": {}},
}

var multiCommand = map[string]struct{}{
	"systemctl": {}, "git": {}, "kubectl": {}, "docker": {}, "helm": {}, "service": {},
}

func Generalize(command string, mode HostGrantMode) (Matcher, error) {
	if strings.Contains(command, "\x00") {
		return Matcher{}, ErrNULCommand
	}
	if !utf8.ValidString(command) {
		return Matcher{}, ErrInvalidUTF8Command
	}
	if mode == "" {
		mode = HostGrantSafePrefix
	}
	forceExact := scanForExactOnly(command)
	tokens := splitASCIIWords(command)
	if len(tokens) == 0 {
		return exactMatcher(command, true)
	}
	head := commandBase(tokens[0])
	promotable := true
	if _, ok := privilegedCommands[head]; ok {
		promotable = false
		forceExact = true
	}
	if isInterpreterOrEscapable(head) || isDestructiveLeaf(head) || hasEnvPrefix(command) {
		forceExact = true
	}
	// splitASCIIWords drops leading spaces, and prefixMatcher rebuilds the
	// pattern from tokens — so a leading-space command would produce a prefix
	// matcher that cannot match the command it came from. The exact matcher
	// preserves bytes, and is the narrower choice regardless.
	if strings.HasPrefix(command, " ") {
		forceExact = true
	}
	if forceExact || mode == HostGrantExact {
		return exactMatcher(command, promotable)
	}

	prefix := prefixForMode(tokens, head, mode)
	tail := tokens[len(prefix):]
	if len(prefix) == 0 || !tailTokensSafe(tail) || (mode == HostGrantSafePrefix && !safePrefixTailTokensSafe(head, tail)) {
		return exactMatcher(command, promotable)
	}
	return prefixMatcher(command, prefix, promotable)
}

func Exact(command string) (Matcher, error) {
	if strings.Contains(command, "\x00") {
		return Matcher{}, ErrNULCommand
	}
	if !utf8.ValidString(command) {
		return Matcher{}, ErrInvalidUTF8Command
	}
	return exactMatcher(command, true)
}

func exactMatcher(command string, promotable bool) (Matcher, error) {
	return newMatcher(Matcher{
		Kind:       MatcherExact,
		Regex:      `\A` + quoteBytesForRegexp(command) + `\z`,
		Promotable: promotable,
		SourceCmd:  command,
	})
}

func prefixMatcher(command string, prefix []string, promotable bool) (Matcher, error) {
	parts := make([]string, 0, len(prefix))
	for _, token := range prefix {
		parts = append(parts, quoteBytesForRegexp(token))
	}
	return newMatcher(Matcher{
		Kind:       MatcherPrefix,
		Regex:      `\A` + strings.Join(parts, `[ \t]+`) + `(?:[ \t]+` + tailTokenClass + `)*[ \t]*\z`,
		Prefix:     append([]string(nil), prefix...),
		Promotable: promotable,
		SourceCmd:  command,
	})
}

func scanForExactOnly(command string) bool {
	for i := 0; i < len(command); i++ {
		b := command[i]
		if b < 0x20 || b == 0x7f {
			return true
		}
		if strings.ContainsRune(";&|(){}`$<>'\"\\*?[]~!#", rune(b)) {
			return true
		}
		if b >= 0x80 {
			for _, r := range command[i:] {
				if unicode.IsSpace(r) {
					return true
				}
			}
			break
		}
	}
	return false
}

func splitASCIIWords(command string) []string {
	var tokens []string
	start := -1
	for i := 0; i < len(command); i++ {
		if command[i] == ' ' {
			if start >= 0 {
				tokens = append(tokens, command[start:i])
				start = -1
			}
			continue
		}
		if start < 0 {
			start = i
		}
	}
	if start >= 0 {
		tokens = append(tokens, command[start:])
	}
	return tokens
}

func hasEnvPrefix(command string) bool {
	trimmed := strings.TrimLeft(command, " ")
	if trimmed == "" {
		return false
	}
	first := trimmed
	if idx := strings.IndexByte(trimmed, ' '); idx >= 0 {
		first = trimmed[:idx]
	}
	eq := strings.IndexByte(first, '=')
	if eq <= 0 || eq == len(first)-1 {
		return false
	}
	for i := 0; i < eq; i++ {
		b := first[i]
		if (b < 'A' || b > 'Z') && (b < 'a' || b > 'z') && (b < '0' || b > '9') && b != '_' {
			return false
		}
	}
	return true
}

func commandBase(token string) string {
	token = strings.TrimSpace(token)
	if idx := strings.LastIndexByte(token, '/'); idx >= 0 {
		token = token[idx+1:]
	}
	return strings.ToLower(token)
}

func isInterpreterOrEscapable(head string) bool {
	if _, ok := interpreterOrEscapable[head]; ok {
		return true
	}
	return strings.HasPrefix(head, "python")
}

func isDestructiveLeaf(head string) bool {
	if _, ok := destructiveLeafCommands[head]; ok {
		return true
	}
	return strings.HasPrefix(head, "mkfs")
}

func prefixForMode(tokens []string, head string, mode HostGrantMode) []string {
	switch mode {
	case HostGrantSafePrefix:
		if _, ok := safeReadonlyLeaf[head]; ok {
			return []string{tokens[0]}
		}
		if subcommands, ok := safeReadonlySubcommands[head]; ok && len(tokens) >= 2 {
			if _, ok := subcommands[strings.ToLower(tokens[1])]; ok {
				prefix := []string{tokens[0], tokens[1]}
				// Multi-tool read-only subcommands still have semantic positionals
				// (for example, kubectl resource names). Pin a leading positional
				// when present so a host grant does not silently widen across them.
				if (head == "git" || head == "kubectl") && len(tokens) >= 3 && !strings.HasPrefix(tokens[2], "-") {
					prefix = append(prefix, tokens[2])
				}
				return prefix
			}
		}
		return nil
	case HostGrantPrefix:
		if _, ok := multiCommand[head]; ok && len(tokens) >= 2 {
			return []string{tokens[0], tokens[1]}
		}
		return []string{tokens[0]}
	default:
		return nil
	}
}

func tailTokensSafe(tokens []string) bool {
	for _, token := range tokens {
		if token == "" {
			return false
		}
		for i := 0; i < len(token); i++ {
			if !isTailByte(token[i]) {
				return false
			}
		}
	}
	return true
}

func safePrefixTailTokensSafe(head string, tokens []string) bool {
	for _, token := range tokens {
		if strings.HasPrefix(token, "-") && strings.Contains(token, "=") {
			return false
		}
		if dangerousSafePrefixOption(head, token) {
			return false
		}
	}
	return true
}

func dangerousSafePrefixOption(head string, token string) bool {
	for _, opt := range dangerousSafePrefixOptions(head) {
		if token == opt || strings.HasPrefix(token, opt+"=") {
			return true
		}
	}
	return false
}

func dangerousSafePrefixOptions(head string) []string {
	opts := []string{
		"--output",
		"--as",
		"--as-group",
		"--token",
		"--kubeconfig",
		"--server",
		"--vacuum-time",
		"--vacuum-size",
		"--vacuum-files",
		"--rotate",
		"--flush",
	}
	if head == "git" {
		opts = append(opts, "-o")
	}
	return opts
}

func isTailByte(b byte) bool {
	return (b >= 'A' && b <= 'Z') ||
		(b >= 'a' && b <= 'z') ||
		(b >= '0' && b <= '9') ||
		b == '@' || b == '%' || b == '+' || b == '=' || b == ':' || b == ',' ||
		b == '.' || b == '/' || b == '_' || b == '-'
}

func quoteBytesForRegexp(value string) string {
	var builder strings.Builder
	for i := 0; i < len(value); {
		b := value[i]
		if (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z') || (b >= '0' && b <= '9') ||
			strings.IndexByte(literalSafePunct, b) >= 0 {
			builder.WriteByte(b)
			i++
			continue
		}
		if b >= 0x80 {
			r, size := utf8.DecodeRuneInString(value[i:])
			if r != utf8.RuneError || size > 1 {
				_, _ = fmt.Fprintf(&builder, `\x{%X}`, r)
				i += size
				continue
			}
		}
		_, _ = fmt.Fprintf(&builder, `\x%02X`, b)
		i++
	}
	return builder.String()
}
