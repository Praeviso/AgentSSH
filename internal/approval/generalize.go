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

const tailTokenClass = `[A-Za-z0-9@%+=:,./_-]+`

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
	if mode == "" {
		mode = HostGrantSafePrefix
	}
	forceExact := scanForExactOnly(command)
	tokens := splitASCIIWords(command)
	if len(tokens) == 0 {
		return exactMatcher(command, true), nil
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
	if forceExact || mode == HostGrantExact {
		return exactMatcher(command, promotable), nil
	}

	prefix := prefixForMode(tokens, head, mode)
	if len(prefix) == 0 || !tailTokensSafe(tokens[len(prefix):]) {
		return exactMatcher(command, promotable), nil
	}
	return prefixMatcher(command, prefix, promotable), nil
}

func Exact(command string) (Matcher, error) {
	if strings.Contains(command, "\x00") {
		return Matcher{}, ErrNULCommand
	}
	return exactMatcher(command, true), nil
}

func exactMatcher(command string, promotable bool) Matcher {
	return mustValidateMatcher(Matcher{
		Kind:       MatcherExact,
		Regex:      `\A` + quoteBytesForRegexp(command) + `\z`,
		Promotable: promotable,
		SourceCmd:  command,
	})
}

func prefixMatcher(command string, prefix []string, promotable bool) Matcher {
	parts := make([]string, 0, len(prefix))
	for _, token := range prefix {
		parts = append(parts, quoteBytesForRegexp(token))
	}
	return mustValidateMatcher(Matcher{
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
				return []string{tokens[0], tokens[1]}
			}
		}
		if head == "journalctl" {
			return []string{tokens[0]}
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
			b == '@' || b == '%' || b == '+' || b == '=' || b == ':' || b == ',' || b == '/' || b == '_' || b == '-' {
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
