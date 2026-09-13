// Package commandline renders literal arguments and recognizes the deliberately
// small shell subset used by task permissions. It is not a shell interpreter.
package commandline

import (
	"fmt"
	"path"
	"slices"
	"strings"
	"unicode/utf8"
)

func Quote(word string) string {
	if word != "" && strings.IndexFunc(word, func(r rune) bool {
		allowed := r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("_@%+=:,./-", r)
		return !allowed
	}) < 0 {
		return word
	}
	return "'" + strings.ReplaceAll(word, "'", "'\"'\"'") + "'"
}

// Render preserves argument boundaries; Shell applies only an optional cwd to
// an already complete shell command. Both reject bytes SSH cannot convey safely.
func Render(argv []string, cwd string) (string, error) {
	if len(argv) == 0 || argv[0] == "" {
		return "", fmt.Errorf("argv requires a non-empty executable")
	}
	words := make([]string, len(argv))
	for i, word := range argv {
		if !utf8.ValidString(word) || strings.ContainsRune(word, 0) {
			return "", fmt.Errorf("argv must be valid UTF-8 without NUL")
		}
		words[i] = Quote(word)
		if i == 0 && (strings.Contains(word, "=") || slices.Contains([]string{"case", "do", "done", "elif", "else", "esac", "fi", "for", "if", "in", "then", "until", "while", "function", "select", "time", "coproc"}, word)) {
			// In command position, assignment words and reserved words need
			// quotes even when they consist only of otherwise safe characters.
			words[i] = "'" + strings.ReplaceAll(word, "'", "'\"'\"'") + "'"
		}
	}
	return Shell(strings.Join(words, " "), cwd)
}

func Shell(command, cwd string) (string, error) {
	if strings.TrimSpace(command) == "" || !utf8.ValidString(command) || strings.ContainsRune(command, 0) {
		return "", fmt.Errorf("command must be non-empty UTF-8 without NUL")
	}
	if cwd == "" {
		return command, nil
	}
	if !path.IsAbs(cwd) || !utf8.ValidString(cwd) || strings.ContainsAny(cwd, "\x00\r\n") {
		return "", fmt.Errorf("cwd must be an absolute remote path without NUL or newlines")
	}
	prefix := "cd " + Quote(path.Clean(cwd)) + " && "
	if _, nestedCWD, err := Parse(command); err == nil && nestedCWD == "" {
		return prefix + command, nil
	}
	// A compound command must be grouped: `cd missing && a; b` would run b
	// even when cd failed. The newline also terminates any trailing comment.
	return prefix + "( " + command + "\n)", nil
}

// Parse accepts literal words plus a single leading `cd <absolute path> &&`.
// Expansions, redirection, comments, globbing, newlines, and other operators are
// rejected. In single quotes all non-control characters are literal.
func Parse(command string) (argv []string, cwd string, err error) {
	if !utf8.ValidString(command) {
		return nil, "", fmt.Errorf("invalid UTF-8")
	}
	var words []string
	var word strings.Builder
	var quote rune
	started := false
	flush := func() {
		if started {
			words = append(words, word.String())
			word.Reset()
			started = false
		}
	}
	runes := []rune(command)
	for i := 0; i < len(runes); i++ {
		r := runes[i]
		if r < 32 && r != '\t' || r == 127 {
			return nil, "", fmt.Errorf("control character")
		}
		if quote == '\'' {
			if r == '\'' {
				quote = 0
			} else {
				word.WriteRune(r)
			}
			continue
		}
		if quote == '"' {
			switch r {
			case '"':
				quote = 0
			case '$', '`', '\\':
				return nil, "", fmt.Errorf("shell expansion or escape")
			default:
				word.WriteRune(r)
			}
			continue
		}
		switch r {
		case ' ', '\t':
			flush()
		case '\'', '"':
			quote = r
			started = true
		case '&':
			flush()
			if i+1 >= len(runes) || runes[i+1] != '&' || len(words) != 2 || words[0] != "cd" || cwd != "" || !path.IsAbs(words[1]) {
				return nil, "", fmt.Errorf("unsupported shell operator")
			}
			cwd = path.Clean(words[1])
			words = nil
			i++
		case ';', '|', '<', '>', '(', ')', '{', '}', '`', '$', '\\', '*', '?', '[', ']', '~', '!', '#':
			return nil, "", fmt.Errorf("unsupported shell syntax")
		default:
			word.WriteRune(r)
			started = true
		}
	}
	if quote != 0 {
		return nil, "", fmt.Errorf("unclosed quote")
	}
	flush()
	if len(words) == 0 || words[0] == "" {
		return nil, "", fmt.Errorf("empty command")
	}
	return words, cwd, nil
}
