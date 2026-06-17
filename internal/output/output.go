package output

import (
	"bytes"
	"fmt"
	"io"
	"regexp"
	"regexp/syntax"
	"unicode/utf8"

	"github.com/Kritoooo/agentssh/internal/policy"
)

const redacted = "«REDACTED»"

// DefaultMaxLineCap bounds an unterminated streaming line before it is forced
// through redaction. It is intentionally far larger than ordinary secrets.
const DefaultMaxLineCap = 1 << 20

// FilterResult is the agent-visible output after redaction and truncation.
type FilterResult struct {
	Stdout          string
	Stderr          string
	OutputTruncated bool
	Redactions      int
}

// Filter redacts and truncates command output before it is returned to an agent.
type Filter interface {
	Apply(stdout string, stderr string) FilterResult
}

// StreamFilter is a compiled filter that can also redact incremental output.
type StreamFilter interface {
	Filter
	NewStreamWriter(dst io.Writer) *StreamWriter
}

// NewFilter compiles output filtering policy.
func NewFilter(config policy.Output) (Filter, error) {
	compiled := compiledFilter{maxBytes: config.MaxBytes}
	for i, pattern := range config.Redact {
		parsed, err := validateRedactPattern(pattern, i)
		if err != nil {
			return nil, err
		}
		expr, err := regexp.Compile(pattern)
		if err != nil {
			return nil, fmt.Errorf("output.redact[%d] invalid regex %q: %w", i, pattern, err)
		}
		beginText, ok := beginTextMode(parsed)
		if !ok {
			return nil, fmt.Errorf("output.redact[%d] pattern %q mixes whole-output anchors with unanchored matches; use (?m) line anchors for streaming output", i, pattern)
		}
		compiled.redact = append(compiled.redact, compiledRedact{
			expr:      expr,
			beginText: beginText,
		})
	}
	return compiled, nil
}

type compiledFilter struct {
	maxBytes int
	redact   []compiledRedact
}

type compiledRedact struct {
	expr      *regexp.Regexp
	beginText bool
}

func (f compiledFilter) NewStreamWriter(dst io.Writer) *StreamWriter {
	return newStreamWriter(dst, f, DefaultMaxLineCap)
}

func (f compiledFilter) Apply(stdout string, stderr string) FilterResult {
	filteredStdout, stdoutRedactions := f.redactString(stdout)
	filteredStderr, stderrRedactions := f.redactString(stderr)

	var stdoutTruncated bool
	var stderrTruncated bool
	filteredStdout, stdoutTruncated = truncateUTF8(filteredStdout, f.maxBytes)
	filteredStderr, stderrTruncated = truncateUTF8(filteredStderr, f.maxBytes)

	return FilterResult{
		Stdout:          filteredStdout,
		Stderr:          filteredStderr,
		OutputTruncated: stdoutTruncated || stderrTruncated,
		Redactions:      stdoutRedactions + stderrRedactions,
	}
}

func (f compiledFilter) redactString(value string) (string, int) {
	return f.redactValue(value, true)
}

func (f compiledFilter) redactLine(value string, atTextStart bool) (string, int) {
	return f.redactValue(value, atTextStart)
}

func (f compiledFilter) redactValue(value string, atTextStart bool) (string, int) {
	redactions := 0
	for _, rule := range f.redact {
		if rule.beginText && !atTextStart {
			continue
		}
		matches := rule.expr.FindAllStringIndex(value, -1)
		redactions += len(matches)
		if len(matches) > 0 {
			value = rule.expr.ReplaceAllString(value, redacted)
		}
	}
	return value, redactions
}

// StreamWriter line-buffers, redacts, truncates, and forwards one output stream.
//
// It assumes a single goroutine calls Write. Stdout and stderr must use
// separate instances.
type StreamWriter struct {
	dst        io.Writer
	filter     compiledFilter
	maxLineCap int

	partial   []byte
	emitted   []byte
	redacts   int
	truncated bool
	processed bool
}

func newStreamWriter(dst io.Writer, filter compiledFilter, maxLineCap int) *StreamWriter {
	if maxLineCap <= 0 {
		maxLineCap = DefaultMaxLineCap
	}
	return &StreamWriter{dst: dst, filter: filter, maxLineCap: maxLineCap}
}

func (w *StreamWriter) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	w.partial = append(w.partial, p...)
	for len(w.partial) > 0 {
		if idx := bytes.IndexByte(w.partial, '\n'); idx >= 0 {
			w.processLine(w.partial[:idx+1])
			w.partial = w.partial[idx+1:]
			continue
		}
		if len(w.partial) >= w.maxLineCap {
			w.processLine(w.partial[:w.maxLineCap])
			w.partial = w.partial[w.maxLineCap:]
			continue
		}
		break
	}
	return len(p), nil
}

// Flush emits the final unterminated line after command execution has finished.
func (w *StreamWriter) Flush() {
	if len(w.partial) == 0 {
		return
	}
	w.processLine(w.partial)
	w.partial = nil
}

func (w *StreamWriter) Emitted() []byte {
	return append([]byte(nil), w.emitted...)
}

func (w *StreamWriter) Redactions() int {
	return w.redacts
}

func (w *StreamWriter) Truncated() bool {
	return w.truncated
}

func (w *StreamWriter) processLine(line []byte) {
	filtered, redactions := w.filter.redactLine(string(line), !w.processed)
	w.processed = true
	w.redacts += redactions
	if w.truncated {
		return
	}
	if w.filter.maxBytes > 0 {
		remaining := w.filter.maxBytes - len(w.emitted)
		if remaining <= 0 {
			if len(filtered) > 0 {
				w.truncated = true
			}
			return
		}
		if len(filtered) > remaining {
			filtered = truncateUTF8Prefix(filtered, remaining)
			w.truncated = true
		}
	}
	w.emit([]byte(filtered))
}

func (w *StreamWriter) emit(p []byte) {
	if len(p) == 0 {
		return
	}
	w.emitted = append(w.emitted, p...)
	if w.dst != nil {
		_, _ = w.dst.Write(p)
	}
}

func truncateUTF8(value string, maxBytes int) (string, bool) {
	if maxBytes <= 0 || len(value) <= maxBytes {
		return value, false
	}

	return truncateUTF8Prefix(value, maxBytes), true
}

func truncateUTF8Prefix(value string, maxBytes int) string {
	if maxBytes <= 0 {
		return ""
	}
	cut := maxBytes
	for cut > 0 && !utf8.ValidString(value[:cut]) {
		cut--
	}
	return value[:cut]
}

func validateRedactPattern(pattern string, index int) (*syntax.Regexp, error) {
	if bytes.Contains([]byte(pattern), []byte{'\n'}) || bytes.Contains([]byte(pattern), []byte(`\n`)) {
		return nil, fmt.Errorf("output.redact[%d] pattern %q spans lines; streaming output only supports line-local redaction", index, pattern)
	}
	parsed, err := syntax.Parse(pattern, syntax.Perl)
	if err == nil && containsDotNL(parsed) {
		return nil, fmt.Errorf("output.redact[%d] pattern %q enables (?s); streaming output only supports line-local redaction", index, pattern)
	}
	return parsed, nil
}

func containsDotNL(expr *syntax.Regexp) bool {
	if expr == nil {
		return false
	}
	if expr.Flags&syntax.DotNL != 0 || expr.Op == syntax.OpAnyChar {
		return true
	}
	for _, sub := range expr.Sub {
		if containsDotNL(sub) {
			return true
		}
	}
	return false
}

func beginTextMode(expr *syntax.Regexp) (bool, bool) {
	if !containsBeginText(expr) {
		return false, true
	}
	return startsWithBeginText(expr), startsWithBeginText(expr)
}

func startsWithBeginText(expr *syntax.Regexp) bool {
	if expr == nil {
		return false
	}
	switch expr.Op {
	case syntax.OpBeginText:
		return true
	case syntax.OpCapture:
		return len(expr.Sub) == 1 && startsWithBeginText(expr.Sub[0])
	case syntax.OpConcat:
		return len(expr.Sub) > 0 && startsWithBeginText(expr.Sub[0])
	case syntax.OpAlternate:
		if len(expr.Sub) == 0 {
			return false
		}
		for _, sub := range expr.Sub {
			if !startsWithBeginText(sub) {
				return false
			}
		}
		return true
	default:
		return false
	}
}

func containsBeginText(expr *syntax.Regexp) bool {
	if expr == nil {
		return false
	}
	if expr.Op == syntax.OpBeginText {
		return true
	}
	for _, sub := range expr.Sub {
		if containsBeginText(sub) {
			return true
		}
	}
	return false
}
