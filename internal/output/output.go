package output

import (
	"fmt"
	"regexp"
	"unicode/utf8"

	"github.com/Kritoooo/agentssh/internal/policy"
)

const redacted = "«REDACTED»"

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

// NewFilter compiles output filtering policy.
func NewFilter(config policy.Output) (Filter, error) {
	compiled := compiledFilter{maxBytes: config.MaxBytes}
	for i, pattern := range config.Redact {
		expr, err := regexp.Compile(pattern)
		if err != nil {
			return nil, fmt.Errorf("output.redact[%d] invalid regex %q: %w", i, pattern, err)
		}
		compiled.redact = append(compiled.redact, expr)
	}
	return compiled, nil
}

type compiledFilter struct {
	maxBytes int
	redact   []*regexp.Regexp
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
	redactions := 0
	for _, expr := range f.redact {
		matches := expr.FindAllStringIndex(value, -1)
		redactions += len(matches)
		if len(matches) > 0 {
			value = expr.ReplaceAllString(value, redacted)
		}
	}
	return value, redactions
}

func truncateUTF8(value string, maxBytes int) (string, bool) {
	if maxBytes <= 0 || len(value) <= maxBytes {
		return value, false
	}

	cut := maxBytes
	for cut > 0 && !utf8.ValidString(value[:cut]) {
		cut--
	}
	return value[:cut], true
}
