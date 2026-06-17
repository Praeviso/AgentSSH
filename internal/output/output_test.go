package output

import (
	"strings"
	"testing"

	"github.com/Kritoooo/agentssh/internal/policy"
)

func TestRedactionReplacesMatchesAndCountsBothStreams(t *testing.T) {
	filter := mustFilter(t, policy.Output{
		Redact: []string{`password=\S+`, `token=\S+`},
	})

	result := filter.Apply("password=secret token=abc\n", "password=stderr\n")
	if got, want := result.Stdout, redacted+" "+redacted+"\n"; got != want {
		t.Fatalf("stdout = %q, want %q", got, want)
	}
	if got, want := result.Stderr, redacted+"\n"; got != want {
		t.Fatalf("stderr = %q, want %q", got, want)
	}
	if result.Redactions != 3 {
		t.Fatalf("redactions = %d, want 3", result.Redactions)
	}
	if result.OutputTruncated {
		t.Fatal("OutputTruncated = true, want false")
	}
}

func TestTruncateMaxBytesUTF8Safe(t *testing.T) {
	filter := mustFilter(t, policy.Output{MaxBytes: 7})
	result := filter.Apply("hello世界", "")
	if got, want := result.Stdout, "hello"; got != want {
		t.Fatalf("stdout = %q, want %q", got, want)
	}
	if !result.OutputTruncated {
		t.Fatal("OutputTruncated = false, want true")
	}
}

func TestRedactThenTruncate(t *testing.T) {
	filter := mustFilter(t, policy.Output{
		MaxBytes: 10,
		Redact:   []string{`password=\S+`},
	})
	result := filter.Apply("prefix password=secret suffix", "")
	if !strings.HasPrefix(result.Stdout, "prefix ") {
		t.Fatalf("stdout was not redacted before truncation: %q", result.Stdout)
	}
	if result.Redactions != 1 || !result.OutputTruncated {
		t.Fatalf("result = %#v", result)
	}
}

func TestNoopPolicy(t *testing.T) {
	filter := mustFilter(t, policy.Output{})
	result := filter.Apply("stdout", "stderr")
	if result.Stdout != "stdout" || result.Stderr != "stderr" || result.Redactions != 0 || result.OutputTruncated {
		t.Fatalf("result = %#v", result)
	}
}

func TestInvalidRegex(t *testing.T) {
	_, err := NewFilter(policy.Output{Redact: []string{"["}})
	if err == nil {
		t.Fatal("NewFilter invalid regex error = nil")
	}
}

func mustFilter(t *testing.T, config policy.Output) Filter {
	t.Helper()
	filter, err := NewFilter(config)
	if err != nil {
		t.Fatalf("NewFilter: %v", err)
	}
	return filter
}
