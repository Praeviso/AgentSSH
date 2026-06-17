package output

import (
	"bytes"
	"strings"
	"testing"

	"github.com/Praeviso/AgentSSH/internal/policy"
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

func TestStreamWriterMatchesBufferedApply(t *testing.T) {
	config := policy.Output{
		MaxBytes: 80,
		Redact:   []string{`password=\S+`, `token=\S+`, `line-secret=\S+`, `end-secret=\S+`, `^start-secret=\S+`},
	}
	inputs := []string{
		"password=secret123\nsafe\n",
		"prefix password=secret123 suffix\r\nnext token=abc\n",
		"line-secret=abc\nplain\nend-secret=xyz",
		"utf8 世界 password=secret\n",
		"no-newline password=tail",
		"start-secret=first\nstart-secret=second\n",
	}
	chunkSizes := []int{1, 2, 3, 7, 64}
	for _, input := range inputs {
		for _, chunkSize := range chunkSizes {
			t.Run(input+"/"+string(rune('0'+chunkSize)), func(t *testing.T) {
				filter := mustStreamFilter(t, config)
				buffered := filter.Apply(input, "")

				var dst bytes.Buffer
				writer := filter.NewStreamWriter(&dst)
				writeChunks(t, writer, []byte(input), chunkSize)
				writer.Flush()

				if got := string(writer.Emitted()); got != buffered.Stdout {
					t.Fatalf("stream emitted = %q, buffered = %q", got, buffered.Stdout)
				}
				if got := dst.String(); got != buffered.Stdout {
					t.Fatalf("dst = %q, buffered = %q", got, buffered.Stdout)
				}
				if writer.Redactions() != buffered.Redactions {
					t.Fatalf("redactions = %d, buffered = %d", writer.Redactions(), buffered.Redactions)
				}
				if writer.Truncated() != buffered.OutputTruncated {
					t.Fatalf("truncated = %t, buffered = %t", writer.Truncated(), buffered.OutputTruncated)
				}
			})
		}
	}
}

func TestStreamWriterDoesNotLeakAcrossChunks(t *testing.T) {
	filter := mustStreamFilter(t, policy.Output{Redact: []string{`password=\S+`}})
	var dst bytes.Buffer
	writer := filter.NewStreamWriter(&dst)
	if n, err := writer.Write([]byte("password=")); err != nil || n != len("password=") {
		t.Fatalf("first write n=%d err=%v", n, err)
	}
	if dst.Len() != 0 {
		t.Fatalf("partial line leaked before newline: %q", dst.String())
	}
	if n, err := writer.Write([]byte("secret\n")); err != nil || n != len("secret\n") {
		t.Fatalf("second write n=%d err=%v", n, err)
	}
	writer.Flush()
	if strings.Contains(dst.String(), "secret") || !strings.Contains(dst.String(), redacted) {
		t.Fatalf("stream output leaked secret: %q", dst.String())
	}
}

func TestStreamWriterTruncatesUTF8AndKeepsConsuming(t *testing.T) {
	filter := mustStreamFilter(t, policy.Output{MaxBytes: 7, Redact: []string{`password=\S+`}})
	var dst bytes.Buffer
	writer := filter.NewStreamWriter(&dst)
	input := []byte("hello世界\npassword=secret\n")
	n, err := writer.Write(input)
	if err != nil || n != len(input) {
		t.Fatalf("write n=%d err=%v, want n=%d nil", n, err, len(input))
	}
	writer.Flush()
	if got, want := dst.String(), "hello"; got != want {
		t.Fatalf("dst = %q, want %q", got, want)
	}
	if got, want := string(writer.Emitted()), "hello"; got != want {
		t.Fatalf("emitted = %q, want %q", got, want)
	}
	if !writer.Truncated() {
		t.Fatal("Truncated = false, want true")
	}
	if writer.Redactions() != 1 {
		t.Fatalf("redactions = %d, want 1", writer.Redactions())
	}
}

func TestStreamWriterFlushesTailLineWithSecret(t *testing.T) {
	filter := mustStreamFilter(t, policy.Output{Redact: []string{`password=\S+`}})
	var dst bytes.Buffer
	writer := filter.NewStreamWriter(&dst)
	if _, err := writer.Write([]byte("tail password=secret")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if dst.Len() != 0 {
		t.Fatalf("tail line emitted before flush: %q", dst.String())
	}
	writer.Flush()
	if got, want := dst.String(), "tail "+redacted; got != want {
		t.Fatalf("dst = %q, want %q", got, want)
	}
}

func TestNewFilterRejectsMultiLinePatterns(t *testing.T) {
	tests := []string{`(?s)BEGIN.*END`, `(?s)secret`, "BEGIN\nEND", `BEGIN\nEND`}
	for _, pattern := range tests {
		t.Run(pattern, func(t *testing.T) {
			_, err := NewFilter(policy.Output{Redact: []string{pattern}})
			if err == nil {
				t.Fatal("NewFilter error = nil")
			}
		})
	}
}

func TestNewFilterAllowsLineLocalAnchors(t *testing.T) {
	if _, err := NewFilter(policy.Output{Redact: []string{`^secret`, `secret$`, `(?m)^secret`, `(?m)secret$`}}); err != nil {
		t.Fatalf("NewFilter with anchors: %v", err)
	}
}

func TestNewFilterRejectsMixedWholeOutputAnchor(t *testing.T) {
	if _, err := NewFilter(policy.Output{Redact: []string{`foo|^secret`}}); err == nil {
		t.Fatal("NewFilter error = nil")
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

func mustStreamFilter(t *testing.T, config policy.Output) StreamFilter {
	t.Helper()
	filter, err := NewFilter(config)
	if err != nil {
		t.Fatalf("NewFilter: %v", err)
	}
	streamFilter, ok := filter.(StreamFilter)
	if !ok {
		t.Fatalf("filter %T does not implement StreamFilter", filter)
	}
	return streamFilter
}

func writeChunks(t *testing.T, writer *StreamWriter, input []byte, chunkSize int) {
	t.Helper()
	for len(input) > 0 {
		n := chunkSize
		if n > len(input) {
			n = len(input)
		}
		written, err := writer.Write(input[:n])
		if err != nil {
			t.Fatalf("write: %v", err)
		}
		if written != n {
			t.Fatalf("write n=%d, want %d", written, n)
		}
		input = input[n:]
	}
}
