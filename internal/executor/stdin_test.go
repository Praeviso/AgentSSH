package executor

import (
	"bytes"
	"context"
	"testing"
)

func TestExecRunnerFeedsStdin(t *testing.T) {
	result := ExecRunner{}.Run(context.Background(), []string{"cat"}, []byte("hello stdin"))
	if result.Err != nil || result.ExitCode != 0 {
		t.Fatalf("cat failed: exit=%d err=%v", result.ExitCode, result.Err)
	}
	if result.Stdout != "hello stdin" {
		t.Fatalf("stdout=%q", result.Stdout)
	}
}

func TestExecRunnerNilStdinKeepsDevNull(t *testing.T) {
	// With no stdin the child must see EOF immediately, not block.
	result := ExecRunner{}.Run(context.Background(), []string{"cat"}, nil)
	if result.Err != nil || result.ExitCode != 0 {
		t.Fatalf("cat failed: exit=%d err=%v", result.ExitCode, result.Err)
	}
	if result.Stdout != "" {
		t.Fatalf("stdout=%q want empty", result.Stdout)
	}
}

func TestRunStreamingProcessFeedsStdin(t *testing.T) {
	var stdout, stderr bytes.Buffer
	result := runStreamingProcess(context.Background(), []string{"cat"}, []byte("streamed"), &stdout, &stderr)
	if result.Err != nil || result.ExitCode != 0 {
		t.Fatalf("cat failed: exit=%d err=%v", result.ExitCode, result.Err)
	}
	if stdout.String() != "streamed" {
		t.Fatalf("stdout=%q", stdout.String())
	}
}
