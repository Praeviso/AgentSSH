package audit_test

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/Praeviso/AgentSSH/internal/audit"
)

// A command string can approach the local execve argument limit (~128 KiB),
// which exceeds the default 64 KiB bufio.Scanner token cap. Appending started
// then completed for such a command re-reads the log to chain; the reader must
// handle the oversized line, and the chain must verify.
func TestAppendVerifyLargeCommandRecords(t *testing.T) {
	store := audit.NewStore(filepath.Join(t.TempDir(), "audit.log"))
	bigCmd := "echo " + strings.Repeat("x", 100*1024) // ~100 KiB, over the 64 KiB scanner cap

	if _, err := store.Append(audit.Record{ReqID: "r1", Event: audit.EventStarted, Host: "web-1", Cmd: bigCmd}); err != nil {
		t.Fatalf("append started: %v", err)
	}
	exit := 0
	if _, err := store.Append(audit.Record{ReqID: "r1", Event: audit.EventCompleted, Host: "web-1", Cmd: bigCmd, ExitCode: &exit}); err != nil {
		t.Fatalf("append completed (re-read of oversized started record failed): %v", err)
	}

	records, err := store.ReadAll()
	if err != nil {
		t.Fatalf("read all: %v", err)
	}
	if len(records) != 2 || records[0].Cmd != bigCmd || records[1].Cmd != bigCmd {
		t.Fatalf("records not round-tripped intact: len=%d", len(records))
	}
	result, err := store.Verify()
	if err != nil || !result.OK {
		t.Fatalf("verify = %#v err=%v", result, err)
	}
}
