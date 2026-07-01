package audit_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Praeviso/AgentSSH/internal/approval"
	"github.com/Praeviso/AgentSSH/internal/audit"
)

func TestAppendVerifyAndSeqContinuation(t *testing.T) {
	store := audit.NewStore(filepath.Join(t.TempDir(), "audit.log"))
	first, err := store.Append(audit.Record{ReqID: "r1", Event: audit.EventStarted, Host: "web-1"})
	if err != nil {
		t.Fatalf("append first: %v", err)
	}
	second, err := store.Append(audit.Record{ReqID: "r1", Event: audit.EventCompleted, Host: "web-1"})
	if err != nil {
		t.Fatalf("append second: %v", err)
	}
	if first.Seq != 0 || first.PrevHash != audit.ZeroHash {
		t.Fatalf("first = %#v", first)
	}
	if second.Seq != 1 || second.PrevHash != first.Hash {
		t.Fatalf("second = %#v first hash=%s", second, first.Hash)
	}
	result, err := store.Verify()
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !result.OK || result.Count != 2 {
		t.Fatalf("verify result = %#v", result)
	}

	reopened := audit.NewStore(store.Path)
	third, err := reopened.Append(audit.Record{ReqID: "r2", Event: audit.EventDenied, Host: "web-2"})
	if err != nil {
		t.Fatalf("append third: %v", err)
	}
	if third.Seq != 2 || third.PrevHash != second.Hash {
		t.Fatalf("third = %#v second hash=%s", third, second.Hash)
	}
}

func TestVerifyDetectsChangedDeletedInsertedRecords(t *testing.T) {
	t.Run("changed", func(t *testing.T) {
		store := testStoreWithRecords(t)
		records := mustRead(t, store)
		records[1].Host = "evil"
		writeRecords(t, store.Path, records)
		result, err := store.Verify()
		if err != nil {
			t.Fatalf("verify changed: %v", err)
		}
		if result.OK || result.BrokenSeq != 1 {
			t.Fatalf("changed result = %#v", result)
		}
	})

	t.Run("deleted", func(t *testing.T) {
		store := testStoreWithRecords(t)
		records := mustRead(t, store)
		writeRecords(t, store.Path, append(records[:1], records[2:]...))
		result, err := store.Verify()
		if err != nil {
			t.Fatalf("verify deleted: %v", err)
		}
		if result.OK || result.BrokenSeq != 2 {
			t.Fatalf("deleted result = %#v", result)
		}
	})

	t.Run("inserted", func(t *testing.T) {
		store := testStoreWithRecords(t)
		records := mustRead(t, store)
		inserted := audit.Record{Seq: 99, ReqID: "inserted", Event: audit.EventStarted, PrevHash: records[0].Hash}
		inserted.Hash = audit.ComputeHash(inserted)
		records = append(records[:1], append([]audit.Record{inserted}, records[1:]...)...)
		writeRecords(t, store.Path, records)
		result, err := store.Verify()
		if err != nil {
			t.Fatalf("verify inserted: %v", err)
		}
		if result.OK || result.BrokenSeq != 99 {
			t.Fatalf("inserted result = %#v", result)
		}
	})
}

func TestApprovalFieldsAreHashProtectedAndOldRecordsVerify(t *testing.T) {
	store := audit.NewStore(filepath.Join(t.TempDir(), "audit.log"))
	old, err := store.Append(audit.Record{ReqID: "old", Event: audit.EventStarted, Host: "web-1"})
	if err != nil {
		t.Fatalf("append old: %v", err)
	}
	approvalRecord, err := store.Append(audit.Record{
		ReqID:           "r1",
		Event:           audit.EventApprovalRequested,
		Host:            "web-1",
		ApprovalID:      "ap_0123456789abcdef01234567",
		ApprovalScope:   "session",
		ApprovalMatcher: `\Aid\z`,
		ApprovalChannel: approval.ChannelExit,
	})
	if err != nil {
		t.Fatalf("append approval: %v", err)
	}
	records := mustRead(t, store)
	records[0].Hash = audit.ComputeHash(records[0])
	if records[0].Hash != old.Hash {
		t.Fatalf("old hash changed after approval fields were added: %s != %s", records[0].Hash, old.Hash)
	}
	result, err := store.Verify()
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !result.OK {
		t.Fatalf("verify = %#v", result)
	}

	fields := []struct {
		name string
		edit func(*audit.Record)
	}{
		{"approval_id", func(r *audit.Record) { r.ApprovalID = "ap_ffffffffffffffffffffffff" }},
		{"approval_scope", func(r *audit.Record) { r.ApprovalScope = "host" }},
		{"approval_matcher", func(r *audit.Record) { r.ApprovalMatcher = `\Als\z` }},
		{"approval_channel", func(r *audit.Record) { r.ApprovalChannel = "cli" }},
	}
	for _, tt := range fields {
		t.Run(tt.name, func(t *testing.T) {
			tampered := append([]audit.Record(nil), records...)
			tt.edit(&tampered[1])
			writeRecords(t, store.Path, tampered)
			result, err := store.Verify()
			if err != nil {
				t.Fatalf("verify tamper: %v", err)
			}
			if result.OK || result.BrokenSeq != approvalRecord.Seq || result.Reason != "hash" {
				t.Fatalf("tamper result = %#v", result)
			}
			writeRecords(t, store.Path, records)
		})
	}
}

func TestTruncateBrokenRemovesBrokenTailAndBacksUp(t *testing.T) {
	store := testStoreWithRecords(t)
	records := mustRead(t, store)
	records[1].Host = "evil"
	writeRecords(t, store.Path, records)

	result, err := store.TruncateBroken()
	if err != nil {
		t.Fatalf("TruncateBroken: %v", err)
	}
	if !result.Changed || result.Kept != 1 || result.Removed != 2 || result.BrokenSeq != 1 || result.Reason != "hash" {
		t.Fatalf("repair result = %#v", result)
	}
	repaired := mustRead(t, store)
	if len(repaired) != 1 || repaired[0].ReqID != "r1" {
		t.Fatalf("repaired records = %#v", repaired)
	}
	verify, err := store.Verify()
	if err != nil {
		t.Fatalf("verify repaired: %v", err)
	}
	if !verify.OK || verify.Count != 1 {
		t.Fatalf("verify repaired = %#v", verify)
	}
	backup, err := os.ReadFile(result.BackupPath)
	if err != nil {
		t.Fatalf("read backup: %v", err)
	}
	if !strings.Contains(string(backup), `"host":"evil"`) {
		t.Fatalf("backup missing original corrupted record:\n%s", backup)
	}
}

func TestTruncateBrokenUsesBrokenIndexNotSeqValue(t *testing.T) {
	store := testStoreWithRecords(t)
	records := mustRead(t, store)
	records[1].Seq = 0
	writeRecords(t, store.Path, records)

	result, err := store.TruncateBroken()
	if err != nil {
		t.Fatalf("TruncateBroken: %v", err)
	}
	if !result.Changed || result.Kept != 1 || result.Removed != 2 || result.BrokenSeq != 0 || result.BrokenIndex != 1 || result.Reason != "seq" {
		t.Fatalf("repair result = %#v", result)
	}
	repaired := mustRead(t, store)
	if len(repaired) != 1 || repaired[0].ReqID != "r1" {
		t.Fatalf("repaired records = %#v", repaired)
	}
}

func TestTruncateBrokenNoopsWhenChainOK(t *testing.T) {
	store := testStoreWithRecords(t)
	result, err := store.TruncateBroken()
	if err != nil {
		t.Fatalf("TruncateBroken ok chain: %v", err)
	}
	if result.Changed || result.Kept != 3 || result.Removed != 0 {
		t.Fatalf("repair result = %#v", result)
	}
}

func testStoreWithRecords(t *testing.T) audit.Store {
	t.Helper()
	store := audit.NewStore(filepath.Join(t.TempDir(), "audit.log"))
	for _, record := range []audit.Record{
		{ReqID: "r1", Event: audit.EventStarted, Host: "web-1"},
		{ReqID: "r1", Event: audit.EventCompleted, Host: "web-1"},
		{ReqID: "r2", Event: audit.EventDenied, Host: "web-2"},
	} {
		if _, err := store.Append(record); err != nil {
			t.Fatalf("append: %v", err)
		}
	}
	return store
}

func mustRead(t *testing.T, store audit.Store) []audit.Record {
	t.Helper()
	records, err := store.ReadAll()
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	return records
}

func writeRecords(t *testing.T, path string, records []audit.Record) {
	t.Helper()
	var builder strings.Builder
	for _, record := range records {
		line, err := json.Marshal(record)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		builder.Write(line)
		builder.WriteByte('\n')
	}
	if err := os.WriteFile(path, []byte(builder.String()), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
}
