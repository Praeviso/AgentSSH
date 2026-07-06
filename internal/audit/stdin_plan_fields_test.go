package audit_test

import (
	"path/filepath"
	"testing"

	"github.com/Praeviso/AgentSSH/internal/audit"
)

// TestStdinAndPlanFieldsAreHashProtectedAndOldRecordsVerify mirrors the
// approval-fields regression test for the stdin_sha256/stdin_bytes/plan_id
// additions: records written before these fields existed keep a byte-identical
// canonical form, and tampering with any new field breaks the chain.
func TestStdinAndPlanFieldsAreHashProtectedAndOldRecordsVerify(t *testing.T) {
	store := audit.NewStore(filepath.Join(t.TempDir(), "audit.log"))
	old, err := store.Append(audit.Record{ReqID: "old", Event: audit.EventStarted, Host: "web-1"})
	if err != nil {
		t.Fatalf("append old: %v", err)
	}
	stamped, err := store.Append(audit.Record{
		ReqID:       "r1",
		Event:       audit.EventStarted,
		Host:        "web-1",
		StdinSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		StdinBytes:  2048,
		PlanID:      "pl_0123456789abcdef01234567",
	})
	if err != nil {
		t.Fatalf("append stamped: %v", err)
	}
	records := mustRead(t, store)
	records[0].Hash = audit.ComputeHash(records[0])
	if records[0].Hash != old.Hash {
		t.Fatalf("old hash changed after stdin/plan fields were added: %s != %s", records[0].Hash, old.Hash)
	}
	if result, err := store.Verify(); err != nil || !result.OK {
		t.Fatalf("verify = %#v err=%v", result, err)
	}

	fields := []struct {
		name string
		edit func(*audit.Record)
	}{
		{"stdin_sha256", func(r *audit.Record) {
			r.StdinSHA256 = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
		}},
		{"stdin_bytes", func(r *audit.Record) { r.StdinBytes = 4096 }},
		{"plan_id", func(r *audit.Record) { r.PlanID = "pl_ffffffffffffffffffffffff" }},
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
			if result.OK || result.BrokenSeq != stamped.Seq || result.Reason != "hash" {
				t.Fatalf("tamper result = %#v", result)
			}
			writeRecords(t, store.Path, records)
		})
	}
}
