package audit_test

import (
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/Praeviso/AgentSSH/internal/audit"
)

// A syntactically valid but altered chain must not accept a new record or
// acknowledge an existing event as safely published.
func TestAppendRefusesACorruptChain(t *testing.T) {
	store := audit.NewStore(filepath.Join(t.TempDir(), "audit.log"))
	record, err := store.Append(audit.Record{Event: audit.EventDeviceRevoked, DeviceID: "dev_a", EventID: "event-a"})
	if err != nil {
		t.Fatal(err)
	}
	record.Note = "changed without updating the hash"
	writeRecords(t, store.Path, []audit.Record{record})
	before, err := os.ReadFile(store.Path)
	if err != nil {
		t.Fatal(err)
	}
	for _, exists := range []func(audit.Record) bool{nil, func(r audit.Record) bool { return r.EventID == "event-a" }} {
		if _, _, err := store.AppendUnless(record, exists); err == nil {
			t.Fatal("corrupt history was accepted for publication")
		}
	}
	after, err := os.ReadFile(store.Path)
	if err != nil || string(before) != string(after) {
		t.Fatalf("failed publication changed the corrupt log: %v", err)
	}
}

// AppendUnless adds a fact once, however many callers record it at the same
// time, and still appends when no record matches.
func TestAppendUnlessAddsAFactOnce(t *testing.T) {
	store := audit.NewStore(filepath.Join(t.TempDir(), "audit.log"))
	end := audit.Record{Event: audit.EventDeviceActivationEnded, DeviceID: "dev_a", ActiveUntil: "2026-10-25T10:00:00Z"}
	same := func(want audit.Record) func(audit.Record) bool {
		return func(r audit.Record) bool {
			return r.Event == want.Event && r.DeviceID == want.DeviceID && r.ActiveUntil == want.ActiveUntil
		}
	}
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, _, err := store.AppendUnless(end, same(end)); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	other := end
	other.ActiveUntil = "2026-10-25T11:00:00Z"
	if _, appended, err := store.AppendUnless(other, same(other)); err != nil || !appended {
		t.Fatalf("a different end: appended %v, %v", appended, err)
	}
	if existing, appended, err := store.AppendUnless(end, same(end)); err != nil || appended || existing.Seq != 0 {
		t.Fatalf("the recorded end again: appended %v, existing %+v, %v", appended, existing, err)
	}
	if result, err := store.Verify(); err != nil || !result.OK || result.Count != 2 {
		t.Fatalf("verify = %+v, %v (want the two ends)", result, err)
	}
}
