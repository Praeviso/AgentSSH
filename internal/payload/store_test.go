package payload

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestStoreCorruptionExpiryPinsAndPreview(t *testing.T) {
	now := time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC)
	store := Store{Dir: t.TempDir(), Now: func() time.Time { return now }}
	ref, err := store.Put([]byte(strings.Repeat("a", PreviewBytes+128)), PutOptions{RetainFor: time.Hour})
	if err != nil {
		t.Fatalf("put: %v", err)
	}
	if err := os.WriteFile(store.dataPath(ref.SHA256), []byte("corrupt"), 0o600); err != nil {
		t.Fatalf("corrupt: %v", err)
	}
	if _, err := store.Get(ref); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("Get corrupt err=%v, want ErrCorrupt", err)
	}
	if _, err := store.Put([]byte(strings.Repeat("a", PreviewBytes+128)), PutOptions{RetainFor: time.Hour}); err != nil {
		t.Fatalf("put should repair corrupt object: %v", err)
	}
	show, err := store.Show(ref, ShowOptions{})
	if err != nil {
		t.Fatalf("show: %v", err)
	}
	if !show.Truncated || len(show.Text) > PreviewBytes {
		t.Fatalf("preview truncated=%v len=%d", show.Truncated, len(show.Text))
	}
	if err := store.Pin(ref, "px_active"); err != nil {
		t.Fatalf("pin: %v", err)
	}
	if err := store.Remove(ref, false); !errors.Is(err, ErrActiveRef) {
		t.Fatalf("remove pinned err=%v, want ErrActiveRef", err)
	}
	store.Now = func() time.Time { return now.Add(2 * time.Hour) }
	removed, err := store.GC()
	if err != nil {
		t.Fatalf("gc pinned: %v", err)
	}
	if len(removed) != 0 {
		t.Fatalf("gc removed pinned payload: %+v", removed)
	}
	if err := store.Unpin(ref, "px_active"); err != nil {
		t.Fatalf("unpin: %v", err)
	}
	removed, err = store.GC()
	if err != nil {
		t.Fatalf("gc expired: %v", err)
	}
	if len(removed) != 1 || removed[0] != ref {
		t.Fatalf("removed=%+v want %s", removed, ref.String())
	}
	if _, err := os.Stat(filepath.Join(store.Dir, "objects", ref.SHA256)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("object still retained err=%v", err)
	}
}

func TestStoreRejectsOversizeRefWithoutReadingWholeFile(t *testing.T) {
	store := Store{Dir: t.TempDir()}
	ref := Ref{SHA256: strings.Repeat("a", 64), Bytes: MaxItemBytes + 1}
	if _, err := store.Get(ref); !errors.Is(err, ErrInvalidRef) {
		t.Fatalf("Get oversized ref err=%v, want ErrInvalidRef", err)
	}
}
