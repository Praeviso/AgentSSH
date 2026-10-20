package remoteserver

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func init() {
	ScryptWorkFactor = 10
}

func newTestStore(t *testing.T) (string, *Store) {
	t.Helper()
	dir := t.TempDir()
	if err := Init(dir, "master", []string{"127.0.0.1"}, time.Now()); err != nil {
		t.Fatalf("Init: %v", err)
	}
	store, err := OpenStore(filepath.Join(dir, FileDatabase))
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return dir, store
}

func TestInitRefusesToOverwriteAndUnlockNeedsMaster(t *testing.T) {
	dir, _ := newTestStore(t)
	if err := Init(dir, "other", nil, time.Now()); err == nil {
		t.Fatal("second Init overwrote an initialized data directory")
	}
	if _, err := Unlock(dir, "wrong"); !errors.Is(err, ErrWrongMaster) {
		t.Fatalf("Unlock(wrong) = %v, want ErrWrongMaster", err)
	}
	keys, err := Unlock(dir, "master")
	if err != nil {
		t.Fatalf("Unlock: %v", err)
	}
	fp, err := LoadCAFingerprint(dir)
	if err != nil || fp != keys.CAFingerprint() {
		t.Fatalf("CA fingerprint mismatch: %q vs %q (%v)", fp, keys.CAFingerprint(), err)
	}
}

func TestEnrollTokenIsSingleUseAndExpires(t *testing.T) {
	_, store := newTestStore(t)
	now := time.Now()
	id, secret, err := store.CreateEnrollToken("laptop", time.Minute, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.RedeemEnrollToken(id, "wrong-secret", now); !errors.Is(err, ErrTokenInvalid) {
		t.Fatalf("wrong secret = %v, want ErrTokenInvalid", err)
	}
	device, err := store.RedeemEnrollToken(id, secret, now)
	if err != nil {
		t.Fatalf("redeem: %v", err)
	}
	if device.Name != "laptop" || !strings.HasPrefix(device.ID, "dev_") {
		t.Fatalf("device = %+v", device)
	}
	if _, err := store.RedeemEnrollToken(id, secret, now); !errors.Is(err, ErrTokenInvalid) {
		t.Fatalf("reused token = %v, want ErrTokenInvalid", err)
	}

	expiredID, expiredSecret, err := store.CreateEnrollToken("late", time.Minute, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.RedeemEnrollToken(expiredID, expiredSecret, now.Add(2*time.Minute)); !errors.Is(err, ErrTokenInvalid) {
		t.Fatalf("expired token = %v, want ErrTokenInvalid", err)
	}
}

func TestPushConfigValidatesManagedInventory(t *testing.T) {
	dir, store := newTestStore(t)
	now := time.Now()
	id, secret, _ := store.CreateEnrollToken("laptop", time.Minute, now)
	device, err := store.RedeemEnrollToken(id, secret, now)
	if err != nil {
		t.Fatal(err)
	}
	recipient, err := LoadRecipient(dir)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := NewIdentity("web", recipient, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.CreateIdentity(identity); err != nil {
		t.Fatal(err)
	}
	if err := store.CreateIdentity(identity); !errors.Is(err, ErrExists) {
		t.Fatalf("duplicate identity = %v, want ErrExists", err)
	}

	good := "hosts:\n  web-1: {addr: 10.0.0.1, user: deploy, identity: web}\n"
	policy := "version: 1\nrules:\n  - {name: ro, match: {cmd_regex: '^uptime$'}, action: allow}\n"
	for name, inv := range map[string]string{
		"unknown identity": "hosts:\n  web-1: {addr: 10.0.0.1, user: deploy, identity: db}\n",
		"ssh_config alias": "hosts:\n  web-1: {ssh_config_alias: web, user: deploy, identity: web}\n",
		"malformed":        "hosts: [",
	} {
		if _, err := PushConfig(store, device.ID, inv, policy, now); err == nil {
			t.Errorf("%s: PushConfig accepted an invalid inventory", name)
		}
	}
	if _, err := PushConfig(store, device.ID, good, "rules:\n  - {match: {cmd_regex: '('}, action: allow}\n", now); err == nil {
		t.Error("PushConfig accepted an uncompilable policy")
	}
	if _, err := PushConfig(store, "dev_missing", good, policy, now); err == nil {
		t.Error("PushConfig accepted an unknown device")
	}
	v1, err := PushConfig(store, device.ID, good, policy, now)
	if err != nil {
		t.Fatalf("PushConfig: %v", err)
	}
	v2, err := PushConfig(store, device.ID, good, policy, now)
	if err != nil || v2 != v1+1 {
		t.Fatalf("second push version = %d (%v), want %d", v2, err, v1+1)
	}
}
