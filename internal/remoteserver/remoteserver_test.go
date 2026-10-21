package remoteserver

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Praeviso/AgentSSH/internal/remote"
)

func init() {
	ScryptWorkFactor = 10
}

func newTestStore(t *testing.T) (string, *Store) {
	t.Helper()
	dir := t.TempDir()
	if err := Init(dir, "master"); err != nil {
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
	if err := Init(dir, "other"); err == nil {
		t.Fatal("second Init overwrote an initialized data directory")
	}
	if _, err := Unlock(dir, "wrong"); !errors.Is(err, ErrWrongMaster) {
		t.Fatalf("Unlock(wrong) = %v, want ErrWrongMaster", err)
	}
	keys, err := Unlock(dir, "master")
	if err != nil {
		t.Fatalf("Unlock: %v", err)
	}
	if _, err := remote.DecodeDevicePublicKey(keys.BundlePublicKey()); err != nil {
		t.Fatal(err)
	}
}

func storedDevice(t *testing.T, store *Store, now time.Time) Device {
	t.Helper()
	token, err := store.CreateEnrollToken("laptop", "https://cp.example", strings.Repeat("ab", 32), time.Minute, now)
	if err != nil {
		t.Fatal(err)
	}
	device, err := store.RedeemEnrollToken(token.ID, token.Secret, token.ServerURL, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", now)
	if err != nil {
		t.Fatal(err)
	}
	return device
}

func TestPushConfigValidatesManagedInventory(t *testing.T) {
	dir, store := newTestStore(t)
	now := time.Now()
	device := storedDevice(t, store, now)
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
	initial, err := PushConfig(store, device.ID, good, policy, now)
	if err != nil {
		t.Fatalf("PushConfig: %v", err)
	}
	next, err := PushConfig(store, device.ID, good, policy, now)
	if err != nil || next != initial+1 {
		t.Fatalf("second push version = %d (%v), want %d", next, err, initial+1)
	}
}
