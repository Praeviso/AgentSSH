package remoteserver

import (
	"crypto/x509"
	"errors"
	"os"
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

func TestRenewTLSKeepsCAAndDeviceTrust(t *testing.T) {
	dir := t.TempDir()
	if err := Init(dir, "master", []string{"cp.example", "127.0.0.1"}, time.Now()); err != nil {
		t.Fatal(err)
	}
	before, err := Unlock(dir, "master")
	if err != nil {
		t.Fatal(err)
	}
	oldCert, err := os.ReadFile(filepath.Join(dir, "tls.crt"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := RenewTLS(dir, "wrong", nil, time.Now()); !errors.Is(err, ErrWrongMaster) {
		t.Fatalf("RenewTLS(wrong master) = %v, want ErrWrongMaster", err)
	}

	later := time.Now().AddDate(1, 11, 0)
	renewed, err := RenewTLS(dir, "master", nil, later)
	if err != nil {
		t.Fatalf("RenewTLS: %v", err)
	}
	if got := strings.Join(CertNames(renewed), ","); got != "cp.example,127.0.0.1" {
		t.Fatalf("renewed names = %q, want the current names kept", got)
	}
	if !renewed.NotAfter.After(before.TLSCert.Leaf.NotAfter) {
		t.Fatalf("renewed NotAfter %v not after the old %v", renewed.NotAfter, before.TLSCert.Leaf.NotAfter)
	}
	after, err := Unlock(dir, "master")
	if err != nil {
		t.Fatalf("Unlock after renew: %v", err)
	}
	if after.CAFingerprint() != before.CAFingerprint() {
		t.Fatal("renewal changed the CA, which would break every enrolled device's pin")
	}
	roots := x509.NewCertPool()
	roots.AddCert(after.CACert)
	if _, err := after.TLSCert.Leaf.Verify(x509.VerifyOptions{DNSName: "cp.example", Roots: roots, CurrentTime: later}); err != nil {
		t.Fatalf("renewed certificate does not verify under the existing CA: %v", err)
	}

	replaced, err := RenewTLS(dir, "master", []string{"new.example"}, time.Now())
	if err != nil || strings.Join(CertNames(replaced), ",") != "new.example" {
		t.Fatalf("RenewTLS with --san = %v (%v), want only new.example", replaced, err)
	}

	// An interrupted renewal (new key, old certificate) is reported plainly.
	if err := os.WriteFile(filepath.Join(dir, "tls.crt"), oldCert, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Unlock(dir, "master"); err == nil || !strings.Contains(err.Error(), "tls renew") {
		t.Fatalf("Unlock with mismatched TLS key = %v, want a renew hint", err)
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
