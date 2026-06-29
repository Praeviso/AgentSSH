package inventory

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadMissingFileReturnsZeroInventory(t *testing.T) {
	inv, err := Load(filepath.Join(t.TempDir(), "inventory.yaml"))
	if err != nil {
		t.Fatalf("Load missing: %v", err)
	}
	if inv.Version != 0 || len(inv.Hosts) != 0 || len(inv.Groups) != 0 {
		t.Fatalf("inventory = %#v, want zero value", inv)
	}
}

func TestAddHostInitializesAndPreservesOriginal(t *testing.T) {
	inv := Inventory{}
	next, err := AddHost(inv, "web-1", Host{Addr: "10.0.0.11"})
	if err != nil {
		t.Fatalf("AddHost: %v", err)
	}
	if next.Version != 1 || next.Hosts["web-1"].Addr != "10.0.0.11" {
		t.Fatalf("next = %#v", next)
	}
	if inv.Hosts != nil || inv.Version != 0 {
		t.Fatalf("AddHost mutated original = %#v", inv)
	}
}

func TestAddHostRejectsDuplicateAndPreservesExisting(t *testing.T) {
	inv := Inventory{Version: 1, Hosts: map[string]Host{"old": {Addr: "10.0.0.10"}}}
	next, err := AddHost(inv, "new", Host{Addr: "10.0.0.11"})
	if err != nil {
		t.Fatalf("AddHost new: %v", err)
	}
	if next.Hosts["old"].Addr != "10.0.0.10" || next.Hosts["new"].Addr != "10.0.0.11" {
		t.Fatalf("next = %#v", next)
	}
	next.Hosts["old"] = Host{Addr: "changed"}
	if inv.Hosts["old"].Addr != "10.0.0.10" {
		t.Fatalf("AddHost map alias mutated original = %#v", inv)
	}
	_, err = AddHost(inv, "old", Host{Addr: "10.0.0.12"})
	if !errors.Is(err, ErrHostExists) {
		t.Fatalf("duplicate err = %v, want ErrHostExists", err)
	}
}

func TestRemoveHost(t *testing.T) {
	inv := Inventory{Hosts: map[string]Host{"old": {Addr: "10.0.0.10"}, "new": {Addr: "10.0.0.11"}}}
	next, err := RemoveHost(inv, "old")
	if err != nil {
		t.Fatalf("RemoveHost: %v", err)
	}
	if _, ok := next.Hosts["old"]; ok {
		t.Fatalf("old still present: %#v", next.Hosts)
	}
	if _, ok := inv.Hosts["old"]; !ok {
		t.Fatalf("RemoveHost mutated original = %#v", inv)
	}
	_, err = RemoveHost(inv, "missing")
	if !errors.Is(err, ErrHostNotFound) {
		t.Fatalf("missing err = %v, want ErrHostNotFound", err)
	}
}

func TestUpdateHost(t *testing.T) {
	inv := Inventory{Hosts: map[string]Host{
		"old": {Addr: "10.0.0.10", User: "deploy", OS: "linux"},
		"new": {Addr: "10.0.0.11"},
	}}
	next, err := UpdateHost(inv, "old", Host{Addr: "10.0.0.12", User: "admin", OS: "linux"})
	if err != nil {
		t.Fatalf("UpdateHost: %v", err)
	}
	if got := next.Hosts["old"]; got.Addr != "10.0.0.12" || got.User != "admin" || got.OS != "linux" {
		t.Fatalf("updated host = %#v", got)
	}
	if inv.Hosts["old"].Addr != "10.0.0.10" {
		t.Fatalf("UpdateHost mutated original = %#v", inv)
	}
	_, err = UpdateHost(inv, "missing", Host{Addr: "10.0.0.12"})
	if !errors.Is(err, ErrHostNotFound) {
		t.Fatalf("missing err = %v, want ErrHostNotFound", err)
	}
}

func TestSaveLoadRoundTripAndOmitEmptyFields(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "inventory.yaml")
	inv := Inventory{
		Hosts: map[string]Host{
			"web-1": {Addr: "10.0.0.11", User: "deploy", Port: 22, IdentityFile: "~/.ssh/web-1"},
		},
	}
	next, err := AddHost(inv, "via-alias", Host{SSHConfigAlias: "prod-web"})
	if err != nil {
		t.Fatalf("AddHost alias: %v", err)
	}
	if err := Save(path, next); err != nil {
		t.Fatalf("Save: %v", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read saved inventory: %v", err)
	}
	text := string(raw)
	for _, unexpected := range []string{"transport:", "host_key_policy:", "tags: []", "addr: \"\"", "identity_file: \"\""} {
		if strings.Contains(text, unexpected) {
			t.Fatalf("saved inventory contains %q:\n%s", unexpected, text)
		}
	}
	if !strings.Contains(text, "identity_file: ~/.ssh/web-1") {
		t.Fatalf("saved inventory missing identity_file:\n%s", text)
	}
	loaded, err := Load(path)
	if err != nil {
		t.Fatalf("Load saved: %v", err)
	}
	if loaded.Hosts["web-1"].User != "deploy" || loaded.Hosts["web-1"].IdentityFile != "~/.ssh/web-1" || loaded.Hosts["via-alias"].SSHConfigAlias != "prod-web" {
		t.Fatalf("loaded = %#v", loaded)
	}
}

func TestHostNames(t *testing.T) {
	names := HostNames(Inventory{Hosts: map[string]Host{"b": {}, "a": {}}})
	if _, ok := names["a"]; !ok {
		t.Fatalf("names missing a: %#v", names)
	}
	names["c"] = struct{}{}
	if _, ok := HostNames(Inventory{Hosts: map[string]Host{"b": {}, "a": {}}})["c"]; ok {
		t.Fatal("HostNames returned shared map")
	}
}
