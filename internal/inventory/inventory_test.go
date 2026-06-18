package inventory

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestResolveHostAndGroupByTags(t *testing.T) {
	var inv Inventory
	input := []byte(`
version: 1
hosts:
  web-1:
    addr: 10.0.0.11
    user: deploy
    tags: [web, prod]
  web-2:
    addr: 10.0.0.12
    user: deploy
    tags: [web, staging]
  db-1:
    addr: 10.0.0.21
    user: deploy
    tags: [db, prod]
groups:
  web: { tags: [web] }
  prod-web: { tags: [web, prod] }
`)
	if err := yaml.Unmarshal(input, &inv); err != nil {
		t.Fatalf("unmarshal inventory: %v", err)
	}

	resolver := NewResolver(inv)
	resolved, err := resolver.Resolve("web-1")
	if err != nil {
		t.Fatalf("resolve host: %v", err)
	}
	if resolved.Kind != TargetKindHost {
		t.Fatalf("host kind = %q, want %q", resolved.Kind, TargetKindHost)
	}
	targets := resolved.Targets
	if len(targets) != 1 || targets[0].Name != "web-1" {
		t.Fatalf("host targets = %#v", targets)
	}
	if targets[0].Host.Port != 22 {
		t.Fatalf("default port = %d, want 22", targets[0].Host.Port)
	}

	resolved, err = resolver.Resolve("prod-web")
	if err != nil {
		t.Fatalf("resolve group: %v", err)
	}
	if resolved.Kind != TargetKindGroup {
		t.Fatalf("group kind = %q, want %q", resolved.Kind, TargetKindGroup)
	}
	targets = resolved.Targets
	if got, want := namesOf(targets), []string{"web-1"}; !equalStrings(got, want) {
		t.Fatalf("group targets = %v, want %v", got, want)
	}
}

func TestPublicInventoryOmitsConnectionDetails(t *testing.T) {
	inv := Inventory{
		Hosts: map[string]Host{
			"web-1": {
				Addr:           "10.0.0.11",
				User:           "deploy",
				Port:           2222,
				SSHConfigAlias: "prod-web",
				IdentityFile:   "~/.ssh/prod_ed25519",
				Tags:           []string{"prod", "web"},
			},
		},
		Groups: map[string]Group{
			"web": {Tags: []string{"web"}},
		},
	}

	public := NewResolver(inv).Public()
	if len(public.Hosts) != 1 || public.Hosts[0].Name != "web-1" {
		t.Fatalf("public hosts = %#v", public.Hosts)
	}
	if got, want := public.Hosts[0].Tags, []string{"prod", "web"}; !equalStrings(got, want) {
		t.Fatalf("public host tags = %v, want %v", got, want)
	}
	if len(public.Groups) != 1 || public.Groups[0].Name != "web" {
		t.Fatalf("public groups = %#v", public.Groups)
	}
}

func TestUnknownTarget(t *testing.T) {
	resolver := NewResolver(Inventory{
		Hosts:  map[string]Host{"web-1": {}},
		Groups: map[string]Group{"web": {}},
	})

	_, err := resolver.Resolve("web-9")
	if !IsUnknown(err) {
		t.Fatalf("Resolve unknown err = %v, want unknown", err)
	}
}

func TestMarshalOmitsEmptyInventoryFields(t *testing.T) {
	inv := Inventory{
		Version: 1,
		Hosts: map[string]Host{
			"web-1": {
				Addr: "10.0.0.11",
			},
			"via-alias": {
				SSHConfigAlias: "prod-web",
			},
		},
	}
	data, err := yaml.Marshal(inv)
	if err != nil {
		t.Fatalf("marshal inventory: %v", err)
	}
	out := string(data)
	for _, unexpected := range []string{"transport:", "host_key_policy:", "user:", "port: 0", "tags: []"} {
		if strings.Contains(out, unexpected) {
			t.Fatalf("marshal output contains %q:\n%s", unexpected, out)
		}
	}
	if !strings.Contains(out, "version: 1") || !strings.Contains(out, "ssh_config_alias: prod-web") {
		t.Fatalf("marshal output missing expected fields:\n%s", out)
	}
}

func TestMarshalIncludesIdentityFileWhenPresent(t *testing.T) {
	inv := Inventory{
		Version: 1,
		Hosts: map[string]Host{
			"web-1": {Addr: "10.0.0.11", IdentityFile: "~/.ssh/prod_ed25519"},
		},
	}
	data, err := yaml.Marshal(inv)
	if err != nil {
		t.Fatalf("marshal inventory: %v", err)
	}
	out := string(data)
	if !strings.Contains(out, "identity_file: ~/.ssh/prod_ed25519") {
		t.Fatalf("marshal output missing identity_file:\n%s", out)
	}
}

func namesOf(targets []Target) []string {
	result := make([]string, 0, len(targets))
	for _, target := range targets {
		result = append(result, target.Name)
	}
	return result
}

func equalStrings(a []string, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
