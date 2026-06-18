package discovery

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Praeviso/AgentSSH/internal/inventory"
)

func TestStaticParsesSSHConfigKnownHostsAndClassifies(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	sshDir := filepath.Join(home, ".ssh")
	if err := os.MkdirAll(sshDir, 0o700); err != nil {
		t.Fatalf("mkdir .ssh: %v", err)
	}
	if err := os.WriteFile(filepath.Join(sshDir, "id_rsa"), []byte("not used by static discovery"), 0o600); err != nil {
		t.Fatalf("write default key: %v", err)
	}
	if err := os.WriteFile(filepath.Join(sshDir, "config"), []byte(`
Host web-1
  HostName 10.0.0.11
  User deploy
  Port 2222
  IdentityFile ~/.ssh/web-1

Host *.example.com
  User skipped
`), 0o600); err != nil {
		t.Fatalf("write ssh config: %v", err)
	}
	if err := os.WriteFile(filepath.Join(sshDir, "web-1"), []byte("fixture"), 0o600); err != nil {
		t.Fatalf("write identity file: %v", err)
	}
	if err := os.WriteFile(filepath.Join(sshDir, "known_hosts"), []byte(`
10.0.0.11 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINotARealKey
db-1 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINotARealKey
|1|salt|hash ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINotARealKey
`), 0o600); err != nil {
		t.Fatalf("write known_hosts: %v", err)
	}

	result, err := Static(Options{
		Home:      home,
		Inventory: inventory.Inventory{Hosts: map[string]inventory.Host{"web-1": {Addr: "10.0.0.11"}}},
	})
	if err != nil {
		t.Fatalf("Static: %v", err)
	}

	web := findCandidate(t, result.Candidates, "web-1")
	if web.Source != SourceSSHConfig || web.Addr != "10.0.0.11" || web.User != "deploy" || web.Port != 2222 {
		t.Fatalf("web candidate = %#v", web)
	}
	if !web.HasKey || !web.InKnownHosts || !web.InInventory {
		t.Fatalf("web classification = %#v", web)
	}
	if web.IdentityFile != filepath.Join(home, ".ssh", "web-1") {
		t.Fatalf("identity_file = %q", web.IdentityFile)
	}

	db := findCandidate(t, result.Candidates, "db-1")
	if db.Source != SourceKnownHosts || !db.InKnownHosts || !db.HasKey || db.InInventory {
		t.Fatalf("db candidate = %#v", db)
	}
	if len(result.Notes) != 1 {
		t.Fatalf("notes = %#v", result.Notes)
	}
	for _, candidate := range result.Candidates {
		if candidate.Name == "*.example.com" {
			t.Fatalf("wildcard candidate was not skipped: %#v", candidate)
		}
	}
}

func TestExecutorTargetUsesAliasForSSHConfig(t *testing.T) {
	// ssh_config candidates must probe via their alias so resolveAlias replays
	// ProxyJump / multiple IdentityFile, not a flattened direct dial.
	tgt := executorTarget(Candidate{Source: SourceSSHConfig, Name: "prod-web", Addr: "10.0.0.11", Port: 22})
	if tgt.Host.SSHConfigAlias != "prod-web" || tgt.Host.Addr != "" {
		t.Fatalf("ssh_config candidate should probe via alias: %#v", tgt.Host)
	}
	// known_hosts candidates have a concrete endpoint and probe directly.
	tgt2 := executorTarget(Candidate{Source: SourceKnownHosts, Name: "db", Addr: "10.0.0.20", Port: 2222})
	if tgt2.Host.Addr != "10.0.0.20" || tgt2.Host.Port != 2222 || tgt2.Host.SSHConfigAlias != "" {
		t.Fatalf("known_hosts candidate should probe direct: %#v", tgt2.Host)
	}
}

func TestKnownHostsSkipsWildcardAndNegatedPatterns(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "known_hosts")
	content := "10.0.0.11 ssh-ed25519 AAAA\n" +
		"*.corp.example ssh-ed25519 BBBB\n" +
		"!badhost ssh-ed25519 CCCC\n" +
		"|1|c2FsdA==|aGFzaA== ssh-ed25519 DDDD\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write known_hosts: %v", err)
	}
	hosts, hashed, err := knownHosts(path)
	if err != nil {
		t.Fatalf("knownHosts: %v", err)
	}
	if _, ok := hosts["10.0.0.11"]; !ok {
		t.Fatalf("concrete host missing: %#v", hosts)
	}
	if _, ok := hosts["*.corp.example"]; ok {
		t.Fatalf("wildcard pattern was enumerated: %#v", hosts)
	}
	if len(hosts) != 1 {
		t.Fatalf("expected only the concrete host, got %#v", hosts)
	}
	if hashed != 1 {
		t.Fatalf("hashed count = %d, want 1", hashed)
	}
}

func findCandidate(t *testing.T, candidates []Candidate, name string) Candidate {
	t.Helper()
	for _, candidate := range candidates {
		if candidate.Name == name {
			return candidate
		}
	}
	t.Fatalf("missing candidate %q in %#v", name, candidates)
	return Candidate{}
}
