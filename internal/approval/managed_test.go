package approval

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/Praeviso/AgentSSH/internal/audit"
	"github.com/Praeviso/AgentSSH/internal/inventory"
	"github.com/Praeviso/AgentSSH/internal/managedmode"
	"github.com/Praeviso/AgentSSH/internal/policy"
)

func TestHostScopeRefusedUnderRemoteControlWithoutBurningRequest(t *testing.T) {
	home := t.TempDir()
	if err := os.MkdirAll(managedmode.Dir(home), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(managedmode.Dir(home), managedmode.MarkerName), []byte("server_url: x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	pending := PendingStore{PendingDir: filepath.Join(home, "pending"), ResponsesDir: filepath.Join(home, "responses")}
	matcher, err := Generalize("ls /var", HostGrantSafePrefix)
	if err != nil {
		t.Fatal(err)
	}
	req, err := pending.Create(PendingRequest{ReqID: "r1", SessionID: "s1", Host: "web-1", Cmd: "ls /var", Candidate: matcher})
	if err != nil {
		t.Fatal(err)
	}
	opts := ApplyOptions{
		Pending:    pending,
		Sessions:   SessionStore{Dir: filepath.Join(home, "sessions")},
		Audit:      audit.NewStore(filepath.Join(home, "audit.log")),
		Bundle:     policy.Bundle{Inventory: inventory.Inventory{Hosts: map[string]inventory.Host{"web-1": {}}}},
		PolicyPath: filepath.Join(home, "policy.yaml"),
	}

	if _, err := ApplyDecision(opts, req.ID, VerdictApproved, ScopeHost); !errors.Is(err, managedmode.ErrManaged) {
		t.Fatalf("host scope under remote control = %v, want ErrManaged", err)
	}
	if _, err := ApplyDecision(opts, req.ID, VerdictApproved, ScopeOnce); err != nil {
		t.Fatalf("request should still be decidable once after a refused host grant: %v", err)
	}
}
