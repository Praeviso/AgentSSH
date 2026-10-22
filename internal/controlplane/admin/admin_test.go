package admin_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Praeviso/AgentSSH/internal/controlplane"
	"github.com/Praeviso/AgentSSH/internal/controlplane/admin"
	"github.com/Praeviso/AgentSSH/internal/remote"
)

func initDir(t *testing.T, mode string) string {
	t.Helper()
	dir := t.TempDir()
	err := controlplane.Init(dir, "master", controlplane.InitOptions{
		Mode:       mode,
		WorkFactor: 10,
		InitStore: func(dir string) error {
			store, err := controlplane.OpenStore(filepath.Join(dir, "test.db"), "")
			if err != nil {
				return err
			}
			return store.Close()
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestDataDirectoryServesExactlyOneMode(t *testing.T) {
	managed := &admin.Program{Name: "agentssh-server", Mode: remote.ModeManaged}
	gateway := &admin.Program{Name: "agentssh-gateway", Mode: remote.ModeGateway}
	managedDir, gatewayDir := initDir(t, remote.ModeManaged), initDir(t, remote.ModeGateway)
	// Directories created before the mode was recorded are managed.
	legacyDir := initDir(t, remote.ModeManaged)
	if err := os.Remove(filepath.Join(legacyDir, "mode")); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name    string
		program *admin.Program
		dir     string
		refused string
	}{
		{"managed own", managed, managedDir, ""},
		{"managed legacy", managed, legacyDir, ""},
		{"gateway own", gateway, gatewayDir, ""},
		{"managed on gateway", managed, gatewayDir, "holds a gateway control plane"},
		{"gateway on managed", gateway, managedDir, "holds a managed control plane"},
		{"gateway on legacy", gateway, legacyDir, "holds a managed control plane"},
		{"uninitialized", gateway, t.TempDir(), "run agentssh-gateway init"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.program.CheckDir(tc.dir)
			if tc.refused == "" && err != nil {
				t.Fatalf("CheckDir: %v", err)
			}
			if tc.refused != "" && (err == nil || !strings.Contains(err.Error(), tc.refused)) {
				t.Fatalf("CheckDir = %v, want refusal containing %q", err, tc.refused)
			}
		})
	}
}
