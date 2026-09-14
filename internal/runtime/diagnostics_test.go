package runtime

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/Praeviso/AgentSSH/internal/config"
)

func TestDiagnosePathsIsReadOnlyAndReportsSplitState(t *testing.T) {
	home := t.TempDir()
	state := filepath.Join(t.TempDir(), "missing-state")
	t.Setenv(config.EnvStateDir, state)
	paths := config.NewPaths(home)

	report := DiagnosePaths(paths)
	if report.Home != home || report.StateDir != state {
		t.Fatalf("report home/state = %q/%q", report.Home, report.StateDir)
	}
	if _, err := os.Stat(state); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("diagnostics created state dir or stat failed unexpectedly: %v", err)
	}

	byName := map[string]DiagnosticPath{}
	for _, item := range report.Paths {
		byName[item.Name] = item
	}
	if got := byName["home"]; got.Status != "ok" || got.Path != home {
		t.Fatalf("home diagnostic = %#v", got)
	}
	if got := byName["state"]; got.Status != "absent" || got.Path != state || got.Impact == "" {
		t.Fatalf("state diagnostic = %#v", got)
	}
	if got := byName["audit"]; got.Path != filepath.Join(state, "audit.log") || got.Status != "absent" || !got.ParentOK {
		t.Fatalf("audit diagnostic = %#v", got)
	}
	if got := byName["inventory"]; got.Path != filepath.Join(home, "inventory.yaml") {
		t.Fatalf("inventory stayed outside home: %#v", got)
	}
}
