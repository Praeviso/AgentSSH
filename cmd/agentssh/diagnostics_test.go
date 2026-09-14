package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestDiagnosticsCommandReportsStateDirWithoutCreatingIt(t *testing.T) {
	home := t.TempDir()
	state := filepath.Join(t.TempDir(), "state")
	t.Setenv("AGENTSSH_HOME", home)
	t.Setenv("AGENTSSH_STATE_DIR", state)

	code, stdout, stderr := runExit(t, "diagnostics", "--json")
	if code != exitOK {
		t.Fatalf("diagnostics exit=%d stderr=%s", code, stderr)
	}
	var report struct {
		Home     string `json:"home"`
		StateDir string `json:"state_dir"`
		Paths    []struct {
			Name   string `json:"name"`
			Path   string `json:"path"`
			Status string `json:"status"`
		} `json:"paths"`
	}
	if err := json.Unmarshal([]byte(stdout), &report); err != nil {
		t.Fatalf("decode diagnostics: %v\n%s", err, stdout)
	}
	if report.Home != home || report.StateDir != state {
		t.Fatalf("report home/state = %q/%q", report.Home, report.StateDir)
	}
	var sawState bool
	for _, item := range report.Paths {
		if item.Name == "state" {
			sawState = true
			if item.Path != state || item.Status != "absent" {
				t.Fatalf("state item = %#v", item)
			}
		}
	}
	if !sawState {
		t.Fatalf("diagnostics did not include state path: %#v", report.Paths)
	}
	if _, err := os.Stat(state); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("diagnostics created state dir or stat failed unexpectedly: %v", err)
	}
}
