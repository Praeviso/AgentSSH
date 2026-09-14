package runtime

import (
	"errors"
	"os"
	"path/filepath"

	"github.com/Praeviso/AgentSSH/internal/config"
	"golang.org/x/sys/unix"
)

type DiagnosticReport struct {
	Home     string           `json:"home"`
	StateDir string           `json:"state_dir"`
	Paths    []DiagnosticPath `json:"paths"`
}

type DiagnosticPath struct {
	Name     string `json:"name"`
	Path     string `json:"path"`
	Kind     string `json:"kind"`
	Required bool   `json:"required"`
	Status   string `json:"status"`
	Writable bool   `json:"writable"`
	Impact   string `json:"impact,omitempty"`
	Error    string `json:"error,omitempty"`
	Parent   string `json:"parent,omitempty"`
	ParentOK bool   `json:"parent_ok,omitempty"`
}

func DiagnosePaths(paths config.Paths) DiagnosticReport {
	specs := []pathSpec{
		{name: "home", path: paths.Home, kind: "dir", required: true, impact: "configuration cannot load"},
		{name: "state", path: paths.StateDir, kind: "dir", required: true, impact: "runtime audit, approvals, grants, plans, executions, and payloads cannot be stored"},
		{name: "inventory", path: paths.InventoryFile, kind: "file", required: false, impact: "configured hosts will be empty until inventory.yaml exists"},
		{name: "policy", path: paths.PolicyFile, kind: "file", required: false, impact: "policy will be default deny until policy.yaml exists"},
		{name: "secrets", path: paths.SecretsFile, kind: "file", required: false, impact: "stored SSH passwords are unavailable"},
		{name: "operator_verifier", path: filepath.Join(paths.Home, "operator.verifier"), kind: "file", required: false, impact: "operator-gated commands need operator init unless secrets exist"},
		{name: "audit", path: paths.AuditFile, kind: "file", required: false, impact: "runs cannot append audit records when the file or parent is unwritable"},
		{name: "approvals", path: paths.ApprovalsDir, kind: "dir", required: false, impact: "async approval runtime cannot store requests"},
		{name: "pending", path: paths.PendingDir, kind: "dir", required: false, impact: "async approval requests cannot be queued"},
		{name: "responses", path: paths.ResponsesDir, kind: "dir", required: false, impact: "approval decisions cannot be observed by waiting agents"},
		{name: "sessions", path: paths.SessionsDir, kind: "dir", required: false, impact: "session and task grants cannot be reused"},
		{name: "plans", path: paths.PlansDir, kind: "dir", required: false, impact: "plan manifests and executions cannot be stored"},
		{name: "payloads", path: paths.PayloadsDir, kind: "dir", required: false, impact: "runtime payload snapshots cannot be stored"},
	}
	report := DiagnosticReport{Home: paths.Home, StateDir: paths.StateDir, Paths: make([]DiagnosticPath, 0, len(specs))}
	for _, spec := range specs {
		report.Paths = append(report.Paths, diagnosePath(spec))
	}
	return report
}

type pathSpec struct {
	name     string
	path     string
	kind     string
	required bool
	impact   string
}

func diagnosePath(spec pathSpec) DiagnosticPath {
	result := DiagnosticPath{
		Name:     spec.name,
		Path:     spec.path,
		Kind:     spec.kind,
		Required: spec.required,
		Impact:   spec.impact,
	}
	info, err := os.Stat(spec.path)
	switch {
	case err == nil:
		result.Status = "ok"
		if spec.kind == "dir" && !info.IsDir() {
			result.Status = "wrong_type"
			result.Error = "not a directory"
		}
		if spec.kind == "file" && info.IsDir() {
			result.Status = "wrong_type"
			result.Error = "is a directory"
		}
		result.Writable = writable(spec.path)
	case errors.Is(err, os.ErrNotExist):
		result.Status = "absent"
		parent := nearestExistingParent(spec.path)
		result.Parent = parent
		result.ParentOK = parent != "" && writable(parent)
		result.Writable = result.ParentOK
	default:
		result.Status = "error"
		result.Error = err.Error()
	}
	if result.Status == "ok" && !result.Writable {
		result.Status = "unwritable"
	}
	return result
}

func writable(path string) bool {
	return unix.Access(path, unix.W_OK) == nil
}

func nearestExistingParent(path string) string {
	dir := path
	for {
		parent := filepath.Dir(dir)
		if parent == dir {
			return ""
		}
		dir = parent
		info, err := os.Stat(dir)
		if err == nil && info.IsDir() {
			return dir
		}
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return ""
		}
	}
}
