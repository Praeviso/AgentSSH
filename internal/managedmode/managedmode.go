// Package managedmode reports whether an AgentSSH home is enrolled with a remote
// control plane. It is a leaf package so the inventory and policy stores can
// refuse local writes without importing the remote client.
package managedmode

import (
	"errors"
	"os"
	"path/filepath"
)

// DirName is the remote-control state directory under the AgentSSH home.
const DirName = "remote"

// MarkerName is the enrollment file whose presence switches a home into remote mode.
const MarkerName = "remote.yaml"

// ErrManaged reports a local configuration write refused because the inventory
// and policy are owned by a remote control plane.
var ErrManaged = errors.New("configuration is managed by a remote control plane; local inventory and policy edits are disabled (deny rules in the local policy.yaml still apply; edit that file directly)")

// Dir returns the remote-control state directory for home.
func Dir(home string) string {
	return filepath.Join(home, DirName)
}

// Enrolled reports whether home has completed remote enrollment.
func Enrolled(home string) bool {
	info, err := os.Stat(filepath.Join(Dir(home), MarkerName))
	return err == nil && info.Mode().IsRegular()
}

// CheckWritable returns ErrManaged when path lives directly in an enrolled home.
func CheckWritable(path string) error {
	if Enrolled(filepath.Dir(path)) {
		return ErrManaged
	}
	return nil
}
