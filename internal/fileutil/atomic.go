package fileutil

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// WriteFileAtomic writes data through a temporary file in path's directory, then
// renames it over the destination.
func WriteFileAtomic(path string, data []byte, perm os.FileMode, tempPattern string) error {
	dir := filepath.Dir(path)
	file, err := os.CreateTemp(dir, tempPattern)
	if err != nil {
		return fmt.Errorf("create temporary file: %w", err)
	}
	tempName := file.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tempName)
		}
	}()
	if err := file.Chmod(perm); err != nil {
		_ = file.Close()
		return fmt.Errorf("chmod temporary file: %w", err)
	}
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		return fmt.Errorf("write temporary file: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close temporary file: %w", err)
	}
	if err := os.Rename(tempName, path); err != nil {
		return fmt.Errorf("replace file: %w", err)
	}
	cleanup = false
	return nil
}

// LabelAtomicError rewrites WriteFileAtomic's generic operation names with the
// caller's file label, preserving package-specific error text.
func LabelAtomicError(err error, label string) error {
	message := err.Error()
	replacements := []struct {
		from string
		to   string
	}{
		{"create temporary file", "create temporary " + label + " file"},
		{"chmod temporary file", "chmod temporary " + label + " file"},
		{"write temporary file", "write temporary " + label + " file"},
		{"close temporary file", "close temporary " + label + " file"},
		{"replace file", "replace " + label + " file"},
	}
	for _, replacement := range replacements {
		if strings.HasPrefix(message, replacement.from) {
			return fmt.Errorf("%s%s", replacement.to, strings.TrimPrefix(message, replacement.from))
		}
	}
	return err
}
