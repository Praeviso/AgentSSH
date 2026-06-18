package secrets

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"syscall"

	"filippo.io/age"
)

// ErrWrongMaster reports an unreadable secrets file: wrong master password,
// corrupt ciphertext, or invalid decrypted payload.
var ErrWrongMaster = errors.New("wrong master password or corrupt secrets file")

const storeVersion = 1

const envMasterPassword = "AGENTSSH_MASTER_PASSWORD"

type filePayload struct {
	Version   int               `json:"version"`
	Passwords map[string]string `json:"passwords"`
}

// Store contains decrypted passwords in memory. Callers must not log or print
// values returned by Password.
type Store struct {
	path      string
	passwords map[string]string
}

// Open decrypts path with master. A missing file returns an empty store.
func Open(path, master string) (*Store, error) {
	if master == "" {
		return nil, ErrWrongMaster
	}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return &Store{path: path, passwords: map[string]string{}}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read secrets file: %w", err)
	}
	identity, err := age.NewScryptIdentity(master)
	if err != nil {
		return nil, ErrWrongMaster
	}
	reader, err := age.Decrypt(bytes.NewReader(data), identity)
	if err != nil {
		return nil, ErrWrongMaster
	}
	plaintext, err := io.ReadAll(reader)
	if err != nil {
		return nil, ErrWrongMaster
	}
	var payload filePayload
	if err := json.Unmarshal(plaintext, &payload); err != nil {
		return nil, ErrWrongMaster
	}
	if payload.Version != storeVersion {
		return nil, ErrWrongMaster
	}
	if payload.Passwords == nil {
		payload.Passwords = map[string]string{}
	}
	return &Store{path: path, passwords: payload.Passwords}, nil
}

// EnvPasswordSource returns a password source suitable for non-interactive agent
// paths. It reads AGENTSSH_MASTER_PASSWORD only, opens the encrypted store at
// most once, and silently disables password auth on any failure. It never
// prompts because TUI/agent callers own or lack the TTY.
func EnvPasswordSource(path string) func(string) (string, bool) {
	var once sync.Once
	var store *Store
	return func(host string) (string, bool) {
		once.Do(func() {
			master := os.Getenv(envMasterPassword)
			if master == "" {
				return
			}
			opened, err := Open(path, master)
			if err != nil {
				return
			}
			store = opened
		})
		if store == nil {
			return "", false
		}
		return store.Password(host)
	}
}

// ensureSafeDir refuses to write the secrets store into a directory that another
// local user could tamper with. The file's own 0600 mode is not enough: the
// directory is the trust root for the atomic temp+rename, so a group/other
// writable or non-owned directory would let another user replace or roll back
// secrets.enc. Fail closed in that case.
func ensureSafeDir(dir string) error {
	info, err := os.Stat(dir)
	if err != nil {
		return fmt.Errorf("stat secrets directory: %w", err)
	}
	if !info.IsDir() {
		return fmt.Errorf("secrets directory %s is not a directory", dir)
	}
	if perm := info.Mode().Perm(); perm&0o022 != 0 {
		return fmt.Errorf("secrets directory %s is writable by group/other (%#o); run: chmod 700 %s", dir, perm, dir)
	}
	if st, ok := info.Sys().(*syscall.Stat_t); ok && int(st.Uid) != os.Getuid() {
		return fmt.Errorf("secrets directory %s is not owned by the current user", dir)
	}
	return nil
}

// Password returns the password for host if one is stored.
func (s *Store) Password(host string) (string, bool) {
	if s == nil {
		return "", false
	}
	password, ok := s.passwords[host]
	return password, ok
}

// Set stores or replaces the password for host.
func (s *Store) Set(host, password string) {
	if s.passwords == nil {
		s.passwords = map[string]string{}
	}
	s.passwords[host] = password
}

// Delete removes any password for host.
func (s *Store) Delete(host string) {
	if s == nil {
		return
	}
	delete(s.passwords, host)
}

// Names returns sorted host names only, never password values.
func (s *Store) Names() []string {
	if s == nil {
		return nil
	}
	names := make([]string, 0, len(s.passwords))
	for name := range s.passwords {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// Save writes the encrypted store atomically with 0600 permissions.
func (s *Store) Save(master string) error {
	if master == "" {
		return ErrWrongMaster
	}
	recipient, err := age.NewScryptRecipient(master)
	if err != nil {
		return ErrWrongMaster
	}
	payload := filePayload{
		Version:   storeVersion,
		Passwords: map[string]string{},
	}
	if s != nil && s.passwords != nil {
		payload.Passwords = s.passwords
	}
	plaintext, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal secrets: %w", err)
	}

	var ciphertext bytes.Buffer
	writer, err := age.Encrypt(&ciphertext, recipient)
	if err != nil {
		return fmt.Errorf("create secrets encryptor: %w", err)
	}
	if _, err := writer.Write(plaintext); err != nil {
		_ = writer.Close()
		return fmt.Errorf("encrypt secrets: %w", err)
	}
	if err := writer.Close(); err != nil {
		return fmt.Errorf("finalize secrets encryption: %w", err)
	}

	path := s.path
	if path == "" {
		return fmt.Errorf("secrets path is empty")
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create secrets directory: %w", err)
	}
	if err := ensureSafeDir(dir); err != nil {
		return err
	}
	file, err := os.CreateTemp(dir, "secrets-*.enc")
	if err != nil {
		return fmt.Errorf("create temporary secrets file: %w", err)
	}
	tempName := file.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tempName)
		}
	}()
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		return fmt.Errorf("chmod temporary secrets file: %w", err)
	}
	if _, err := file.Write(ciphertext.Bytes()); err != nil {
		_ = file.Close()
		return fmt.Errorf("write temporary secrets file: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close temporary secrets file: %w", err)
	}
	if err := os.Rename(tempName, path); err != nil {
		return fmt.Errorf("replace secrets file: %w", err)
	}
	cleanup = false
	return nil
}
