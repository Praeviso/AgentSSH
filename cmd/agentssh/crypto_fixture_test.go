package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"
	"github.com/Praeviso/AgentSSH/internal/secrets"
)

// This helper exists only in the test binary. It writes real age ciphertext;
// application code still performs all decoding, authentication and validation.
func writeEncryptedFixture(t *testing.T, path, master string, payload []byte) {
	t.Helper()
	recipient, err := age.NewScryptRecipient(master)
	if err != nil {
		t.Fatal(err)
	}
	recipient.SetWorkFactor(10)
	var ciphertext bytes.Buffer
	writer, err := age.Encrypt(&ciphertext, recipient)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write(payload); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, ciphertext.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
}

func writeSecretsFixture(t *testing.T, home, master string, passwords map[string]string) {
	t.Helper()
	payload, err := json.Marshal(map[string]any{"Version": 1, "Passwords": passwords})
	if err != nil {
		t.Fatal(err)
	}
	writeEncryptedFixture(t, filepath.Join(home, "secrets.enc"), master, payload)
}

func TestOperatorVerifierProductionParameters(t *testing.T) {
	home := t.TempDir()
	t.Setenv("AGENTSSH_HOME", home)
	withOperatorPrompt(t, func(string) (string, error) { return "master", nil })
	if _, stderr, err := runCommandForTest(t, "operator", "init"); err != nil {
		t.Fatalf("operator init: %v stderr=%s", err, stderr)
	}
	path := filepath.Join(home, "operator.verifier")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	// age's production default is 2^18. The fixture's 2^10 must never become
	// the cost used by the production writer.
	lines := strings.Split(string(raw), "\n")
	if len(lines) < 2 || !strings.HasPrefix(lines[1], "-> scrypt ") || !strings.HasSuffix(lines[1], " 18") {
		t.Fatalf("unexpected production scrypt stanza: %q", lines[:min(2, len(lines))])
	}
	if err := verifyOperatorVerifier(path, "master"); err != nil {
		t.Fatalf("verify production ciphertext: %v", err)
	}
	if err := verifyOperatorVerifier(path, "wrong"); !errors.Is(err, secrets.ErrWrongMaster) {
		t.Fatalf("wrong password: %v", err)
	}
}
