package tui

import (
	"strings"
	"testing"
)

// The policy pane in a host's detail evaluates the command as that host, so the
// host's group overrides apply without the operator typing a host: prefix.
func TestPolicyPaneScopesEvaluationToHost(t *testing.T) {
	// prod-web-01 is tagged web; the sample policy denies group web except ^ls.
	m := buildApp(t)
	ps := m.policy.withHost("prod-web-01")

	ps.input.SetValue("ls -la")
	ps.evaluate()
	if !strings.HasPrefix(ps.result, "allow") {
		t.Fatalf("allowlisted cmd result = %q, want allow", ps.result)
	}
	if !strings.Contains(ps.result, "host=prod-web-01") {
		t.Fatalf("result missing host scope: %q", ps.result)
	}

	ps.input.SetValue("cat /etc/passwd")
	ps.evaluate()
	if !strings.HasPrefix(ps.result, "deny") {
		t.Fatalf("non-allowlisted cmd on denied group result = %q, want deny", ps.result)
	}
}

// Drives evaluation through the real Update/key path (not a direct evaluate call)
// to prove the value-receiver Update persists the result back to the shell.
func TestPolicyEvaluateThroughKeyPathPersists(t *testing.T) {
	m := sized(t, buildApp(t), 100, 30)
	m = press(t, m, "enter") // open "bare"
	m = press(t, m, "3")     // policy pane
	m = press(t, m, "t")     // focus test input
	m.policy.input.SetValue("whoami")
	m = press(t, m, "enter") // evaluate
	if m.policy.result == "" {
		t.Fatal("policy result empty after evaluate via key path — Update lost the mutation")
	}
	if !strings.Contains(m.policy.result, "host=bare") {
		t.Fatalf("result = %q, want it scoped to host=bare", m.policy.result)
	}
}

func TestPolicyPaneAtRoot(t *testing.T) {
	m := buildApp(t)
	ps := m.policy.withHost("bare")
	if !ps.atRoot() {
		t.Fatal("policy pane with blurred input should be at root")
	}
	cmd := ps.input.Focus()
	_ = cmd
	if ps.atRoot() {
		t.Fatal("policy pane with focused input should not be at root")
	}
}
