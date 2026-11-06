package gateway_test

import (
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Praeviso/AgentSSH/internal/gateway"
	"github.com/Praeviso/AgentSSH/internal/remote"
)

func requireStorageGuidance(t *testing.T, p page, context, recovery, diagnostic string) {
	t.Helper()
	if p.status != http.StatusInternalServerError {
		t.Fatalf("storage failure status = %d, want 500: %s", p.status, p.body)
	}
	for _, text := range []string{context, recovery, "gateway administrator", "Diagnostic: " + diagnostic} {
		if !strings.Contains(p.body, text) {
			t.Errorf("storage failure is missing %q: %s", text, p.body)
		}
	}
}

func TestSignInStorageFailuresExplainRecovery(t *testing.T) {
	t.Run("password session", func(t *testing.T) {
		w := newWebFixture(t)
		if _, err := w.store.DB().Exec(`CREATE TRIGGER fail_session BEFORE INSERT ON web_sessions BEGIN SELECT RAISE(FAIL, 'injected session failure'); END`); err != nil {
			t.Fatal(err)
		}
		p := w.browser(t).password("alice", operatorPassword)
		requireStorageGuidance(t, p, "Sign-in is temporarily unavailable", "Try signing in again", "session storage unavailable")
	})
	t.Run("authenticator setup", func(t *testing.T) {
		w := newWebFixture(t)
		b := w.browser(t)
		b.password("alice", operatorPassword)
		if _, err := w.store.DB().Exec(`CREATE TRIGGER fail_setup BEFORE UPDATE OF pending_totp ON web_sessions BEGIN SELECT RAISE(FAIL, 'injected setup failure'); END`); err != nil {
			t.Fatal(err)
		}
		p := b.do(http.MethodGet, "/login/totp", nil)
		requireStorageGuidance(t, p, "Authenticator setup is temporarily unavailable", "Reload this page", "session storage unavailable")
	})
	t.Run("verified session", func(t *testing.T) {
		w := newWebFixture(t)
		w.browser(t).signIn("alice")
		b := w.browser(t)
		b.password("alice", operatorPassword)
		csrf := csrfOf(t, b.do(http.MethodGet, "/login/totp", nil))
		w.clock.Add(30 * time.Second)
		if _, err := w.store.DB().Exec(`CREATE TRIGGER fail_session BEFORE INSERT ON web_sessions BEGIN SELECT RAISE(FAIL, 'injected session failure'); END`); err != nil {
			t.Fatal(err)
		}
		p := b.do(http.MethodPost, "/login/totp", url.Values{"csrf": {csrf}, "code": {gateway.TOTPCode(w.secrets["alice"], w.clock.Now())}})
		requireStorageGuidance(t, p, "Sign-in could not be completed", "Start again from the sign-in page", "session storage unavailable")
	})
}

func TestDeviceStorageFailuresExplainRecovery(t *testing.T) {
	for _, tc := range []struct{ table, context, diagnostic string }{
		{"devices", "Devices are temporarily unavailable", "device store unavailable"},
		{"oauth_grants", "Device access details are temporarily unavailable", "OAuth grant store unavailable"},
		{"device_activations", "Device activation details are temporarily unavailable", "activation state unavailable"},
	} {
		t.Run(tc.table, func(t *testing.T) {
			w := newWebFixture(t)
			b := w.browser(t)
			b.signIn("alice")
			if _, err := w.store.DB().Exec("ALTER TABLE " + tc.table + " RENAME TO unavailable_table"); err != nil {
				t.Fatal(err)
			}
			requireStorageGuidance(t, b.do(http.MethodGet, "/devices", nil), tc.context, "Reload this page", tc.diagnostic)
		})
	}
}

func TestApprovalStorageFailureExplainsRecovery(t *testing.T) {
	w := newWebFixture(t)
	id := w.grayRun(t)
	b := w.browser(t)
	csrf := b.signIn("alice")
	pending := filepath.Join(w.dir, "devices", w.client.State.DeviceID, "approval", "pending")
	if err := os.Rename(pending, pending+"-saved"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pending, []byte("not a directory"), 0o600); err != nil {
		t.Fatal(err)
	}
	requireStorageGuidance(t, b.do(http.MethodGet, "/approvals", nil), "Approvals are temporarily unavailable", "Reload this page", "approval store unavailable")
	p := b.do(http.MethodPost, "/approvals/"+id, url.Values{"csrf": {csrf}, "decision": {"once"}, "device": {w.client.State.DeviceID}})
	u, err := url.Parse(p.location)
	if err != nil || p.status != http.StatusSeeOther {
		t.Fatalf("decision response: %+v, %v", p, err)
	}
	message := u.Query().Get("error")
	if !strings.Contains(message, "Could not confirm the decision") || !strings.Contains(message, "check the audit before trying again") || !strings.Contains(message, "Details:") {
		t.Fatalf("decision failure lacks recovery guidance and diagnostics: %q", message)
	}
}

func TestOAuthStorageFailureExplainsRecovery(t *testing.T) {
	w := newWebFixture(t)
	o := webOAuth(t, w)
	client := publicClient(t, w.fixture)
	_, challenge := pkce("storage-error")
	path := remote.PathOAuthAuthorize + "?" + authorizationQuery(o, client, "https://agent.example/callback", challenge).Encode()
	b := w.browser(t)
	b.signIn("alice")
	if _, err := w.store.DB().Exec(`ALTER TABLE oauth_clients RENAME TO unavailable_clients`); err != nil {
		t.Fatal(err)
	}
	requireStorageGuidance(t, b.do(http.MethodGet, path, nil), "Client authorization is temporarily unavailable", "Reload this page", "authorization store unavailable")
}

// Authorize can commit a grant before audit publication fails. The browser
// must tell the operator to inspect grants instead of claiming nothing changed.
func TestOAuthConsentAuditFailureDirectsOperatorToCheckGrants(t *testing.T) {
	w := newWebFixture(t)
	o := webOAuth(t, w)
	device := activeTokenDevice(t, w.fixture)
	client := publicClient(t, w.fixture)
	_, challenge := pkce("consent-audit-error")
	path := remote.PathOAuthAuthorize + "?" + authorizationQuery(o, client, "https://agent.example/callback", challenge).Encode()
	b := w.browser(t)
	csrf := b.signIn("alice")
	interruptAudit(t, w.dir, "unwritable")
	p := b.do(http.MethodPost, path, url.Values{"csrf": {csrf}, "decision": {"authorize"}, "device": {device.DeviceID}})
	requireStorageGuidance(t, p, "Could not confirm client authorization", "Check the device's grants before trying again", "authorization recording error")
	grantCount(t, w, 1)
}
