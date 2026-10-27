package gateway_test

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/Praeviso/AgentSSH/internal/gateway"
)

func TestWebRestrictionsReportEffectiveStateDuringAuditFailure(t *testing.T) {
	w := newWebFixture(t)
	o := webOAuth(t, w)
	device := activeTokenDevice(t, w.fixture)
	client := publicClient(t, w.fixture)
	_, challenge := pkce("web-audit")
	_, grant := consent(t, w.fixture, o, client, challenge, device.DeviceID)
	b := w.browser(t)
	csrf := b.signIn("alice")
	restore := interruptAudit(t, w.dir, "unwritable")
	for _, operation := range []struct{ path, applied string }{
		{"/devices/" + device.DeviceID + "/oauth/" + grant.ID + "/revoke", "The grant is revoked"},
		{"/devices/" + device.DeviceID + "/deactivate", "The device is inactive"},
	} {
		p := b.do(http.MethodPost, operation.path, url.Values{"csrf": {csrf}})
		u, err := url.Parse(p.location)
		if err != nil || p.status != http.StatusSeeOther {
			t.Fatalf("restriction redirect: %+v, %v", p, err)
		}
		message := u.Query().Get("error")
		if !strings.Contains(message, operation.applied) || !strings.Contains(message, "repair") {
			t.Fatalf("Web UI misreported a committed restriction: %q", message)
		}
	}
	grants, err := gateway.Grants(w.store)
	if err != nil || len(grants) != 1 || grants[0].RevokedAt.IsZero() {
		t.Fatalf("Web UI grant revocation: %+v, %v", grants, err)
	}
	a, err := gateway.DeviceActivation(w.store, device.DeviceID)
	if err != nil || a.Active(time.Now()) {
		t.Fatalf("Web UI deactivation: %+v, %v", a, err)
	}
	restore()
	if err := gateway.RecordPendingAudits(w.dir, w.store); err != nil {
		t.Fatal(err)
	}
}
