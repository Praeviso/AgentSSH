package gateway_test

import (
	"encoding/base32"
	"encoding/json"
	"html"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/Praeviso/AgentSSH/internal/audit"
	"github.com/Praeviso/AgentSSH/internal/gateway"
	"github.com/Praeviso/AgentSSH/internal/remote"
)

func webOAuth(t *testing.T, w *webFixture) gateway.OAuth {
	t.Helper()
	o, err := gateway.NewOAuth(w.base, w.site.URL)
	if err != nil {
		t.Fatal(err)
	}
	w.web.OAuth = &o
	w.server.WebOrigin = w.site.URL
	handler, err := w.server.Handler(w.base)
	if err != nil {
		t.Fatal(err)
	}
	w.handler.Store(&handler)
	return o
}

func formValue(t *testing.T, p page, name string) string {
	t.Helper()
	pattern := regexp.MustCompile(`name="` + regexp.QuoteMeta(name) + `" value="([^"]*)"`)
	m := pattern.FindStringSubmatch(p.body)
	if m == nil {
		t.Fatalf("no %s field in %d page: %.500s", name, p.status, p.body)
	}
	return html.UnescapeString(m[1])
}

func grantCount(t *testing.T, w *webFixture, want int) []gateway.Grant {
	t.Helper()
	grants, err := gateway.Grants(w.store)
	if err != nil || len(grants) != want {
		t.Fatalf("grants: %+v, %v; want %d", grants, err, want)
	}
	return grants
}

// An unauthenticated OAuth client starts the flow; the operator returns to
// exactly that request after password and TOTP, including failed attempts.
func TestOAuthConsentReturnsThroughPasswordAndTOTP(t *testing.T) {
	w := newWebFixture(t)
	o := webOAuth(t, w)
	device := activeTokenDevice(t, w.fixture)
	client := publicClient(t, w.fixture)
	verifier, challenge := pkce("browser")
	path := remote.PathOAuthAuthorize + "?" + authorizationQuery(o, client, "https://agent.example/callback", challenge).Encode()
	b := w.browser(t)
	start := b.do(http.MethodGet, path, nil)
	if start.status != http.StatusSeeOther || !strings.HasPrefix(start.location, "/login?next=") {
		t.Fatalf("start: %+v", start)
	}
	login := b.do(http.MethodGet, start.location, nil)
	if next := formValue(t, login, "next"); next != path {
		t.Fatalf("login return path %q, want %q", next, path)
	}
	wrong := b.do(http.MethodPost, "/login", url.Values{"csrf": {csrfOf(t, login)}, "next": {formValue(t, login, "next")}, "name": {"alice"}, "password": {"wrong"}})
	if wrong.status != http.StatusUnauthorized || formValue(t, wrong, "next") != path {
		t.Fatalf("password retry: %+v", wrong)
	}
	password := b.do(http.MethodPost, "/login", url.Values{"csrf": {csrfOf(t, wrong)}, "next": {formValue(t, wrong, "next")}, "name": {"alice"}, "password": {operatorPassword}})
	if password.status != http.StatusSeeOther || !strings.HasPrefix(password.location, "/login/totp?next=") {
		t.Fatalf("password: %+v", password)
	}
	// A password-stage session still cannot see or submit consent.
	if p := b.do(http.MethodGet, path, nil); p.location != password.location {
		t.Fatalf("password-only consent page: %+v", p)
	}
	totp := b.do(http.MethodGet, password.location, nil)
	secretMatch := secretField.FindStringSubmatch(totp.body)
	if secretMatch == nil {
		t.Fatal("no TOTP enrollment key")
	}
	secret, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ReplaceAll(secretMatch[1], " ", ""))
	if err != nil {
		t.Fatal(err)
	}
	badCode := b.do(http.MethodPost, "/login/totp", url.Values{"csrf": {csrfOf(t, totp)}, "next": {formValue(t, totp, "next")}, "code": {"12345"}})
	if badCode.status != http.StatusUnauthorized || formValue(t, badCode, "next") != path {
		t.Fatalf("TOTP retry: %+v", badCode)
	}
	verified := b.do(http.MethodPost, "/login/totp", url.Values{"csrf": {csrfOf(t, badCode)}, "next": {formValue(t, badCode, "next")}, "code": {gateway.TOTPCode(secret, w.clock.Now())}})
	if verified.status != http.StatusSeeOther || verified.location != path {
		t.Fatalf("after TOTP: %+v", verified)
	}
	consentPage := b.do(http.MethodGet, verified.location, nil)
	for _, text := range []string{"Hosted agent", client, "Requested access", "self-reported", "does not activate", `value="` + device.DeviceID + `"`} {
		if consentPage.status != http.StatusOK || !strings.Contains(consentPage.body, text) {
			t.Fatalf("consent page lacks %q: %d %.600s", text, consentPage.status, consentPage.body)
		}
	}
	grantCount(t, w, 0)
	approved := b.do(http.MethodPost, path, url.Values{"csrf": {csrfOf(t, consentPage)}, "decision": {"authorize"}, "device": {device.DeviceID}})
	callback, err := url.Parse(approved.location)
	if err != nil || approved.status != http.StatusSeeOther || callback.Host != "agent.example" || callback.Query().Get("state") != "st-1" || callback.Query().Get("iss") != o.Issuer || callback.Query().Get("code") == "" {
		t.Fatalf("consent callback: %+v", approved)
	}
	grant := grantCount(t, w, 1)[0]
	if grant.ClientID != client || grant.DeviceID != device.DeviceID || grant.CreatedBy != "web:alice" {
		t.Fatalf("consented grant: %+v", grant)
	}
	tk := issued(t, tokenRequest(t, w.fixture, exchange(client, callback.Query().Get("code"), verifier)))
	c := &mcpClient{t: t, f: w.fixture, token: tk.AccessToken}
	if r := mcpInit(c); r.status != http.StatusOK {
		t.Fatalf("authorized MCP client: %d %s", r.status, r.raw)
	}
	if result := c.call("run", map[string]any{"host": "web-1", "command": "uptime", "session": "s_consent"}); result.Structured["result"] != "ok" || !strings.Contains(result.Content[0].Text, "up 3 days") {
		t.Fatalf("authorized run: %+v", result)
	}
	devices := b.do(http.MethodGet, "/devices", nil)
	revokePath := "/devices/" + device.DeviceID + "/oauth/" + grant.ID + "/revoke"
	if !strings.Contains(devices.body, revokePath) || !strings.Contains(devices.body, client) || !strings.Contains(devices.body, "web:alice") {
		t.Fatalf("device's grants: %.1000s", devices.body)
	}
	other := tokenDevice(t, w.fixture)
	if p := b.do(http.MethodPost, "/devices/"+other.DeviceID+"/oauth/"+grant.ID+"/revoke", url.Values{"csrf": {csrfOf(t, devices)}}); p.status != http.StatusNotFound {
		t.Fatalf("revoke on another device: %+v", p)
	}
	if p := b.do(http.MethodPost, revokePath, url.Values{"csrf": {csrfOf(t, devices)}}); p.status != http.StatusSeeOther || !strings.Contains(p.location, "notice=") {
		t.Fatalf("revoke: %+v", p)
	}
	if r := c.request("tools/list", nil); r.status != http.StatusUnauthorized {
		t.Fatalf("client's next request after revocation: %d %s", r.status, r.raw)
	}
	refused(t, tokenRequest(t, w.fixture, refreshWith(client, tk.RefreshToken)), "invalid_grant", "revoked")
	if page := b.do(http.MethodGet, "/devices", nil); strings.Contains(page.body, revokePath) || !strings.Contains(page.body, "Revoked") {
		t.Fatalf("revoked grant still actionable: %.900s", page.body)
	}
	// A repeated POST is harmless and produces no second revocation record.
	b.do(http.MethodPost, revokePath, url.Values{"csrf": {csrfOf(t, devices)}})
	var events []audit.Event
	for _, record := range auditRecords(t, w.fixture) {
		if record.GrantID == grant.ID && (record.Event == audit.EventOAuthGrantCreated || record.Event == audit.EventOAuthGrantRevoked) {
			if record.Operator != "web:alice" || record.DeviceID != device.DeviceID || record.ClientID != client {
				t.Fatalf("consent/revocation audit: %+v", record)
			}
			events = append(events, record.Event)
		}
	}
	if len(events) != 2 || events[0] != audit.EventOAuthGrantCreated || events[1] != audit.EventOAuthGrantRevoked {
		t.Fatalf("consent/revocation events: %v", events)
	}
	if result, err := audit.NewStore(w.dir + "/" + gateway.FileAudit).Verify(); err != nil || !result.OK {
		t.Fatalf("audit chain: %+v, %v", result, err)
	}
}

func TestOAuthMutationsRequireTheOperatorTOTPAndCSRF(t *testing.T) {
	w := newWebFixture(t)
	o := webOAuth(t, w)
	device := activeTokenDevice(t, w.fixture)
	client := publicClient(t, w.fixture)
	_, challenge := pkce("operator")
	path := remote.PathOAuthAuthorize + "?" + authorizationQuery(o, client, "https://agent.example/callback", challenge).Encode()
	anonymous := w.browser(t)
	halfway := w.browser(t)
	halfway.password("bob", operatorPassword)
	b := w.browser(t)
	csrf := b.signIn("alice")
	form := url.Values{"csrf": {csrf}, "decision": {"authorize"}, "device": {device.DeviceID}}
	for name, tc := range map[string]struct {
		browser *browser
		csrf    string
		header  []string
	}{
		"anonymous":        {anonymous, csrf, nil},
		"password only":    {halfway, csrfOf(t, halfway.do(http.MethodGet, "/login/totp", nil)), nil},
		"no CSRF":          {b, "", nil},
		"wrong CSRF":       {b, "bad", nil},
		"another origin":   {b, csrf, []string{"Origin", "https://evil.example"}},
		"cross-site fetch": {b, csrf, []string{"Sec-Fetch-Site", "cross-site"}},
	} {
		t.Run(name, func(t *testing.T) {
			form.Set("csrf", tc.csrf)
			if p := tc.browser.do(http.MethodPost, path, form, tc.header...); p.status != http.StatusForbidden {
				t.Fatalf("consent without operator authority: %+v", p)
			}
			grantCount(t, w, 0)
		})
	}
	form.Set("csrf", csrf)
	approved := b.do(http.MethodPost, path, form)
	if approved.status != http.StatusSeeOther {
		t.Fatalf("consent: %+v", approved)
	}
	grant := grantCount(t, w, 1)[0]
	revokePath := "/devices/" + device.DeviceID + "/oauth/" + grant.ID + "/revoke"
	for _, tc := range []struct {
		b      *browser
		form   url.Values
		header []string
	}{
		{anonymous, url.Values{"csrf": {csrf}}, nil},
		{halfway, url.Values{"csrf": {csrfOf(t, halfway.do(http.MethodGet, "/login/totp", nil))}}, nil},
		{b, nil, nil},
		{b, url.Values{"csrf": {csrf}}, []string{"Origin", "https://evil.example"}},
	} {
		if p := tc.b.do(http.MethodPost, revokePath, tc.form, tc.header...); p.status != http.StatusForbidden {
			t.Fatalf("revocation without operator authority: %+v", p)
		}
		if !grantCount(t, w, 1)[0].RevokedAt.IsZero() {
			t.Fatal("unauthorized revocation changed the grant")
		}
	}
}

func TestOAuthConsentValidatesRequestsAndDeviceChoice(t *testing.T) {
	w := newWebFixture(t)
	o := webOAuth(t, w)
	client := publicClient(t, w.fixture)
	_, challenge := pkce("choice")
	query := authorizationQuery(o, client, "https://agent.example/callback", challenge)
	path := remote.PathOAuthAuthorize + "?" + query.Encode()
	b := w.browser(t)
	csrf := b.signIn("alice")
	inactive := tokenDevice(t, w.fixture)
	revoked := tokenDevice(t, w.fixture)
	if err := w.store.RevokeDevice(revoked.DeviceID, time.Now()); err != nil {
		t.Fatal(err)
	}
	consentPage := b.do(http.MethodGet, path, nil)
	if !strings.Contains(consentPage.body, `value="`+inactive.DeviceID+`"`) || strings.Contains(consentPage.body, `value="`+revoked.DeviceID+`"`) || strings.Contains(consentPage.body, `value="`+w.client.State.DeviceID+`"`) {
		t.Fatalf("device choices: %.1500s", consentPage.body)
	}
	for _, id := range []string{"", "dev_unknown", revoked.DeviceID, w.client.State.DeviceID} {
		if p := b.do(http.MethodPost, path, url.Values{"csrf": {csrf}, "decision": {"authorize"}, "device": {id}}); p.status != http.StatusBadRequest {
			t.Fatalf("invalid device %q: %+v", id, p)
		}
		grantCount(t, w, 0)
	}
	for _, key := range []string{"client_id", "redirect_uri", "code_challenge"} {
		bad, _ := url.ParseQuery(query.Encode())
		bad.Set(key, "unknown")
		for _, method := range []string{http.MethodGet, http.MethodPost} {
			p := b.do(method, remote.PathOAuthAuthorize+"?"+bad.Encode(), url.Values{"csrf": {csrf}, "decision": {"authorize"}, "device": {inactive.DeviceID}})
			if key == "code_challenge" {
				if p.status != http.StatusSeeOther || !strings.HasPrefix(p.location, "https://agent.example/callback?") || !strings.Contains(p.location, "error=invalid_request") {
					t.Fatalf("invalid PKCE: %+v", p)
				}
			} else if p.status != http.StatusBadRequest || p.location != "" {
				t.Fatalf("untrusted %s: %+v", key, p)
			}
			grantCount(t, w, 0)
		}
	}
	// Denial needs no device, creates no grant, and returns state and issuer.
	denied := b.do(http.MethodPost, path, url.Values{"csrf": {csrf}, "decision": {"deny"}})
	callback, err := url.Parse(denied.location)
	if err != nil || denied.status != http.StatusSeeOther || callback.Query().Get("error") != "access_denied" || callback.Query().Get("state") != "st-1" || callback.Query().Get("iss") != o.Issuer || callback.Query().Get("code") != "" {
		t.Fatalf("denial: %+v", denied)
	}
	grantCount(t, w, 0)
	// Consent is allowed while inactive but never activates the device.
	if p := b.do(http.MethodPost, path, url.Values{"csrf": {csrf}, "decision": {"authorize"}, "device": {inactive.DeviceID}}); p.status != http.StatusSeeOther {
		t.Fatalf("inactive consent: %+v", p)
	}
	grantCount(t, w, 1)
	if a, err := gateway.DeviceActivation(w.store, inactive.DeviceID); err != nil || a.Active(time.Now()) {
		t.Fatalf("consent activated the device: %+v, %v", a, err)
	}
	w.web.OAuth = nil
	if p := b.do(http.MethodGet, path, nil); p.status != http.StatusNotFound {
		t.Fatalf("OAuth disabled: %+v", p)
	}
}

func TestOAuthLoginReturnCannotLeaveTheAuthorizationEndpoint(t *testing.T) {
	w := newWebFixture(t)
	b := w.browser(t)
	b.signIn("alice")
	for _, next := range []string{"https://evil.example/oauth/authorize", "//evil.example/oauth/authorize", "/devices", "/oauth/authorize/../devices", "/oauth%2fauthorize", "/oauth/authorize#elsewhere", strings.Repeat("a", 8193)} {
		if p := b.do(http.MethodGet, "/login?"+url.Values{"next": {next}}.Encode(), nil); p.status != http.StatusSeeOther || p.location != "/approvals" {
			t.Fatalf("unsafe return %q: %+v", next, p)
		}
	}
	// A signed-in operator still reviews consent; login never authorizes.
	next := "/oauth/authorize?client_id=oc_example&state=a%2Bb"
	if p := b.do(http.MethodGet, "/login?"+url.Values{"next": {next}}.Encode(), nil); p.location != next {
		t.Fatalf("valid return: %+v", p)
	}
	grantCount(t, w, 0)
}

func TestOAuthConsentCSPAllowsOnlyItsValidatedCallbackOrigin(t *testing.T) {
	w := newWebFixture(t)
	o := webOAuth(t, w)
	b := w.browser(t)
	b.signIn("alice")
	_, challenge := pkce("csp")
	for _, tc := range []struct{ callback, source string }{
		{"https://agent.example/callback?keep=yes", "https://agent.example"},
		{"http://127.0.0.1:32123/callback", "http://127.0.0.1:32123"},
		{"http://[::1]:32123/callback", "http://[::1]:32123"},
		{"https://*.example/callback", "https://%2A.example"},
		{"https://client.example;script-src/callback", "https://client.example%3Bscript-src"},
	} {
		client := register(t, w.fixture, map[string]any{"client_name": "Browser client", "redirect_uris": []string{tc.callback}, "token_endpoint_auth_method": "none"})["client_id"].(string)
		path := remote.PathOAuthAuthorize + "?" + authorizationQuery(o, client, tc.callback, challenge).Encode()
		p := b.do(http.MethodGet, path, nil)
		csp := p.header.Get("Content-Security-Policy")
		if p.status != http.StatusOK || !strings.Contains(csp, "form-action 'self' "+tc.source+";") || strings.Count(csp, "form-action") != 1 || !strings.Contains(csp, "script-src 'self';") {
			t.Fatalf("callback %q: %d %q", tc.callback, p.status, csp)
		}
	}
	if p := b.do(http.MethodGet, "/devices", nil); !strings.Contains(p.header.Get("Content-Security-Policy"), "form-action 'self';") {
		t.Fatalf("other pages' form policy changed: %v", p.header)
	}
}

// Every transport uses a real Web UI approval and the real SSH run pipeline.
func TestAgentApprovalWorkflowThroughWebUI(t *testing.T) {
	for _, transport := range []string{"JSON", "MCP", "OAuth MCP"} {
		t.Run(transport, func(t *testing.T) {
			w := newWebFixture(t)
			device := activeTokenDevice(t, w.fixture)
			b := w.browser(t)
			csrf := b.signIn("alice")
			credential := device.Token
			if transport == "OAuth MCP" {
				o := webOAuth(t, w)
				client := publicClient(t, w.fixture)
				verifier, challenge := pkce("workflow")
				path := remote.PathOAuthAuthorize + "?" + authorizationQuery(o, client, "https://agent.example/callback", challenge).Encode()
				p := b.do(http.MethodPost, path, url.Values{"csrf": {csrf}, "decision": {"authorize"}, "device": {device.DeviceID}})
				callback, err := url.Parse(p.location)
				if err != nil || p.status != http.StatusSeeOther {
					t.Fatalf("consent: %+v", p)
				}
				credential = issued(t, tokenRequest(t, w.fixture, exchange(client, callback.Query().Get("code"), verifier))).AccessToken
			}
			c := &mcpClient{t: t, f: w.fixture, token: credential}
			if transport != "JSON" {
				if r := mcpInit(c); r.status != http.StatusOK {
					t.Fatalf("initialize: %d %s", r.status, r.raw)
				}
			}
			call := func(name string, args map[string]any) map[string]any {
				t.Helper()
				if transport != "JSON" {
					result := c.call(name, args)
					if result.IsError {
						t.Fatalf("%s: %+v", name, result)
					}
					return result.Structured
				}
				path := map[string]string{"hosts": remote.PathTokenHosts, "new_session": remote.PathAPISession, "run": remote.PathAPIRun, "approval_status": remote.PathAPIApprovalStatus}[name]
				var answer apiAnswer
				if name == "hosts" {
					answer = bearer(t, w.fixture, path, credential)
				} else {
					answer = apiCall(t, w.fixture, credential, path, args)
				}
				var result map[string]any
				if answer.status != http.StatusOK || json.Unmarshal(answer.raw, &result) != nil {
					t.Fatalf("%s: %d %s", name, answer.status, answer.raw)
				}
				return result
			}
			if hosts, _ := json.Marshal(call("hosts", nil)); !strings.Contains(string(hosts), "web-1") {
				t.Fatalf("hosts: %s", hosts)
			}
			session := call("new_session", map[string]any{})["session_id"]
			runCommand := func(command string) map[string]any {
				return call("run", map[string]any{"host": "web-1", "command": command, "session": session})
			}
			if got := runCommand("uptime"); got["result"] != "ok" || got["exit_code"] != 0.0 {
				t.Fatalf("allowed run: %v", got)
			}
			if got := runCommand("reboot"); got["result"] != "denied" || got["exit_code"] != 6.0 {
				t.Fatalf("denied run: %v", got)
			}
			gray := runCommand("uname -s")
			if gray["result"] != "approval_required" || gray["exit_code"] != 7.0 {
				t.Fatalf("gray run: %v", gray)
			}
			id := gray["responses"].([]any)[0].(map[string]any)["approval_id"].(string)
			if got := call("approval_status", map[string]any{"approval_id": id, "wait_ms": 0}); got["status"] != "pending" {
				t.Fatalf("pending: %v", got)
			}
			approved := make(chan map[string]any, 1)
			go func() { approved <- call("approval_status", map[string]any{"approval_id": id, "wait_ms": 5000}) }()
			if p := b.do(http.MethodPost, "/approvals/"+id, url.Values{"csrf": {csrf}, "decision": {"session"}, "device": {device.DeviceID}}); p.status != http.StatusSeeOther || !strings.Contains(p.location, "notice=") {
				t.Fatalf("Web UI approval: %+v", p)
			}
			select {
			case got := <-approved:
				if got["status"] != "approved" {
					t.Fatalf("wait after approval: %v", got)
				}
			case <-time.After(10 * time.Second):
				t.Fatal("approval wait did not return")
			}
			got := runCommand("uname -s")
			body, _ := json.Marshal(got)
			if got["result"] != "ok" || got["exit_code"] != 0.0 || !strings.Contains(string(body), "Linux") {
				t.Fatalf("rerun after approval: %s", body)
			}
		})
	}
}
