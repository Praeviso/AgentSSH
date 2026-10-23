package gateway_test

import (
	"context"
	"encoding/base32"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Praeviso/AgentSSH/internal/approval"
	"github.com/Praeviso/AgentSSH/internal/audit"
	"github.com/Praeviso/AgentSSH/internal/gateway"
	"github.com/Praeviso/AgentSSH/internal/remote"
)

func init() {
	gateway.PasswordParams.Time, gateway.PasswordParams.MemoryKiB = 1, 64
}

// clock is a settable time for sessions, TOTP steps and login windows.
type clock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *clock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.now }
func (c *clock) Add(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// webFixture is the Web UI over an exec gateway, behind TLS.
type webFixture struct {
	*fixture
	site  *httptest.Server
	clock *clock
	// secrets are the operators' TOTP keys, as their authenticator holds them.
	secrets map[string][]byte
}

const operatorPassword = "correct horse battery"

func newWebFixture(t *testing.T) *webFixture {
	t.Helper()
	f, _ := execGateway(t)
	web, err := gateway.NewWebUI(f.dir, f.store, f.keys)
	if err != nil {
		t.Fatal(err)
	}
	c := &clock{now: time.Now()}
	web.Now = c.Now
	site := httptest.NewTLSServer(web.Handler())
	t.Cleanup(site.Close)
	for _, name := range []string{"alice", "bob"} {
		if err := gateway.AddOperator(f.store, name, operatorPassword, time.Now()); err != nil {
			t.Fatal(err)
		}
	}
	return &webFixture{fixture: f, site: site, clock: c, secrets: map[string][]byte{}}
}

// browser is one operator's browser: a cookie jar that never follows
// redirects, so tests see each response.
type browser struct {
	t      *testing.T
	w      *webFixture
	client *http.Client
}

func (w *webFixture) browser(t *testing.T) *browser {
	jar, _ := cookiejar.New(nil)
	// Client returns one shared client; each browser needs its own jar.
	client := *w.site.Client()
	client.Jar = jar
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &browser{t: t, w: w, client: &client}
}

type page struct {
	status   int
	location string
	body     string
	header   http.Header
}

func (b *browser) do(method, path string, form url.Values, header ...string) page {
	b.t.Helper()
	req, err := http.NewRequest(method, b.w.site.URL+path, strings.NewReader(form.Encode()))
	if err != nil {
		b.t.Fatal(err)
	}
	if method == http.MethodPost {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	for i := 0; i+1 < len(header); i += 2 {
		req.Header.Set(header[i], header[i+1])
	}
	resp, err := b.client.Do(req)
	if err != nil {
		b.t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	return page{status: resp.StatusCode, location: resp.Header.Get("Location"), body: string(body), header: resp.Header}
}

var csrfField = regexp.MustCompile(`name="csrf" value="([0-9a-f]+)"`)

func csrfOf(t *testing.T, p page) string {
	t.Helper()
	m := csrfField.FindStringSubmatch(p.body)
	if m == nil {
		t.Fatalf("no CSRF token in %d page:\n%.400s", p.status, p.body)
	}
	return m[1]
}

// password signs in with name and password only.
func (b *browser) password(name, password string) page {
	b.t.Helper()
	login := b.do(http.MethodGet, "/login", nil)
	return b.do(http.MethodPost, "/login", url.Values{"csrf": {csrfOf(b.t, login)}, "name": {name}, "password": {password}})
}

var secretField = regexp.MustCompile(`class="secret">([A-Z2-7 ]+)<`)

// signIn completes a login, enrolling TOTP the first time, and returns the
// session's CSRF token.
func (b *browser) signIn(name string) string {
	b.t.Helper()
	if p := b.password(name, operatorPassword); p.status != http.StatusSeeOther || p.location != "/login/totp" {
		b.t.Fatalf("password step: %+v", p)
	}
	totp := b.do(http.MethodGet, "/login/totp", nil)
	if m := secretField.FindStringSubmatch(totp.body); m != nil {
		secret, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ReplaceAll(m[1], " ", ""))
		if err != nil {
			b.t.Fatal(err)
		}
		b.w.secrets[name] = secret
	}
	// A code is accepted once, so each sign-in uses the next step.
	b.w.clock.Add(30 * time.Second)
	code := gateway.TOTPCode(b.w.secrets[name], b.w.clock.Now())
	if p := b.do(http.MethodPost, "/login/totp", url.Values{"csrf": {csrfOf(b.t, totp)}, "code": {code}}); p.status != http.StatusSeeOther || p.location != "/approvals" {
		b.t.Fatalf("TOTP step: %d %s\n%.300s", p.status, p.location, p.body)
	}
	approvals := b.do(http.MethodGet, "/approvals", nil)
	if approvals.status != http.StatusOK {
		b.t.Fatalf("approvals: %+v", approvals)
	}
	return csrfOf(b.t, approvals)
}

func (w *webFixture) grayRun(t *testing.T) string {
	t.Helper()
	result, err := w.client.Exec(context.Background(), execReq("uname"), io.Discard, io.Discard)
	if err != nil || result.ExitCode != 7 {
		t.Fatalf("gray-zone run = %+v, %v", result, err)
	}
	return result.Responses[0].ApprovalID
}

func (w *webFixture) status(t *testing.T, id string) string {
	t.Helper()
	status, err := w.client.ApprovalStatus(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	return status.Status.Status
}

// The operator approves in the browser and the decision is audited with
// their name.
func TestOperatorDecidesInTheBrowser(t *testing.T) {
	w := newWebFixture(t)
	id := w.grayRun(t)
	b := w.browser(t)
	csrf := b.signIn("alice")
	if page := b.do(http.MethodGet, "/approvals", nil); !strings.Contains(page.body, id) || !strings.Contains(page.body, "1 waiting for a decision") || !strings.Contains(page.body, ">uname</pre>") {
		t.Fatalf("approvals page lacks the request:\n%.600s", page.body)
	}
	p := b.do(http.MethodPost, "/approvals/"+id, url.Values{"csrf": {csrf}, "decision": {"once"}, "device": {w.client.State.DeviceID}})
	if p.status != http.StatusSeeOther || !strings.Contains(p.location, "notice=") {
		t.Fatalf("decision: %+v", p)
	}
	if got := w.status(t, id); got != "approved" {
		t.Fatalf("status after the decision = %s", got)
	}
	records, err := audit.NewStore(w.dir + "/" + gateway.FileAudit).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	last := records[len(records)-1]
	if last.Event != audit.EventApprovalGranted || last.Operator != "web:alice" || last.ApprovalScope != "once" {
		t.Fatalf("decision record = %+v", last)
	}
	if page := b.do(http.MethodGet, "/audit", nil); !strings.Contains(page.body, "Hash chain intact") || !strings.Contains(page.body, "web:alice") {
		t.Fatalf("audit page:\n%.600s", page.body)
	}
}

// Only an operator's signed-in browser reaches decisions: not an anonymous
// request, not a device's signed request.
func TestDecisionsNeedAnOperatorSession(t *testing.T) {
	w := newWebFixture(t)
	id := w.grayRun(t)
	anonymous := w.browser(t)
	if p := anonymous.do(http.MethodGet, "/approvals", nil); p.status != http.StatusSeeOther || p.location != "/login" {
		t.Fatalf("anonymous approvals page: %+v", p)
	}
	if p := anonymous.do(http.MethodPost, "/approvals/"+id, url.Values{"decision": {"once"}}); p.status != http.StatusForbidden {
		t.Fatalf("anonymous decision: %+v", p)
	}
	// A device's own signed request, aimed at the Web UI.
	home := w.enrollHome(t, "tampered")
	if status := signedPost(t, &fixture{base: w.site.URL}, home, "/approvals/"+id, []byte("decision=once")); status != http.StatusForbidden {
		t.Fatalf("device-signed decision answered %d", status)
	}
	if got := w.status(t, id); got != "pending" {
		t.Fatalf("status = %s", got)
	}
}

// A decision must carry the session's CSRF token and come from the page.
func TestDecisionsNeedTheCSRFToken(t *testing.T) {
	w := newWebFixture(t)
	id := w.grayRun(t)
	b := w.browser(t)
	csrf := b.signIn("alice")
	for name, form := range map[string]url.Values{
		"no token":    {"decision": {"once"}},
		"wrong token": {"decision": {"once"}, "csrf": {strings.Repeat("0", len(csrf))}},
	} {
		if p := b.do(http.MethodPost, "/approvals/"+id, form); p.status != http.StatusForbidden {
			t.Fatalf("%s: %+v", name, p)
		}
	}
	if p := b.do(http.MethodPost, "/approvals/"+id, url.Values{"decision": {"once"}, "csrf": {csrf}}, "Sec-Fetch-Site", "cross-site"); p.status != http.StatusForbidden {
		t.Fatalf("cross-site decision: %+v", p)
	}
	for _, origin := range []string{"https://evil.example", "null"} {
		if p := b.do(http.MethodPost, "/approvals/"+id, url.Values{"decision": {"once"}, "csrf": {csrf}}, "Origin", origin); p.status != http.StatusForbidden {
			t.Fatalf("decision from origin %s: %+v", origin, p)
		}
	}
	if got := w.status(t, id); got != "pending" {
		t.Fatalf("status = %s", got)
	}
}

// A password alone opens only the TOTP step: no approvals, no decisions,
// whether or not the operator has set TOTP up.
func TestAPasswordAloneCannotDecide(t *testing.T) {
	w := newWebFixture(t)
	id := w.grayRun(t)
	b := w.browser(t)
	if p := b.password("alice", operatorPassword); p.location != "/login/totp" {
		t.Fatalf("password step: %+v", p)
	}
	csrf := csrfOf(t, b.do(http.MethodGet, "/login/totp", nil))
	if p := b.do(http.MethodGet, "/approvals", nil); p.status != http.StatusSeeOther || p.location != "/login/totp" {
		t.Fatalf("approvals before TOTP: %+v", p)
	}
	if p := b.do(http.MethodPost, "/approvals/"+id, url.Values{"decision": {"once"}, "csrf": {csrf}}); p.status != http.StatusForbidden {
		t.Fatalf("decision before TOTP: %+v", p)
	}
	if p := b.do(http.MethodPost, "/login/totp", url.Values{"csrf": {csrf}, "code": {"000000"}}); p.status != http.StatusUnauthorized {
		t.Fatalf("wrong code: %+v", p)
	}
	if got := w.status(t, id); got != "pending" {
		t.Fatalf("status = %s", got)
	}
}

// A TOTP code works once; a replay in the same step is refused.
func TestATOTPCodeWorksOnce(t *testing.T) {
	w := newWebFixture(t)
	w.browser(t).signIn("alice")
	code := gateway.TOTPCode(w.secrets["alice"], w.clock.Now())
	b := w.browser(t)
	b.password("alice", operatorPassword)
	csrf := csrfOf(t, b.do(http.MethodGet, "/login/totp", nil))
	if p := b.do(http.MethodPost, "/login/totp", url.Values{"csrf": {csrf}, "code": {code}}); p.status != http.StatusUnauthorized {
		t.Fatalf("replayed code: %+v", p)
	}
}

// Revoking an operator ends their sessions on the next request.
func TestRevocationEndsSessionsAtOnce(t *testing.T) {
	w := newWebFixture(t)
	id := w.grayRun(t)
	b := w.browser(t)
	csrf := b.signIn("alice")
	if err := gateway.RevokeOperator(w.store, "alice", time.Now()); err != nil {
		t.Fatal(err)
	}
	if p := b.do(http.MethodPost, "/approvals/"+id, url.Values{"decision": {"once"}, "csrf": {csrf}}); p.status != http.StatusForbidden {
		t.Fatalf("decision after revocation: %+v", p)
	}
	if p := b.do(http.MethodGet, "/approvals", nil); p.location != "/login" {
		t.Fatalf("page after revocation: %+v", p)
	}
	if p := w.browser(t).password("alice", operatorPassword); p.status != http.StatusUnauthorized {
		t.Fatalf("revoked operator signed in: %+v", p)
	}
}

// Failed sign-ins lock the account for the window, even for the right
// password, while other operators can still sign in.
func TestFailedLoginsAreRateLimited(t *testing.T) {
	w := newWebFixture(t)
	b := w.browser(t)
	for i := 0; i < 5; i++ {
		if p := b.password("alice", "wrong password!"); p.status != http.StatusUnauthorized {
			t.Fatalf("attempt %d: %+v", i, p)
		}
	}
	if p := b.password("alice", operatorPassword); p.status != http.StatusTooManyRequests {
		t.Fatalf("attempt beyond the limit: %+v", p)
	}
	w.browser(t).signIn("bob")
	w.clock.Add(16 * time.Minute)
	if p := b.password("alice", operatorPassword); p.status != http.StatusSeeOther {
		t.Fatalf("after the window: %+v", p)
	}
}

// Session and login cookies are HttpOnly, Secure, SameSite=Strict; pages
// forbid framing and inline script.
func TestCookiesAndHeaders(t *testing.T) {
	w := newWebFixture(t)
	b := w.browser(t)
	login := b.do(http.MethodGet, "/login", nil)
	resp := b.password("alice", operatorPassword)
	for _, p := range []page{login, resp} {
		for _, cookie := range p.header.Values("Set-Cookie") {
			if !strings.Contains(cookie, "HttpOnly") || !strings.Contains(cookie, "Secure") || !strings.Contains(cookie, "SameSite=Strict") || !strings.Contains(cookie, "Path=/") {
				t.Fatalf("cookie %q", cookie)
			}
		}
	}
	if !strings.Contains(strings.Join(resp.header.Values("Set-Cookie"), "\n"), "agentssh_session=") {
		t.Fatal("no session cookie after the password step")
	}
	csp := login.header.Get("Content-Security-Policy")
	// A browser sends "Origin: null" on form posts under no-referrer, which
	// the origin check would refuse.
	if !strings.Contains(csp, "default-src 'none'") || !strings.Contains(csp, "frame-ancestors 'none'") || strings.Contains(csp, "unsafe-inline") || login.header.Get("Cache-Control") != "no-store" || login.header.Get("Referrer-Policy") != "same-origin" {
		t.Fatalf("headers: %v", login.header)
	}
}

// A plan is decided as a whole after single rows are denied, and host scope
// is not offered for it.
func TestPlansAreDecidedAsAWholeAfterRowDenials(t *testing.T) {
	w := newWebFixture(t)
	planID, _ := approval.NewPlanID()
	result, err := w.client.SubmitPlan(context.Background(), remote.PlanSubmitRequest{PlanID: planID, Host: "web-1", Session: "s_test",
		Review:   approval.PlanReview{Metadata: approval.PlanMetadata{Title: "rollout", Description: "restart app\nthen check"}},
		Commands: []remote.PlanSubmitCommand{{ID: "a", Cmd: "systemctl restart app"}, {ID: "b", Cmd: "rm -f /tmp/cache; true"}}})
	if err != nil || result.Response.Pending != 2 {
		t.Fatalf("submit = %+v, %v", result, err)
	}
	b := w.browser(t)
	csrf := b.signIn("alice")
	page := b.do(http.MethodGet, "/approvals", nil)
	if !strings.Contains(page.body, "Plan · rollout") || !strings.Contains(page.body, "Uses shell syntax") || !strings.Contains(page.body, "restart app\nthen check") || strings.Contains(page.body, `action="/plans/`+planID+`"`) && strings.Contains(page.body, `value="host"`) {
		t.Fatalf("plan view:\n%.1200s", page.body)
	}
	deny := result.Response.Commands[1].ApprovalID
	if p := b.do(http.MethodPost, "/approvals/"+deny, url.Values{"csrf": {csrf}, "decision": {"deny"}, "device": {w.client.State.DeviceID}}); p.status != http.StatusSeeOther {
		t.Fatalf("row deny: %+v", p)
	}
	if p := b.do(http.MethodPost, "/plans/"+planID, url.Values{"csrf": {csrf}, "decision": {"host"}}); !strings.Contains(p.location, "error=") {
		t.Fatalf("whole-plan host scope: %+v", p)
	}
	if p := b.do(http.MethodPost, "/plans/"+planID, url.Values{"csrf": {csrf}, "decision": {"session"}, "device": {w.client.State.DeviceID}}); !strings.Contains(p.location, "notice=") {
		t.Fatalf("plan approve: %+v", p)
	}
	status, err := w.client.PlanStatus(context.Background(), planID)
	if err != nil || status.Status.Approved != 1 || status.Status.Denied != 1 || status.Status.Status != "denied" {
		t.Fatalf("plan status = %+v, %v", status.Status, err)
	}
}

// Checking the limit and counting an attempt are one step: a burst of
// concurrent wrong passwords gets at most the account's allowance checked.
func TestConcurrentLoginsCannotPassTheLimit(t *testing.T) {
	w := newWebFixture(t)
	type attempt struct {
		b    *browser
		csrf string
	}
	var attempts []attempt
	for i := 0; i < 30; i++ {
		b := w.browser(t)
		attempts = append(attempts, attempt{b, csrfOf(t, b.do(http.MethodGet, "/login", nil))})
	}
	statuses := make(chan int, len(attempts))
	var wg sync.WaitGroup
	for _, a := range attempts {
		wg.Add(1)
		go func() {
			defer wg.Done()
			statuses <- a.b.do(http.MethodPost, "/login", url.Values{"csrf": {a.csrf}, "name": {"alice"}, "password": {"wrong password!"}}).status
		}()
	}
	wg.Wait()
	close(statuses)
	checked := 0
	for status := range statuses {
		if status == http.StatusUnauthorized {
			checked++
		}
	}
	if checked > 5 {
		t.Fatalf("%d concurrent wrong passwords were checked; the limit is 5", checked)
	}
}
