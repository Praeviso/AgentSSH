package gateway

import (
	"context"
	"crypto/subtle"
	"embed"
	"encoding/base32"
	"encoding/base64"
	"errors"
	"fmt"
	"html/template"
	"io/fs"
	"log"
	"mime"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Praeviso/AgentSSH/internal/approval"
	"github.com/Praeviso/AgentSSH/internal/audit"
	"github.com/Praeviso/AgentSSH/internal/controlplane"
	"github.com/Praeviso/AgentSSH/internal/qr"
	"github.com/Praeviso/AgentSSH/internal/remote"
)

//go:embed webui
var webAssets embed.FS

// Cookie names. The session cookie carries a random token whose digest keys
// web_sessions; the login cookie is a double-submit token for the login form.
const (
	sessionCookie = "agentssh_session"
	loginCookie   = "agentssh_login"
)

// Login throttling: failures within loginWindow count against both the
// account and the client address; at the limit further attempts are refused
// until the window passes. A client address may be a shared proxy, so it
// gets a looser limit than an account.
const (
	loginWindow       = 15 * time.Minute
	accountFailures   = 5
	addressFailures   = 20
	webIssuer         = "AgentSSH gateway"
	auditPageMaxLines = 200
	// maxFormBytes bounds a POST body; the largest form is a plan decision.
	maxFormBytes = 64 << 10
)

// passwordWait is how long a sign-in waits for a free password check
// before it is refused as busy.
var passwordWait = 5 * time.Second

// WebUI serves the operator Web UI: login with password and TOTP, approval
// decisions, and the audit chain. It runs on its own listener, never on the
// device API's.
type WebUI struct {
	Dir   string
	Store *controlplane.Store
	Keys  *controlplane.Keys
	Now   func() time.Time
	// Origin is the origin browsers reach the Web UI at (see WebOrigin).
	// Empty compares a request's Origin header with its Host, which holds
	// when browsers connect directly or a proxy preserves Host.
	Origin string
	// OAuth is the same issuer/resource descriptor as the device API's.
	// Nil leaves the authorization endpoint unavailable.
	OAuth *OAuth

	pages   map[string]*template.Template
	limiter *loginLimiter
}

// NewWebUI wires the gateway's data directory, store and unlocked keys.
func NewWebUI(dir string, store *controlplane.Store, keys *controlplane.Keys) (*WebUI, error) {
	w := &WebUI{Dir: dir, Store: store, Keys: keys, Now: time.Now, pages: map[string]*template.Template{}, limiter: newLoginLimiter()}
	funcs := template.FuncMap{
		"when":    func(ts string) string { return formatWhen(ts) },
		"shell":   hasShellSyntax,
		"short":   func(s string, n int) string { return shorten(s, n) },
		"offers":  func(scopes []approval.Scope, s string) bool { return offers(scopes, approval.Scope(s)) },
		"fmtTime": func(t time.Time) string { return t.UTC().Format(time.RFC3339) },
	}
	for _, page := range []string{"login", "totp", "approvals", "audit", "devices", "oauth"} {
		t, err := template.New("layout.html").Funcs(funcs).ParseFS(webAssets, "webui/layout.html", "webui/"+page+".html")
		if err != nil {
			return nil, err
		}
		w.pages[page] = t
	}
	return w, nil
}

func (w *WebUI) now() time.Time {
	if w.Now != nil {
		return w.Now()
	}
	return time.Now()
}

// Handler routes the Web UI.
func (w *WebUI) Handler() http.Handler {
	mux := http.NewServeMux()
	static, _ := fs.Sub(webAssets, "webui/static")
	mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServerFS(static)))
	mux.HandleFunc("GET /{$}", func(rw http.ResponseWriter, r *http.Request) { http.Redirect(rw, r, "/approvals", http.StatusSeeOther) })
	mux.HandleFunc("GET /login", w.loginPage)
	mux.HandleFunc("POST /login", w.login)
	mux.HandleFunc("GET /login/totp", w.withSession(StagePassword, w.totpPage))
	mux.HandleFunc("POST /login/totp", w.withSession(StagePassword, w.totp))
	mux.HandleFunc("POST /logout", w.withSession("", w.logout))
	mux.HandleFunc("GET /approvals", w.withSession(StageActive, w.approvalsPage))
	mux.HandleFunc("POST /approvals/{id}", w.withSession(StageActive, w.decideApproval))
	mux.HandleFunc("POST /plans/{id}", w.withSession(StageActive, w.decidePlan))
	mux.HandleFunc("GET /audit", w.withSession(StageActive, w.auditPage))
	mux.HandleFunc("GET /devices", w.withSession(StageActive, w.devicesPage))
	mux.HandleFunc("POST /devices/{id}/activate", w.withSession(StageActive, w.activateDevice))
	mux.HandleFunc("POST /devices/{id}/deactivate", w.withSession(StageActive, w.deactivateDevice))
	mux.HandleFunc("GET /oauth/authorize", w.withSession(StageActive, w.oauthPage))
	mux.HandleFunc("POST /oauth/authorize", w.withSession(StageActive, w.consentOAuth))
	mux.HandleFunc("POST /devices/{id}/oauth/{grant}/revoke", w.withSession(StageActive, w.revokeOAuthGrant))
	return securityHeaders(formPosts(mux))
}

// WebOrigin checks an HTTPS origin, such as https://gw.example, and returns it
// as browsers send it in an Origin header.
func WebOrigin(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "" && u.Path != "/" {
		return "", fmt.Errorf("%q is not an HTTPS origin such as https://gw.example (no path)", raw)
	}
	host := strings.ToLower(u.Host)
	if u.Port() == "443" {
		host = strings.ToLower(u.Hostname())
		if strings.Contains(host, ":") {
			host = "[" + host + "]"
		}
	}
	return "https://" + host, nil
}

// formPosts accepts only bounded URL-encoded POST bodies and parses them
// before any handler reads a field, so no request streams a multipart body
// to memory or disk.
func formPosts(next http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			if mediaType, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type")); mediaType != "application/x-www-form-urlencoded" {
				http.Error(rw, "forms are URL-encoded", http.StatusUnsupportedMediaType)
				return
			}
			r.Body = http.MaxBytesReader(rw, r.Body, maxFormBytes)
			if err := r.ParseForm(); err != nil {
				var tooLarge *http.MaxBytesError
				if errors.As(err, &tooLarge) {
					http.Error(rw, "form too large", http.StatusRequestEntityTooLarge)
				} else {
					http.Error(rw, "malformed form", http.StatusBadRequest)
				}
				return
			}
		}
		next.ServeHTTP(rw, r)
	})
}

// securityHeaders forbids framing, inline script, cross-site referrers and
// caching on every response.
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		h := rw.Header()
		h.Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
		h.Set("X-Content-Type-Options", "nosniff")
		// same-origin, not no-referrer: with no-referrer a browser sends
		// "Origin: null" on form posts, which sameOrigin refuses.
		h.Set("Referrer-Policy", "same-origin")
		h.Set("Cache-Control", "no-store")
		h.Set("X-Frame-Options", "DENY")
		next.ServeHTTP(rw, r)
	})
}

type sessionHandler func(http.ResponseWriter, *http.Request, WebSession, string)

// withSession requires a session at stage ("" accepts any). A POST must be
// same-origin and carry the session's CSRF token.
func (w *WebUI) withSession(stage string, next sessionHandler) http.HandlerFunc {
	return func(rw http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie(sessionCookie)
		var session WebSession
		ok := err == nil
		if ok {
			session, ok = lookupSession(w.Store, cookie.Value, w.now())
		}
		if !ok || stage != "" && session.Stage != stage {
			if r.Method != http.MethodGet {
				http.Error(rw, "sign in first", http.StatusForbidden)
				return
			}
			next := "/login"
			switch {
			case ok && session.Stage == StageActive:
				next = "/approvals"
			case ok:
				next = "/login/totp"
			}
			if r.URL.Path == remote.PathOAuthAuthorize {
				next = withLoginNext(next, r.URL.RequestURI())
			}
			http.Redirect(rw, r, next, http.StatusSeeOther)
			return
		}
		if r.Method == http.MethodPost && (!w.sameOrigin(r) || !validToken(r.PostFormValue("csrf"), session.CSRF)) {
			http.Error(rw, "the form expired or did not come from this page; reload and try again", http.StatusForbidden)
			return
		}
		next(rw, r, session, cookie.Value)
	}
}

func validToken(got, want string) bool {
	return got != "" && subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1
}

// sameOrigin refuses a POST a browser marks as cross-site. Browsers that send
// neither header still need the CSRF token.
func (w *WebUI) sameOrigin(r *http.Request) bool {
	if site := r.Header.Get("Sec-Fetch-Site"); site != "" && site != "same-origin" && site != "none" {
		return false
	}
	if origin := r.Header.Get("Origin"); origin != "" {
		if w.Origin != "" {
			return origin == w.Origin
		}
		u, err := url.Parse(origin)
		return err == nil && u.Host == r.Host
	}
	return true
}

func setCookie(rw http.ResponseWriter, name, value string, maxAge int) {
	http.SetCookie(rw, &http.Cookie{Name: name, Value: value, Path: "/", MaxAge: maxAge, HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode})
}

func (w *WebUI) render(rw http.ResponseWriter, status int, page string, data map[string]any) {
	rw.Header().Set("Content-Type", "text/html; charset=utf-8")
	rw.WriteHeader(status)
	if err := w.pages[page].Execute(rw, data); err != nil {
		log.Printf("agentssh-gateway: web: render %s: %v", page, err)
	}
}

// Login: name and password, then TOTP (or its enrollment). A password alone
// opens only a short password-stage session.

// loginNext accepts only the local OAuth authorization page, never an
// arbitrary redirect. The OAuth request is validated again after sign-in.
func loginNext(r *http.Request) string {
	next := r.URL.Query().Get("next")
	if r.Method == http.MethodPost {
		next = r.PostFormValue("next")
	}
	if len(next) > 8192 {
		return ""
	}
	u, err := url.Parse(next)
	if err != nil || u.IsAbs() || u.Host != "" || u.User != nil || u.Opaque != "" || u.Fragment != "" || u.Path != remote.PathOAuthAuthorize || u.RawPath != "" {
		return ""
	}
	return u.RequestURI()
}

func withLoginNext(path, next string) string {
	if next == "" {
		return path
	}
	return path + "?" + url.Values{"next": {next}}.Encode()
}

func afterLogin(r *http.Request) string {
	if next := loginNext(r); next != "" {
		return next
	}
	return "/approvals"
}

func (w *WebUI) loginPage(rw http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie(sessionCookie); err == nil {
		if session, ok := lookupSession(w.Store, cookie.Value, w.now()); ok && session.Stage == StageActive {
			http.Redirect(rw, r, afterLogin(r), http.StatusSeeOther)
			return
		}
	}
	w.renderLogin(rw, r, http.StatusOK, "")
}

func (w *WebUI) renderLogin(rw http.ResponseWriter, r *http.Request, status int, message string) {
	token := controlplane.RandomHex(16)
	setCookie(rw, loginCookie, token, int(passwordStageTTL.Seconds()))
	w.render(rw, status, "login", map[string]any{"Title": "Sign in", "CSRF": token, "Error": message, "Next": loginNext(r)})
}

func clientAddress(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func (w *WebUI) login(rw http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie(loginCookie)
	if err != nil || !w.sameOrigin(r) || !validToken(r.PostFormValue("csrf"), cookie.Value) {
		w.renderLogin(rw, r, http.StatusForbidden, "The sign-in form expired; try again.")
		return
	}
	name, address := strings.TrimSpace(r.PostFormValue("name")), clientAddress(r)
	now := w.now()
	succeeded, ok := w.limiter.begin(name, address, now)
	if !ok {
		w.renderLogin(rw, r, http.StatusTooManyRequests, "Too many failed attempts; wait 15 minutes and try again.")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), passwordWait)
	op, err := checkOperatorPassword(ctx, w.Store, name, r.PostFormValue("password"))
	cancel()
	if errors.Is(err, ErrPasswordsBusy) {
		// The password was never checked, so the attempt is not a failure.
		succeeded(false)
		w.renderLogin(rw, r, http.StatusServiceUnavailable, "The gateway is busy signing others in; try again in a moment.")
		return
	}
	if err != nil {
		w.renderLogin(rw, r, http.StatusUnauthorized, "Wrong name or password.")
		return
	}
	succeeded(false)
	token, err := newSession(w.Store, op.ID, StagePassword, now)
	if err != nil {
		http.Error(rw, "session storage unavailable", http.StatusInternalServerError)
		return
	}
	setCookie(rw, loginCookie, "", -1)
	setCookie(rw, sessionCookie, token, int(passwordStageTTL.Seconds()))
	http.Redirect(rw, r, withLoginNext("/login/totp", loginNext(r)), http.StatusSeeOther)
}

func (w *WebUI) totpPage(rw http.ResponseWriter, r *http.Request, session WebSession, token string) {
	w.renderTOTP(rw, r, http.StatusOK, session, token, "")
}

func (w *WebUI) renderTOTP(rw http.ResponseWriter, r *http.Request, status int, session WebSession, token, message string) {
	data := map[string]any{"Title": "Verify", "CSRF": session.CSRF, "Operator": session.Operator.Name, "Error": message, "Enroll": !session.Operator.TOTPEnrolled, "Next": loginNext(r)}
	if !session.Operator.TOTPEnrolled {
		secret, err := pendingTOTP(w.Store, w.Keys, token)
		if err != nil {
			http.Error(rw, "session storage unavailable", http.StatusInternalServerError)
			return
		}
		encoded := strings.TrimRight(base32Encode(secret), "=")
		uri := TOTPURI(webIssuer, session.Operator.Name, encoded)
		code, err := qr.Encode([]byte(uri))
		if err != nil {
			http.Error(rw, "cannot draw the enrollment code", http.StatusInternalServerError)
			return
		}
		data["QR"] = template.URL("data:image/svg+xml;base64," + base64Std(code.SVG()))
		data["Secret"] = groupSecret(encoded)
	}
	w.render(rw, status, "totp", data)
}

func (w *WebUI) totp(rw http.ResponseWriter, r *http.Request, session WebSession, token string) {
	now := w.now()
	address := clientAddress(r)
	succeeded, ok := w.limiter.begin(session.Operator.Name, address, now)
	if !ok {
		w.renderTOTP(rw, r, http.StatusTooManyRequests, session, token, "Too many failed attempts; wait 15 minutes and sign in again.")
		return
	}
	code := strings.ReplaceAll(strings.TrimSpace(r.PostFormValue("code")), " ", "")
	var err error
	if session.Operator.TOTPEnrolled {
		err = checkTOTP(w.Store, w.Keys, session.Operator.ID, code, now)
	} else {
		var secret []byte
		if secret, err = pendingTOTP(w.Store, w.Keys, token); err == nil {
			err = enrollTOTP(w.Store, w.Keys, session.Operator.ID, secret, code, now)
		}
	}
	if err != nil {
		w.renderTOTP(rw, r, http.StatusUnauthorized, session, token, "That code did not match; enter the current one.")
		return
	}
	succeeded(true)
	// A new token for the signed-in session, so a password-stage token
	// never becomes a full one.
	_ = endSession(w.Store, token)
	active, err := newSession(w.Store, session.Operator.ID, StageActive, now)
	if err != nil {
		http.Error(rw, "session storage unavailable", http.StatusInternalServerError)
		return
	}
	sweepSessions(w.Store, now)
	setCookie(rw, sessionCookie, active, int(sessionTTL.Seconds()))
	http.Redirect(rw, r, afterLogin(r), http.StatusSeeOther)
}

func (w *WebUI) logout(rw http.ResponseWriter, r *http.Request, _ WebSession, token string) {
	_ = endSession(w.Store, token)
	setCookie(rw, sessionCookie, "", -1)
	http.Redirect(rw, r, "/login", http.StatusSeeOther)
}

// Approvals.

type planView struct {
	DeviceID, DeviceName string
	Status               approval.PlanStatus
	Pending              []approval.PlanMember
}

type requestView struct {
	DeviceName string
	DeviceApproval
}

func (w *WebUI) deviceNames() map[string]string {
	names := map[string]string{}
	if devices, err := w.Store.Devices(); err == nil {
		for _, d := range devices {
			names[d.ID] = d.Name
		}
	}
	return names
}

func (w *WebUI) approvalsPage(rw http.ResponseWriter, r *http.Request, session WebSession, _ string) {
	requests, err := ListApprovals(w.Dir)
	if err != nil {
		http.Error(rw, "approval store unavailable", http.StatusInternalServerError)
		return
	}
	names := w.deviceNames()
	var plans []planView
	var singles []requestView
	seenPlans := map[string]bool{}
	for _, req := range requests {
		if req.PlanID != "" {
			key := req.DeviceID + "/" + req.PlanID
			if seenPlans[key] {
				continue
			}
			if _, status, err := PlanStatus(w.Dir, req.DeviceID, req.PlanID); err == nil {
				seenPlans[key] = true
				view := planView{DeviceID: req.DeviceID, DeviceName: names[req.DeviceID], Status: status}
				for _, m := range status.Members {
					if m.Status == "pending" && m.Request != nil {
						view.Pending = append(view.Pending, m)
					}
				}
				plans = append(plans, view)
				continue
			}
		}
		singles = append(singles, requestView{DeviceName: names[req.DeviceID], DeviceApproval: req})
	}
	total := len(singles)
	for _, p := range plans {
		total += len(p.Pending)
	}
	w.render(rw, http.StatusOK, "approvals", map[string]any{
		"Title": "Approvals", "Nav": "approvals", "CSRF": session.CSRF, "Operator": session.Operator.Name,
		"Plans": plans, "Requests": singles, "Total": total, "Notice": r.URL.Query().Get("notice"), "Error": r.URL.Query().Get("error"),
	})
}

func backToApprovals(rw http.ResponseWriter, r *http.Request, key, message string) {
	http.Redirect(rw, r, "/approvals?"+url.Values{key: {message}}.Encode(), http.StatusSeeOther)
}

// decisionError explains a refused decision to the operator.
func decisionError(err error) string {
	switch {
	case errors.Is(err, approval.ErrAlreadyResolved), errors.Is(err, approval.ErrPlanNoPending):
		return "Already decided, perhaps by another operator."
	case errors.Is(err, approval.ErrPendingNotFound), errors.Is(err, approval.ErrPlanNotFound):
		return "No such request; it may have expired."
	case errors.Is(err, controlplane.ErrConfigChanged):
		return "The device's configuration changed while you decided, so no rule was added; the device's rerun will ask again."
	case errors.Is(err, ErrAmbiguousID):
		return "More than one device holds this ID; decide it with agentssh-gateway --device."
	default:
		return "Not decided: " + err.Error()
	}
}

var webScopes = map[string]approval.Scope{"once": approval.ScopeOnce, "session": approval.ScopeSession, "task": approval.ScopeTask, "host": approval.ScopeHost}

func (w *WebUI) decideApproval(rw http.ResponseWriter, r *http.Request, session WebSession, _ string) {
	id, choice := r.PathValue("id"), r.PostFormValue("decision")
	verdict, scope := approval.VerdictApproved, webScopes[choice]
	if choice == "deny" {
		verdict, scope = approval.VerdictDenied, ""
	} else if scope == "" {
		backToApprovals(rw, r, "error", "Choose once, session, task, host or deny.")
		return
	}
	by := Decider{Operator: operatorLabel(session.Operator.Name), DeviceID: r.PostFormValue("device")}
	if _, _, err := DecideApproval(w.Dir, w.Store, by, id, verdict, scope); err != nil {
		backToApprovals(rw, r, "error", decisionError(err))
		return
	}
	if verdict == approval.VerdictDenied {
		backToApprovals(rw, r, "notice", "Denied "+id+".")
		return
	}
	backToApprovals(rw, r, "notice", fmt.Sprintf("Approved %s (%s).", id, scope))
}

func (w *WebUI) decidePlan(rw http.ResponseWriter, r *http.Request, session WebSession, _ string) {
	id, choice := r.PathValue("id"), r.PostFormValue("decision")
	verdict, scope := approval.VerdictApproved, webScopes[choice]
	if choice == "deny" {
		verdict, scope = approval.VerdictDenied, ""
	} else if scope == "" || scope == approval.ScopeHost {
		backToApprovals(rw, r, "error", "A whole plan is approved once, for the session or for the task.")
		return
	}
	by := Decider{Operator: operatorLabel(session.Operator.Name), DeviceID: r.PostFormValue("device")}
	_, results, err := DecidePlan(w.Dir, w.Store, by, id, verdict, scope)
	if err != nil {
		backToApprovals(rw, r, "error", decisionError(err))
		return
	}
	action := "Denied"
	if verdict == approval.VerdictApproved {
		action = fmt.Sprintf("Approved (%s)", scope)
	}
	backToApprovals(rw, r, "notice", fmt.Sprintf("%s %d command(s) of plan %s.", action, len(results), id))
}

// Audit.

func (w *WebUI) auditPage(rw http.ResponseWriter, r *http.Request, session WebSession, _ string) {
	store := audit.NewStore(filepath.Join(w.Dir, FileAudit))
	records, err := store.ReadAll()
	if err != nil {
		http.Error(rw, "audit unavailable", http.StatusInternalServerError)
		return
	}
	verify, verifyErr := store.Verify()
	q := r.URL.Query()
	device, host, sessionID := q.Get("device"), strings.TrimSpace(q.Get("host")), strings.TrimSpace(q.Get("session"))
	var shown []audit.Record
	matched := 0
	for i := len(records) - 1; i >= 0; i-- {
		rec := records[i]
		if device != "" && rec.DeviceID != device || host != "" && rec.Host != host || sessionID != "" && rec.SessionID != sessionID {
			continue
		}
		matched++
		if len(shown) < auditPageMaxLines {
			shown = append(shown, rec)
		}
	}
	names := w.deviceNames()
	var devices []map[string]string
	for id, name := range names {
		devices = append(devices, map[string]string{"ID": id, "Name": name})
	}
	sort.Slice(devices, func(i, j int) bool { return devices[i]["Name"] < devices[j]["Name"] })
	w.render(rw, http.StatusOK, "audit", map[string]any{
		"Title": "Audit", "Nav": "audit", "CSRF": session.CSRF, "Operator": session.Operator.Name,
		"Records": shown, "Matched": matched, "Total": len(records), "Limit": auditPageMaxLines,
		"Verify": verify, "VerifyErr": verifyErr, "Devices": devices, "Names": names,
		"Device": device, "Host": host, "Session": sessionID,
	})
}

// Helpers for templates.

func formatWhen(ts string) string {
	t, err := time.Parse(time.RFC3339, ts)
	if err != nil {
		return ts
	}
	return t.UTC().Format("2006-01-02 15:04:05Z")
}

// shellSyntax spots commands whose meaning depends on shell expansion,
// which the operator should read with care.
var shellSyntax = regexp.MustCompile("[;&|$`<>(){}*?!\\\\\n]")

func hasShellSyntax(cmd string) bool { return shellSyntax.MatchString(cmd) }

func shorten(s string, n int) string {
	if len([]rune(s)) <= n {
		return s
	}
	return string([]rune(s)[:n-1]) + "…"
}

func offers(scopes []approval.Scope, want approval.Scope) bool {
	for _, s := range scopes {
		if s == want {
			return true
		}
	}
	return false
}

func base32Encode(b []byte) string { return base32.StdEncoding.EncodeToString(b) }

func base64Std(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

// groupSecret spaces a base32 key in fours for typing.
func groupSecret(s string) string {
	var parts []string
	for len(s) > 4 {
		parts = append(parts, s[:4])
		s = s[4:]
	}
	return strings.Join(append(parts, s), " ")
}

// loginLimiter counts recent failures per account and per client address.
type loginLimiter struct {
	mu       sync.Mutex
	failures map[string][]time.Time
}

func newLoginLimiter() *loginLimiter {
	return &loginLimiter{failures: map[string][]time.Time{}}
}

func (l *loginLimiter) recent(key string, now time.Time) int {
	kept := l.failures[key][:0]
	for _, t := range l.failures[key] {
		if now.Sub(t) < loginWindow {
			kept = append(kept, t)
		}
	}
	if len(kept) == 0 {
		delete(l.failures, key)
		return 0
	}
	l.failures[key] = kept
	return len(kept)
}

// begin reserves an attempt for account and address, counted as a failure
// until the caller reports success, and refuses once either is at its limit.
// Checking and counting are one step, so concurrent attempts cannot pass the
// limit together. succeeded(signedIn) takes the reservation back; signedIn
// also clears the account's earlier failures.
func (l *loginLimiter) begin(account, address string, now time.Time) (succeeded func(signedIn bool), ok bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	accountKey, addressKey := "account:"+account, "address:"+address
	if l.recent(accountKey, now) >= accountFailures || l.recent(addressKey, now) >= addressFailures {
		return nil, false
	}
	l.failures[accountKey] = append(l.failures[accountKey], now)
	l.failures[addressKey] = append(l.failures[addressKey], now)
	return func(signedIn bool) {
		l.mu.Lock()
		defer l.mu.Unlock()
		for _, key := range []string{accountKey, addressKey} {
			if signedIn && key == accountKey {
				delete(l.failures, key)
				continue
			}
			for i, t := range l.failures[key] {
				if t.Equal(now) {
					l.failures[key] = append(l.failures[key][:i], l.failures[key][i+1:]...)
					break
				}
			}
		}
	}, true
}

// Devices: each device's activation window, opened for a chosen duration or
// closed early by an operator.

// activationPresets are the durations the Devices page offers.
var activationPresets = []struct{ Value, Label string }{
	{"30m", "30 minutes"}, {"1h", "1 hour"}, {"4h", "4 hours"}, {"8h", "8 hours"}, {"24h", "24 hours"},
}

// maxNoteBytes bounds an activation note.
const maxNoteBytes = 200

type deviceView struct {
	controlplane.Device
	Kind         string
	Activation   Activation
	Active       bool
	Revoked      bool
	Left         string
	LastActivity string
	Grants       []Grant
}

// deviceEvents are the audit events a device's own requests cause, which
// make its last activity.
var deviceEvents = map[audit.Event]bool{
	audit.EventStarted: true, audit.EventCompleted: true, audit.EventFailed: true,
	audit.EventDenied: true, audit.EventApprovalRequested: true,
}

func (w *WebUI) devicesPage(rw http.ResponseWriter, r *http.Request, session WebSession, _ string) {
	devices, err := w.Store.Devices()
	if err != nil {
		http.Error(rw, "device store unavailable", http.StatusInternalServerError)
		return
	}
	grants, err := Grants(w.Store)
	if err != nil {
		http.Error(rw, "OAuth grant store unavailable", http.StatusInternalServerError)
		return
	}
	byDevice := map[string][]Grant{}
	for _, grant := range grants {
		byDevice[grant.DeviceID] = append(byDevice[grant.DeviceID], grant)
	}
	last := map[string]string{}
	if records, err := audit.NewStore(filepath.Join(w.Dir, FileAudit)).ReadAll(); err == nil {
		for _, rec := range records {
			if rec.DeviceID != "" && deviceEvents[rec.Event] {
				last[rec.DeviceID] = rec.TS
			}
		}
	}
	now := activationNow()
	views := make([]deviceView, 0, len(devices))
	active := 0
	for _, d := range devices {
		a, err := DeviceActivation(w.Store, d.ID)
		if err != nil {
			http.Error(rw, "activation state unavailable", http.StatusInternalServerError)
			return
		}
		v := deviceView{Device: d, Kind: DeviceKind(d), Activation: a, Revoked: d.Status == remote.DeviceRevoked, LastActivity: last[d.ID], Grants: byDevice[d.ID]}
		if !v.Revoked && a.Active(now) {
			v.Active, v.Left = true, Remaining(a.Until, now)
			active++
		}
		views = append(views, v)
	}
	rank := func(v deviceView) int {
		switch {
		case v.Active:
			return 0
		case v.Revoked:
			return 2
		}
		return 1
	}
	sort.SliceStable(views, func(i, j int) bool {
		if rank(views[i]) != rank(views[j]) {
			return rank(views[i]) < rank(views[j])
		}
		return views[i].Name < views[j].Name
	})
	w.render(rw, http.StatusOK, "devices", map[string]any{
		"Title": "Devices", "Nav": "devices", "CSRF": session.CSRF, "Operator": session.Operator.Name,
		"Devices": views, "Active": active, "Presets": activationPresets,
		"Notice": r.URL.Query().Get("notice"), "Error": r.URL.Query().Get("error"),
	})
}

func backToDevices(rw http.ResponseWriter, r *http.Request, key, message string) {
	http.Redirect(rw, r, "/devices?"+url.Values{key: {message}}.Encode(), http.StatusSeeOther)
}

func (w *WebUI) activateDevice(rw http.ResponseWriter, r *http.Request, session WebSession, _ string) {
	id := r.PathValue("id")
	choice := r.PostFormValue("for")
	if choice == "" {
		backToDevices(rw, r, "error", "Choose how long the device may use the gateway.")
		return
	}
	d, err := time.ParseDuration(choice)
	if err != nil {
		backToDevices(rw, r, "error", "Choose one of the offered durations.")
		return
	}
	note := strings.TrimSpace(r.PostFormValue("note"))
	if len(note) > maxNoteBytes {
		backToDevices(rw, r, "error", fmt.Sprintf("Keep the note under %d characters.", maxNoteBytes))
		return
	}
	a, err := ActivateDevice(w.Dir, w.Store, id, d, operatorLabel(session.Operator.Name), note, activationNow())
	switch {
	case errors.Is(err, ErrActivationDuration):
		backToDevices(rw, r, "error", "Not activated: "+err.Error()+".")
	case errors.Is(err, controlplane.ErrDeviceRevoked):
		backToDevices(rw, r, "error", "Not activated: the device is revoked, and a revoked device cannot be activated again.")
	case errors.Is(err, controlplane.ErrNotFound):
		backToDevices(rw, r, "error", "No such device.")
	case err != nil:
		backToDevices(rw, r, "error", "Not activated: "+err.Error())
	default:
		backToDevices(rw, r, "notice", fmt.Sprintf("Activated %s until %s.", w.deviceLabel(id), formatWhen(a.Until.UTC().Format(time.RFC3339))))
	}
}

func (w *WebUI) deactivateDevice(rw http.ResponseWriter, r *http.Request, session WebSession, _ string) {
	id := r.PathValue("id")
	closed, err := DeactivateDevice(w.Dir, w.Store, id, operatorLabel(session.Operator.Name), activationNow())
	switch {
	case errors.Is(err, controlplane.ErrNotFound):
		backToDevices(rw, r, "error", "No such device.")
	case isAuditPending(err):
		backToDevices(rw, r, "error", "The device is inactive; its audit record needs repair. Running commands stop within 30 seconds.")
	case err != nil:
		backToDevices(rw, r, "error", "Not deactivated: "+err.Error())
	case !closed:
		backToDevices(rw, r, "notice", w.deviceLabel(id)+" was not active.")
	default:
		backToDevices(rw, r, "notice", "Deactivated "+w.deviceLabel(id)+"; its running commands stop within 30 seconds.")
	}
}

// activationNow is the time activation windows are opened, closed and shown
// at: the system clock, which the device API checks them against, not the
// Web UI's own clock (Now), which tests move to step TOTP codes.
func activationNow() time.Time { return time.Now() }

// deviceLabel is a device's name, or its ID when it has none.
func (w *WebUI) deviceLabel(id string) string {
	if name := w.deviceNames()[id]; name != "" {
		return name
	}
	return id
}
