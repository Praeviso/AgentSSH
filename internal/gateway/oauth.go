package gateway

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"mime"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/Praeviso/AgentSSH/internal/audit"
	"github.com/Praeviso/AgentSSH/internal/controlplane"
	"github.com/Praeviso/AgentSSH/internal/remote"
)

// The gateway is its own OAuth 2.1 authorization server, for MCP clients that
// connect only through OAuth. A client registers itself (RFC 7591), which
// grants nothing; an operator's consent on the Web UI binds it to one token
// device, a grant. The grant is the long-lived, revocable part: its access
// tokens last an hour at most and are issued and accepted only while the
// device is active, and its refresh tokens rotate on every use. Codes and
// tokens are opaque, and only their SHA-256 is kept.
const oauthSchema = `
CREATE TABLE IF NOT EXISTS oauth_clients (
	id TEXT PRIMARY KEY,
	name TEXT NOT NULL,
	redirect_uris TEXT NOT NULL,
	auth_method TEXT NOT NULL,
	secret_sha256 TEXT NOT NULL DEFAULT '',
	created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS oauth_grants (
	id TEXT PRIMARY KEY,
	client_id TEXT NOT NULL REFERENCES oauth_clients(id),
	device_id TEXT NOT NULL REFERENCES devices(id),
	scope TEXT NOT NULL,
	created_at TEXT NOT NULL,
	created_by TEXT NOT NULL,
	revoked_at TEXT NOT NULL DEFAULT '',
	revoked_by TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS oauth_grants_device ON oauth_grants(device_id);
CREATE TABLE IF NOT EXISTS oauth_tokens (
	id TEXT PRIMARY KEY,
	grant_id TEXT NOT NULL REFERENCES oauth_grants(id),
	kind TEXT NOT NULL,
	secret_sha256 TEXT NOT NULL,
	expires_at TEXT NOT NULL,
	used_at TEXT NOT NULL DEFAULT '',
	redirect_uri TEXT NOT NULL DEFAULT '',
	code_challenge TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS oauth_tokens_grant ON oauth_tokens(grant_id);
CREATE INDEX IF NOT EXISTS oauth_tokens_expiry ON oauth_tokens(expires_at);
`

// Lifetimes. A code is exchanged at once; an access token never outlives
// the device's activation window either; a refresh token is replaced on
// every use, so only an unused grant's runs out.
const (
	codeLifetime    = 5 * time.Minute
	accessLifetime  = time.Hour
	refreshLifetime = 30 * 24 * time.Hour
	// A client no grant was made for is kept pendingClientLifetime, and at
	// most maxPendingClients exist, so open registration cannot fill the
	// database.
	pendingClientLifetime = time.Hour
)

var maxPendingClients = 1000

// The kinds of oauth_tokens rows, and the prefix each one's token starts with.
const (
	kindCode    = "code"
	kindAccess  = "access"
	kindRefresh = "refresh"
)

var oauthPrefixes = map[string]string{kindCode: "agc", kindAccess: "ago", kindRefresh: "agr"}

var (
	oauthTokenPattern = regexp.MustCompile(`^(agc|ago|agr)_([0-9a-f]{16})_([A-Za-z0-9_-]{43})$`)
	// PKCE (RFC 7636): a verifier of 43 to 128 unreserved characters, and
	// its S256 challenge.
	verifierPattern  = regexp.MustCompile(`^[A-Za-z0-9._~-]{43,128}$`)
	challengePattern = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)
)

// Token endpoint authentication methods a client may register.
var clientAuthMethods = []string{"none", "client_secret_basic", "client_secret_post"}

// OAuth says where the authorization server's endpoints are: the issuer is
// the gateway's public URL, where the platform's servers register and get
// tokens; authorization is on the Web UI, where the operator consents.
type OAuth struct {
	Issuer string
	// Resource is the MCP endpoint, the one resource tokens are for.
	Resource              string
	AuthorizationEndpoint string
}

// NewOAuth derives the authorization server from the gateway's public URL
// and the Web UI's origin.
func NewOAuth(publicURL, webOrigin string) (OAuth, error) {
	base, err := remote.HTTPSBaseURL(publicURL)
	if err != nil {
		return OAuth{}, err
	}
	origin, err := WebOrigin(webOrigin)
	if err != nil {
		return OAuth{}, err
	}
	return OAuth{Issuer: base, Resource: base + remote.PathMCP, AuthorizationEndpoint: origin + remote.PathOAuthAuthorize}, nil
}

func splitURL(raw string) (origin, path string) {
	u, _ := url.Parse(raw)
	return u.Scheme + "://" + u.Host, u.Path
}

// The well-known URIs sit at the origin's root with the resource's or
// issuer's path inserted (RFC 9728 section 3.1, RFC 8414 section 3.1).
func (o OAuth) resourceMetadataPath() string {
	_, path := splitURL(o.Resource)
	return "/.well-known/oauth-protected-resource" + path
}

func (o OAuth) resourceMetadataURL() string {
	origin, _ := splitURL(o.Resource)
	return origin + o.resourceMetadataPath()
}

func (o OAuth) serverMetadataPath() string {
	_, path := splitURL(o.Issuer)
	return "/.well-known/oauth-authorization-server" + path
}

// oauthRoutes are the discovery documents, registration and the token
// endpoint.
func (s *Server) oauthRoutes() []controlplane.OpenRoute {
	o := *s.oauth
	resource := map[string]any{
		"resource":                 o.Resource,
		"resource_name":            "AgentSSH gateway",
		"authorization_servers":    []string{o.Issuer},
		"bearer_methods_supported": []string{"header"},
		"scopes_supported":         []string{remote.OAuthScope},
	}
	server := map[string]any{
		"issuer":                                         o.Issuer,
		"authorization_endpoint":                         o.AuthorizationEndpoint,
		"token_endpoint":                                 o.Issuer + remote.PathOAuthToken,
		"registration_endpoint":                          o.Issuer + remote.PathOAuthRegister,
		"scopes_supported":                               []string{remote.OAuthScope},
		"response_types_supported":                       []string{"code"},
		"grant_types_supported":                          []string{"authorization_code", "refresh_token"},
		"code_challenge_methods_supported":               []string{"S256"},
		"token_endpoint_auth_methods_supported":          clientAuthMethods,
		"authorization_response_iss_parameter_supported": true,
	}
	document := func(value any) http.HandlerFunc {
		return func(w http.ResponseWriter, _ *http.Request) { controlplane.WriteJSON(w, http.StatusOK, value) }
	}
	return []controlplane.OpenRoute{
		{Method: "GET", Path: o.resourceMetadataPath(), Root: true, Handler: document(resource)},
		{Method: "GET", Path: o.serverMetadataPath(), Root: true, Handler: document(server)},
		{Method: "POST", Path: remote.PathOAuthRegister, Handler: s.handleRegister},
		{Method: "POST", Path: remote.PathOAuthToken, Handler: s.handleToken},
	}
}

// oauthTime formats t at a fixed width, so the stored times compare as
// strings.
func oauthTime(t time.Time) string { return t.UTC().Format("2006-01-02T15:04:05.000000000Z07:00") }

func randomSecret() string {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		panic(fmt.Sprintf("crypto/rand: %v", err))
	}
	return base64.RawURLEncoding.EncodeToString(buf)
}

// oauthError answers as the OAuth endpoints do (RFC 6749 section 5.2, RFC
// 7591 section 3.2.2).
func oauthError(w http.ResponseWriter, status int, code, description string) {
	controlplane.WriteJSON(w, status, map[string]string{"error": code, "error_description": description})
}

type oauthClient struct {
	ID           string
	Name         string
	RedirectURIs []string
	AuthMethod   string
	secretSHA256 string
}

type querier interface {
	QueryRow(query string, args ...any) *sql.Row
}

func loadClient(db querier, id string) (oauthClient, error) {
	var c oauthClient
	var uris string
	err := db.QueryRow(`SELECT id, name, redirect_uris, auth_method, secret_sha256 FROM oauth_clients WHERE id = ?`, id).
		Scan(&c.ID, &c.Name, &uris, &c.AuthMethod, &c.secretSHA256)
	if errors.Is(err, sql.ErrNoRows) {
		return oauthClient{}, controlplane.ErrNotFound
	}
	if err != nil {
		return oauthClient{}, err
	}
	return c, json.Unmarshal([]byte(uris), &c.RedirectURIs)
}

func loopback(host string) bool {
	ip := net.ParseIP(host)
	return host == "localhost" || ip != nil && ip.IsLoopback()
}

// validRedirectURI accepts an HTTPS URI, or HTTP on a loopback address for a
// client on the operator's own machine; never a fragment or a custom scheme.
func validRedirectURI(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || len(raw) > 2000 || strings.Contains(raw, "#") || u.User != nil || u.Host == "" || u.Opaque != "" {
		return false
	}
	return u.Scheme == "https" || u.Scheme == "http" && loopback(u.Hostname())
}

// redirects reports whether uri is one of c's redirect URIs; a loopback one
// may name any port (RFC 8252 section 7.3).
func (c oauthClient) redirects(uri string) bool {
	if slices.Contains(c.RedirectURIs, uri) {
		return true
	}
	got, err := url.Parse(uri)
	if err != nil || got.Scheme != "http" || !loopback(got.Hostname()) {
		return false
	}
	for _, registered := range c.RedirectURIs {
		want, err := url.Parse(registered)
		if err == nil && want.Scheme == "http" && want.Hostname() == got.Hostname() && want.Path == got.Path && want.RawQuery == got.RawQuery && !strings.Contains(uri, "#") {
			return true
		}
	}
	return false
}

// clientMetadata is the part of a registration request (RFC 7591 section 2)
// the gateway uses; other fields are ignored.
type clientMetadata struct {
	RedirectURIs            []string `json:"redirect_uris"`
	ClientName              string   `json:"client_name"`
	GrantTypes              []string `json:"grant_types"`
	ResponseTypes           []string `json:"response_types"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
}

// handleRegister registers a client. Anyone may: a client is only a name and
// redirect URIs, and nothing is granted until an operator consents.
func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	body, err := controlplane.ReadBody(r, 0)
	if err != nil {
		oauthError(w, http.StatusBadRequest, "invalid_client_metadata", "request body too large or unreadable")
		return
	}
	var meta clientMetadata
	if err := json.Unmarshal(body, &meta); err != nil {
		oauthError(w, http.StatusBadRequest, "invalid_client_metadata", "the body is not client metadata in JSON")
		return
	}
	if len(meta.RedirectURIs) == 0 || len(meta.RedirectURIs) > 10 {
		oauthError(w, http.StatusBadRequest, "invalid_redirect_uri", "register 1 to 10 redirect_uris")
		return
	}
	for _, uri := range meta.RedirectURIs {
		if !validRedirectURI(uri) {
			oauthError(w, http.StatusBadRequest, "invalid_redirect_uri", fmt.Sprintf("%q is not an HTTPS URI or HTTP on a loopback address", uri))
			return
		}
	}
	for _, grantType := range meta.GrantTypes {
		if grantType != "authorization_code" && grantType != "refresh_token" {
			oauthError(w, http.StatusBadRequest, "invalid_client_metadata", "grant_types are authorization_code and refresh_token")
			return
		}
	}
	for _, responseType := range meta.ResponseTypes {
		if responseType != "code" {
			oauthError(w, http.StatusBadRequest, "invalid_client_metadata", "the only response_type is code")
			return
		}
	}
	method := meta.TokenEndpointAuthMethod
	if method == "" {
		method = "client_secret_basic" // RFC 7591's default
	}
	if !slices.Contains(clientAuthMethods, method) {
		oauthError(w, http.StatusBadRequest, "invalid_client_metadata", "token_endpoint_auth_method is one of "+strings.Join(clientAuthMethods, ", "))
		return
	}
	name := strings.Map(func(r rune) rune {
		if r < ' ' || r == 0x7f {
			return -1
		}
		return r
	}, strings.TrimSpace(meta.ClientName))
	if name == "" {
		name = "unnamed client"
	}
	if len(name) > 200 {
		oauthError(w, http.StatusBadRequest, "invalid_client_metadata", "client_name is at most 200 bytes")
		return
	}

	now := s.now()
	client := oauthClient{ID: "oc_" + controlplane.RandomHex(16), Name: name, RedirectURIs: meta.RedirectURIs, AuthMethod: method}
	var secret string
	if method != "none" {
		secret = randomSecret()
		client.secretSHA256 = secretSHA256(secret)
	}
	uris, _ := json.Marshal(client.RedirectURIs)
	s.registerMu.Lock()
	defer s.registerMu.Unlock()
	pending, err := prunePendingClients(s.Store.DB(), now)
	if err != nil {
		oauthError(w, http.StatusInternalServerError, "server_error", "registration unavailable")
		return
	}
	if pending >= maxPendingClients {
		oauthError(w, http.StatusServiceUnavailable, "temporarily_unavailable", "too many clients are waiting for an operator's consent; try again later")
		return
	}
	if _, err := s.Store.DB().Exec(`INSERT INTO oauth_clients (id, name, redirect_uris, auth_method, secret_sha256, created_at) VALUES (?, ?, ?, ?, ?, ?)`,
		client.ID, client.Name, string(uris), client.AuthMethod, client.secretSHA256, oauthTime(now)); err != nil {
		oauthError(w, http.StatusInternalServerError, "server_error", "registration unavailable")
		return
	}
	answer := map[string]any{
		"client_id":                  client.ID,
		"client_id_issued_at":        now.Unix(),
		"client_name":                client.Name,
		"redirect_uris":              client.RedirectURIs,
		"grant_types":                []string{"authorization_code", "refresh_token"},
		"response_types":             []string{"code"},
		"token_endpoint_auth_method": client.AuthMethod,
		"scope":                      remote.OAuthScope,
	}
	if secret != "" {
		answer["client_secret"], answer["client_secret_expires_at"] = secret, 0
	}
	controlplane.WriteJSON(w, http.StatusCreated, answer)
}

// prunePendingClients deletes clients no grant was made for that are older
// than pendingClientLifetime and counts those left.
func prunePendingClients(db *sql.DB, now time.Time) (int, error) {
	const pending = `id NOT IN (SELECT client_id FROM oauth_grants)`
	if _, err := db.Exec(`DELETE FROM oauth_clients WHERE `+pending+` AND created_at < ?`, oauthTime(now.Add(-pendingClientLifetime))); err != nil {
		return 0, err
	}
	var n int
	err := db.QueryRow(`SELECT COUNT(*) FROM oauth_clients WHERE ` + pending).Scan(&n)
	return n, err
}

// Grant binds an OAuth client to a token device, by an operator's consent.
type Grant struct {
	ID         string
	ClientID   string
	ClientName string
	DeviceID   string
	Scope      string
	CreatedAt  time.Time
	CreatedBy  string
	RevokedAt  time.Time
	RevokedBy  string
}

const grantColumns = `g.id, g.client_id, c.name, g.device_id, g.scope, g.created_at, g.created_by, g.revoked_at, g.revoked_by FROM oauth_grants g JOIN oauth_clients c ON c.id = g.client_id`

func scanGrant(scan func(...any) error) (Grant, error) {
	var g Grant
	var created, revoked string
	if err := scan(&g.ID, &g.ClientID, &g.ClientName, &g.DeviceID, &g.Scope, &created, &g.CreatedBy, &revoked, &g.RevokedBy); err != nil {
		return Grant{}, err
	}
	g.CreatedAt, g.RevokedAt = controlplane.ParseTime(created), controlplane.ParseTime(revoked)
	return g, nil
}

func loadGrant(db querier, id string) (Grant, error) {
	g, err := scanGrant(db.QueryRow(`SELECT `+grantColumns+` WHERE g.id = ?`, id).Scan)
	if errors.Is(err, sql.ErrNoRows) {
		return Grant{}, controlplane.ErrNotFound
	}
	return g, err
}

// Grants lists every grant, newest first.
func Grants(store *controlplane.Store) ([]Grant, error) {
	rows, err := store.DB().Query(`SELECT ` + grantColumns + ` ORDER BY g.created_at DESC, g.id`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var grants []Grant
	for rows.Next() {
		g, err := scanGrant(rows.Scan)
		if err != nil {
			return nil, err
		}
		grants = append(grants, g)
	}
	return grants, rows.Err()
}

// RevokeGrant revokes a grant: none of its tokens is accepted again. It
// reports false when the grant was already revoked.
func RevokeGrant(dir string, store *controlplane.Store, grantID, operator string, now time.Time) (bool, error) {
	grant, err := loadGrant(store.DB(), grantID)
	if err != nil {
		return false, err
	}
	return revokeGrant(dir, store, grant, operator, "", now, "")
}

// revokeGrant commits the restriction and its audit facts together. A replay
// refusal belongs to the same transaction, so its publication cannot prevent
// revocation. refreshID identifies the reused credential, never its secret.
func revokeGrant(dir string, store *controlplane.Store, grant Grant, operator, note string, now time.Time, refreshID string) (bool, error) {
	tx, err := store.DB().Begin()
	if err != nil {
		return false, err
	}
	defer func() { _ = tx.Rollback() }()
	res, err := tx.Exec(`UPDATE oauth_grants SET revoked_at = ?, revoked_by = ? WHERE id = ? AND revoked_at = ''`, oauthTime(now), operator, grant.ID)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	refusalKey := "refresh-replay/" + refreshID
	if refreshID != "" {
		if _, err := enqueueSecurityAudit(tx, refusalKey, audit.Record{
			TS: now.UTC().Format(time.RFC3339), Event: audit.EventOAuthRefreshRefused,
			DeviceID: grant.DeviceID, GrantID: grant.ID, ClientID: grant.ClientID, Note: note,
		}); err != nil {
			return false, err
		}
	}
	key := "grant-revocation/" + grant.ID
	if n != 0 {
		if _, err := enqueueSecurityAudit(tx, key, audit.Record{
			TS: now.UTC().Format(time.RFC3339), Event: audit.EventOAuthGrantRevoked, DeviceID: grant.DeviceID,
			GrantID: grant.ID, ClientID: grant.ClientID, Operator: operator, Note: note,
		}); err != nil {
			return false, err
		}
	}
	if err := tx.Commit(); err != nil {
		return false, err
	}
	var failed error
	if refreshID != "" {
		failed = publishSecurityAudit(dir, store, refusalKey)
	}
	failed = errors.Join(failed, publishSecurityAudit(dir, store, key))
	return n != 0, pendingAudit("the grant is revoked", failed)
}

// issue stores a new code or token of kind for a grant and returns it.
func issue(tx *sql.Tx, kind, grantID string, expires time.Time, redirectURI, challenge string) (string, error) {
	id, secret := controlplane.RandomHex(8), randomSecret()
	_, err := tx.Exec(`INSERT INTO oauth_tokens (id, grant_id, kind, secret_sha256, expires_at, redirect_uri, code_challenge) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		id, grantID, kind, secretSHA256(secret), oauthTime(expires), redirectURI, challenge)
	return oauthPrefixes[kind] + "_" + id + "_" + secret, err
}

type storedToken struct {
	ID          string
	Kind        string
	GrantID     string
	Expires     time.Time
	Used        bool
	RedirectURI string
	Challenge   string
}

// lookupToken finds the code or token of kind that raw is: errBadToken when
// there is none, whatever its expiry or use.
func lookupToken(db querier, raw, kind string) (storedToken, error) {
	m := oauthTokenPattern.FindStringSubmatch(raw)
	if m == nil || m[1] != oauthPrefixes[kind] {
		return storedToken{}, errBadToken
	}
	t := storedToken{ID: m[2]}
	var digest, expires, used string
	err := db.QueryRow(`SELECT grant_id, kind, secret_sha256, expires_at, used_at, redirect_uri, code_challenge FROM oauth_tokens WHERE id = ?`, t.ID).
		Scan(&t.GrantID, &t.Kind, &digest, &expires, &used, &t.RedirectURI, &t.Challenge)
	if errors.Is(err, sql.ErrNoRows) {
		return storedToken{}, errBadToken
	}
	if err != nil {
		return storedToken{}, err
	}
	if t.Kind != kind || subtle.ConstantTimeCompare([]byte(digest), []byte(secretSHA256(m[3]))) != 1 {
		return storedToken{}, errBadToken
	}
	t.Expires, t.Used = controlplane.ParseTime(expires), used != ""
	return t, nil
}

// accessGrant is the grant of an unexpired access token whose grant stands;
// errBadToken otherwise. The device's standing is the caller's to check.
func accessGrant(store *controlplane.Store, raw string, now time.Time) (Grant, error) {
	t, err := lookupToken(store.DB(), raw, kindAccess)
	if err != nil {
		return Grant{}, err
	}
	if !now.Before(t.Expires) {
		return Grant{}, errBadToken
	}
	grant, err := loadGrant(store.DB(), t.GrantID)
	if err != nil {
		return Grant{}, err
	}
	if !grant.RevokedAt.IsZero() {
		return Grant{}, errBadToken
	}
	return grant, nil
}

// sameResource compares resource indicators (RFC 8707) as URLs: scheme and
// host in any case, the default port, and a trailing slash do not matter.
func sameResource(a, b string) bool {
	canonical := func(raw string) string {
		u, err := url.Parse(raw)
		if err != nil || u.RawQuery != "" || u.Fragment != "" {
			return "\x00" + raw
		}
		host := strings.ToLower(u.Host)
		if strings.EqualFold(u.Scheme, "https") {
			host = strings.TrimSuffix(host, ":443")
		}
		return strings.ToLower(u.Scheme) + "://" + host + strings.TrimSuffix(u.Path, "/")
	}
	return canonical(a) == canonical(b)
}

func validScope(scope string) bool {
	for _, s := range strings.Fields(scope) {
		if s != remote.OAuthScope {
			return false
		}
	}
	return true
}

// tokenAnswer is the token endpoint's success (RFC 6749 section 5.1).
type tokenAnswer struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	Scope        string `json:"scope"`
}

// handleToken exchanges an authorization code or a refresh token for an
// access token and a new refresh token.
func (s *Server) handleToken(w http.ResponseWriter, r *http.Request) {
	body, err := controlplane.ReadBody(r, 0)
	if err != nil {
		oauthError(w, http.StatusBadRequest, "invalid_request", "request body too large or unreadable")
		return
	}
	if mediaType, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type")); mediaType != "application/x-www-form-urlencoded" {
		oauthError(w, http.StatusBadRequest, "invalid_request", "the body is a URL-encoded form")
		return
	}
	form, err := url.ParseQuery(string(body))
	if err != nil {
		oauthError(w, http.StatusBadRequest, "invalid_request", "malformed form")
		return
	}
	for name, values := range form {
		if len(values) > 1 {
			oauthError(w, http.StatusBadRequest, "invalid_request", name+" is repeated")
			return
		}
	}
	client, err := s.authenticateClient(r, form)
	if errors.Is(err, errBadClient) {
		if _, _, basic := r.BasicAuth(); basic {
			w.Header().Set("WWW-Authenticate", `Basic realm="agentssh-gateway"`)
		}
		oauthError(w, http.StatusUnauthorized, "invalid_client", "unknown client or wrong client credentials")
		return
	}
	if err != nil {
		oauthError(w, http.StatusInternalServerError, "server_error", "client check unavailable")
		return
	}
	if resource := form.Get("resource"); resource != "" && !sameResource(resource, s.oauth.Resource) {
		oauthError(w, http.StatusBadRequest, "invalid_target", "tokens are only for "+s.oauth.Resource)
		return
	}
	switch form.Get("grant_type") {
	case "authorization_code":
		s.exchangeCode(w, client, form)
	case "refresh_token":
		s.refresh(w, client, form)
	case "":
		oauthError(w, http.StatusBadRequest, "invalid_request", "grant_type is required")
	default:
		oauthError(w, http.StatusBadRequest, "unsupported_grant_type", "grant_type is authorization_code or refresh_token")
	}
}

var errBadClient = errors.New("bad client credentials")

// authenticateClient finds the client a token request names, checking its
// secret unless it is a public client; the secret comes in a Basic
// Authorization header or the form, not both.
func (s *Server) authenticateClient(r *http.Request, form url.Values) (oauthClient, error) {
	id, secret := form.Get("client_id"), form.Get("client_secret")
	if user, password, ok := r.BasicAuth(); ok {
		// RFC 6749 section 2.3.1: both are form-encoded first.
		basicID, err1 := url.QueryUnescape(user)
		basicSecret, err2 := url.QueryUnescape(password)
		if err1 != nil || err2 != nil || secret != "" || id != "" && id != basicID {
			return oauthClient{}, errBadClient
		}
		id, secret = basicID, basicSecret
	}
	client, err := loadClient(s.Store.DB(), id)
	if errors.Is(err, controlplane.ErrNotFound) {
		return oauthClient{}, errBadClient
	}
	if err != nil {
		return oauthClient{}, err
	}
	if client.AuthMethod != "none" && (secret == "" || subtle.ConstantTimeCompare([]byte(client.secretSHA256), []byte(secretSHA256(secret))) != 1) {
		return oauthClient{}, errBadClient
	}
	return client, nil
}

// grantStanding is whether a grant's device may get tokens now: until when,
// or why not.
func (s *Server) grantStanding(grant Grant, now time.Time) (until time.Time, refusal string, err error) {
	device, err := s.Store.Device(grant.DeviceID)
	if err != nil {
		return time.Time{}, "", err
	}
	if device.Status == remote.DeviceRevoked {
		return time.Time{}, "the device is revoked", nil
	}
	a, active, err := s.checkActivation(device.ID, now)
	if err != nil {
		return time.Time{}, "", err
	}
	if !active {
		return time.Time{}, "the device is not activated; an operator must activate it on the gateway", nil
	}
	return a.Until, "", nil
}

// exchangeCode redeems an authorization code once, with its PKCE verifier.
// A code redeemed again with its verifier revokes its grant (RFC 6749
// section 4.1.2); a device that is not active leaves the code unredeemed.
func (s *Server) exchangeCode(w http.ResponseWriter, client oauthClient, form url.Values) {
	now := s.now()
	code, err := lookupToken(s.Store.DB(), form.Get("code"), kindCode)
	if errors.Is(err, errBadToken) {
		oauthError(w, http.StatusBadRequest, "invalid_grant", "unknown authorization code")
		return
	}
	if err != nil {
		oauthError(w, http.StatusInternalServerError, "server_error", "code check unavailable")
		return
	}
	grant, err := loadGrant(s.Store.DB(), code.GrantID)
	if err != nil {
		oauthError(w, http.StatusInternalServerError, "server_error", "grant lookup failed")
		return
	}
	// A used code is no secret (it was in a redirect URL), so it counts as
	// reused, revoking the grant, only with its verifier: only the client, or
	// someone who also stole the verifier, can show it.
	switch {
	case grant.ClientID != client.ID:
		oauthError(w, http.StatusBadRequest, "invalid_grant", "the code was issued to another client")
		return
	case form.Get("redirect_uri") != "" && form.Get("redirect_uri") != code.RedirectURI:
		oauthError(w, http.StatusBadRequest, "invalid_grant", "redirect_uri differs from the authorization request's")
		return
	case !pkceMatches(form.Get("code_verifier"), code.Challenge):
		oauthError(w, http.StatusBadRequest, "invalid_grant", "code_verifier does not match the code challenge")
		return
	case code.Used:
		s.revokeReused(w, grant, code, now)
		return
	case !now.Before(code.Expires):
		oauthError(w, http.StatusBadRequest, "invalid_grant", "the authorization code expired")
		return
	case !grant.RevokedAt.IsZero():
		oauthError(w, http.StatusBadRequest, "invalid_grant", "the grant was revoked")
		return
	}
	until, refusal, err := s.grantStanding(grant, now)
	if err != nil {
		oauthError(w, http.StatusInternalServerError, "server_error", "device standing unavailable")
		return
	}
	if refusal != "" {
		oauthError(w, http.StatusBadRequest, "invalid_grant", refusal)
		return
	}
	s.issueTokens(w, grant, code, until, now)
}

// refresh replaces a refresh token with a new one and an access token. A
// refresh token used again revokes its grant; a refusal of a refresh token
// the gateway issued is audited.
func (s *Server) refresh(w http.ResponseWriter, client oauthClient, form url.Values) {
	now := s.now()
	token, err := lookupToken(s.Store.DB(), form.Get("refresh_token"), kindRefresh)
	if errors.Is(err, errBadToken) {
		oauthError(w, http.StatusBadRequest, "invalid_grant", "unknown refresh token")
		return
	}
	if err != nil {
		oauthError(w, http.StatusInternalServerError, "server_error", "token check unavailable")
		return
	}
	grant, err := loadGrant(s.Store.DB(), token.GrantID)
	if err != nil {
		oauthError(w, http.StatusInternalServerError, "server_error", "grant lookup failed")
		return
	}
	refuse := func(reason string) {
		if err := s.auditRefreshRefused(grant, reason, now); err != nil {
			oauthError(w, http.StatusInternalServerError, "server_error", "audit unavailable")
			return
		}
		oauthError(w, http.StatusBadRequest, "invalid_grant", reason)
	}
	switch {
	case grant.ClientID != client.ID:
		refuse("the refresh token was issued to another client")
		return
	case !grant.RevokedAt.IsZero():
		refuse("the grant was revoked")
		return
	case token.Used:
		s.revokeReused(w, grant, token, now)
		return
	case !now.Before(token.Expires):
		refuse("the refresh token expired")
		return
	case !validScope(form.Get("scope")):
		oauthError(w, http.StatusBadRequest, "invalid_scope", "the only scope is "+remote.OAuthScope)
		return
	}
	until, refusal, err := s.grantStanding(grant, now)
	if err != nil {
		oauthError(w, http.StatusInternalServerError, "server_error", "device standing unavailable")
		return
	}
	if refusal != "" {
		refuse(refusal)
		return
	}
	s.issueTokens(w, grant, token, until, now)
}

// issueTokens marks used (a code or refresh token) as used and issues an
// access token, valid an hour but not past until, and a refresh token. If
// another request used it first, it was reused.
func (s *Server) issueTokens(w http.ResponseWriter, grant Grant, used storedToken, until time.Time, now time.Time) {
	expires := now.Add(accessLifetime)
	if until.Before(expires) {
		expires = until
	}
	var answer tokenAnswer
	tx, err := s.Store.DB().Begin()
	if err != nil {
		oauthError(w, http.StatusInternalServerError, "server_error", "token store unavailable")
		return
	}
	defer func() { _ = tx.Rollback() }()
	current, err := loadGrant(tx, grant.ID)
	if err != nil {
		oauthError(w, http.StatusInternalServerError, "server_error", "grant lookup failed")
		return
	}
	if !current.RevokedAt.IsZero() {
		oauthError(w, http.StatusBadRequest, "invalid_grant", "the grant was revoked")
		return
	}
	res, err := tx.Exec(`UPDATE oauth_tokens SET used_at = ? WHERE id = ? AND used_at = ''`, oauthTime(now), used.ID)
	if err == nil {
		if n, _ := res.RowsAffected(); n == 0 {
			_ = tx.Rollback()
			s.revokeReused(w, grant, used, now)
			return
		}
		answer.AccessToken, err = issue(tx, kindAccess, grant.ID, expires, "", "")
	}
	if err == nil {
		answer.RefreshToken, err = issue(tx, kindRefresh, grant.ID, now.Add(refreshLifetime), "", "")
	}
	if err == nil {
		// Expired codes and tokens can no longer be checked for reuse or
		// accepted, so they go.
		_, err = tx.Exec(`DELETE FROM oauth_tokens WHERE expires_at < ?`, oauthTime(now))
	}
	if err == nil {
		err = tx.Commit()
	}
	if err != nil {
		oauthError(w, http.StatusInternalServerError, "server_error", "token store unavailable")
		return
	}
	answer.TokenType, answer.Scope = "Bearer", grant.Scope
	answer.ExpiresIn = max(int64(expires.Sub(now)/time.Second), 1)
	controlplane.WriteJSON(w, http.StatusOK, answer)
}

// revokeReused revokes a grant whose code or refresh token came back after
// it was used: one of the two holders is not the client.
func (s *Server) revokeReused(w http.ResponseWriter, grant Grant, used storedToken, now time.Time) {
	reason, refreshID := "authorization code reused", ""
	if used.Kind == kindRefresh {
		reason, refreshID = "refresh token reused", used.ID
	}
	if _, err := revokeGrant(s.Dir, s.Store, grant, "", reason, now, refreshID); err != nil {
		var pending *AuditPendingError
		if errors.As(err, &pending) {
			log.Printf("agentssh-gateway: grant %s: %v", grant.ID, err)
			oauthError(w, http.StatusInternalServerError, "server_error", "the grant is revoked; audit repair is pending")
		} else {
			log.Printf("agentssh-gateway: grant %s: revocation failed: %v", grant.ID, err)
			oauthError(w, http.StatusInternalServerError, "server_error", "revocation failed")
		}
		return
	}
	oauthError(w, http.StatusBadRequest, "invalid_grant", reason+": the grant is revoked; an operator must authorize the client again")
}

func (s *Server) auditRefreshRefused(grant Grant, reason string, now time.Time) error {
	_, err := activationAudit(s.Dir).Append(audit.Record{
		TS: now.UTC().Format(time.RFC3339), Event: audit.EventOAuthRefreshRefused, DeviceID: grant.DeviceID,
		GrantID: grant.ID, ClientID: grant.ClientID, Note: reason,
	})
	return err
}

func pkceMatches(verifier, challenge string) bool {
	if !verifierPattern.MatchString(verifier) {
		return false
	}
	sum := sha256.Sum256([]byte(verifier))
	return subtle.ConstantTimeCompare([]byte(base64.RawURLEncoding.EncodeToString(sum[:])), []byte(challenge)) == 1
}

// AuthorizationRequest is a validated authorization request (RFC 6749
// section 4.1.1 with PKCE), awaiting the operator's consent.
type AuthorizationRequest struct {
	ClientID      string
	ClientName    string
	RedirectURI   string
	State         string
	CodeChallenge string
	Scope         string
}

// AuthorizationError refuses an authorization request.
type AuthorizationError struct {
	Code        string
	Description string
	// Redirect tells the client at its redirect URI. It is empty when the
	// client or redirect URI is unknown: such a request must not be sent
	// anywhere (RFC 6749 section 4.1.2.1), so the page shows the error.
	Redirect string
}

func (e *AuthorizationError) Error() string { return e.Code + ": " + e.Description }

// ParseAuthorization validates an authorization request's query.
func ParseAuthorization(store *controlplane.Store, o OAuth, query url.Values) (AuthorizationRequest, error) {
	for _, name := range []string{"client_id", "redirect_uri"} {
		if len(query[name]) != 1 {
			return AuthorizationRequest{}, &AuthorizationError{Code: "invalid_request", Description: "the request needs exactly one " + name}
		}
	}
	client, err := loadClient(store.DB(), query.Get("client_id"))
	if errors.Is(err, controlplane.ErrNotFound) {
		return AuthorizationRequest{}, &AuthorizationError{Code: "invalid_client", Description: "this client is not registered with the gateway"}
	}
	if err != nil {
		return AuthorizationRequest{}, err
	}
	req := AuthorizationRequest{ClientID: client.ID, ClientName: client.Name, RedirectURI: query.Get("redirect_uri"), State: query.Get("state")}
	if !client.redirects(req.RedirectURI) {
		return AuthorizationRequest{}, &AuthorizationError{Code: "invalid_request", Description: "redirect_uri is not one the client registered"}
	}
	refuse := func(code, description string) (AuthorizationRequest, error) {
		redirect := callback(o, req.RedirectURI, url.Values{"error": {code}, "error_description": {description}, "state": {req.State}})
		return AuthorizationRequest{}, &AuthorizationError{Code: code, Description: description, Redirect: redirect}
	}
	for name, values := range query {
		if len(values) > 1 {
			return refuse("invalid_request", name+" is repeated")
		}
	}
	switch {
	case query.Get("response_type") != "code":
		return refuse("unsupported_response_type", "response_type must be code")
	case query.Get("code_challenge_method") != "S256" || !challengePattern.MatchString(query.Get("code_challenge")):
		return refuse("invalid_request", "PKCE is required: an S256 code_challenge")
	case !validScope(query.Get("scope")):
		return refuse("invalid_scope", "the only scope is "+remote.OAuthScope)
	case query.Get("resource") != "" && !sameResource(query.Get("resource"), o.Resource):
		return refuse("invalid_target", "tokens are only for "+o.Resource)
	case len(req.State) > 1024:
		return refuse("invalid_request", "state is at most 1024 bytes")
	}
	req.CodeChallenge, req.Scope = query.Get("code_challenge"), remote.OAuthScope
	return req, nil
}

// callback is the client's redirect URI with params and the issuer added
// (RFC 9207), keeping its own query; an empty param is left out.
func callback(o OAuth, redirectURI string, params url.Values) string {
	u, _ := url.Parse(redirectURI)
	query := u.Query()
	for name, values := range params {
		if values[0] != "" {
			query.Set(name, values[0])
		}
	}
	query.Set("iss", o.Issuer)
	u.RawQuery = query.Encode()
	return u.String()
}

// Authorize records an operator's consent to req: a grant binding its client
// to the token device deviceID, and a code for it. It returns the redirect
// that hands the client the code.
func Authorize(dir string, store *controlplane.Store, o OAuth, req AuthorizationRequest, deviceID, operator string, now time.Time) (string, Grant, error) {
	device, err := store.Device(deviceID)
	if err != nil {
		return "", Grant{}, err
	}
	if DeviceKind(device) != remote.DeviceKindToken {
		return "", Grant{}, ErrNotTokenDevice
	}
	if device.Status == remote.DeviceRevoked {
		return "", Grant{}, controlplane.ErrDeviceRevoked
	}
	tx, err := store.DB().Begin()
	if err != nil {
		return "", Grant{}, err
	}
	defer func() { _ = tx.Rollback() }()
	client, err := loadClient(tx, req.ClientID)
	if err != nil {
		return "", Grant{}, err
	}
	grant := Grant{ID: "og_" + controlplane.RandomHex(8), ClientID: client.ID, ClientName: client.Name, DeviceID: deviceID, Scope: req.Scope, CreatedAt: now, CreatedBy: operator}
	if _, err := tx.Exec(`INSERT INTO oauth_grants (id, client_id, device_id, scope, created_at, created_by) VALUES (?, ?, ?, ?, ?, ?)`,
		grant.ID, grant.ClientID, grant.DeviceID, grant.Scope, oauthTime(now), operator); err != nil {
		return "", Grant{}, err
	}
	code, err := issue(tx, kindCode, grant.ID, now.Add(codeLifetime), req.RedirectURI, req.CodeChallenge)
	if err != nil {
		return "", Grant{}, err
	}
	if err := tx.Commit(); err != nil {
		return "", Grant{}, err
	}
	if _, err := activationAudit(dir).Append(audit.Record{
		TS: now.UTC().Format(time.RFC3339), Event: audit.EventOAuthGrantCreated, DeviceID: deviceID,
		GrantID: grant.ID, ClientID: client.ID, Operator: operator, Note: client.Name,
	}); err != nil {
		return "", Grant{}, fmt.Errorf("the grant was made, but its audit record failed: %w", err)
	}
	return callback(o, req.RedirectURI, url.Values{"code": {code}, "state": {req.State}}), grant, nil
}

// Deny is the redirect telling req's client the operator refused it.
func Deny(o OAuth, req AuthorizationRequest) string {
	return callback(o, req.RedirectURI, url.Values{"error": {"access_denied"}, "error_description": {"the operator did not authorize this client"}, "state": {req.State}})
}
