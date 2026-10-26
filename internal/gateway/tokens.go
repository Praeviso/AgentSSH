package gateway

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/Praeviso/AgentSSH/internal/audit"
	"github.com/Praeviso/AgentSSH/internal/controlplane"
	"github.com/Praeviso/AgentSSH/internal/remote"
)

// A token device is a gateway device whose credential is a bearer token
// instead of an enrolled Ed25519 key, for agents that cannot run agentssh. It
// is a row in the shared devices table with no public key, so it can never
// sign, plus its tokens here. Only the SHA-256 of a token's secret is kept.
const tokenSchema = `
CREATE TABLE IF NOT EXISTS device_tokens (
	id TEXT PRIMARY KEY,
	device_id TEXT NOT NULL REFERENCES devices(id),
	secret_sha256 TEXT NOT NULL,
	created_at TEXT NOT NULL,
	revoked_at TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS device_tokens_device ON device_tokens(device_id);
`

// tokenPrefix starts every token, so a leaked one is recognizable.
const tokenPrefix = "agt"

var tokenPattern = regexp.MustCompile(`^agt_([0-9a-f]{16})_([A-Za-z0-9_-]{43})$`)

// ErrNotTokenDevice refuses a token operation on a signed device.
var ErrNotTokenDevice = errors.New("not a token device")

// DeviceKind is a device's kind: token devices have no public key.
func DeviceKind(device controlplane.Device) string {
	if device.PublicKey == "" {
		return remote.DeviceKindToken
	}
	return remote.DeviceKindSigned
}

// IssuedToken is a token as its device's operator receives it, once.
type IssuedToken struct {
	DeviceID string
	TokenID  string
	// Token is the bearer credential; it is never stored or shown again.
	Token string
}

func newToken() (id, secret, token string) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		panic(fmt.Sprintf("crypto/rand: %v", err))
	}
	id, secret = controlplane.RandomHex(8), base64.RawURLEncoding.EncodeToString(buf)
	return id, secret, tokenPrefix + "_" + id + "_" + secret
}

func secretSHA256(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:])
}

// CreateTokenDevice adds a token device named name with its first token. The
// device starts inactive, like every gateway device.
func CreateTokenDevice(dir string, store *controlplane.Store, name, operator string, now time.Time) (IssuedToken, error) {
	if strings.TrimSpace(name) == "" {
		return IssuedToken{}, errors.New("a token device needs a name")
	}
	deviceID := "dev_" + controlplane.RandomHex(8)
	tokenID, secret, token := newToken()
	tx, err := store.DB().Begin()
	if err != nil {
		return IssuedToken{}, err
	}
	defer func() { _ = tx.Rollback() }()
	// The shared devices table, with no public key: the signed routes refuse a
	// device without one.
	if _, err := tx.Exec(`INSERT INTO devices (id, name, public_key, status, created_at) VALUES (?, ?, '', ?, ?)`,
		deviceID, name, remote.DeviceActive, controlplane.FormatTime(now)); err != nil {
		return IssuedToken{}, err
	}
	if _, err := tx.Exec(`INSERT INTO device_tokens (id, device_id, secret_sha256, created_at) VALUES (?, ?, ?, ?)`,
		tokenID, deviceID, secretSHA256(secret), controlplane.FormatTime(now)); err != nil {
		return IssuedToken{}, err
	}
	if err := tx.Commit(); err != nil {
		return IssuedToken{}, err
	}
	if _, err := activationAudit(dir).Append(audit.Record{
		TS: now.UTC().Format(time.RFC3339), Event: audit.EventTokenIssued, DeviceID: deviceID, TokenID: tokenID, Operator: operator,
	}); err != nil {
		return IssuedToken{}, fmt.Errorf("the device was created, but its audit record failed: %w", err)
	}
	return IssuedToken{DeviceID: deviceID, TokenID: tokenID, Token: token}, nil
}

// RotateToken replaces a token device's token: the new one is issued and the
// old one refused from the same moment.
func RotateToken(dir string, store *controlplane.Store, deviceID, operator string, now time.Time) (IssuedToken, error) {
	device, err := store.Device(deviceID)
	if err != nil {
		return IssuedToken{}, err
	}
	if DeviceKind(device) != remote.DeviceKindToken {
		return IssuedToken{}, ErrNotTokenDevice
	}
	if device.Status == remote.DeviceRevoked {
		return IssuedToken{}, controlplane.ErrDeviceRevoked
	}
	tokenID, secret, token := newToken()
	tx, err := store.DB().Begin()
	if err != nil {
		return IssuedToken{}, err
	}
	defer func() { _ = tx.Rollback() }()
	var old []string
	rows, err := tx.Query(`SELECT id FROM device_tokens WHERE device_id = ? AND revoked_at = ''`, deviceID)
	if err != nil {
		return IssuedToken{}, err
	}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			_ = rows.Close()
			return IssuedToken{}, err
		}
		old = append(old, id)
	}
	if err := rows.Close(); err != nil {
		return IssuedToken{}, err
	}
	if _, err := tx.Exec(`UPDATE device_tokens SET revoked_at = ? WHERE device_id = ? AND revoked_at = ''`, controlplane.FormatTime(now), deviceID); err != nil {
		return IssuedToken{}, err
	}
	if _, err := tx.Exec(`INSERT INTO device_tokens (id, device_id, secret_sha256, created_at) VALUES (?, ?, ?, ?)`,
		tokenID, deviceID, secretSHA256(secret), controlplane.FormatTime(now)); err != nil {
		return IssuedToken{}, err
	}
	if err := tx.Commit(); err != nil {
		return IssuedToken{}, err
	}
	log := activationAudit(dir)
	ts := now.UTC().Format(time.RFC3339)
	for _, id := range old {
		if _, err := log.Append(audit.Record{TS: ts, Event: audit.EventTokenRevoked, DeviceID: deviceID, TokenID: id, Operator: operator}); err != nil {
			return IssuedToken{}, fmt.Errorf("the token was rotated, but its audit record failed: %w", err)
		}
	}
	if _, err := log.Append(audit.Record{TS: ts, Event: audit.EventTokenIssued, DeviceID: deviceID, TokenID: tokenID, Operator: operator}); err != nil {
		return IssuedToken{}, fmt.Errorf("the token was rotated, but its audit record failed: %w", err)
	}
	return IssuedToken{DeviceID: deviceID, TokenID: tokenID, Token: token}, nil
}

// errBadToken is every authentication failure a token holder sees: which
// part was wrong is not revealed.
var errBadToken = errors.New("invalid bearer token")

// credential is what a token device's request authenticated with: a device
// token, or an OAuth access token of a grant.
type credential struct {
	tokenID string
	grantID string
}

// authenticateToken returns the device and credential a request's bearer
// token names; an OAuth access token counts only when oauth is set. A revoked
// device is controlplane.ErrDeviceRevoked; anything else that fails is
// errBadToken.
func authenticateToken(store *controlplane.Store, header string, oauth bool, now time.Time) (controlplane.Device, credential, error) {
	raw, ok := strings.CutPrefix(header, "Bearer ")
	if !ok {
		return controlplane.Device{}, credential{}, errBadToken
	}
	var deviceID string
	var cred credential
	if m := tokenPattern.FindStringSubmatch(raw); m != nil {
		tokenID, secret := m[1], m[2]
		var digest, revoked string
		err := store.DB().QueryRow(`SELECT device_id, secret_sha256, revoked_at FROM device_tokens WHERE id = ?`, tokenID).Scan(&deviceID, &digest, &revoked)
		if errors.Is(err, sql.ErrNoRows) {
			return controlplane.Device{}, credential{}, errBadToken
		}
		if err != nil {
			return controlplane.Device{}, credential{}, err
		}
		if subtle.ConstantTimeCompare([]byte(digest), []byte(secretSHA256(secret))) != 1 || revoked != "" {
			return controlplane.Device{}, credential{}, errBadToken
		}
		cred.tokenID = tokenID
	} else if oauth {
		grant, err := accessGrant(store, raw, now)
		if err != nil {
			return controlplane.Device{}, credential{}, err
		}
		deviceID, cred.grantID = grant.DeviceID, grant.ID
	} else {
		return controlplane.Device{}, credential{}, errBadToken
	}
	device, err := store.Device(deviceID)
	if err != nil {
		return controlplane.Device{}, credential{}, err
	}
	if DeviceKind(device) != remote.DeviceKindToken {
		return controlplane.Device{}, credential{}, errBadToken
	}
	if device.Status == remote.DeviceRevoked {
		return controlplane.Device{}, credential{}, controlplane.ErrDeviceRevoked
	}
	return device, cred, nil
}

// TokenHandler serves a token device's request: the device and its
// credential are authenticated and, unless the route allows otherwise, the
// device is active.
type TokenHandler func(w http.ResponseWriter, r *http.Request, device controlplane.Device, cred credential, body []byte)

// tokenOptions shape a token route.
type tokenOptions struct {
	// needsActive refuses a device outside its activation window, as every
	// signed route but /status does.
	needsActive bool
	// oauth accepts OAuth access tokens as well as device tokens: only the
	// MCP endpoint, the resource they are issued for.
	oauth bool
	// maxBody bounds the body (zero means 64 KiB); a larger one gets
	// controlplane.StreamingBodyTimeout to arrive.
	maxBody int64
	// respondWithin, when set, extends the response deadline past the
	// server's own, for a route that waits on a run.
	respondWithin time.Duration
}

// tokenRoute authenticates a request's bearer token and checks its device's
// standing, reads the body, then checks both again before next runs: the
// first check keeps unauthenticated clients from holding an upload, and the
// second, as the signed routes check after the body, keeps a token rotated
// or a device revoked or deactivated during a slow upload from running
// anything.
func (s *Server) tokenRoute(method, path string, opts tokenOptions, next TokenHandler) controlplane.OpenRoute {
	return controlplane.OpenRoute{Method: method, Path: path, Handler: func(w http.ResponseWriter, r *http.Request) {
		if _, _, ok := s.admitToken(w, r, opts); !ok {
			return
		}
		rc := http.NewResponseController(w)
		if opts.maxBody > 0 {
			_ = rc.SetReadDeadline(time.Now().Add(controlplane.StreamingBodyTimeout))
		}
		body, err := controlplane.ReadBody(r, opts.maxBody)
		if err != nil {
			controlplane.WriteError(w, http.StatusRequestEntityTooLarge, remote.CodeBadRequest, "request body too large or unreadable")
			return
		}
		device, cred, ok := s.admitToken(w, r, opts)
		if !ok {
			return
		}
		if opts.respondWithin > 0 {
			_ = rc.SetWriteDeadline(time.Now().Add(opts.respondWithin))
		}
		next(w, r, device, cred, body)
	}}
}

// admitToken authenticates r's bearer token and, for a route that needs it,
// checks the device is active, answering the request itself when not.
func (s *Server) admitToken(w http.ResponseWriter, r *http.Request, opts tokenOptions) (controlplane.Device, credential, bool) {
	oauth := opts.oauth && s.oauth != nil
	device, cred, err := authenticateToken(s.Store, r.Header.Get("Authorization"), oauth, s.now())
	switch {
	case errors.Is(err, errBadToken):
		challenge := `Bearer realm="agentssh-gateway"`
		if oauth {
			// Where an MCP client finds how to get a token (RFC 9728).
			challenge = fmt.Sprintf(`Bearer resource_metadata=%q, scope=%q`, s.oauth.resourceMetadataURL(), remote.OAuthScope)
			if r.Header.Get("Authorization") != "" {
				challenge += `, error="invalid_token"`
			}
		}
		w.Header().Set("WWW-Authenticate", challenge)
		controlplane.WriteError(w, http.StatusUnauthorized, remote.CodeUnauthenticated, errBadToken.Error())
		return controlplane.Device{}, credential{}, false
	case errors.Is(err, controlplane.ErrDeviceRevoked):
		controlplane.WriteError(w, http.StatusForbidden, remote.CodeDeviceRevoked, "this device has been revoked by the control plane")
		return controlplane.Device{}, credential{}, false
	case err != nil:
		controlplane.WriteError(w, http.StatusInternalServerError, remote.CodeInternal, "token check unavailable")
		return controlplane.Device{}, credential{}, false
	}
	if opts.needsActive {
		if _, active, err := deviceActive(s.Dir, s.Store, device.ID, s.now()); err != nil {
			controlplane.WriteError(w, http.StatusInternalServerError, remote.CodeInternal, "activation state unavailable")
			return controlplane.Device{}, credential{}, false
		} else if !active {
			controlplane.WriteError(w, http.StatusForbidden, remote.CodeDeviceInactive, "this device is not activated; an operator must activate it on the gateway")
			return controlplane.Device{}, credential{}, false
		}
	}
	return device, cred, true
}

// tokenRoutes are the bearer-token API. /api/status answers like /status,
// also while the device is inactive; every other route needs it active.
func (s *Server) tokenRoutes() []controlplane.OpenRoute {
	var routes []controlplane.OpenRoute
	for _, op := range s.apiOperations() {
		routes = append(routes, s.tokenRoute(op.method, op.path, op.opts, op.handler))
	}
	return append(routes, s.mcpRoutes()...)
}

func (s *Server) handleTokenStatus(w http.ResponseWriter, _ *http.Request, device controlplane.Device, _ credential, _ []byte) {
	status := remote.StatusResponse{DeviceID: device.ID, Status: device.Status, Mode: remote.ModeGateway}
	s.describeStatus(device, &status)
	controlplane.WriteJSON(w, http.StatusOK, status)
}
