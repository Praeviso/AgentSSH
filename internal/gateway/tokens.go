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

// authenticateToken returns the device and token ID a request's bearer token
// names. A revoked device is controlplane.ErrDeviceRevoked; anything else
// that fails is errBadToken.
func authenticateToken(store *controlplane.Store, header string) (controlplane.Device, string, error) {
	raw, ok := strings.CutPrefix(header, "Bearer ")
	if !ok {
		return controlplane.Device{}, "", errBadToken
	}
	m := tokenPattern.FindStringSubmatch(raw)
	if m == nil {
		return controlplane.Device{}, "", errBadToken
	}
	tokenID, secret := m[1], m[2]
	var deviceID, digest, revoked string
	err := store.DB().QueryRow(`SELECT device_id, secret_sha256, revoked_at FROM device_tokens WHERE id = ?`, tokenID).Scan(&deviceID, &digest, &revoked)
	if errors.Is(err, sql.ErrNoRows) {
		return controlplane.Device{}, "", errBadToken
	}
	if err != nil {
		return controlplane.Device{}, "", err
	}
	if subtle.ConstantTimeCompare([]byte(digest), []byte(secretSHA256(secret))) != 1 || revoked != "" {
		return controlplane.Device{}, "", errBadToken
	}
	device, err := store.Device(deviceID)
	if err != nil {
		return controlplane.Device{}, "", err
	}
	if DeviceKind(device) != remote.DeviceKindToken {
		return controlplane.Device{}, "", errBadToken
	}
	if device.Status == remote.DeviceRevoked {
		return controlplane.Device{}, "", controlplane.ErrDeviceRevoked
	}
	return device, tokenID, nil
}

// TokenHandler serves a token device's request: the device and token are
// authenticated and, unless the route allows otherwise, the device is active.
type TokenHandler func(w http.ResponseWriter, r *http.Request, device controlplane.Device, tokenID string, body []byte)

// tokenRoute authenticates a request's bearer token for next. A route with
// needsActive set refuses a device outside its activation window, as every
// signed route but /status does.
func (s *Server) tokenRoute(method, path string, needsActive bool, next TokenHandler) controlplane.OpenRoute {
	return controlplane.OpenRoute{Method: method, Path: path, Handler: func(w http.ResponseWriter, r *http.Request, body []byte) {
		device, tokenID, err := authenticateToken(s.Store, r.Header.Get("Authorization"))
		switch {
		case errors.Is(err, errBadToken):
			w.Header().Set("WWW-Authenticate", `Bearer realm="agentssh-gateway"`)
			controlplane.WriteError(w, http.StatusUnauthorized, remote.CodeUnauthenticated, errBadToken.Error())
			return
		case errors.Is(err, controlplane.ErrDeviceRevoked):
			controlplane.WriteError(w, http.StatusForbidden, remote.CodeDeviceRevoked, "this device has been revoked by the control plane")
			return
		case err != nil:
			controlplane.WriteError(w, http.StatusInternalServerError, remote.CodeInternal, "token check unavailable")
			return
		}
		if needsActive {
			if _, active, err := deviceActive(s.Dir, s.Store, device.ID, s.now()); err != nil {
				controlplane.WriteError(w, http.StatusInternalServerError, remote.CodeInternal, "activation state unavailable")
				return
			} else if !active {
				controlplane.WriteError(w, http.StatusForbidden, remote.CodeDeviceInactive, "this device is not activated; an operator must activate it on the gateway")
				return
			}
		}
		next(w, r, device, tokenID, body)
	}}
}

// tokenRoutes are the bearer-token API. /api/status answers like /status,
// also while the device is inactive; every other route needs it active.
func (s *Server) tokenRoutes() []controlplane.OpenRoute {
	return []controlplane.OpenRoute{
		s.tokenRoute("GET", remote.PathTokenStatus, false, s.handleTokenStatus),
		s.tokenRoute("GET", remote.PathTokenHosts, true, func(w http.ResponseWriter, r *http.Request, device controlplane.Device, _ string, body []byte) {
			s.handleHosts(w, r, device, body)
		}),
	}
}

func (s *Server) handleTokenStatus(w http.ResponseWriter, _ *http.Request, device controlplane.Device, _ string, _ []byte) {
	status := remote.StatusResponse{DeviceID: device.ID, Status: device.Status, Mode: remote.ModeGateway}
	s.describeStatus(device, &status)
	controlplane.WriteJSON(w, http.StatusOK, status)
}
