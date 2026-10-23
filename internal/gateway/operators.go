package gateway

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/Praeviso/AgentSSH/internal/controlplane"
	"golang.org/x/crypto/argon2"
)

// Operators decide approvals in the Web UI. They are a separate kind of
// account from devices: a device key cannot log in, and an operator cannot
// call the device API.
const operatorSchema = `
CREATE TABLE IF NOT EXISTS operators (
	id INTEGER PRIMARY KEY,
	name TEXT NOT NULL UNIQUE,
	password_hash TEXT NOT NULL,
	totp_secret BLOB,
	totp_last_step INTEGER NOT NULL DEFAULT 0,
	status TEXT NOT NULL,
	created_at TEXT NOT NULL,
	revoked_at TEXT
);
CREATE TABLE IF NOT EXISTS web_sessions (
	token_sha256 TEXT PRIMARY KEY,
	operator_id INTEGER NOT NULL REFERENCES operators(id) ON DELETE CASCADE,
	stage TEXT NOT NULL,
	csrf TEXT NOT NULL,
	pending_totp BLOB,
	created_at TEXT NOT NULL,
	seen_at TEXT NOT NULL,
	expires_at TEXT NOT NULL
);
`

// Operator states.
const (
	OperatorActive  = "active"
	OperatorRevoked = "revoked"
)

// Operator is one Web UI account.
type Operator struct {
	ID        int64
	Name      string
	Status    string
	CreatedAt time.Time
	// TOTPEnrolled is false until the operator verifies a code at first login.
	TOTPEnrolled bool
}

// MinOperatorPassword is the shortest operator password accepted.
const MinOperatorPassword = 12

var operatorName = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)

var (
	ErrOperatorExists   = errors.New("an operator with this name already exists")
	ErrOperatorNotFound = errors.New("no such operator")
	ErrBadCredentials   = errors.New("wrong name, password or code")
	ErrPasswordsBusy    = errors.New("too many sign-ins at once")
)

// PasswordParams are the argon2id costs of new operator passwords. Tests
// lower them; stored hashes carry their own.
var PasswordParams = struct {
	Time, MemoryKiB uint32
	Threads         uint8
}{Time: 3, MemoryKiB: 64 << 10, Threads: 4}

// hashPassword returns an argon2id PHC string.
func hashPassword(password string) string {
	salt := make([]byte, 16)
	_, _ = rand.Read(salt)
	p := PasswordParams
	key := argon2.IDKey([]byte(password), salt, p.Time, p.MemoryKiB, p.Threads, 32)
	enc := base64.RawStdEncoding
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s", argon2.Version, p.MemoryKiB, p.Time, p.Threads, enc.EncodeToString(salt), enc.EncodeToString(key))
}

// checkPassword compares password with a PHC string from hashPassword.
func checkPassword(encoded, password string) bool {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" || parts[2] != fmt.Sprintf("v=%d", argon2.Version) {
		return false
	}
	var memory, time uint32
	var threads uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &time, &threads); err != nil {
		return false
	}
	enc := base64.RawStdEncoding
	salt, err1 := enc.DecodeString(parts[4])
	want, err2 := enc.DecodeString(parts[5])
	if err1 != nil || err2 != nil || len(want) == 0 {
		return false
	}
	got := argon2.IDKey([]byte(password), salt, time, memory, threads, uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1
}

// dummyHash is checked against for unknown names, so a login takes as long
// whether or not the operator exists.
var dummyHash = hashPassword("agentssh-gateway unknown operator")

// AddOperator creates an operator who enrolls TOTP at first login.
func AddOperator(store *controlplane.Store, name, password string, now time.Time) error {
	if !operatorName.MatchString(name) {
		return errors.New("operator names are 1-64 lowercase letters, digits, '.', '_' or '-', starting with a letter or digit")
	}
	if len(password) < MinOperatorPassword {
		return fmt.Errorf("an operator password has at least %d characters", MinOperatorPassword)
	}
	_, err := store.DB().Exec(`INSERT INTO operators (name, password_hash, status, created_at) VALUES (?, ?, ?, ?)`,
		name, hashPassword(password), OperatorActive, controlplane.FormatTime(now))
	if err != nil && strings.Contains(err.Error(), "UNIQUE") {
		return ErrOperatorExists
	}
	return err
}

// Operators lists every operator.
func Operators(store *controlplane.Store) ([]Operator, error) {
	rows, err := store.DB().Query(`SELECT id, name, status, created_at, totp_secret IS NOT NULL FROM operators ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []Operator
	for rows.Next() {
		var op Operator
		var created string
		if err := rows.Scan(&op.ID, &op.Name, &op.Status, &created, &op.TOTPEnrolled); err != nil {
			return nil, err
		}
		op.CreatedAt = controlplane.ParseTime(created)
		out = append(out, op)
	}
	return out, rows.Err()
}

// RevokeOperator disables an operator and ends all their sessions at once.
func RevokeOperator(store *controlplane.Store, name string, now time.Time) error {
	tx, err := store.DB().Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	var id int64
	if err := tx.QueryRow(`SELECT id FROM operators WHERE name = ?`, name).Scan(&id); errors.Is(err, sql.ErrNoRows) {
		return ErrOperatorNotFound
	} else if err != nil {
		return err
	}
	if _, err := tx.Exec(`UPDATE operators SET status = ?, revoked_at = ? WHERE id = ?`, OperatorRevoked, controlplane.FormatTime(now), id); err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM web_sessions WHERE operator_id = ?`, id); err != nil {
		return err
	}
	return tx.Commit()
}

// passwordChecks bounds the argon2id checks running at once. Each holds
// PasswordParams.MemoryKiB, so sign-ins from any number of clients stay
// within a fixed memory budget; the failure limits alone bound only how many
// attempts fail, not how many run together.
var passwordChecks = make(chan struct{}, 2)

// checkOperatorPassword returns the active operator name and password
// identify, or ErrBadCredentials. It waits for a free password check until
// ctx ends (ErrPasswordsBusy).
func checkOperatorPassword(ctx context.Context, store *controlplane.Store, name, password string) (Operator, error) {
	select {
	case passwordChecks <- struct{}{}:
		defer func() { <-passwordChecks }()
	case <-ctx.Done():
		return Operator{}, ErrPasswordsBusy
	}
	var op Operator
	var hash string
	err := store.DB().QueryRow(`SELECT id, name, status, password_hash, totp_secret IS NOT NULL FROM operators WHERE name = ?`, name).
		Scan(&op.ID, &op.Name, &op.Status, &hash, &op.TOTPEnrolled)
	if errors.Is(err, sql.ErrNoRows) {
		checkPassword(dummyHash, password)
		return Operator{}, ErrBadCredentials
	}
	if err != nil {
		return Operator{}, err
	}
	if !checkPassword(hash, password) || op.Status != OperatorActive {
		return Operator{}, ErrBadCredentials
	}
	return op, nil
}

// TOTP (RFC 6238): HMAC-SHA1, six digits, 30-second steps, one step of
// clock drift either way.
const (
	totpPeriod = 30
	totpDigits = 6
)

func totpCode(secret []byte, step int64) string {
	mac := hmac.New(sha1.New, secret)
	_ = binary.Write(mac, binary.BigEndian, step)
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	value := binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7fffffff
	return fmt.Sprintf("%0*d", totpDigits, value%1000000)
}

// TOTPCode is the code an authenticator shows for secret at t.
func TOTPCode(secret []byte, t time.Time) string {
	return totpCode(secret, t.Unix()/totpPeriod)
}

// matchTOTP returns the step code matches near now, or -1.
func matchTOTP(secret []byte, code string, now time.Time) int64 {
	if len(code) != totpDigits {
		return -1
	}
	step := now.Unix() / totpPeriod
	for _, s := range []int64{step, step - 1, step + 1} {
		if subtle.ConstantTimeCompare([]byte(totpCode(secret, s)), []byte(code)) == 1 {
			return s
		}
	}
	return -1
}

// NewTOTPSecret returns a fresh 20-byte TOTP key and its base32 form.
func NewTOTPSecret() ([]byte, string) {
	secret := make([]byte, 20)
	_, _ = rand.Read(secret)
	return secret, base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(secret)
}

// TOTPURI is the otpauth:// URI an authenticator app enrolls from.
func TOTPURI(issuer, account, encoded string) string {
	label := strings.ReplaceAll(issuer+":"+account, " ", "%20")
	return "otpauth://totp/" + label + "?secret=" + encoded + "&issuer=" + strings.ReplaceAll(issuer, " ", "%20") + "&algorithm=SHA1&digits=6&period=30"
}

// enrollTOTP stores an operator's TOTP key, sealed, once a code from it
// verified. An operator enrolls once; resetting means a new account.
func enrollTOTP(store *controlplane.Store, keys *controlplane.Keys, operatorID int64, secret []byte, code string, now time.Time) error {
	step := matchTOTP(secret, code, now)
	if step < 0 {
		return ErrBadCredentials
	}
	sealed, err := keys.Seal(secret)
	if err != nil {
		return err
	}
	result, err := store.DB().Exec(`UPDATE operators SET totp_secret = ?, totp_last_step = ? WHERE id = ? AND totp_secret IS NULL AND status = ?`,
		sealed, step, operatorID, OperatorActive)
	if err != nil {
		return err
	}
	if n, _ := result.RowsAffected(); n != 1 {
		return ErrBadCredentials
	}
	return nil
}

// checkTOTP verifies code against an enrolled operator. A code is accepted
// once: recording its step succeeds only if no later or equal step was
// recorded, which also settles two sign-ins racing with one code.
func checkTOTP(store *controlplane.Store, keys *controlplane.Keys, operatorID int64, code string, now time.Time) error {
	var sealed []byte
	err := store.DB().QueryRow(`SELECT totp_secret FROM operators WHERE id = ? AND status = ?`, operatorID, OperatorActive).Scan(&sealed)
	if err != nil || sealed == nil {
		return ErrBadCredentials
	}
	secret, err := keys.Open(sealed)
	if err != nil {
		return err
	}
	step := matchTOTP(secret, code, now)
	if step < 0 {
		return ErrBadCredentials
	}
	result, err := store.DB().Exec(`UPDATE operators SET totp_last_step = ? WHERE id = ? AND totp_last_step < ?`, step, operatorID, step)
	if err != nil {
		return err
	}
	if n, _ := result.RowsAffected(); n != 1 {
		return ErrBadCredentials
	}
	return nil
}

// Session stages: a password alone reaches only the TOTP step.
const (
	StagePassword = "password"
	StageActive   = "active"
)

// Session lifetimes.
const (
	passwordStageTTL = 10 * time.Minute
	sessionTTL       = 12 * time.Hour
	sessionIdle      = 30 * time.Minute
)

// WebSession is a logged-in browser.
type WebSession struct {
	Operator Operator
	Stage    string
	CSRF     string
}

func tokenDigest(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// newSession starts a session at stage and returns its cookie token.
func newSession(store *controlplane.Store, operatorID int64, stage string, now time.Time) (string, error) {
	token := controlplane.RandomHex(32)
	ttl := sessionTTL
	if stage == StagePassword {
		ttl = passwordStageTTL
	}
	_, err := store.DB().Exec(`INSERT INTO web_sessions (token_sha256, operator_id, stage, csrf, created_at, seen_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		tokenDigest(token), operatorID, stage, controlplane.RandomHex(32), controlplane.FormatTime(now), controlplane.FormatTime(now), controlplane.FormatTime(now.Add(ttl)))
	return token, err
}

// lookupSession returns the session for token, refreshing its idle timer. A
// revoked operator's, expired or idle session is gone.
func lookupSession(store *controlplane.Store, token string, now time.Time) (WebSession, bool) {
	var s WebSession
	var seen, expires, created string
	err := store.DB().QueryRow(`SELECT o.id, o.name, o.status, o.totp_secret IS NOT NULL, w.stage, w.csrf, w.seen_at, w.expires_at, o.created_at
		FROM web_sessions w JOIN operators o ON o.id = w.operator_id WHERE w.token_sha256 = ?`, tokenDigest(token)).
		Scan(&s.Operator.ID, &s.Operator.Name, &s.Operator.Status, &s.Operator.TOTPEnrolled, &s.Stage, &s.CSRF, &seen, &expires, &created)
	if err != nil {
		return WebSession{}, false
	}
	if s.Operator.Status != OperatorActive || !now.Before(controlplane.ParseTime(expires)) || now.Sub(controlplane.ParseTime(seen)) > sessionIdle {
		_ = endSession(store, token)
		return WebSession{}, false
	}
	_, _ = store.DB().Exec(`UPDATE web_sessions SET seen_at = ? WHERE token_sha256 = ?`, controlplane.FormatTime(now), tokenDigest(token))
	return s, true
}

// pendingTOTP returns the sealed key a password-stage session is enrolling,
// minting and keeping one on first use, so the code verified is for the
// key the operator scanned. Of concurrent first uses (two tabs) only one
// key is kept, and every page shows that one.
func pendingTOTP(store *controlplane.Store, keys *controlplane.Keys, token string) ([]byte, error) {
	var sealed []byte
	if err := store.DB().QueryRow(`SELECT pending_totp FROM web_sessions WHERE token_sha256 = ?`, tokenDigest(token)).Scan(&sealed); err != nil {
		return nil, err
	}
	if sealed != nil {
		return keys.Open(sealed)
	}
	secret, _ := NewTOTPSecret()
	sealed, err := keys.Seal(secret)
	if err != nil {
		return nil, err
	}
	res, err := store.DB().Exec(`UPDATE web_sessions SET pending_totp = ? WHERE token_sha256 = ? AND pending_totp IS NULL`, sealed, tokenDigest(token))
	if err != nil {
		return nil, err
	}
	if n, err := res.RowsAffected(); err != nil || n == 0 {
		// Another request kept its key first (or the session ended).
		return pendingTOTP(store, keys, token)
	}
	return secret, nil
}

func endSession(store *controlplane.Store, token string) error {
	_, err := store.DB().Exec(`DELETE FROM web_sessions WHERE token_sha256 = ?`, tokenDigest(token))
	return err
}

// sweepSessions deletes expired sessions.
func sweepSessions(store *controlplane.Store, now time.Time) {
	_, _ = store.DB().Exec(`DELETE FROM web_sessions WHERE expires_at <= ?`, controlplane.FormatTime(now))
}

// operatorLabel is how decisions name their operator in the audit chain.
func operatorLabel(name string) string { return "web:" + name }
