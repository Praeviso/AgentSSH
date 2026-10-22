package controlplane

import (
	"crypto/rand"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"errors"
	"time"

	"github.com/Praeviso/AgentSSH/internal/remote"
)

// CreateEnrollToken creates a token bound to the canonical public base.
func (s *Store) CreateEnrollToken(name, publicURL, fingerprint string, ttl time.Duration, now time.Time) (remote.EnrollToken, error) {
	base, err := remote.HTTPSBaseURL(publicURL)
	if err != nil {
		return remote.EnrollToken{}, err
	}
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return remote.EnrollToken{}, err
	}
	token := remote.EnrollToken{ID: "et_" + RandomHex(6), Secret: base64.RawURLEncoding.EncodeToString(secret),
		ServerURL: base, BundleFingerprint: fingerprint}
	if _, err := remote.ParseEnrollToken(token.String()); err != nil {
		return remote.EnrollToken{}, err
	}
	_, err = s.db.Exec(`INSERT INTO enroll_tokens (id,name,secret_sha256,public_url,expires_at) VALUES (?,?,?,?,?)`,
		token.ID, name, secretDigest(token.Secret), base, FormatTime(now.Add(ttl)))
	return token, err
}

// RedeemEnrollToken consumes the token and persists the public key in the
// same transaction. The caller verifies proof of possession before calling it.
func (s *Store) RedeemEnrollToken(id, secret, publicURL, publicKey string, now time.Time) (Device, error) {
	if _, err := remote.DecodePublicKey(publicKey); err != nil {
		return Device{}, err
	}
	tx, err := s.db.Begin()
	if err != nil {
		return Device{}, err
	}
	defer func() { _ = tx.Rollback() }()
	var name, digest, expires, used, base string
	err = tx.QueryRow(`SELECT name,secret_sha256,public_url,expires_at,used_at FROM enroll_tokens WHERE id=?`, id).
		Scan(&name, &digest, &base, &expires, &used)
	if errors.Is(err, sql.ErrNoRows) {
		return Device{}, ErrTokenInvalid
	}
	if err != nil {
		return Device{}, err
	}
	if used != "" || !now.Before(ParseTime(expires)) || base != publicURL ||
		subtle.ConstantTimeCompare([]byte(digest), []byte(secretDigest(secret))) != 1 {
		return Device{}, ErrTokenInvalid
	}
	res, err := tx.Exec(`UPDATE enroll_tokens SET used_at=? WHERE id=? AND used_at=''`, FormatTime(now), id)
	if err != nil {
		return Device{}, err
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return Device{}, ErrTokenInvalid
	}
	d := Device{ID: "dev_" + RandomHex(8), Name: name, PublicKey: publicKey, Status: remote.DeviceActive, CreatedAt: now}
	if _, err := tx.Exec(`INSERT INTO devices (id,name,public_key,status,created_at) VALUES (?,?,?,?,?)`, d.ID, d.Name, d.PublicKey, d.Status, FormatTime(now)); err != nil {
		return Device{}, err
	}
	if err := tx.Commit(); err != nil {
		return Device{}, err
	}
	return d, nil
}

// consumeNonce orders request authorization against revocation and replay in
// authoritative storage. Never derive the refusal from a cached Device value.
func (s *Store) consumeNonce(device, nonce string, expires int64, clock func() time.Time) error {
	results, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = results.Rollback() }()
	var status string
	if err := results.QueryRow(`SELECT status FROM devices WHERE id=?`, device).Scan(&status); err != nil {
		return err
	}
	if status != remote.DeviceActive {
		return ErrDeviceRevoked
	}
	// BEGIN IMMEDIATE may have waited for another writer. Check time after
	// acquiring the lock, so an expired proof cannot outlive its nonce record.
	now := clock().Unix()
	if expires <= now {
		return remote.ErrRequestTime
	}
	// Use the expiry index once per minute, in the same write transaction as
	// admission. No per-request cleanup or background worker lifecycle is needed.
	prune := now >= s.nextNoncePrune.Load()
	if prune {
		if _, err := results.Exec(`DELETE FROM request_nonces WHERE expires_at<=?`, now); err != nil {
			return err
		}
		// Schedule while holding the writer lock. If this transaction rolls
		// back, expired rows can safely wait until the next maintenance pass.
		s.nextNoncePrune.Store(now + int64(time.Minute/time.Second))
	}
	res, err := results.Exec(`INSERT INTO request_nonces (device_id,nonce,expires_at) VALUES (?,?,?)
 ON CONFLICT(device_id,nonce) DO NOTHING`, device, nonce, expires)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return ErrRequestReplayed
	}
	if err := results.Commit(); err != nil {
		return err
	}
	return nil
}
