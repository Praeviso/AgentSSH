package approval

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/Praeviso/AgentSSH/internal/fileutil"
)

type SessionStore struct {
	Dir string
	Now func() time.Time
}

type Grant struct {
	Scope      Scope       `json:"scope"`
	Kind       MatcherKind `json:"kind"`
	Regex      string      `json:"regex"`
	Prefix     []string    `json:"prefix,omitempty"`
	SourceCmd  string      `json:"source_cmd"`
	Host       string      `json:"host"`
	GrantedTS  string      `json:"granted_ts"`
	ExpiresTS  string      `json:"expires_ts"`
	ApprovalID string      `json:"approval_id"`
	ReqID      string      `json:"req_id"`
	Channel    string      `json:"channel"`
	// StdinSHA256 binds the grant to one exact stdin payload. Empty means the
	// approved command had no stdin; a grant never matches a run whose stdin
	// hash differs from the one the operator approved.
	StdinSHA256 string `json:"stdin_sha256,omitempty"`
	// ClaimReqID/ClaimTS implement two-phase once-grant consumption: Claim marks
	// the grant as reserved by one run request; Commit deletes it once the command
	// reached the remote; Release restores it when the command never executed.
	// A claim never expires by wall clock: a crash between claim and settle leaves
	// the grant unusable (fail-closed), same as a consumed grant.
	ClaimReqID string `json:"claim_req_id,omitempty"`
	ClaimTS    string `json:"claim_ts,omitempty"`
}

type sessionFile struct {
	Version   int     `json:"version"`
	SessionID string  `json:"session_id"`
	Host      string  `json:"host,omitempty"`
	Updated   string  `json:"updated"`
	Grants    []Grant `json:"grants"`
}

func (s SessionStore) Grant(sessionID string, host string, scope Scope, matcher Matcher, stdinSHA256 string, approvalID string, reqID string, ttl time.Duration, channel string) (Grant, error) {
	if scope != ScopeOnce && scope != ScopeSession {
		return Grant{}, fmt.Errorf("session store cannot grant scope %q", scope)
	}
	if err := os.MkdirAll(s.Dir, 0o700); err != nil {
		return Grant{}, fmt.Errorf("create approval session directory: %w", err)
	}
	now := s.now()
	grant := Grant{
		Scope:       scope,
		Kind:        matcher.Kind,
		Regex:       matcher.Regex,
		Prefix:      append([]string(nil), matcher.Prefix...),
		SourceCmd:   matcher.SourceCmd,
		Host:        host,
		GrantedTS:   now.UTC().Format(time.RFC3339),
		ExpiresTS:   now.Add(ttl).UTC().Format(time.RFC3339),
		ApprovalID:  approvalID,
		ReqID:       reqID,
		Channel:     channel,
		StdinSHA256: stdinSHA256,
	}
	err := s.withLockedSession(sessionID, func(doc *sessionFile) error {
		if doc.Version == 0 {
			doc.Version = 1
		}
		if doc.SessionID == "" {
			doc.SessionID = sessionID
		}
		if doc.SessionID != sessionID {
			return fmt.Errorf("session store file mismatch: %q != %q", doc.SessionID, sessionID)
		}
		doc.Grants = filterLiveGrants(doc.Grants, now)
		out := doc.Grants[:0]
		for _, existing := range doc.Grants {
			if existing.Host == host && existing.Scope == scope && existing.Regex == grant.Regex && existing.StdinSHA256 == grant.StdinSHA256 {
				continue
			}
			out = append(out, existing)
		}
		doc.Grants = append(out, grant)
		doc.Updated = now.UTC().Format(time.RFC3339)
		return nil
	})
	return grant, err
}

// Peek reports whether a grant would authorize the command without reserving
// or consuming anything. Once grants already claimed by an in-flight run are
// invisible: they can no longer authorize a different request.
func (s SessionStore) Peek(sessionID string, host string, command string, stdinSHA256 string) (Grant, bool, error) {
	return s.match(sessionID, host, command, stdinSHA256, "")
}

// Claim matches a grant for one run request. A matching once grant is marked
// as claimed by reqID (in the same lock, so two concurrent runs can never
// claim the same once grant); session grants match without side effects.
// The caller must settle every once claim with Commit or Release.
func (s SessionStore) Claim(sessionID string, host string, command string, stdinSHA256 string, reqID string) (Grant, bool, error) {
	if reqID == "" {
		return Grant{}, false, fmt.Errorf("once-grant claim requires a request id")
	}
	return s.match(sessionID, host, command, stdinSHA256, reqID)
}

// Commit consumes every once grant claimed by reqID. Call it as soon as the
// command has been handed to the remote: from that point re-running requires a
// fresh approval.
func (s SessionStore) Commit(sessionID string, reqID string) error {
	return s.settleClaims(sessionID, reqID, true)
}

// Release restores every once grant claimed by reqID. Call it only when the
// command verifiably never executed (local cancel, transport failure before
// the remote ran it, audit append failure before execution).
func (s SessionStore) Release(sessionID string, reqID string) error {
	return s.settleClaims(sessionID, reqID, false)
}

func (s SessionStore) settleClaims(sessionID string, reqID string, consume bool) error {
	if sessionID == "" || reqID == "" {
		return nil
	}
	now := s.now()
	return s.withLockedSession(sessionID, func(doc *sessionFile) error {
		if doc.SessionID == "" {
			return nil
		}
		if doc.SessionID != sessionID {
			return fmt.Errorf("session store file mismatch: %q != %q", doc.SessionID, sessionID)
		}
		changed := false
		remaining := doc.Grants[:0]
		for _, grant := range doc.Grants {
			if grant.Scope != ScopeOnce || grant.ClaimReqID != reqID {
				remaining = append(remaining, grant)
				continue
			}
			changed = true
			if consume {
				continue
			}
			grant.ClaimReqID = ""
			grant.ClaimTS = ""
			remaining = append(remaining, grant)
		}
		if changed {
			doc.Grants = remaining
			doc.Updated = now.UTC().Format(time.RFC3339)
		}
		return nil
	})
}

// match implements Peek (claimReqID == "") and Claim (claimReqID != "").
func (s SessionStore) match(sessionID string, host string, command string, stdinSHA256 string, claimReqID string) (Grant, bool, error) {
	if sessionID == "" {
		return Grant{}, false, nil
	}
	now := s.now()
	var matched Grant
	var ok bool
	err := s.withLockedSession(sessionID, func(doc *sessionFile) error {
		if doc.SessionID == "" {
			return nil
		}
		if doc.SessionID != sessionID {
			return fmt.Errorf("session store file mismatch: %q != %q", doc.SessionID, sessionID)
		}
		live := filterLiveGrants(doc.Grants, now)
		changed := len(live) != len(doc.Grants)
		remaining := make([]Grant, 0, len(live))
		for _, grant := range live {
			if ok {
				remaining = append(remaining, grant)
				continue
			}
			if grant.Host != host {
				remaining = append(remaining, grant)
				continue
			}
			// A grant only covers the exact stdin payload it was approved with.
			if grant.StdinSHA256 != stdinSHA256 {
				remaining = append(remaining, grant)
				continue
			}
			// A once grant claimed by another in-flight request is spoken for.
			if grant.Scope == ScopeOnce && grant.ClaimReqID != "" && grant.ClaimReqID != claimReqID {
				remaining = append(remaining, grant)
				continue
			}
			matcher := grant.matcher()
			matches, err := matcher.Match(command)
			if err != nil {
				return err
			}
			if !matches {
				remaining = append(remaining, grant)
				continue
			}
			if grant.Scope == ScopeOnce && claimReqID != "" && grant.ClaimReqID != claimReqID {
				grant.ClaimReqID = claimReqID
				grant.ClaimTS = now.UTC().Format(time.RFC3339)
				changed = true
			}
			matched = grant
			ok = true
			remaining = append(remaining, grant)
		}
		if changed {
			doc.Grants = remaining
			doc.Updated = now.UTC().Format(time.RFC3339)
		}
		return nil
	})
	return matched, ok, err
}

func (s SessionStore) End(sessionID string) error {
	if sessionID == "" {
		return nil
	}
	if err := os.MkdirAll(s.Dir, 0o700); err != nil {
		return fmt.Errorf("create approval session directory: %w", err)
	}
	if err := removeSessionFile(sessionPath(s.Dir, sessionID)); err != nil {
		return err
	}
	entries, err := os.ReadDir(s.Dir)
	if err != nil {
		return fmt.Errorf("list approval sessions: %w", err)
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		path := filepath.Join(s.Dir, entry.Name())
		lock, err := lockSessionPath(path)
		if err != nil {
			return err
		}
		doc, err := readSessionFile(path)
		if err != nil {
			unlockAndClose(lock)
			return err
		}
		if doc.SessionID == sessionID || strings.HasPrefix(doc.SessionID, sessionID+"@") {
			if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
				unlockAndClose(lock)
				return fmt.Errorf("remove approval session: %w", err)
			}
		}
		unlockAndClose(lock)
	}
	return nil
}

func removeSessionFile(path string) error {
	lock, err := lockSessionPath(path)
	if err != nil {
		return err
	}
	defer unlockAndClose(lock)
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove approval session: %w", err)
	}
	return nil
}

func (s SessionStore) withLockedSession(sessionID string, fn func(*sessionFile) error) error {
	if sessionID == "" {
		return fmt.Errorf("approval session id is required")
	}
	path := sessionPath(s.Dir, sessionID)
	lock, err := lockSessionPath(path)
	if err != nil {
		return err
	}
	defer unlockAndClose(lock)
	doc, err := readSessionFile(path)
	if err != nil {
		return err
	}
	before, _ := json.Marshal(doc)
	if err := fn(&doc); err != nil {
		return err
	}
	after, _ := json.Marshal(doc)
	if string(before) == string(after) {
		return nil
	}
	data, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal approval session: %w", err)
	}
	if err := fileutil.WriteFileAtomic(path, append(data, '\n'), 0o600, "session-*.json"); err != nil {
		return fileutil.LabelAtomicError(err, "approval session")
	}
	return nil
}

func readSessionFile(path string) (sessionFile, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return sessionFile{}, nil
	}
	if err != nil {
		return sessionFile{}, fmt.Errorf("read approval session: %w", err)
	}
	if len(data) == 0 {
		return sessionFile{}, nil
	}
	var doc sessionFile
	if err := json.Unmarshal(data, &doc); err != nil {
		return sessionFile{}, fmt.Errorf("parse approval session: %w", err)
	}
	return doc, nil
}

func lockSessionPath(path string) (*os.File, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("create approval session directory: %w", err)
	}
	lockPath := path + ".lock"
	file, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open approval session lock: %w", err)
	}
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("lock approval session: %w", err)
	}
	return file, nil
}

func unlockAndClose(file *os.File) {
	_ = syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
	_ = file.Close()
}

func sessionPath(dir string, sessionID string) string {
	sum := sha256.Sum256([]byte(sessionID))
	return filepath.Join(dir, hex.EncodeToString(sum[:])+".json")
}

func filterLiveGrants(grants []Grant, now time.Time) []Grant {
	out := make([]Grant, 0, len(grants))
	for _, grant := range grants {
		if grant.ExpiresTS == "" {
			out = append(out, grant)
			continue
		}
		expires, err := time.Parse(time.RFC3339, grant.ExpiresTS)
		if err != nil || !now.Before(expires) {
			continue
		}
		out = append(out, grant)
	}
	return out
}

func (s SessionStore) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (g Grant) matcher() Matcher {
	return Matcher{
		Kind:       g.Kind,
		Regex:      g.Regex,
		Prefix:     append([]string(nil), g.Prefix...),
		Promotable: true,
		SourceCmd:  g.SourceCmd,
	}
}
