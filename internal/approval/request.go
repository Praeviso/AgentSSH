package approval

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

type PendingStore struct {
	PendingDir   string
	ResponsesDir string
	Now          func() time.Time
}

const resolvedReapTTL = 24 * time.Hour

type PendingRequest struct {
	Version        int     `json:"version"`
	ID             string  `json:"id"`
	ReqID          string  `json:"req_id"`
	SessionID      string  `json:"session_id"`
	Host           string  `json:"host"`
	Cmd            string  `json:"cmd"`
	CmdSHA256      string  `json:"cmd_sha256"`
	Candidate      Matcher `json:"candidate_matcher"`
	MatcherSHA256  string  `json:"matcher_sha256"`
	Kind           string  `json:"kind"`
	Promotable     bool    `json:"promotable"`
	TS             string  `json:"ts"`
	ProposedScopes []Scope `json:"proposed_scope"`
}

type Resolution struct {
	Version   int     `json:"version"`
	ID        string  `json:"id"`
	ReqDigest string  `json:"req_digest"`
	Verdict   Verdict `json:"verdict"`
	Scope     Scope   `json:"scope,omitempty"`
	TS        string  `json:"ts"`
}

type StatusResult struct {
	ID      string          `json:"id"`
	Verdict Verdict         `json:"verdict,omitempty"`
	Scope   Scope           `json:"scope,omitempty"`
	Status  string          `json:"status"`
	Request *PendingRequest `json:"request,omitempty"`
}

var (
	ErrInvalidID         = errors.New("invalid approval id")
	ErrPendingNotFound   = errors.New("approval request not found")
	ErrAlreadyResolved   = errors.New("approval request already resolved")
	ErrCorruptResolution = errors.New("corrupt approval resolution")
)

func NewID() (string, error) {
	var bytes [12]byte
	if _, err := rand.Read(bytes[:]); err != nil {
		return "", fmt.Errorf("generate approval id: %w", err)
	}
	return "ap_" + hex.EncodeToString(bytes[:]), nil
}

func (s PendingStore) Create(req PendingRequest) (PendingRequest, error) {
	_ = s.reapResolved(resolvedReapTTL)
	if existing, ok, err := s.findUnresolved(req.SessionID, req.Host, shaHex(req.Cmd)); err != nil {
		return PendingRequest{}, err
	} else if ok {
		return existing, nil
	}
	if req.ID == "" {
		id, err := NewID()
		if err != nil {
			return PendingRequest{}, err
		}
		req.ID = id
	}
	if !validApprovalID(req.ID) {
		return PendingRequest{}, ErrInvalidID
	}
	if err := os.MkdirAll(s.PendingDir, 0o700); err != nil {
		return PendingRequest{}, fmt.Errorf("create pending approval directory: %w", err)
	}
	now := s.now().UTC()
	req.Version = 1
	req.CmdSHA256 = shaHex(req.Cmd)
	req.MatcherSHA256 = req.Candidate.SHA256()
	req.Kind = string(req.Candidate.Kind)
	req.Promotable = req.Candidate.Promotable
	if req.TS == "" {
		req.TS = now.Format(time.RFC3339)
	}
	if len(req.ProposedScopes) == 0 {
		req.ProposedScopes = proposedScopes(req.Candidate)
	}
	data, err := json.MarshalIndent(req, "", "  ")
	if err != nil {
		return PendingRequest{}, fmt.Errorf("marshal pending approval: %w", err)
	}
	path := pendingPath(s.PendingDir, req.ID)
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if errors.Is(err, os.ErrExist) {
		return PendingRequest{}, fmt.Errorf("approval id collision %s: %w", req.ID, err)
	}
	if err != nil {
		return PendingRequest{}, fmt.Errorf("create pending approval: %w", err)
	}
	if _, err := file.Write(append(data, '\n')); err != nil {
		_ = file.Close()
		return PendingRequest{}, fmt.Errorf("write pending approval: %w", err)
	}
	if err := file.Close(); err != nil {
		return PendingRequest{}, fmt.Errorf("close pending approval: %w", err)
	}
	return req, nil
}

func (s PendingStore) Get(id string) (PendingRequest, error) {
	if !validApprovalID(id) {
		return PendingRequest{}, ErrInvalidID
	}
	data, err := os.ReadFile(pendingPath(s.PendingDir, id))
	if errors.Is(err, os.ErrNotExist) {
		return PendingRequest{}, ErrPendingNotFound
	}
	if err != nil {
		return PendingRequest{}, fmt.Errorf("read pending approval: %w", err)
	}
	var req PendingRequest
	if err := json.Unmarshal(data, &req); err != nil {
		return PendingRequest{}, fmt.Errorf("parse pending approval: %w", err)
	}
	if req.ID != id || req.MatcherSHA256 != req.Candidate.SHA256() || req.CmdSHA256 != shaHex(req.Cmd) {
		return PendingRequest{}, fmt.Errorf("pending approval %s digest mismatch", id)
	}
	return req, nil
}

func (s PendingStore) List() ([]PendingRequest, error) {
	_ = s.reapResolved(resolvedReapTTL)
	entries, err := os.ReadDir(s.PendingDir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("list pending approvals: %w", err)
	}
	var out []PendingRequest
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		id := strings.TrimSuffix(entry.Name(), ".json")
		req, err := s.Get(id)
		if err != nil {
			continue
		}
		if status, err := s.Status(id); err == nil && status.Status != "pending" {
			continue
		}
		out = append(out, req)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].TS != out[j].TS {
			return out[i].TS < out[j].TS
		}
		return out[i].ID < out[j].ID
	})
	return out, nil
}

func (s PendingStore) Resolve(req PendingRequest, verdict Verdict, scope Scope) (Resolution, error) {
	if !validApprovalID(req.ID) {
		return Resolution{}, ErrInvalidID
	}
	if err := os.MkdirAll(s.ResponsesDir, 0o700); err != nil {
		return Resolution{}, fmt.Errorf("create approval response directory: %w", err)
	}
	resolution := Resolution{
		Version:   1,
		ID:        req.ID,
		ReqDigest: RequestDigest(req, scope),
		Verdict:   verdict,
		Scope:     scope,
		TS:        s.now().UTC().Format(time.RFC3339),
	}
	data, err := json.MarshalIndent(resolution, "", "  ")
	if err != nil {
		return Resolution{}, fmt.Errorf("marshal approval response: %w", err)
	}
	path := responsePath(s.ResponsesDir, req.ID)
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if errors.Is(err, os.ErrExist) {
		return Resolution{}, ErrAlreadyResolved
	}
	if err != nil {
		return Resolution{}, fmt.Errorf("create approval response: %w", err)
	}
	if _, err := file.Write(append(data, '\n')); err != nil {
		_ = file.Close()
		return Resolution{}, fmt.Errorf("write approval response: %w", err)
	}
	if err := file.Close(); err != nil {
		return Resolution{}, fmt.Errorf("close approval response: %w", err)
	}
	return resolution, nil
}

func (s PendingStore) Status(id string) (StatusResult, error) {
	req, err := s.Get(id)
	if err != nil {
		return StatusResult{}, err
	}
	resolution, ok, err := s.readResolution(id)
	if err != nil {
		return StatusResult{}, err
	}
	if !ok || resolution.ReqDigest != RequestDigest(req, resolution.Scope) {
		return StatusResult{ID: id, Status: "pending", Request: &req}, nil
	}
	switch resolution.Verdict {
	case VerdictApproved:
		return StatusResult{ID: id, Status: "approved", Verdict: resolution.Verdict, Scope: resolution.Scope, Request: &req}, nil
	case VerdictDenied:
		return StatusResult{ID: id, Status: "denied", Verdict: resolution.Verdict, Scope: resolution.Scope, Request: &req}, nil
	default:
		return StatusResult{ID: id, Status: "pending", Request: &req}, nil
	}
}

func (s PendingStore) Wait(id string, timeout time.Duration) (StatusResult, error) {
	deadline := time.Now().Add(timeout)
	sleep := 50 * time.Millisecond
	for {
		status, err := s.Status(id)
		if err != nil {
			return StatusResult{}, err
		}
		if status.Status == "approved" || status.Status == "denied" {
			return status, nil
		}
		if !time.Now().Before(deadline) {
			return status, nil
		}
		time.Sleep(sleep)
		if sleep < 500*time.Millisecond {
			sleep *= 2
		}
	}
}

func (s PendingStore) readResolution(id string) (Resolution, bool, error) {
	data, err := os.ReadFile(responsePath(s.ResponsesDir, id))
	if errors.Is(err, os.ErrNotExist) {
		return Resolution{}, false, nil
	}
	if err != nil {
		return Resolution{}, false, fmt.Errorf("read approval response: %w", err)
	}
	var resolution Resolution
	if err := json.Unmarshal(data, &resolution); err != nil {
		return Resolution{}, false, fmt.Errorf("%w for %s", ErrCorruptResolution, id)
	}
	if resolution.ID != id {
		return Resolution{}, false, fmt.Errorf("%w for %s", ErrCorruptResolution, id)
	}
	return resolution, true, nil
}

func (s PendingStore) findUnresolved(sessionID string, host string, cmdSHA256 string) (PendingRequest, bool, error) {
	entries, err := os.ReadDir(s.PendingDir)
	if errors.Is(err, os.ErrNotExist) {
		return PendingRequest{}, false, nil
	}
	if err != nil {
		return PendingRequest{}, false, fmt.Errorf("list pending approvals: %w", err)
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		id := strings.TrimSuffix(entry.Name(), ".json")
		req, err := s.Get(id)
		if err != nil {
			continue
		}
		if req.SessionID != sessionID || req.Host != host || req.CmdSHA256 != cmdSHA256 {
			continue
		}
		if _, ok, err := s.readResolution(id); err != nil {
			continue
		} else if !ok {
			return req, true, nil
		}
	}
	return PendingRequest{}, false, nil
}

func (s PendingStore) reapResolved(ttl time.Duration) error {
	if ttl <= 0 {
		return nil
	}
	entries, err := os.ReadDir(s.PendingDir)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("list pending approvals: %w", err)
	}
	cutoff := s.now().Add(-ttl)
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		id := strings.TrimSuffix(entry.Name(), ".json")
		if _, ok, err := s.readResolution(id); err != nil || !ok {
			continue
		}
		pendingPath := pendingPath(s.PendingDir, id)
		info, err := os.Stat(pendingPath)
		if err != nil {
			continue
		}
		if info.ModTime().After(cutoff) {
			continue
		}
		_ = os.Remove(pendingPath)
		_ = os.Remove(responsePath(s.ResponsesDir, id))
	}
	return nil
}

func RequestDigest(req PendingRequest, scope Scope) string {
	parts := []string{req.ID, req.ReqID, req.SessionID, req.Host, req.CmdSHA256, req.MatcherSHA256, string(scope)}
	sum := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return hex.EncodeToString(sum[:])
}

func proposedScopes(matcher Matcher) []Scope {
	scopes := []Scope{ScopeOnce, ScopeSession}
	if matcher.Promotable {
		scopes = append(scopes, ScopeHost)
	}
	return scopes
}

func validApprovalID(id string) bool {
	if !strings.HasPrefix(id, "ap_") || len(id) < len("ap_")+24 {
		return false
	}
	for _, r := range id[len("ap_"):] {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return false
		}
	}
	return true
}

func pendingPath(dir string, id string) string {
	return filepath.Join(dir, id+".json")
}

func responsePath(dir string, id string) string {
	return filepath.Join(dir, id+".json")
}

func shaHex(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func (s PendingStore) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}
