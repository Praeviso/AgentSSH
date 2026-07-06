package approval

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// A plan bundles the gray-zone commands of one multi-step task into a single
// review unit. Approving a plan mints one ordinary once/session grant per
// command — execution still happens per command through `run` → Authorize, so
// audit granularity and explicit-deny precedence are untouched.

var (
	ErrInvalidPlanID = errors.New("invalid plan id")
	ErrPlanNotFound  = errors.New("plan not found")
	ErrPlanScope     = errors.New("plan approvals support --once or --session only")
	ErrPlanNoPending = errors.New("plan has no pending requests")
	ErrPlansDirUnset = errors.New("plan store directory is not configured")
)

// PlanManifest is the authoritative membership record for one submitted plan,
// written once (O_EXCL) at submit time. Member requests resolve individually
// through the ordinary pending/response stores.
type PlanManifest struct {
	Version   int      `json:"version"`
	ID        string   `json:"id"`
	SessionID string   `json:"session_id"`
	Host      string   `json:"host"`
	TS        string   `json:"ts"`
	MemberIDs []string `json:"member_ids"`
}

// PlanMember pairs one member request with its current resolution status.
type PlanMember struct {
	ApprovalID string          `json:"approval_id"`
	Status     string          `json:"status"` // pending | approved | denied | expired
	Scope      Scope           `json:"scope,omitempty"`
	Request    *PendingRequest `json:"request,omitempty"`
}

// PlanStatus is the aggregate view returned by plan status/wait.
type PlanStatus struct {
	ID        string       `json:"id"`
	SessionID string       `json:"session_id"`
	Host      string       `json:"host"`
	Status    string       `json:"status"` // pending | approved | denied | expired
	Pending   int          `json:"pending"`
	Approved  int          `json:"approved"`
	Denied    int          `json:"denied"`
	Expired   int          `json:"expired,omitempty"`
	Members   []PlanMember `json:"members"`
}

func NewPlanID() (string, error) {
	return newPrefixedID("pl_")
}

func validPlanID(id string) bool {
	return validPrefixedID(id, "pl_")
}

func (s PendingStore) CreatePlan(manifest PlanManifest) (PlanManifest, error) {
	if s.PlansDir == "" {
		return PlanManifest{}, ErrPlansDirUnset
	}
	if manifest.ID == "" {
		id, err := NewPlanID()
		if err != nil {
			return PlanManifest{}, err
		}
		manifest.ID = id
	}
	if !validPlanID(manifest.ID) {
		return PlanManifest{}, ErrInvalidPlanID
	}
	if err := os.MkdirAll(s.PlansDir, 0o700); err != nil {
		return PlanManifest{}, fmt.Errorf("create plan directory: %w", err)
	}
	manifest.Version = 1
	if manifest.TS == "" {
		manifest.TS = s.now().UTC().Format(time.RFC3339)
	}
	data, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return PlanManifest{}, fmt.Errorf("marshal plan manifest: %w", err)
	}
	file, err := os.OpenFile(planPath(s.PlansDir, manifest.ID), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if errors.Is(err, os.ErrExist) {
		return PlanManifest{}, fmt.Errorf("plan id collision %s: %w", manifest.ID, err)
	}
	if err != nil {
		return PlanManifest{}, fmt.Errorf("create plan manifest: %w", err)
	}
	if _, err := file.Write(append(data, '\n')); err != nil {
		_ = file.Close()
		return PlanManifest{}, fmt.Errorf("write plan manifest: %w", err)
	}
	if err := file.Close(); err != nil {
		return PlanManifest{}, fmt.Errorf("close plan manifest: %w", err)
	}
	return manifest, nil
}

func (s PendingStore) GetPlan(id string) (PlanManifest, error) {
	if s.PlansDir == "" {
		return PlanManifest{}, ErrPlansDirUnset
	}
	if !validPlanID(id) {
		return PlanManifest{}, ErrInvalidPlanID
	}
	data, err := os.ReadFile(planPath(s.PlansDir, id))
	if errors.Is(err, os.ErrNotExist) {
		return PlanManifest{}, ErrPlanNotFound
	}
	if err != nil {
		return PlanManifest{}, fmt.Errorf("read plan manifest: %w", err)
	}
	var manifest PlanManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return PlanManifest{}, fmt.Errorf("parse plan manifest: %w", err)
	}
	if manifest.ID != id {
		return PlanManifest{}, fmt.Errorf("plan manifest %s id mismatch", id)
	}
	return manifest, nil
}

// PlanStatus resolves every member's current status. A member whose pending
// file has been reaped after resolution counts as expired — fail-closed, the
// plan never reports approved from unknowable members — but expiry is kept
// distinct from denied so an approved-then-reaped plan is not misreported as
// operator-rejected.
func (s PendingStore) PlanStatus(id string) (PlanStatus, error) {
	manifest, err := s.GetPlan(id)
	if err != nil {
		return PlanStatus{}, err
	}
	status := PlanStatus{ID: manifest.ID, SessionID: manifest.SessionID, Host: manifest.Host}
	for _, memberID := range manifest.MemberIDs {
		member := PlanMember{ApprovalID: memberID, Status: "expired"}
		if result, err := s.Status(memberID); err == nil {
			member.Status = result.Status
			member.Scope = result.Scope
			member.Request = result.Request
		}
		switch member.Status {
		case "approved":
			status.Approved++
		case "denied":
			status.Denied++
		case "expired":
			status.Expired++
		default:
			status.Pending++
		}
		status.Members = append(status.Members, member)
	}
	switch {
	case status.Pending > 0:
		status.Status = "pending"
	case status.Denied > 0:
		status.Status = "denied"
	case status.Expired > 0:
		status.Status = "expired"
	default:
		status.Status = "approved"
	}
	return status, nil
}

// WaitPlan polls until every member is resolved or the timeout elapses,
// mirroring PendingStore.Wait for single approvals.
func (s PendingStore) WaitPlan(id string, timeout time.Duration) (PlanStatus, error) {
	deadline := time.Now().Add(timeout)
	sleep := 50 * time.Millisecond
	for {
		status, err := s.PlanStatus(id)
		if err != nil {
			return PlanStatus{}, err
		}
		if status.Pending == 0 {
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

// ApplyPlanDecision adjudicates every still-pending member of a plan with one
// verdict. Approvals are capped at once/session: host promotion widens policy
// permanently and must stay a deliberate per-command decision.
func ApplyPlanDecision(opts ApplyOptions, id string, verdict Verdict, scope Scope) ([]ApplyResult, error) {
	if verdict == VerdictApproved && scope != ScopeOnce && scope != ScopeSession {
		return nil, ErrPlanScope
	}
	status, err := opts.Pending.PlanStatus(id)
	if err != nil {
		return nil, err
	}
	var results []ApplyResult
	for _, member := range status.Members {
		if member.Status != "pending" {
			continue
		}
		result, err := ApplyDecision(opts, member.ApprovalID, verdict, scope)
		if errors.Is(err, ErrAlreadyResolved) {
			continue
		}
		if err != nil {
			return results, fmt.Errorf("plan %s member %s: %w", id, member.ApprovalID, err)
		}
		results = append(results, result)
	}
	if len(results) == 0 {
		return nil, ErrPlanNoPending
	}
	return results, nil
}

func planPath(dir string, id string) string {
	return filepath.Join(dir, id+".json")
}
