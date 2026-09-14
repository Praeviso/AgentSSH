package approval

import (
	"crypto/sha256"
	"encoding/hex"
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
	ErrPlanScope     = errors.New("plan approvals support --once, --session or --task only")
	ErrPlanNoPending = errors.New("plan has no pending requests")
	ErrPlansDirUnset = errors.New("plan store directory is not configured")
	ErrPlanDigest    = errors.New("plan review digest mismatch")
)

type PlanMetadata struct {
	Title       string `json:"title,omitempty" yaml:"title,omitempty"`
	Version     string `json:"version,omitempty" yaml:"version,omitempty"`
	Revision    string `json:"revision,omitempty" yaml:"revision,omitempty"`
	Description string `json:"description,omitempty" yaml:"description,omitempty"`
	Impact      string `json:"impact,omitempty" yaml:"impact,omitempty"`
	Recovery    string `json:"recovery,omitempty" yaml:"recovery,omitempty"`
}

type PlanReview struct {
	Version     int              `json:"version"`
	PlanID      string           `json:"plan_id,omitempty"`
	ExecutionID string           `json:"execution_id,omitempty"`
	SessionID   string           `json:"session_id"`
	Host        string           `json:"host"`
	Metadata    PlanMetadata     `json:"metadata,omitempty"`
	Steps       []PlanReviewStep `json:"steps"`
}

type PlanReviewStep struct {
	Seq               int             `json:"seq"`
	ID                string          `json:"id"`
	Name              string          `json:"name,omitempty"`
	Phase             string          `json:"phase,omitempty"`
	OnFailure         string          `json:"on_failure,omitempty"`
	Cmd               string          `json:"cmd"`
	Status            string          `json:"status"` // allowed | denied | approval_pending
	PolicyRule        string          `json:"policy_rule,omitempty"`
	ApprovalID        string          `json:"approval_id,omitempty"`
	StdinSHA256       string          `json:"stdin_sha256,omitempty"`
	StdinBytes        int64           `json:"stdin_bytes,omitempty"`
	PayloadRef        string          `json:"payload_ref,omitempty"`
	PayloadRetained   bool            `json:"payload_retained,omitempty"`
	Task              *TaskPermission `json:"task_permission,omitempty"`
	AlreadyAuthorized bool            `json:"already_authorized,omitempty"`
}

// PlanManifest is the authoritative membership record for one submitted plan,
// written once (O_EXCL) at submit time. Member requests resolve individually
// through the ordinary pending/response stores.
type PlanManifest struct {
	Version      int          `json:"version"`
	ID           string       `json:"id"`
	SessionID    string       `json:"session_id"`
	Host         string       `json:"host"`
	TS           string       `json:"ts"`
	ExecutionID  string       `json:"execution_id,omitempty"`
	Metadata     PlanMetadata `json:"metadata,omitempty"`
	Review       *PlanReview  `json:"review,omitempty"`
	ReviewSHA256 string       `json:"review_sha256,omitempty"`
	MemberIDs    []string     `json:"member_ids"`
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
	ID           string       `json:"id"`
	SessionID    string       `json:"session_id"`
	Host         string       `json:"host"`
	ExecutionID  string       `json:"execution_id,omitempty"`
	Metadata     PlanMetadata `json:"metadata,omitempty"`
	Review       *PlanReview  `json:"review,omitempty"`
	ReviewSHA256 string       `json:"review_sha256,omitempty"`
	Status       string       `json:"status"` // pending | approved | denied | expired
	Pending      int          `json:"pending"`
	Approved     int          `json:"approved"`
	Denied       int          `json:"denied"`
	Expired      int          `json:"expired,omitempty"`
	Members      []PlanMember `json:"members"`
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
	if manifest.Review != nil {
		manifest.Review.Version = 1
		manifest.Review.PlanID = manifest.ID
		manifest.Review.SessionID = manifest.SessionID
		manifest.Review.Host = manifest.Host
		if manifest.Review.ExecutionID == "" {
			manifest.Review.ExecutionID = manifest.ExecutionID
		}
		if isZeroMetadata(manifest.Review.Metadata) {
			manifest.Review.Metadata = manifest.Metadata
		}
		manifest.ReviewSHA256 = PlanManifestReviewDigest(manifest)
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
	if manifest.Review != nil {
		if manifest.ReviewSHA256 == "" || PlanManifestReviewDigest(manifest) != manifest.ReviewSHA256 || !manifestReviewMatchesEnvelope(manifest) {
			return PlanManifest{}, ErrPlanDigest
		}
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
	status := PlanStatus{ID: manifest.ID, SessionID: manifest.SessionID, Host: manifest.Host, ExecutionID: manifest.ExecutionID, Metadata: manifest.Metadata, Review: manifest.Review, ReviewSHA256: manifest.ReviewSHA256}
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
	if verdict == VerdictApproved && scope != ScopeOnce && scope != ScopeSession && scope != ScopeTask {
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
		memberScope, memberOpts := scope, opts
		memberOpts.PlanID = id
		memberOpts.ReviewSHA256 = status.ReviewSHA256
		memberOpts.ExecutionID = status.ExecutionID
		if member.Request != nil {
			memberOpts.StepID = unambiguousStepID(status.Review, member.Request.ID)
		}
		if scope == ScopeTask && member.Request != nil && TaskCandidate(member.Request.Cmd, member.Request.StdinSHA256) == nil {
			memberScope = ScopeSession
			memberOpts.SessionTTL = opts.TaskTTL
			if memberOpts.SessionTTL <= 0 {
				memberOpts.SessionTTL = DefaultTaskTTL
			}
		}
		result, err := ApplyDecision(memberOpts, member.ApprovalID, verdict, memberScope)
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

func unambiguousStepID(review *PlanReview, approvalID string) string {
	if review == nil || approvalID == "" {
		return ""
	}
	var found string
	for _, step := range review.Steps {
		if step.ApprovalID != approvalID {
			continue
		}
		if found != "" && found != step.ID {
			return ""
		}
		found = step.ID
	}
	return found
}

func planPath(dir string, id string) string {
	return filepath.Join(dir, id+".json")
}

func PlanReviewDigest(review PlanReview) string {
	review.Version = 1
	data, _ := json.Marshal(review)
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func PlanManifestReviewDigest(manifest PlanManifest) string {
	manifest.Version = 1
	manifest.TS = ""
	manifest.ReviewSHA256 = ""
	data, _ := json.Marshal(struct {
		ID          string       `json:"id"`
		SessionID   string       `json:"session_id"`
		Host        string       `json:"host"`
		ExecutionID string       `json:"execution_id,omitempty"`
		Metadata    PlanMetadata `json:"metadata,omitempty"`
		MemberIDs   []string     `json:"member_ids"`
		Review      *PlanReview  `json:"review"`
	}{
		ID: manifest.ID, SessionID: manifest.SessionID, Host: manifest.Host,
		ExecutionID: manifest.ExecutionID, Metadata: manifest.Metadata,
		MemberIDs: append([]string(nil), manifest.MemberIDs...), Review: manifest.Review,
	})
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func manifestReviewMatchesEnvelope(manifest PlanManifest) bool {
	if manifest.Review == nil {
		return true
	}
	review := manifest.Review
	if review.PlanID != manifest.ID || review.SessionID != manifest.SessionID || review.Host != manifest.Host {
		return false
	}
	if !isZeroMetadata(manifest.Metadata) && review.Metadata != manifest.Metadata {
		return false
	}
	want := map[string]bool{}
	for _, id := range manifest.MemberIDs {
		want[id] = true
	}
	got := map[string]bool{}
	for _, step := range review.Steps {
		if step.ApprovalID != "" {
			got[step.ApprovalID] = true
		}
	}
	if len(want) != len(got) {
		return false
	}
	for id := range want {
		if !got[id] {
			return false
		}
	}
	return true
}

func isZeroMetadata(metadata PlanMetadata) bool {
	return metadata == PlanMetadata{}
}
