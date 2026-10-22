package runner

import (
	"fmt"
	"slices"

	"github.com/Praeviso/AgentSSH/internal/approval"
	"github.com/Praeviso/AgentSSH/internal/audit"
	"github.com/Praeviso/AgentSSH/internal/session"
)

// PlanCommand is one line of a plan being submitted for approval.
type PlanCommand struct {
	ID         string
	Name       string
	Phase      string
	OnFailure  string
	Cmd        string
	Stdin      Stdin
	PayloadRef string
}

// PlanSubmitRequest submits a plan's commands for one host and session.
type PlanSubmitRequest struct {
	PlanID   string
	Host     string
	Session  session.Context
	Commands []PlanCommand
	// Review carries the execution id, metadata, and any richer step details
	// (from a plan run) to merge into the review manifest.
	Review approval.PlanReview
}

// PlanSubmitLine is one command's preflight result.
type PlanSubmitLine struct {
	Seq         int                      `json:"seq"`
	Cmd         string                   `json:"cmd"`
	Status      string                   `json:"status"` // allowed | denied | approval_pending
	PolicyRule  string                   `json:"policy_rule,omitempty"`
	ApprovalID  string                   `json:"approval_id,omitempty"`
	StdinSHA256 string                   `json:"stdin_sha256,omitempty"`
	StdinBytes  int64                    `json:"stdin_bytes,omitempty"`
	Task        *approval.TaskPermission `json:"task_permission,omitempty"`
}

// PlanSubmitResponse is the result of `plan submit`.
type PlanSubmitResponse struct {
	PlanID       string                `json:"plan_id,omitempty"`
	SessionID    string                `json:"session_id"`
	Host         string                `json:"host"`
	Metadata     approval.PlanMetadata `json:"metadata,omitempty"`
	ReviewSHA256 string                `json:"review_sha256,omitempty"`
	Commands     []PlanSubmitLine      `json:"commands"`
	Allowed      int                   `json:"allowed"`
	Denied       int                   `json:"denied"`
	Pending      int                   `json:"pending"`
}

// SubmitPlan preflights every command without executing or claiming grants:
// allowed commands need nothing, explicit denies are terminal, and gray-zone
// commands become pending requests grouped under one plan manifest. It returns
// the merged exit code (0, 6, or 7) beside the response. The response's PlanID
// is set only when a manifest was created.
func SubmitPlan(env Env, req PlanSubmitRequest) (PlanSubmitResponse, int, error) {
	reviewTemplate := req.Review
	metadata := reviewTemplate.Metadata
	sessionCtx := req.Session

	response := PlanSubmitResponse{SessionID: sessionCtx.ID, Host: req.Host, Metadata: metadata}
	memberIDs := make([]string, 0, len(req.Commands))
	requestedRecords := make([]audit.Record, 0, len(req.Commands))
	reviewSteps := make([]approval.PlanReviewStep, 0, len(req.Commands))
	exitCode := ExitOK
	for i, command := range req.Commands {
		line := PlanSubmitLine{
			Seq:         i + 1,
			Cmd:         command.Cmd,
			StdinSHA256: command.Stdin.SHA256,
			StdinBytes:  command.Stdin.Bytes,
			Task:        approval.TaskCandidate(command.Cmd, command.Stdin.SHA256),
		}
		auth, err := approval.PreflightAuthorize(env.Policy, env.Inventory, env.Sessions, env.Approval, sessionCtx.ID, req.Host, command.Cmd, command.Stdin.SHA256)
		if err != nil {
			return response, exitCode, usageErrorf("policy.yaml is invalid: %v\n  fix the rule in ~/.agentssh/policy.yaml (check: agentssh policy show)", err)
		}
		line.PolicyRule = auth.Decision.Rule
		switch auth.Status {
		case approval.AuthAllow, approval.AuthAllowByGrant:
			line.Status = "allowed"
			response.Allowed++
		case approval.AuthHardDeny:
			line.Status = "denied"
			response.Denied++
			exitCode = MergeExitCode(exitCode, ExitPolicyDenied)
		case approval.AuthNeedsApproval:
			if !env.Approval.Enabled {
				line.Status = "denied"
				response.Denied++
				exitCode = MergeExitCode(exitCode, ExitPolicyDenied)
				break
			}
			reqID, err := env.newReqID()
			if err != nil {
				return response, exitCode, err
			}
			pending, err := env.Pending.Create(approval.PendingRequest{
				ReqID:       reqID,
				SessionID:   sessionCtx.ID,
				Host:        req.Host,
				Cmd:         command.Cmd,
				Candidate:   auth.ApprovalMatcher,
				StdinSHA256: command.Stdin.SHA256,
				StdinBytes:  command.Stdin.Bytes,
				PlanID:      req.PlanID,
				PlanSeq:     i + 1,
				PlanTotal:   len(req.Commands),
			})
			if err != nil {
				return response, exitCode, err
			}
			line.Status = "approval_pending"
			line.ApprovalID = pending.ID
			// Two identical lines share one pending request; the manifest must
			// still list it once.
			if !slices.Contains(memberIDs, pending.ID) {
				memberIDs = append(memberIDs, pending.ID)
			}
			exit := ExitApprovalRequired
			record := baseRecord(reqID, sessionCtx, audit.EventApprovalRequested, req.Host, command.Cmd, auth.Decision, &exit, "", 0)
			record.StdinSHA256 = command.Stdin.SHA256
			record.StdinBytes = command.Stdin.Bytes
			record.ApprovalID = pending.ID
			record.ApprovalMatcher = pending.Candidate.Regex
			record.ApprovalChannel = approval.ChannelPlan
			record.PlanID = req.PlanID
			record.ExecutionID = reviewTemplate.ExecutionID
			record.StepID = command.ID
			requestedRecords = append(requestedRecords, record)
			exitCode = MergeExitCode(exitCode, ExitApprovalRequired)
		default:
			return response, exitCode, fmt.Errorf("unknown approval authorization status %q", auth.Status)
		}
		response.Commands = append(response.Commands, line)
		reviewSteps = append(reviewSteps, approval.PlanReviewStep{
			Seq:               i + 1,
			ID:                command.ID,
			Name:              command.Name,
			Phase:             command.Phase,
			OnFailure:         command.OnFailure,
			Cmd:               command.Cmd,
			Status:            line.Status,
			PolicyRule:        line.PolicyRule,
			ApprovalID:        line.ApprovalID,
			StdinSHA256:       line.StdinSHA256,
			StdinBytes:        line.StdinBytes,
			PayloadRef:        command.PayloadRef,
			PayloadRetained:   command.PayloadRef != "",
			Task:              line.Task,
			AlreadyAuthorized: line.Status == "allowed",
		})
	}

	// Identical lines share one pending request, so count distinct members --
	// otherwise submit reports more approvals than plan status will ever show.
	response.Pending = len(memberIDs)

	if len(memberIDs) > 0 {
		review := approval.PlanReview{
			Version:     1,
			PlanID:      req.PlanID,
			ExecutionID: reviewTemplate.ExecutionID,
			SessionID:   sessionCtx.ID,
			Host:        req.Host,
			Metadata:    metadata,
			Steps:       mergePlanReviewSteps(reviewTemplate.Steps, reviewSteps),
		}
		manifest, err := env.Pending.CreatePlan(approval.PlanManifest{
			ID:          req.PlanID,
			SessionID:   sessionCtx.ID,
			Host:        req.Host,
			ExecutionID: reviewTemplate.ExecutionID,
			Metadata:    metadata,
			Review:      &review,
			MemberIDs:   memberIDs,
		})
		if err != nil {
			return response, exitCode, err
		}
		response.PlanID = manifest.ID
		response.ReviewSHA256 = manifest.ReviewSHA256
		for _, record := range requestedRecords {
			record.ReviewSHA256 = manifest.ReviewSHA256
			if _, err := env.Audit.Append(record); err != nil {
				return response, exitCode, err
			}
		}
	}
	return response, exitCode, nil
}

// mergePlanReviewSteps overlays this round's step results onto a richer
// template (from a plan run), keeping template-only steps in place.
func mergePlanReviewSteps(template []approval.PlanReviewStep, current []approval.PlanReviewStep) []approval.PlanReviewStep {
	if len(template) == 0 {
		return current
	}
	out := append([]approval.PlanReviewStep(nil), template...)
	index := map[string]int{}
	for i, step := range out {
		if step.ID != "" {
			index[step.ID] = i
		}
	}
	for _, step := range current {
		if i, ok := index[step.ID]; ok {
			out[i] = step
			continue
		}
		out = append(out, step)
	}
	for i := range out {
		if out[i].Seq == 0 {
			out[i].Seq = i + 1
		}
	}
	return out
}
