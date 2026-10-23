package runner

import (
	"crypto/sha256"
	"encoding/hex"
	"unicode/utf8"

	"github.com/Praeviso/AgentSSH/internal/approval"
	"github.com/Praeviso/AgentSSH/internal/audit"
)

// Response is one target's result, in the shape of `run --json`.
type Response struct {
	ExecutionState  string                   `json:"execution_state"`
	NextAction      string                   `json:"next_action,omitempty"`
	GrantScope      string                   `json:"grant_scope,omitempty"`
	GrantExpiresTS  string                   `json:"grant_expires_ts,omitempty"`
	Task            *approval.TaskPermission `json:"task_permission,omitempty"`
	ReqID           string                   `json:"req_id"`
	SessionID       string                   `json:"session_id"`
	Host            string                   `json:"host"`
	Cmd             string                   `json:"cmd,omitempty"`
	CmdSHA256       string                   `json:"cmd_sha256,omitempty"`
	CmdTruncated    bool                     `json:"cmd_truncated,omitempty"`
	StdinSHA256     string                   `json:"stdin_sha256,omitempty"`
	StdinBytes      int64                    `json:"stdin_bytes,omitempty"`
	Status          string                   `json:"status"`
	ExitCode        int                      `json:"exit_code"`
	DurationMS      int64                    `json:"duration_ms"`
	Stdout          string                   `json:"stdout"`
	Stderr          string                   `json:"stderr"`
	OutputTruncated bool                     `json:"output_truncated"`
	Redactions      int                      `json:"redactions"`
	PolicyAction    string                   `json:"policy_action,omitempty"`
	PolicyRule      string                   `json:"policy_rule,omitempty"`
	ApprovalID      string                   `json:"approval_id,omitempty"`
	ApprovalMatcher string                   `json:"approval_matcher,omitempty"`
	ProposedScopes  []string                 `json:"proposed_scope,omitempty"`
	ApprovalReason  string                   `json:"approval_reason,omitempty"`
	ExecutionID     string                   `json:"execution_id,omitempty"`
	StepID          string                   `json:"step_id,omitempty"`
	ReviewSHA256    string                   `json:"review_sha256,omitempty"`
}

// CmdEchoMaxBytes caps the command echoed back in responses. The full command
// stays in the audit log; callers that need to correlate use cmd_sha256.
const CmdEchoMaxBytes = 2048

// Finalize derives execution_state and next_action from each status, stamps
// cmd_sha256 (of the full command), truncates oversized cmd echoes so a large
// command payload is not mirrored back verbatim, and stamps the stdin identity
// on every response so all status branches carry the same fields.
//
// It is not idempotent: a second pass would hash the truncated echo. Run
// finalizes its responses exactly once.
func Finalize(responses []Response, stdin Stdin) {
	for i := range responses {
		switch responses[i].Status {
		case "completed", "failed":
			responses[i].ExecutionState = "finished"
		case "ssh_error":
			responses[i].ExecutionState = "unknown"
			responses[i].NextAction = "inspect_before_retry"
		default:
			responses[i].ExecutionState = "not_started"
		}
		if responses[i].Status == "approval_pending" {
			responses[i].NextAction = "wait_for_approval"
		}
		if responses[i].Status == "denied" {
			responses[i].NextAction = "stop"
		}
		responses[i].StdinSHA256 = stdin.SHA256
		responses[i].StdinBytes = stdin.Bytes
		if responses[i].Cmd == "" {
			continue
		}
		sum := sha256.Sum256([]byte(responses[i].Cmd))
		responses[i].CmdSHA256 = hex.EncodeToString(sum[:])
		if len(responses[i].Cmd) > CmdEchoMaxBytes {
			cut := CmdEchoMaxBytes
			for cut > 0 && !utf8.RuneStart(responses[i].Cmd[cut]) {
				cut--
			}
			responses[i].Cmd = responses[i].Cmd[:cut]
			responses[i].CmdTruncated = true
		}
	}
}

// RequestStatus summarizes the latest of records for reqID, as
// `agentssh status --json` prints it. It reports false when no record has
// that request ID.
func RequestStatus(records []audit.Record, reqID string) (Response, bool) {
	var latest *audit.Record
	for i := range records {
		if records[i].ReqID == reqID {
			latest = &records[i]
		}
	}
	if latest == nil {
		return Response{}, false
	}
	exitCode := 0
	if latest.ExitCode != nil {
		exitCode = *latest.ExitCode
	} else if latest.Event == audit.EventDenied {
		exitCode = ExitPolicyDenied
	}
	return Response{
		ReqID:           latest.ReqID,
		SessionID:       latest.SessionID,
		Host:            latest.Host,
		Cmd:             latest.Cmd,
		Status:          string(latest.Event),
		ExitCode:        exitCode,
		DurationMS:      latest.DurationMS,
		OutputTruncated: latest.OutputTruncated,
		Redactions:      latest.Redactions,
		PolicyAction:    latest.PolicyAction,
		PolicyRule:      latest.PolicyRule,
		ExecutionID:     latest.ExecutionID,
		StepID:          latest.StepID,
		ReviewSHA256:    latest.ReviewSHA256,
	}, true
}
