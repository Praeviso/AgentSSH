package remote

import (
	"github.com/Praeviso/AgentSSH/internal/approval"
	"github.com/Praeviso/AgentSSH/internal/runner"
)

// Gateway approval endpoints. A device submits and queries; only the
// gateway's operator decides, so no device endpoint resolves anything.
const (
	// PathApprovalStatus reports one of the device's approval requests.
	PathApprovalStatus = "/approvals/status"
	// PathPlanSubmit preflights a plan and turns its gray-zone commands into
	// approval requests grouped under one manifest, without executing.
	PathPlanSubmit = "/plans/submit"
	// PathPlanStatus reports one of the device's plans.
	PathPlanStatus = "/plans/status"
	// PathAuthorize preflights commands against the gateway's policy and
	// grants, with no side effects.
	PathAuthorize = "/authorize"
)

// MaxPlanCommands bounds one plan submission or authorization query.
const MaxPlanCommands = 1000

// ApprovalStatusRequest names one approval request of the calling device.
type ApprovalStatusRequest struct {
	ApprovalID string `json:"approval_id"`
}

// ApprovalStatusResponse is the request's status, as `approval status`
// prints it, and the device policy's default wait.
type ApprovalStatusResponse struct {
	Status        approval.StatusResult `json:"status"`
	WaitTimeoutMS int64                 `json:"wait_timeout_ms"`
}

// PlanStatusRequest names one plan of the calling device.
type PlanStatusRequest struct {
	PlanID string `json:"plan_id"`
}

// PlanStatusResponse is the plan's status, as `plan status` prints it, and
// the device policy's default wait.
type PlanStatusResponse struct {
	Status        approval.PlanStatus `json:"status"`
	WaitTimeoutMS int64               `json:"wait_timeout_ms"`
}

// PlanSubmitRequest submits a plan for one host and session. The device
// mints PlanID. Commands carry their stdin identity only; the content stays
// on the device until its step runs.
type PlanSubmitRequest struct {
	PlanID       string              `json:"plan_id"`
	Host         string              `json:"host"`
	Session      string              `json:"session"`
	SessionLabel string              `json:"session_label,omitempty"`
	Commands     []PlanSubmitCommand `json:"commands"`
	// Review carries the execution ID, metadata and the steps of a plan run,
	// shown to the operator beside the requests it creates.
	Review approval.PlanReview `json:"review"`
}

// PlanSubmitCommand is one command of a submitted plan.
type PlanSubmitCommand struct {
	ID          string `json:"id,omitempty"`
	Name        string `json:"name,omitempty"`
	Phase       string `json:"phase,omitempty"`
	OnFailure   string `json:"on_failure,omitempty"`
	Cmd         string `json:"cmd"`
	StdinSHA256 string `json:"stdin_sha256,omitempty"`
	StdinBytes  int64  `json:"stdin_bytes,omitempty"`
	PayloadRef  string `json:"payload_ref,omitempty"`
}

// PlanSubmitResult is `plan submit`'s response and its exit code (0, 6 or 7).
type PlanSubmitResult struct {
	Response runner.PlanSubmitResponse `json:"response"`
	ExitCode int                       `json:"exit_code"`
}

// AuthorizeRequest asks how each check would be authorized now.
type AuthorizeRequest struct {
	Checks []AuthorizeCheck `json:"checks"`
}

// AuthorizeCheck is one command for one host in one session.
type AuthorizeCheck struct {
	Host        string `json:"host"`
	Session     string `json:"session"`
	Cmd         string `json:"cmd"`
	StdinSHA256 string `json:"stdin_sha256,omitempty"`
}

// AuthorizeResponse holds one approval.AuthorizationStatus per check, and
// whether the device's policy enables approvals at all.
type AuthorizeResponse struct {
	ApprovalEnabled bool                           `json:"approval_enabled"`
	Results         []approval.AuthorizationStatus `json:"results"`
}
