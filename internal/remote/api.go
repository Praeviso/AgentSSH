package remote

import (
	"encoding/json"
	"time"
)

// The token-device API runs commands with JSON in and out, for callers that
// cannot read /exec's frames or hold a stream open: hosted agent platforms
// time out tool calls and HTTP actions, often within a minute. A call waits a
// bounded time, then answers with the run's state and the output so far; the
// caller continues from next_offset.
const (
	PathAPIRun       = "/api/run"
	PathAPIRunOutput = "/api/run/output"
	PathAPIRunCancel = "/api/run/cancel"
	// PathAPIRequestStatus answers like `agentssh status --json`,
	// PathAPIApprovalStatus like `agentssh approval status`, PathAPISession
	// like `agentssh session new`; PathAPIOpenAPI serves the API's OpenAPI
	// document, without authentication.
	PathAPIRequestStatus  = "/api/request/status"
	PathAPIApprovalStatus = "/api/approval/status"
	PathAPISession        = "/api/session"
	PathAPIOpenAPI        = "/api/openapi.json"
	// PathMCP is the gateway's MCP endpoint (Streamable HTTP): the token API
	// as MCP tools.
	PathMCP = "/mcp"
	// The gateway's OAuth 2.1 authorization server, for MCP clients that
	// connect only through OAuth: registration and tokens under the public
	// URL, authorization on the Web UI, where the operator consents.
	PathOAuthRegister  = "/oauth/register"
	PathOAuthToken     = "/oauth/token"
	PathOAuthAuthorize = "/oauth/authorize"
	// OAuthScope is the one scope a grant carries: the device's MCP tools.
	OAuthScope = "agentssh"

	// DefaultAPIWait is how long a call waits for a run when it names no
	// wait; MaxAPIWait caps any wait.
	DefaultAPIWait = 20 * time.Second
	MaxAPIWait     = 50 * time.Second
)

// APIRunRequest starts a command, or joins the run RunID already names.
type APIRunRequest struct {
	// RunID, when set, is an idempotency key, as for /exec.
	RunID        string `json:"run_id,omitempty"`
	Host         string `json:"host"`
	Command      string `json:"command"`
	Session      string `json:"session"`
	SessionLabel string `json:"session_label,omitempty"`
	// Stdin is base64 in JSON; absent or null means no stdin, "" empty stdin.
	Stdin []byte `json:"stdin,omitempty"`
	// WaitMS is how long to wait for the run before answering: absent means
	// DefaultAPIWait, 0 answers at once, and MaxAPIWait caps it.
	WaitMS *int64 `json:"wait_ms,omitempty"`
}

// APIRunOutputRequest reads a run from Offset (a next_offset it answered).
type APIRunOutputRequest struct {
	RunID  string `json:"run_id"`
	Offset int64  `json:"offset"`
	WaitMS *int64 `json:"wait_ms,omitempty"`
}

// Run states and results in APIRun.
const (
	APIRunRunning  = "running"
	APIRunFinished = "finished"

	APIResultOK               = "ok"
	APIResultFailed           = "failed"
	APIResultDenied           = "denied"
	APIResultApprovalRequired = "approval_required"
	APIResultSSHError         = "ssh_error"
	APIResultUsage            = "usage"
	// APIResultError means the run ended with an error instead of a result;
	// Error says why (for example the gateway stopped it).
	APIResultError = "error"
)

// APIRun is a run as the API answers it: everything since the offset asked
// for, and where to continue.
type APIRun struct {
	RunID string `json:"run_id"`
	ReqID string `json:"req_id,omitempty"`
	State string `json:"state"`
	// Result and ExitCode are set once finished; ExitCode has the CLI's
	// meaning (0, 1, 6 denied, 7 approval required, 9 SSH error), and Result
	// names it.
	Result     string `json:"result,omitempty"`
	ExitCode   *int   `json:"exit_code,omitempty"`
	Truncated  bool   `json:"truncated,omitempty"`
	TargetKind string `json:"target_kind,omitempty"`
	// Stdout and Stderr are the output streamed since the offset, as text
	// (bytes that are not valid UTF-8 read as U+FFFD).
	Stdout string `json:"stdout"`
	Stderr string `json:"stderr"`
	// Responses are the per-target `run --json` objects written since the
	// offset; together they are the run's result, with its complete filtered
	// output.
	Responses []json.RawMessage `json:"responses"`
	Error     *ErrorResponse    `json:"error,omitempty"`
	// NextOffset is where the next read continues, so every byte arrives once.
	NextOffset int64 `json:"next_offset"`
}

// APIResult names an exit code.
func APIResult(exitCode int) string {
	switch exitCode {
	case 0:
		return APIResultOK
	case 2:
		return APIResultUsage
	case 6:
		return APIResultDenied
	case 7:
		return APIResultApprovalRequired
	case 9:
		return APIResultSSHError
	}
	return APIResultFailed
}

// APIApprovalStatusRequest asks for an approval request's status, waiting up
// to WaitMS (as for runs) while it is still pending.
type APIApprovalStatusRequest struct {
	ApprovalID string `json:"approval_id"`
	WaitMS     *int64 `json:"wait_ms,omitempty"`
}

// APISession is a fresh session ID, as `agentssh session new` prints one.
type APISession struct {
	SessionID string `json:"session_id"`
}
