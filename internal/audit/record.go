package audit

// Event is the audit lifecycle state recorded for a request.
type Event string

const (
	EventStarted   Event = "started"
	EventCompleted Event = "completed"
	EventFailed    Event = "failed"
	EventDenied    Event = "denied"
)

// Record is one append-only JSONL audit entry.
//
// The fields intentionally match docs/architecture/overview.md section 6.
type Record struct {
	Seq             uint64 `json:"seq"`
	TS              string `json:"ts"`
	ReqID           string `json:"req_id"`
	SessionID       string `json:"session_id"`
	SessionLabel    string `json:"session_label"`
	Event           Event  `json:"event"`
	Agent           string `json:"agent"`
	Skill           string `json:"skill"`
	Host            string `json:"host"`
	Cmd             string `json:"cmd"`
	PolicyAction    string `json:"policy_action"`
	PolicyRule      string `json:"policy_rule"`
	ExitCode        *int   `json:"exit_code,omitempty"`
	OutputSHA256    string `json:"output_sha256"`
	OutputTruncated bool   `json:"output_truncated"`
	Redactions      int    `json:"redactions"`
	PrevHash        string `json:"prev_hash"`
	Hash            string `json:"hash"`
}
