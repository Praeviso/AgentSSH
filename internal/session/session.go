package session

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"sort"

	"github.com/Praeviso/AgentSSH/internal/audit"
)

const EnvSession = "AGENTSSH_SESSION"

// ErrNoSession is returned when a run declares no session id. Sessions are
// caller-declared so each task maps to exactly one session that audit can review as
// a unit. AgentSSH never infers task boundaries from time (two unrelated tasks on
// the same host minutes apart would merge), so a missing id is a hard error, not a
// guess — see docs/architecture/overview.md §6.1.
var ErrNoSession = errors.New("no session declared (pass --session or set AGENTSSH_SESSION)")

// Resolver resolves the session id for a run. It holds no state: a session is
// whatever the caller declares, nothing is persisted between runs.
type Resolver struct{}

// Context is the resolved session information for a run. Callers that fan out
// across multiple hosts must derive a host-specific ID before writing audit
// records, so one stored session id stays bound to one host.
type Context struct {
	ID    string
	Host  string
	Label string
}

// Resolve binds a session id to host from --session or AGENTSSH_SESSION. A run MUST
// declare one so logically distinct tasks never merge into a single audit session;
// absent both, Resolve returns ErrNoSession rather than inventing or resuming an id.
// The explicit flag wins over the env var so a single task can override a harness's
// ambient session for one run.
func (r Resolver) Resolve(host string, explicitID string, label string) (Context, error) {
	if explicitID != "" {
		return Context{ID: explicitID, Host: host, Label: label}, nil
	}
	if envID := os.Getenv(EnvSession); envID != "" {
		return Context{ID: envID, Host: host, Label: label}, nil
	}
	return Context{}, ErrNoSession
}

// NewID creates a short random session id (e.g. "s_1a2b3c4d"). Callers that need a
// fresh per-task id — `agentssh session new`, a harness — use this to mint one.
func NewID() (string, error) {
	var bytes [4]byte
	if _, err := rand.Read(bytes[:]); err != nil {
		return "", fmt.Errorf("generate session id: %w", err)
	}
	return "s_" + hex.EncodeToString(bytes[:]), nil
}

// Summary is one aggregated session row from audit.log. Host is scalar because
// new run paths write one stored session id per host; legacy multi-host audit
// data resolves to the first host seen for that session id.
type Summary struct {
	ID           string
	Label        string
	Host         string // the host this session is bound to (first non-empty seen)
	Start        string
	End          string
	CommandCount int
	Denied       int // count of policy-denied events in the session
	Failed       int // count of failed events in the session
}

// Summaries groups audit records by session id.
func Summaries(records []audit.Record) []Summary {
	byID := map[string]*Summary{}
	reqsByID := map[string]map[string]struct{}{}
	for _, record := range records {
		if record.SessionID == "" {
			continue
		}
		summary := byID[record.SessionID]
		if summary == nil {
			summary = &Summary{ID: record.SessionID, Start: record.TS, End: record.TS}
			byID[record.SessionID] = summary
			reqsByID[record.SessionID] = map[string]struct{}{}
		}
		if record.SessionLabel != "" {
			summary.Label = record.SessionLabel
		}
		if record.Host != "" && summary.Host == "" {
			summary.Host = record.Host
		}
		if summary.Start == "" || record.TS < summary.Start {
			summary.Start = record.TS
		}
		if summary.End == "" || record.TS > summary.End {
			summary.End = record.TS
		}
		if record.ReqID != "" {
			reqsByID[record.SessionID][record.ReqID] = struct{}{}
		}
		switch record.Event {
		case audit.EventDenied:
			summary.Denied++
		case audit.EventFailed:
			summary.Failed++
		}
	}

	result := make([]Summary, 0, len(byID))
	for id, summary := range byID {
		summary.CommandCount = len(reqsByID[id])
		result = append(result, *summary)
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].End != result[j].End {
			return result[i].End > result[j].End
		}
		return result[i].ID < result[j].ID
	})
	return result
}
