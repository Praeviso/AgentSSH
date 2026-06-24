package session

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/Praeviso/AgentSSH/internal/audit"
)

const EnvSession = "AGENTSSH_SESSION"

const idleWindow = 30 * time.Minute

// Clock supplies the current time for deterministic tests.
type Clock interface {
	Now() time.Time
}

type realClock struct{}

func (realClock) Now() time.Time {
	return time.Now().UTC()
}

// Resolver resolves the session id for a run.
type Resolver struct {
	Path  string
	Clock Clock
	NewID func() (string, error)
}

// Context is the resolved session information for a run. A session is bound to
// exactly one host: Host records which host this session id belongs to, so a
// session never spans more than one target.
type Context struct {
	ID    string
	Host  string
	Label string
}

// Resolve binds a session id to host, following --session, AGENTSSH_SESSION, then
// the per-host current-session pointer. The pointer is keyed by host so resuming
// within the idle window never crosses hosts — a run against a different host
// always gets that host's own session, enforcing one-session-per-host.
func (r Resolver) Resolve(host string, explicitID string, label string) (Context, error) {
	if explicitID != "" {
		return Context{ID: explicitID, Host: host, Label: label}, nil
	}
	if envID := os.Getenv(EnvSession); envID != "" {
		return Context{ID: envID, Host: host, Label: label}, nil
	}

	clock := r.clock()
	now := clock.Now().UTC()
	pointers, err := readPointers(r.Path)
	if err != nil {
		return Context{}, err
	}
	if current, ok := pointers.Hosts[host]; ok && current.ID != "" && now.Sub(current.LastActivity) <= idleWindow {
		return Context{ID: current.ID, Host: host, Label: label}, nil
	}

	newID, err := r.newID()
	if err != nil {
		return Context{}, err
	}
	if err := r.Update(host, newID, now); err != nil {
		return Context{}, err
	}
	return Context{ID: newID, Host: host, Label: label}, nil
}

// Update writes the current-session pointer activity time for host.
func (r Resolver) Update(host string, id string, when time.Time) error {
	if id == "" || host == "" || r.Path == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(r.Path), 0o700); err != nil {
		return fmt.Errorf("create session directory: %w", err)
	}
	current, err := readPointers(r.Path)
	if err != nil {
		return err
	}
	if current.Hosts == nil {
		current.Hosts = map[string]pointer{}
	}
	current.Hosts[host] = pointer{ID: id, LastActivity: when.UTC()}
	data, err := json.Marshal(current)
	if err != nil {
		return fmt.Errorf("marshal session pointer: %w", err)
	}
	// Write atomically (temp + rename) so a concurrent or interrupted write can't
	// leave a torn file that readPointers would treat as empty — that would reset
	// every host's pointer at once. The residual read-modify-write race between
	// two processes can still lose an update, but the cost is only a fresh session
	// for one host (pointers are ephemeral), never a corrupt file.
	return writeFileAtomic(r.Path, append(data, '\n'))
}

func writeFileAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	file, err := os.CreateTemp(dir, "session-*.tmp")
	if err != nil {
		return fmt.Errorf("create temporary session file: %w", err)
	}
	tempName := file.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tempName)
		}
	}()
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		return fmt.Errorf("chmod temporary session file: %w", err)
	}
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		return fmt.Errorf("write session pointer: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close temporary session file: %w", err)
	}
	if err := os.Rename(tempName, path); err != nil {
		return fmt.Errorf("replace session pointer: %w", err)
	}
	cleanup = false
	return nil
}

func (r Resolver) clock() Clock {
	if r.Clock != nil {
		return r.Clock
	}
	return realClock{}
}

func (r Resolver) newID() (string, error) {
	if r.NewID != nil {
		return r.NewID()
	}
	return NewID()
}

// NewID creates a short random session id.
func NewID() (string, error) {
	var bytes [4]byte
	if _, err := rand.Read(bytes[:]); err != nil {
		return "", fmt.Errorf("generate session id: %w", err)
	}
	return "s_" + hex.EncodeToString(bytes[:]), nil
}

type pointer struct {
	ID           string    `json:"id"`
	LastActivity time.Time `json:"last_activity"`
}

// pointers is the on-disk current-session file: a per-host map so each host
// tracks its own active session id independently.
type pointers struct {
	Hosts map[string]pointer `json:"hosts"`
}

// readPointers loads the per-host pointer file. A missing file is an empty set.
// A file in the legacy single-pointer format (no "hosts" key) is treated as
// empty: sessions are ephemeral (30-min idle window), so starting fresh is
// harmless and avoids binding a pre-existing global session to a host.
func readPointers(path string) (pointers, error) {
	if path == "" {
		return pointers{}, nil
	}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return pointers{}, nil
	}
	if err != nil {
		return pointers{}, fmt.Errorf("read session pointer: %w", err)
	}
	var current pointers
	if err := json.Unmarshal(data, &current); err != nil {
		// Unparseable (or legacy single-pointer) file: start fresh rather than fail.
		return pointers{}, nil
	}
	return current, nil
}

// Summary is one aggregated session row from audit.log. A session is bound to a
// single host (see Context.Host), so Host is scalar; legacy multi-host audit
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
		return result[i].End > result[j].End
	})
	return result
}
