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

// Context is the resolved session information for a run.
type Context struct {
	ID    string
	Label string
}

// Resolve follows --session, AGENTSSH_SESSION, then current-session pointer.
func (r Resolver) Resolve(explicitID string, label string) (Context, error) {
	if explicitID != "" {
		return Context{ID: explicitID, Label: label}, nil
	}
	if envID := os.Getenv(EnvSession); envID != "" {
		return Context{ID: envID, Label: label}, nil
	}

	clock := r.clock()
	now := clock.Now().UTC()
	pointer, err := readPointer(r.Path)
	if err != nil {
		return Context{}, err
	}
	if pointer.ID != "" && now.Sub(pointer.LastActivity) <= idleWindow {
		return Context{ID: pointer.ID, Label: label}, nil
	}

	newID, err := r.newID()
	if err != nil {
		return Context{}, err
	}
	if err := r.Update(newID, now); err != nil {
		return Context{}, err
	}
	return Context{ID: newID, Label: label}, nil
}

// Update writes the current-session pointer activity time.
func (r Resolver) Update(id string, when time.Time) error {
	if id == "" || r.Path == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(r.Path), 0o700); err != nil {
		return fmt.Errorf("create session directory: %w", err)
	}
	data, err := json.Marshal(pointer{ID: id, LastActivity: when.UTC()})
	if err != nil {
		return fmt.Errorf("marshal session pointer: %w", err)
	}
	if err := os.WriteFile(r.Path, append(data, '\n'), 0o600); err != nil {
		return fmt.Errorf("write session pointer: %w", err)
	}
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

func readPointer(path string) (pointer, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) || path == "" {
		return pointer{}, nil
	}
	if err != nil {
		return pointer{}, fmt.Errorf("read session pointer: %w", err)
	}
	var current pointer
	if err := json.Unmarshal(data, &current); err != nil {
		return pointer{}, fmt.Errorf("parse session pointer: %w", err)
	}
	return current, nil
}

// Summary is one aggregated session row from audit.log.
type Summary struct {
	ID           string
	Label        string
	Start        string
	End          string
	CommandCount int
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
		if summary.Start == "" || record.TS < summary.Start {
			summary.Start = record.TS
		}
		if summary.End == "" || record.TS > summary.End {
			summary.End = record.TS
		}
		if record.ReqID != "" {
			reqsByID[record.SessionID][record.ReqID] = struct{}{}
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
