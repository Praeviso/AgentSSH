package audit

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

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
	DurationMS      int64  `json:"duration_ms"`
	PrevHash        string `json:"prev_hash"`
	Hash            string `json:"hash"`
}

const ZeroHash = "0000000000000000000000000000000000000000000000000000000000000000"

// Store appends and reads an audit JSONL hash chain.
type Store struct {
	Path string
}

// NewStore returns a file-backed audit store.
func NewStore(path string) Store {
	return Store{Path: path}
}

// Append adds one record to the hash chain, assigning seq, prev_hash, and hash.
func (s Store) Append(record Record) (Record, error) {
	if err := os.MkdirAll(filepath.Dir(s.Path), 0o700); err != nil {
		return Record{}, fmt.Errorf("create audit directory: %w", err)
	}

	file, err := os.OpenFile(s.Path, os.O_CREATE|os.O_RDWR|os.O_APPEND, 0o600)
	if err != nil {
		return Record{}, fmt.Errorf("open audit log: %w", err)
	}
	defer func() {
		_ = file.Close()
	}()
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX); err != nil {
		return Record{}, fmt.Errorf("lock audit log: %w", err)
	}
	defer func() {
		_ = syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
	}()

	records, err := readRecords(file)
	if err != nil {
		return Record{}, err
	}
	prevHash := ZeroHash
	if len(records) > 0 {
		last := records[len(records)-1]
		prevHash = last.Hash
		record.Seq = last.Seq + 1
	}
	record.PrevHash = prevHash
	record.Hash = ""
	if record.TS == "" {
		record.TS = time.Now().UTC().Format(time.RFC3339)
	}
	record.Hash = ComputeHash(record)

	line, err := json.Marshal(record)
	if err != nil {
		return Record{}, fmt.Errorf("marshal audit record: %w", err)
	}
	if _, err := file.Write(append(line, '\n')); err != nil {
		return Record{}, fmt.Errorf("append audit record: %w", err)
	}

	return record, nil
}

// ReadAll reads all audit records. A missing audit log is an empty log.
func (s Store) ReadAll() ([]Record, error) {
	file, err := os.Open(s.Path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("open audit log: %w", err)
	}
	defer func() {
		_ = file.Close()
	}()
	return readRecords(file)
}

func readRecords(file *os.File) ([]Record, error) {
	if _, err := file.Seek(0, 0); err != nil {
		return nil, fmt.Errorf("seek audit log: %w", err)
	}
	var records []Record
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		var record Record
		if err := json.Unmarshal(scanner.Bytes(), &record); err != nil {
			return nil, fmt.Errorf("parse audit log: %w", err)
		}
		records = append(records, record)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read audit log: %w", err)
	}
	return records, nil
}

// Verify recalculates the hash chain from the beginning of the log.
func (s Store) Verify() (VerifyResult, error) {
	records, err := s.ReadAll()
	if err != nil {
		return VerifyResult{}, err
	}
	prevHash := ZeroHash
	for i, record := range records {
		if record.Seq != uint64(i) {
			return VerifyResult{OK: false, BrokenSeq: record.Seq, Reason: "seq"}, nil
		}
		if record.PrevHash != prevHash {
			return VerifyResult{OK: false, BrokenSeq: record.Seq, Reason: "prev_hash"}, nil
		}
		if ComputeHash(record) != record.Hash {
			return VerifyResult{OK: false, BrokenSeq: record.Seq, Reason: "hash"}, nil
		}
		prevHash = record.Hash
	}
	return VerifyResult{OK: true, Count: len(records)}, nil
}

// VerifyResult describes audit chain verification.
type VerifyResult struct {
	OK        bool
	Count     int
	BrokenSeq uint64
	Reason    string
}

// Filters narrows audit list results.
type Filters struct {
	Host      string
	SessionID string
	Event     Event
}

// FilterRecords applies host/session/event filters.
func FilterRecords(records []Record, filters Filters) []Record {
	result := make([]Record, 0, len(records))
	for _, record := range records {
		if filters.Host != "" && record.Host != filters.Host {
			continue
		}
		if filters.SessionID != "" && record.SessionID != filters.SessionID {
			continue
		}
		if filters.Event != "" && record.Event != filters.Event {
			continue
		}
		result = append(result, record)
	}
	return result
}

// ComputeOutputSHA256 returns the sha256 of stdout+stderr bytes captured in M2.
func ComputeOutputSHA256(stdout string, stderr string) string {
	sum := sha256.Sum256([]byte(stdout + stderr))
	return hex.EncodeToString(sum[:])
}

// ComputeHash calculates SHA256(prev_hash || canonical_json(record_without_hash)).
func ComputeHash(record Record) string {
	record.Hash = ""
	canonical, err := canonicalJSON(record)
	if err != nil {
		panic(err)
	}
	sum := sha256.Sum256(append([]byte(record.PrevHash), canonical...))
	return hex.EncodeToString(sum[:])
}

type canonicalRecord struct {
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
	DurationMS      int64  `json:"duration_ms"`
	PrevHash        string `json:"prev_hash"`
}

func canonicalJSON(record Record) ([]byte, error) {
	return json.Marshal(canonicalRecord{
		Seq:             record.Seq,
		TS:              record.TS,
		ReqID:           record.ReqID,
		SessionID:       record.SessionID,
		SessionLabel:    record.SessionLabel,
		Event:           record.Event,
		Agent:           record.Agent,
		Skill:           record.Skill,
		Host:            record.Host,
		Cmd:             record.Cmd,
		PolicyAction:    record.PolicyAction,
		PolicyRule:      record.PolicyRule,
		ExitCode:        record.ExitCode,
		OutputSHA256:    record.OutputSHA256,
		OutputTruncated: record.OutputTruncated,
		Redactions:      record.Redactions,
		DurationMS:      record.DurationMS,
		PrevHash:        record.PrevHash,
	})
}
