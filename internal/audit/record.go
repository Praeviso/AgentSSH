package audit

import (
	"bufio"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

// Event is the audit lifecycle state recorded for a request.
type Event string

const (
	EventStarted           Event = "started"
	EventCompleted         Event = "completed"
	EventFailed            Event = "failed"
	EventDenied            Event = "denied"
	EventApprovalRequested Event = "approval_requested"
	EventApprovalGranted   Event = "approval_granted"
	EventApprovalDenied    Event = "approval_denied"
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
	Host            string `json:"host"`
	Cmd             string `json:"cmd"`
	PolicyAction    string `json:"policy_action"`
	PolicyRule      string `json:"policy_rule"`
	Error           string `json:"error,omitempty"`
	ExitCode        *int   `json:"exit_code,omitempty"`
	OutputSHA256    string `json:"output_sha256"`
	OutputTruncated bool   `json:"output_truncated"`
	Redactions      int    `json:"redactions"`
	DurationMS      int64  `json:"duration_ms"`
	PrevHash        string `json:"prev_hash"`
	Hash            string `json:"hash"`
	ApprovalID      string `json:"approval_id,omitempty"`
	ApprovalScope   string `json:"approval_scope,omitempty"`
	ApprovalMatcher string `json:"approval_matcher,omitempty"`
	ApprovalChannel string `json:"approval_channel,omitempty"`
	// StdinSHA256/StdinBytes record the stdin payload fed to the remote command
	// (content stays out of the log). Appended after the approval fields with
	// omitempty so pre-stdin records keep a byte-identical canonical form.
	StdinSHA256 string `json:"stdin_sha256,omitempty"`
	StdinBytes  int64  `json:"stdin_bytes,omitempty"`
	// PlanID links approval lifecycle events minted by one `plan submit`.
	PlanID string `json:"plan_id,omitempty"`
}

const ZeroHash = "0000000000000000000000000000000000000000000000000000000000000000"

// maxAuditLineBytes bounds a single JSONL record when reading the log. It sits
// well above a worst-case record (a ~128 KiB command plus JSON escaping and the
// surrounding fields) so the scanner never truncates a line the writer emitted.
const maxAuditLineBytes = 8 << 20

// Store appends and reads an audit JSONL hash chain.
type Store struct {
	Path string
}

// NewStore returns a file-backed audit store.
func NewStore(path string) Store {
	return Store{Path: path}
}

// NewReqID returns a short request id for auditable local operations.
func NewReqID() (string, error) {
	var bytes [3]byte
	if _, err := rand.Read(bytes[:]); err != nil {
		return "", fmt.Errorf("generate request id: %w", err)
	}
	return hex.EncodeToString(bytes[:]), nil
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
	// A record embeds the full command, which can approach the local execve
	// argument limit (~128 KiB) before JSON escaping. The default 64 KiB scanner
	// token cap would fail to read such a line — breaking append (which re-reads
	// the log to chain) and verify. Raise the cap well above any accepted record.
	scanner.Buffer(make([]byte, 0, 64*1024), maxAuditLineBytes)
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

func writeRecordsAtomic(path string, records []Record) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create audit directory: %w", err)
	}
	file, err := os.CreateTemp(dir, "audit-*.log")
	if err != nil {
		return fmt.Errorf("create temporary audit log: %w", err)
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
		return fmt.Errorf("chmod temporary audit log: %w", err)
	}
	for _, record := range records {
		line, err := json.Marshal(record)
		if err != nil {
			_ = file.Close()
			return fmt.Errorf("marshal audit record: %w", err)
		}
		if _, err := file.Write(append(line, '\n')); err != nil {
			_ = file.Close()
			return fmt.Errorf("write audit record: %w", err)
		}
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close temporary audit log: %w", err)
	}
	if err := os.Rename(tempName, path); err != nil {
		return fmt.Errorf("replace audit log: %w", err)
	}
	cleanup = false
	return nil
}

func copyFileIfExists(src string, dst string) error {
	data, err := os.ReadFile(src)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read audit backup source: %w", err)
	}
	if err := os.WriteFile(dst, data, 0o600); err != nil {
		return fmt.Errorf("write audit backup: %w", err)
	}
	return nil
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
			return VerifyResult{OK: false, BrokenSeq: record.Seq, BrokenIndex: i, Reason: "seq"}, nil
		}
		if record.PrevHash != prevHash {
			return VerifyResult{OK: false, BrokenSeq: record.Seq, BrokenIndex: i, Reason: "prev_hash"}, nil
		}
		if ComputeHash(record) != record.Hash {
			return VerifyResult{OK: false, BrokenSeq: record.Seq, BrokenIndex: i, Reason: "hash"}, nil
		}
		prevHash = record.Hash
	}
	return VerifyResult{OK: true, Count: len(records)}, nil
}

// VerifyResult describes audit chain verification.
type VerifyResult struct {
	OK          bool
	Count       int
	BrokenSeq   uint64
	BrokenIndex int
	Reason      string
}

// RepairResult describes a destructive audit-log repair.
type RepairResult struct {
	Changed     bool
	Kept        int
	Removed     int
	BrokenSeq   uint64
	BrokenIndex int
	Reason      string
	BackupPath  string
}

// TruncateBroken removes the first broken record and every later record.
//
// This is intentionally narrower than arbitrary audit deletion: after a hash
// chain break, later records no longer have independently verifiable ancestry.
func (s Store) TruncateBroken() (RepairResult, error) {
	records, err := s.ReadAll()
	if err != nil {
		return RepairResult{}, err
	}
	result, err := s.Verify()
	if err != nil {
		return RepairResult{}, err
	}
	if result.OK {
		return RepairResult{Changed: false, Kept: len(records)}, nil
	}
	cut := result.BrokenIndex
	if cut < 0 || cut > len(records) {
		cut = len(records)
	}
	backup := s.Path + ".bak"
	if err := copyFileIfExists(s.Path, backup); err != nil {
		return RepairResult{}, err
	}
	if err := writeRecordsAtomic(s.Path, records[:cut]); err != nil {
		return RepairResult{}, err
	}
	return RepairResult{
		Changed:     true,
		Kept:        cut,
		Removed:     len(records) - cut,
		BrokenSeq:   result.BrokenSeq,
		BrokenIndex: result.BrokenIndex,
		Reason:      result.Reason,
		BackupPath:  backup,
	}, nil
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
		if filters.SessionID != "" && !sessionIDMatches(record.SessionID, filters.SessionID) {
			continue
		}
		if filters.Event != "" && record.Event != filters.Event {
			continue
		}
		result = append(result, record)
	}
	return result
}

// sessionIDMatches accepts an exact session id or, for group runs that derive
// per-host ids ("s_x@web-1"), the base id shared by all targets.
func sessionIDMatches(recordID string, filter string) bool {
	return recordID == filter || strings.HasPrefix(recordID, filter+"@")
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
	Host            string `json:"host"`
	Cmd             string `json:"cmd"`
	PolicyAction    string `json:"policy_action"`
	PolicyRule      string `json:"policy_rule"`
	Error           string `json:"error,omitempty"`
	ExitCode        *int   `json:"exit_code,omitempty"`
	OutputSHA256    string `json:"output_sha256"`
	OutputTruncated bool   `json:"output_truncated"`
	Redactions      int    `json:"redactions"`
	DurationMS      int64  `json:"duration_ms"`
	PrevHash        string `json:"prev_hash"`
	ApprovalID      string `json:"approval_id,omitempty"`
	ApprovalScope   string `json:"approval_scope,omitempty"`
	ApprovalMatcher string `json:"approval_matcher,omitempty"`
	ApprovalChannel string `json:"approval_channel,omitempty"`
	StdinSHA256     string `json:"stdin_sha256,omitempty"`
	StdinBytes      int64  `json:"stdin_bytes,omitempty"`
	PlanID          string `json:"plan_id,omitempty"`
}

func canonicalJSON(record Record) ([]byte, error) {
	return json.Marshal(canonicalRecord{
		Seq:             record.Seq,
		TS:              record.TS,
		ReqID:           record.ReqID,
		SessionID:       record.SessionID,
		SessionLabel:    record.SessionLabel,
		Event:           record.Event,
		Host:            record.Host,
		Cmd:             record.Cmd,
		PolicyAction:    record.PolicyAction,
		PolicyRule:      record.PolicyRule,
		Error:           record.Error,
		ExitCode:        record.ExitCode,
		OutputSHA256:    record.OutputSHA256,
		OutputTruncated: record.OutputTruncated,
		Redactions:      record.Redactions,
		DurationMS:      record.DurationMS,
		PrevHash:        record.PrevHash,
		ApprovalID:      record.ApprovalID,
		ApprovalScope:   record.ApprovalScope,
		ApprovalMatcher: record.ApprovalMatcher,
		ApprovalChannel: record.ApprovalChannel,
		StdinSHA256:     record.StdinSHA256,
		StdinBytes:      record.StdinBytes,
		PlanID:          record.PlanID,
	})
}
