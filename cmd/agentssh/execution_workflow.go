package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/Praeviso/AgentSSH/internal/approval"
	"github.com/Praeviso/AgentSSH/internal/config"
	"github.com/Praeviso/AgentSSH/internal/payload"
)

const (
	executionStepApply  = "apply"
	executionStepVerify = "verify"

	executionOnFailureStop     = "stop"
	executionOnFailureContinue = "continue"

	executionEventMaxOutputBytes  = 4096
	executionEventMaxJournalBytes = 1 << 20
)

type executionApprovalRound struct {
	PlanID       string `json:"plan_id"`
	Status       string `json:"status"`
	Reason       string `json:"reason,omitempty"`
	ReviewSHA256 string `json:"review_sha256,omitempty"`
	TS           string `json:"ts"`
	Pending      int    `json:"pending,omitempty"`
	Denied       int    `json:"denied,omitempty"`
	Expired      int    `json:"expired,omitempty"`
}

type executionNextAction struct {
	Argv   []string `json:"argv,omitempty"`
	Reason string   `json:"reason,omitempty"`
}

type executionPhaseSummary struct {
	Total      int `json:"total"`
	Completed  int `json:"completed"`
	Failed     int `json:"failed"`
	Pending    int `json:"pending"`
	Unknown    int `json:"unknown"`
	Continued  int `json:"continued,omitempty"`
	NotStarted int `json:"not_started,omitempty"`
}

type executionEvent struct {
	Seq         uint64           `json:"seq"`
	TS          string           `json:"ts"`
	Type        string           `json:"type"`
	ExecutionID string           `json:"execution_id"`
	StepID      string           `json:"step_id,omitempty"`
	RequestID   string           `json:"request_id,omitempty"`
	PlanID      string           `json:"plan_id,omitempty"`
	Status      string           `json:"status,omitempty"`
	Reason      string           `json:"reason,omitempty"`
	Output      *executionOutput `json:"output,omitempty"`
}

type executionOutput struct {
	Stdout          string `json:"stdout,omitempty"`
	Stderr          string `json:"stderr,omitempty"`
	Stream          string `json:"stream,omitempty"`
	Data            string `json:"data,omitempty"`
	OutputTruncated bool   `json:"output_truncated,omitempty"`
	Redactions      int    `json:"redactions,omitempty"`
}

type executionEventWriter struct {
	path        string
	executionID string
	stream      io.Writer
	mu          sync.Mutex
	nextSeq     uint64
	loadedSeq   bool
}

type payloadRefJSON = payload.Ref

func stableStepID(index int, requested string) string {
	requested = strings.TrimSpace(requested)
	if requested != "" {
		return requested
	}
	return fmt.Sprintf("step-%03d", index+1)
}

func prepareExecutionPlanInputs(cfg *config.Config, commands []planCommand, savePayloads bool, retainFor time.Duration, owner string) (refs []payload.Ref, resultErr error) {
	store := planPayloadStore(cfg.Paths)
	var pinnedRefs []payload.Ref
	defer func() {
		if resultErr == nil || len(pinnedRefs) == 0 {
			return
		}
		for _, ref := range pinnedRefs {
			if ref.SHA256 == "" {
				continue
			}
			_ = store.Unpin(ref, owner)
		}
	}()
	for i := range commands {
		if err := validateExecutionPlanCommand(commands[i], i); err != nil {
			return nil, err
		}
		if commands[i].PayloadRef != "" {
			if commands[i].StdinFile != "" {
				return nil, newUsageError("structured plan commands[%d] must choose stdin_file or payload_ref", i)
			}
			ref, err := payload.ParseRef(commands[i].PayloadRef)
			if err != nil {
				return nil, mapPayloadError(err)
			}
			data, err := store.Get(ref)
			if err != nil {
				return nil, mapPayloadError(err)
			}
			if err := store.Pin(ref, owner); err != nil {
				return nil, mapPayloadError(err)
			}
			refs = append(refs, ref)
			pinnedRefs = append(pinnedRefs, ref)
			commands[i].stdin = stdinSpec{data: data, sha256: ref.SHA256, bytes: ref.Bytes}
			continue
		}
		stdin, err := loadStdinSpec(fmt.Sprintf("commands[%d].stdin_file", i), commands[i].StdinFile)
		if err != nil {
			return nil, err
		}
		if savePayloads && stdin.sha256 != "" {
			ref, err := store.PutAndPin(stdin.data, payload.PutOptions{Name: commands[i].ID, RetainFor: retainFor}, owner)
			if err != nil {
				return nil, mapPayloadError(err)
			}
			refs = append(refs, ref)
			pinnedRefs = append(pinnedRefs, ref)
			if ref.SHA256 != stdin.sha256 || ref.Bytes != stdin.bytes {
				return nil, newUsageError("saved payload identity mismatch")
			}
			commands[i].PayloadRef = ref.String()
		}
		if !savePayloads {
			stdin.data = nil
		}
		commands[i].stdin = stdin
	}
	return refs, nil
}

func validateExecutionPlanCommand(command planCommand, index int) error {
	return validatePlanCommand(command, index)
}

func approvalCommandsFromExecution(steps []planExecutionStep) ([]planCommand, error) {
	commands := make([]planCommand, 0, len(steps))
	for _, step := range steps {
		if step.Status == "completed" || step.Status == "failed_continued" {
			continue
		}
		if step.Status != "not_started" {
			return nil, newUsageError("execution has a non-resumable step")
		}
		stdin, err := stepStdinSpec(step)
		if err != nil {
			return nil, err
		}
		stdin.data = nil
		commands = append(commands, planCommand{
			ID: step.ID, Name: step.Name, Phase: step.Phase, OnFailure: step.OnFailure,
			Cmd: step.Cmd, StdinFile: step.StdinFile, PayloadRef: step.PayloadRef, stdin: stdin,
		})
	}
	return commands, nil
}

func stepStdinSpec(step planExecutionStep) (stdinSpec, error) {
	if step.PayloadRef != "" {
		stdin, err := loadSavedPayload(step.PayloadRef, step.StdinSHA256, step.StdinBytes)
		if err != nil {
			return stdinSpec{}, err
		}
		return stdin, nil
	}
	stdin, err := loadStdinSpec("saved stdin_file", step.StdinFile)
	if err != nil {
		return stdinSpec{}, err
	}
	if stdin.sha256 != step.StdinSHA256 || stdin.bytes != step.StdinBytes {
		return stdinSpec{}, newUsageError("saved stdin changed; submit a new plan with the new content")
	}
	return stdin, nil
}

func loadSavedPayload(path string, wantHash string, wantBytes int64) (stdinSpec, error) {
	ref, err := payload.ParseRef(path)
	if err != nil {
		return stdinSpec{}, newUsageError("saved payload identity mismatch")
	}
	if ref.SHA256 != wantHash || ref.Bytes != wantBytes {
		return stdinSpec{}, newUsageError("saved payload identity mismatch")
	}
	cfg, err := config.Load()
	if err != nil {
		return stdinSpec{}, classifyConfigError(err)
	}
	data, err := planPayloadStore(cfg.Paths).Get(ref)
	if err != nil {
		return stdinSpec{}, newUsageError("cannot read saved payload: %v", err)
	}
	return stdinSpec{data: data, sha256: ref.SHA256, bytes: ref.Bytes}, nil
}

func releaseExecutionPayloadPins(cfg *config.Config, run *planExecution) error {
	if len(run.ActivePayloadRefs) == 0 {
		return nil
	}
	store := planPayloadStore(cfg.Paths)
	for _, ref := range run.ActivePayloadRefs {
		if ref.SHA256 == "" {
			continue
		}
		if err := store.Unpin(ref, run.ID); err != nil {
			return mapPayloadError(err)
		}
	}
	run.ActivePayloadRefs = nil
	return nil
}

func executionPlanReview(run *planExecution) approval.PlanReview {
	steps := make([]approval.PlanReviewStep, 0, len(run.Steps))
	for i, step := range run.Steps {
		reviewStatus := step.Status
		if reviewStatus == "" {
			reviewStatus = "not_started"
		}
		steps = append(steps, approval.PlanReviewStep{
			Seq:             i + 1,
			ID:              step.ID,
			Name:            step.Name,
			Phase:           step.Phase,
			OnFailure:       step.OnFailure,
			Cmd:             step.Cmd,
			Status:          reviewStatus,
			StdinSHA256:     step.StdinSHA256,
			StdinBytes:      step.StdinBytes,
			PayloadRef:      step.PayloadRef,
			PayloadRetained: step.PayloadRef != "",
		})
	}
	return approval.PlanReview{
		Version:     1,
		ExecutionID: run.ID,
		SessionID:   run.SessionID,
		Host:        run.Host,
		Metadata:    run.Metadata,
		Steps:       steps,
	}
}

func (w *executionEventWriter) append(event executionEvent) error {
	if w == nil {
		return nil
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.path == "" {
		if w.stream != nil {
			event.Seq = 0
			event.TS = time.Now().UTC().Format(time.RFC3339Nano)
			event.ExecutionID = w.executionID
			data, err := json.Marshal(event)
			if err != nil {
				return err
			}
			_, err = fmt.Fprintln(w.stream, string(data))
			return err
		}
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(w.path), 0o700); err != nil {
		return err
	}
	if !w.loadedSeq {
		seq, err := nextExecutionEventSeq(w.path)
		if err != nil {
			return err
		}
		w.nextSeq = seq
		w.loadedSeq = true
	}
	event.Seq = w.nextSeq
	w.nextSeq++
	event.TS = time.Now().UTC().Format(time.RFC3339Nano)
	event.ExecutionID = w.executionID
	data, err := json.Marshal(event)
	if err != nil {
		return err
	}
	file, err := os.OpenFile(w.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err := file.Write(append(data, '\n')); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := trimExecutionEventJournal(w.path, executionEventMaxJournalBytes); err != nil {
		return err
	}
	if w.stream != nil {
		_, err = fmt.Fprintln(w.stream, string(data))
	}
	return err
}

func trimExecutionEventJournal(path string, maxBytes int64) error {
	if maxBytes <= 0 {
		return nil
	}
	info, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) || (err == nil && info.Size() <= maxBytes) {
		return nil
	}
	if err != nil {
		return err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if int64(len(data)) <= maxBytes {
		return nil
	}
	start := len(data) - int(maxBytes)
	if start < 0 {
		start = 0
	}
	if idx := bytesIndexByte(data[start:], '\n'); idx >= 0 {
		start += idx + 1
	}
	trimmed := data[start:]
	if len(trimmed) == 0 {
		trimmed = data[len(data)-int(maxBytes):]
		if idx := bytesIndexByte(trimmed, '\n'); idx >= 0 {
			trimmed = trimmed[idx+1:]
		}
	}
	return fileutilWriteEventJournal(path, trimmed)
}

func bytesIndexByte(data []byte, c byte) int {
	for i, b := range data {
		if b == c {
			return i
		}
	}
	return -1
}

func fileutilWriteEventJournal(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".trim-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return err
	}
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	return os.Rename(tmpName, path)
}

func nextExecutionEventSeq(path string) (uint64, error) {
	events, err := readExecutionEvents(path)
	if err != nil {
		return 0, err
	}
	var maxSeq uint64
	for _, event := range events {
		if event.Seq > maxSeq {
			maxSeq = event.Seq
		}
	}
	return maxSeq + 1, nil
}

func readExecutionEvents(path string) ([]executionEvent, error) {
	file, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()
	var events []executionEvent
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 0, 64*1024), 2*1024*1024)
	for scanner.Scan() {
		var event executionEvent
		if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
			return nil, fmt.Errorf("parse execution event: %w", err)
		}
		events = append(events, event)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return events, nil
}

func followExecutionEvents(ctx context.Context, out io.Writer, cfg *config.Config, executionID, eventsPath, snapshotPath, lockPath string, afterSeq uint64) error {
	seen := afterSeq
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for {
		run, err := readExecution(snapshotPath, executionID)
		if err != nil {
			return err
		}
		refreshExecutionDerivedStatus(cfg, &run, executionHasLiveOwner(lockPath))
		snapshotStatus := run.Status
		events, err := readExecutionEvents(eventsPath)
		if err != nil {
			return err
		}
		if len(events) > 0 && seen > 0 && seen < events[0].Seq-1 {
			gap := executionEvent{Seq: events[0].Seq - 1, TS: time.Now().UTC().Format(time.RFC3339Nano), Type: "cursor_gap", ExecutionID: executionID, Reason: "requested cursor is older than retained events"}
			data, err := json.Marshal(gap)
			if err != nil {
				return err
			}
			if _, err := fmt.Fprintln(out, string(data)); err != nil {
				return err
			}
			seen = events[0].Seq - 1
		}
		for _, event := range events {
			if event.Seq <= seen {
				continue
			}
			data, err := json.Marshal(event)
			if err != nil {
				return err
			}
			if _, err := fmt.Fprintln(out, string(data)); err != nil {
				return err
			}
			seen = event.Seq
			if isTerminalExecutionEvent(event.Type) {
				return nil
			}
		}
		if isTerminalExecutionStatus(snapshotStatus) {
			if !eventsContainTerminal(events) {
				reason := "execution has terminal snapshot and no retained terminal event"
				if snapshotStatus == "unknown" {
					reason = "running checkpoint has no active owner"
				}
				event := executionEvent{Seq: 0, TS: time.Now().UTC().Format(time.RFC3339Nano), Type: "execution_snapshot", ExecutionID: executionID, Status: snapshotStatus, Reason: reason}
				data, err := json.Marshal(event)
				if err != nil {
					return err
				}
				if _, err := fmt.Fprintln(out, string(data)); err != nil {
					return err
				}
			}
			return nil
		}
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}

func eventsContainTerminal(events []executionEvent) bool {
	for _, event := range events {
		if isTerminalExecutionEvent(event.Type) {
			return true
		}
	}
	return false
}

func isTerminalExecutionEvent(eventType string) bool {
	switch eventType {
	case "execution_completed", "execution_failed", "execution_denied", "execution_unknown":
		return true
	default:
		return false
	}
}

func isTerminalExecutionStatus(status string) bool {
	switch status {
	case "completed", "failed", "denied", "expired", "unknown":
		return true
	default:
		return false
	}
}

func executionEventsPath(cfg *config.Config, id string) (string, error) {
	path, err := executionPath(cfg, id)
	if err != nil {
		return "", err
	}
	return strings.TrimSuffix(path, ".json") + ".events.jsonl", nil
}

func executionLockPath(cfg *config.Config, id string) (string, error) {
	path, err := executionPath(cfg, id)
	if err != nil {
		return "", err
	}
	return path + ".lock", nil
}

func executionHasLiveOwner(lockPath string) bool {
	lock, err := os.OpenFile(lockPath, os.O_RDWR, 0)
	if err != nil {
		return false
	}
	defer func() { _ = lock.Close() }()
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return true
	}
	_ = syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
	return false
}

func refreshExecutionDerivedStatus(cfg *config.Config, run *planExecution, live bool) {
	run.PhaseSummary = summarizeExecutionPhases(run.Steps)
	run.NextAction = nil
	switch run.Status {
	case "pending":
		run.NextAction = &executionNextAction{Argv: []string{"agentssh", "plan", "execution", run.ID, "--follow", "--timeout", "30s"}, Reason: "approval is still pending; follow observes without executing"}
		if run.ApprovalPlanID != "" {
			run.NextAction = &executionNextAction{Argv: []string{"agentssh", "plan", "wait", run.ApprovalPlanID, "--timeout", "30s", "--json"}, Reason: "approval is still pending; wait for the existing plan decision"}
			if status, err := approvalStore(cfg.Paths).PlanStatus(run.ApprovalPlanID); err == nil {
				switch status.Status {
				case "approved":
					run.Status = "ready"
					run.NextAction = &executionNextAction{Argv: []string{"agentssh", "plan", "resume", run.ID, "--json"}, Reason: "approval is ready; resume will recheck authorization before executing unstarted steps"}
				case "denied":
					run.Status = "denied"
					run.NextAction = &executionNextAction{Reason: "operator denied the approval plan"}
				case "expired":
					run.Status = "expired"
					run.NextAction = &executionNextAction{Argv: []string{"agentssh", "plan", "resume", run.ID, "--json"}, Reason: "approval records expired; resume will submit a fresh approval round for unstarted steps"}
				}
			}
		}
	case "ready":
		run.NextAction = &executionNextAction{Argv: []string{"agentssh", "plan", "resume", run.ID, "--json"}, Reason: "resume will recheck authorization before executing unstarted steps"}
	case "running":
		if live {
			run.NextAction = &executionNextAction{Argv: []string{"agentssh", "plan", "execution", run.ID, "--follow", "--timeout", "30s"}, Reason: "execution is currently owned by a running process"}
		} else {
			run.Status = "unknown"
			run.NextAction = &executionNextAction{Reason: "a running checkpoint has no active owner; inspect before retry"}
		}
	case "denied":
		run.NextAction = &executionNextAction{Reason: "operator denied the approval plan"}
	case "expired":
		run.NextAction = &executionNextAction{Argv: []string{"agentssh", "plan", "resume", run.ID, "--json"}, Reason: "approval records expired; resume will submit a fresh approval round for unstarted steps"}
	case "failed", "unknown":
		run.NextAction = &executionNextAction{Reason: "inspect results before creating a new plan"}
	}
}

func summarizeExecutionPhases(steps []planExecutionStep) map[string]executionPhaseSummary {
	out := map[string]executionPhaseSummary{}
	for _, step := range steps {
		phase := step.Phase
		if phase == "" {
			phase = executionStepApply
		}
		summary := out[phase]
		summary.Total++
		switch step.Status {
		case "completed":
			summary.Completed++
		case "failed", "failed_continued":
			summary.Failed++
			if step.Status == "failed_continued" {
				summary.Continued++
			}
		case "pending":
			summary.Pending++
		case "unknown", "running":
			summary.Unknown++
		default:
			summary.NotStarted++
		}
		out[phase] = summary
	}
	return out
}

func appendApprovalRound(run *planExecution, planID, status, reason string, pending, denied, expired int) {
	if planID == "" {
		return
	}
	for i := range run.ApprovalRounds {
		if run.ApprovalRounds[i].PlanID == planID {
			run.ApprovalRounds[i].Status = status
			run.ApprovalRounds[i].Pending = pending
			run.ApprovalRounds[i].Denied = denied
			run.ApprovalRounds[i].Expired = expired
			if run.ReviewSHA256 != "" {
				run.ApprovalRounds[i].ReviewSHA256 = run.ReviewSHA256
			}
			if reason != "" {
				run.ApprovalRounds[i].Reason = reason
			}
			return
		}
	}
	run.ApprovalRounds = append(run.ApprovalRounds, executionApprovalRound{
		PlanID:       planID,
		Status:       status,
		Reason:       reason,
		ReviewSHA256: run.ReviewSHA256,
		TS:           time.Now().UTC().Format(time.RFC3339),
		Pending:      pending,
		Denied:       denied,
		Expired:      expired,
	})
}

func truncateExecutionOutput(value string) (string, bool) {
	if len(value) <= executionEventMaxOutputBytes {
		return value, false
	}
	return value[:executionEventMaxOutputBytes], true
}

func eventOutputFromRun(row runResponse) *executionOutput {
	stdout, stdoutTruncated := truncateExecutionOutput(row.Stdout)
	stderr, stderrTruncated := truncateExecutionOutput(row.Stderr)
	if stdout == "" && stderr == "" && row.Redactions == 0 && !row.OutputTruncated {
		return nil
	}
	return &executionOutput{
		Stdout:          stdout,
		Stderr:          stderr,
		OutputTruncated: row.OutputTruncated || stdoutTruncated || stderrTruncated,
		Redactions:      row.Redactions,
	}
}

func eventOutputFromStream(event runOutputEvent) *executionOutput {
	data, truncated := truncateExecutionOutput(event.Data)
	return &executionOutput{
		Stream:          event.Stream,
		Data:            data,
		OutputTruncated: truncated,
	}
}
