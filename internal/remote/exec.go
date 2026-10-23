package remote

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/Praeviso/AgentSSH/internal/runner"
)

// Gateway execution endpoints (gateway mode only).
const (
	// PathExec starts a run and streams it.
	PathExec = "/exec"
	// PathExecAttach streams an existing run from a spool offset.
	PathExecAttach = "/exec/attach"
	// PathExecCancel stops a run. Dropping a connection does not.
	PathExecCancel = "/exec/cancel"
	// PathHosts lists the device's hosts and groups, as `agentssh hosts`
	// prints them (inventory.PublicInventory).
	PathHosts = "/hosts"
	// PathRequestStatus reports the device's latest audit record for one
	// request, as `agentssh status --json` prints it (runner.Response).
	PathRequestStatus = "/requests/status"
)

// RequestStatusRequest names one request of the calling device.
type RequestStatusRequest struct {
	ReqID string `json:"req_id"`
}

// CodeRequestNotFound refuses a request ID the device's audit does not hold.
const CodeRequestNotFound = "request_not_found"

// Execution request limits. Every field lands in the audit chain, whose reader
// caps one record at 8 MiB; these keep a record far below that even when JSON
// escapes every byte.
const (
	// MaxExecStdinBytes matches the CLI's --stdin-file limit.
	MaxExecStdinBytes = 32 << 20
	// MaxExecCommandBytes matches what a local run can pass: Linux caps one
	// argv string at 128 KiB.
	MaxExecCommandBytes = 128 << 10
	// MaxExecFieldBytes bounds the host, session and plan identifiers.
	MaxExecFieldBytes = 256
	// MaxExecLabelBytes bounds the human-readable session label.
	MaxExecLabelBytes = 1 << 10
	// MaxExecOutputBytes is the gateway's per-stream output cap, applied when
	// the policy sets no lower output.max_bytes. With JSON's worst-case 6x
	// escaping, one target's response stays within MaxMessageFrameBytes.
	MaxExecOutputBytes = 1 << 20
)

// ExecRequest asks a gateway to authorize and run one command for the calling
// device. Stdin is nil for no stdin and non-nil (possibly empty) otherwise; the
// gateway computes its digest itself.
type ExecRequest struct {
	// RunID, when set, is the client's idempotency key: a repeat of the same
	// request with the same ID joins the existing run instead of starting the
	// command again, so a client that lost the first response can recover.
	// The gateway mints one when it is empty.
	RunID        string `json:"run_id,omitempty"`
	Host         string `json:"host"`
	Cmd          string `json:"cmd"`
	Stdin        []byte `json:"stdin"`
	Session      string `json:"session"`
	SessionLabel string `json:"session_label,omitempty"`
	ExecutionID  string `json:"execution_id,omitempty"`
	StepID       string `json:"step_id,omitempty"`
	ReviewSHA256 string `json:"review_sha256,omitempty"`
	// Stream asks for stdout/stderr frames while a single-host command runs.
	// The result carries the filtered output either way.
	Stream bool `json:"stream,omitempty"`
}

// ExecResult is the outcome of a run: the merged exit code (the CLI contract:
// 0, 1, 6, 7, 9) and one `run --json` object per target. Truncated means the
// run's spool cap dropped output, so the result is incomplete; the exit code is
// then at least 1.
type ExecResult struct {
	RunID     string `json:"run_id"`
	ExitCode  int    `json:"exit_code"`
	Truncated bool   `json:"truncated,omitempty"`
	// TargetKind is "host" or "group": `run --json` prints one object for a
	// host and an array for a group.
	TargetKind string            `json:"target_kind,omitempty"`
	Responses  []runner.Response `json:"responses"`
}

// ExecFinal is the payload of a result frame.
type ExecFinal struct {
	ExitCode   int    `json:"exit_code"`
	Truncated  bool   `json:"truncated,omitempty"`
	TargetKind string `json:"target_kind,omitempty"`
}

// ExecRun is the payload of the run frame that starts every /exec and
// /exec/attach response. ReqID is the request ID of a single-host run, known
// before its output so streamed output can be attributed to it.
type ExecRun struct {
	RunID string `json:"run_id"`
	ReqID string `json:"req_id,omitempty"`
}

// ExecAttachRequest resumes streaming a run. Offset is ExecStream.Offset: the
// spool bytes of the frames already consumed.
type ExecAttachRequest struct {
	RunID  string `json:"run_id"`
	Offset int64  `json:"offset"`
}

// ExecCancelRequest stops a run.
type ExecCancelRequest struct {
	RunID string `json:"run_id"`
}

// ExecCancelResponse reports whether the run was still running.
type ExecCancelResponse struct {
	RunID     string `json:"run_id"`
	Cancelled bool   `json:"cancelled"`
}

// Run errors. A run that is unknown, belongs to another device, or has expired
// is refused alike, so run IDs reveal nothing.
const (
	CodeRunNotFound    = "run_not_found"
	CodeRunInterrupted = "run_interrupted"
	// CodeRunConflict refuses a run ID reused for a different request.
	CodeRunConflict = "run_conflict"
	// CodeRunCancelled refuses a run cancelled before its request arrived.
	CodeRunCancelled = "run_cancelled"
)

// NewRunID mints a run ID.
func NewRunID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(fmt.Sprintf("crypto/rand: %v", err))
	}
	return "rn_" + hex.EncodeToString(b[:])
}

// ValidRunID reports whether id has the run ID shape: "rn_" and 32 lowercase
// hex characters.
func ValidRunID(id string) bool {
	hexPart, ok := strings.CutPrefix(id, "rn_")
	if !ok || len(hexPart) != 32 {
		return false
	}
	for _, c := range hexPart {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// ExecContentType labels an /exec response body made of frames.
const ExecContentType = "application/vnd.agentssh.exec-frames"

// Frame types. A run's spool holds any number of stdout/stderr frames, then
// one response frame per target, then exactly one result frame; an error frame
// may replace everything after the data frames. Each HTTP response carries a
// run frame and then the spool from the requested offset.
const (
	FrameStdout   byte = 1
	FrameStderr   byte = 2
	FrameResult   byte = 3
	FrameError    byte = 4
	FrameResponse byte = 5
	FrameRun      byte = 6
)

const (
	frameHeaderBytes = 5
	// MaxDataFrameBytes bounds one stdout/stderr frame; writers split larger
	// chunks.
	MaxDataFrameBytes = 64 << 10
	// MaxMessageFrameBytes bounds a response, result, error or run frame.
	MaxMessageFrameBytes = 16 << 20
)

var (
	// ErrNoResult means the stream ended or broke before its final frame: the
	// outcome is not known yet, and the run can be reattached.
	ErrNoResult = errors.New("execution stream ended before a result")
	// ErrFrameTooLarge rejects a frame above its type's limit.
	ErrFrameTooLarge = errors.New("execution frame too large")
	errUnknownFrame  = errors.New("unknown execution frame type")
)

// WriteFrame writes one frame. Data payloads above MaxDataFrameBytes are split.
func WriteFrame(w io.Writer, kind byte, payload []byte) error {
	limit := MaxMessageFrameBytes
	if kind == FrameStdout || kind == FrameStderr {
		limit = MaxDataFrameBytes
		for len(payload) > limit {
			if err := writeFrame(w, kind, payload[:limit]); err != nil {
				return err
			}
			payload = payload[limit:]
		}
	} else if kind != FrameResult && kind != FrameError && kind != FrameResponse && kind != FrameRun {
		return fmt.Errorf("unknown execution frame type %d", kind)
	}
	if len(payload) > limit {
		return ErrFrameTooLarge
	}
	return writeFrame(w, kind, payload)
}

func writeFrame(w io.Writer, kind byte, payload []byte) error {
	var header [frameHeaderBytes]byte
	header[0] = kind
	binary.BigEndian.PutUint32(header[1:], uint32(len(payload)))
	if _, err := w.Write(header[:]); err != nil {
		return err
	}
	_, err := w.Write(payload)
	return err
}

// ReadFrame reads one frame, enforcing the per-type size limit before
// allocating. A clean end of stream before a header is io.EOF; a partial
// frame is io.ErrUnexpectedEOF.
func ReadFrame(r io.Reader) (byte, []byte, error) {
	var header [frameHeaderBytes]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return 0, nil, err
	}
	kind := header[0]
	size := binary.BigEndian.Uint32(header[1:])
	switch kind {
	case FrameStdout, FrameStderr:
		if size > MaxDataFrameBytes {
			return 0, nil, ErrFrameTooLarge
		}
	case FrameResult, FrameError, FrameResponse, FrameRun:
		if size > MaxMessageFrameBytes {
			return 0, nil, ErrFrameTooLarge
		}
	default:
		return 0, nil, fmt.Errorf("%w %d", errUnknownFrame, kind)
	}
	// Grow with the bytes that actually arrive rather than trusting the
	// declared size up front.
	payload, err := io.ReadAll(io.LimitReader(r, int64(size)))
	if err != nil {
		return 0, nil, err
	}
	if len(payload) != int(size) {
		return 0, nil, io.ErrUnexpectedEOF
	}
	return kind, payload, nil
}

// FrameSize is the encoded size of a frame with payload bytes.
func FrameSize(payload int) int64 {
	return int64(frameHeaderBytes + payload)
}

// ExecStream reads one run across reconnects. RunID is set by the first run
// frame; Offset counts the spool bytes of complete frames consumed, so a
// reattach from Offset delivers every remaining frame exactly once; responses
// collected before a break are kept.
type ExecStream struct {
	RunID string
	// ReqID is the run frame's request ID of a single-host run.
	ReqID string
	// Started is set once a run frame arrived: the gateway has the run, so
	// the stream is resumed with /exec/attach rather than a repeated /exec.
	Started bool
	Offset  int64
	// OnRun, when set, is called with each run frame before the output that
	// follows it.
	OnRun     func(ExecRun)
	responses []runner.Response
}

// Read consumes one /exec or /exec/attach response body. It returns the
// result at the result frame, an *APIError for an error frame, and an error
// wrapping ErrNoResult when the body ends or breaks first; the stream can then
// be reattached from Offset.
func (s *ExecStream) Read(r io.Reader, stdout, stderr io.Writer) (ExecResult, error) {
	kind, payload, err := ReadFrame(r)
	if err != nil {
		return ExecResult{}, broken(err)
	}
	var run ExecRun
	if kind != FrameRun || json.Unmarshal(payload, &run) != nil || !ValidRunID(run.RunID) {
		return ExecResult{}, errors.New("execution stream does not start with a run frame")
	}
	if s.RunID != "" && s.RunID != run.RunID {
		return ExecResult{}, fmt.Errorf("reattached to run %s instead of %s", run.RunID, s.RunID)
	}
	s.RunID, s.ReqID, s.Started = run.RunID, run.ReqID, true
	if s.OnRun != nil {
		s.OnRun(run)
	}
	for {
		kind, payload, err := ReadFrame(r)
		if err != nil {
			return ExecResult{}, broken(err)
		}
		switch kind {
		case FrameStdout, FrameStderr:
			if s.responses != nil {
				return ExecResult{}, errors.New("execution output after a response frame")
			}
			dst := stdout
			if kind == FrameStderr {
				dst = stderr
			}
			if _, err := dst.Write(payload); err != nil {
				return ExecResult{}, err
			}
		case FrameResponse:
			var response runner.Response
			if err := json.Unmarshal(payload, &response); err != nil {
				return ExecResult{}, fmt.Errorf("malformed execution response: %w", err)
			}
			s.responses = append(s.responses, response)
		case FrameResult, FrameError:
			// The final frame is complete; only another well-formed frame
			// after it is a protocol violation. A connection that breaks
			// before the body ends cleanly loses nothing.
			if _, _, err := ReadFrame(r); err == nil || errors.Is(err, ErrFrameTooLarge) || errors.Is(err, errUnknownFrame) {
				return ExecResult{}, errors.New("execution stream continues after its final frame")
			}
			s.Offset += FrameSize(len(payload))
			if kind == FrameError {
				var refusal ErrorResponse
				if err := json.Unmarshal(payload, &refusal); err != nil || refusal.Code == "" {
					return ExecResult{}, errors.New("malformed execution error frame")
				}
				return ExecResult{}, &APIError{Code: refusal.Code, Message: refusal.Error}
			}
			var final ExecFinal
			if err := json.Unmarshal(payload, &final); err != nil {
				return ExecResult{}, fmt.Errorf("malformed execution result: %w", err)
			}
			return ExecResult{RunID: s.RunID, ExitCode: final.ExitCode, Truncated: final.Truncated, TargetKind: final.TargetKind, Responses: s.responses}, nil
		default:
			return ExecResult{}, errors.New("unexpected run frame inside an execution stream")
		}
		s.Offset += FrameSize(len(payload))
	}
}

// broken classifies a read failure: a size or type violation is a protocol
// error; anything else (end of body, connection reset) means the stream broke
// and the outcome is not known yet.
func broken(err error) error {
	if errors.Is(err, ErrFrameTooLarge) || errors.Is(err, errUnknownFrame) {
		return err
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return ErrNoResult
	}
	return fmt.Errorf("%w: %v", ErrNoResult, err)
}
