package remote

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/Praeviso/AgentSSH/internal/runner"
)

// PathExec runs one command on a gateway (gateway mode only).
const PathExec = "/exec"

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

// ExecResult is the outcome of an execution: the merged exit code (the CLI
// contract: 0, 1, 6, 7, 9) and one `run --json` object per target. On the
// wire each response is its own frame, followed by a result frame with the
// exit code, so a group's size never adds up into one frame.
type ExecResult struct {
	ExitCode  int               `json:"exit_code"`
	Responses []runner.Response `json:"responses"`
}

type execFinal struct {
	ExitCode int `json:"exit_code"`
}

// ExecContentType labels an /exec response body made of frames.
const ExecContentType = "application/vnd.agentssh.exec-frames"

// Frame types. A stream holds any number of stdout/stderr frames, then one
// response frame per target, then exactly one result frame. An error frame
// may replace everything after the data frames.
const (
	FrameStdout   byte = 1
	FrameStderr   byte = 2
	FrameResult   byte = 3
	FrameError    byte = 4
	FrameResponse byte = 5
)

const (
	frameHeaderBytes = 5
	// MaxDataFrameBytes bounds one stdout/stderr frame; writers split larger
	// chunks.
	MaxDataFrameBytes = 64 << 10
	// MaxMessageFrameBytes bounds a response, result or error frame.
	MaxMessageFrameBytes = 16 << 20
)

var (
	// ErrNoResult means the stream ended before its result frame: the outcome
	// of the command is unknown.
	ErrNoResult = errors.New("execution stream ended before a result")
	// ErrFrameTooLarge rejects a frame above its type's limit.
	ErrFrameTooLarge = errors.New("execution frame too large")
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
	} else if kind != FrameResult && kind != FrameError && kind != FrameResponse {
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
	case FrameResult, FrameError, FrameResponse:
		if size > MaxMessageFrameBytes {
			return 0, nil, ErrFrameTooLarge
		}
	default:
		return 0, nil, fmt.Errorf("unknown execution frame type %d", kind)
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

// EncodeExecResult renders result as response frames and a result frame,
// checking every size before the first frame is emitted, so an oversized
// response never leaves a stream half written.
func EncodeExecResult(result ExecResult) ([][]byte, error) {
	payloads := make([][]byte, 0, len(result.Responses)+1)
	for _, response := range result.Responses {
		payload, err := json.Marshal(response)
		if err != nil {
			return nil, err
		}
		if len(payload) > MaxMessageFrameBytes {
			return nil, ErrFrameTooLarge
		}
		payloads = append(payloads, payload)
	}
	final, err := json.Marshal(execFinal{ExitCode: result.ExitCode})
	if err != nil {
		return nil, err
	}
	return append(payloads, final), nil
}

// WriteExecResult writes EncodeExecResult's frames through write.
func WriteExecResult(write func(kind byte, payload []byte) error, result ExecResult) error {
	payloads, err := EncodeExecResult(result)
	if err != nil {
		return err
	}
	for i, payload := range payloads {
		kind := FrameResponse
		if i == len(payloads)-1 {
			kind = FrameResult
		}
		if err := write(kind, payload); err != nil {
			return err
		}
	}
	return nil
}

// ReadExecStream copies data frames to stdout and stderr, collects response
// frames, and returns at the result frame. An error frame is returned as an
// *APIError. Data after a response, anything after the final frame, or a
// stream without one, is an error.
func ReadExecStream(r io.Reader, stdout, stderr io.Writer) (ExecResult, error) {
	var result ExecResult
	for {
		kind, payload, err := ReadFrame(r)
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return ExecResult{}, ErrNoResult
		}
		if err != nil {
			return ExecResult{}, err
		}
		switch kind {
		case FrameStdout, FrameStderr:
			if result.Responses != nil {
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
			result.Responses = append(result.Responses, response)
		case FrameResult, FrameError:
			if _, _, err := ReadFrame(r); !errors.Is(err, io.EOF) {
				return ExecResult{}, errors.New("execution stream continues after its final frame")
			}
			if kind == FrameError {
				var refusal ErrorResponse
				if err := json.Unmarshal(payload, &refusal); err != nil || refusal.Code == "" {
					return ExecResult{}, errors.New("malformed execution error frame")
				}
				return ExecResult{}, &APIError{Code: refusal.Code, Message: refusal.Error}
			}
			var final execFinal
			if err := json.Unmarshal(payload, &final); err != nil {
				return ExecResult{}, fmt.Errorf("malformed execution result: %w", err)
			}
			result.ExitCode = final.ExitCode
			return result, nil
		}
	}
}
