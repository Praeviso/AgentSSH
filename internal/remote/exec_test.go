package remote

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/Praeviso/AgentSSH/internal/runner"
)

func frame(kind byte, payload string) []byte {
	var buf bytes.Buffer
	var header [frameHeaderBytes]byte
	header[0] = kind
	binary.BigEndian.PutUint32(header[1:], uint32(len(payload)))
	buf.Write(header[:])
	buf.WriteString(payload)
	return buf.Bytes()
}

func header(kind byte, size uint32) []byte {
	var h [frameHeaderBytes]byte
	h[0] = kind
	binary.BigEndian.PutUint32(h[1:], size)
	return h[:]
}

func concat(parts ...[]byte) []byte {
	return bytes.Join(parts, nil)
}

const testRunID = "rn_0123456789abcdef0123456789abcdef"

// runFrame starts every /exec and /exec/attach body.
var runFrame = frame(FrameRun, `{"run_id":"`+testRunID+`"}`)

func read(stream *ExecStream, body []byte) (ExecResult, string, string, error) {
	var stdout, stderr bytes.Buffer
	result, err := stream.Read(bytes.NewReader(body), &stdout, &stderr)
	return result, stdout.String(), stderr.String(), err
}

func TestExecStreamRead(t *testing.T) {
	response := `{"execution_state":"finished","req_id":"r1","session_id":"s","host":"web-1","status":"failed","exit_code":3,"duration_ms":5,"stdout":"","stderr":"","output_truncated":false,"redactions":0}`
	for _, tc := range []struct {
		name           string
		spool          []byte
		noRunFrame     bool
		stdout, stderr string
		exit           int
		hosts          int
		truncated      bool
		err            string
	}{
		{name: "output, responses, result", spool: concat(frame(FrameStdout, "a"), frame(FrameStderr, "b"), frame(FrameStdout, "c"), frame(FrameResponse, response), frame(FrameResponse, response), frame(FrameResult, `{"exit_code":1}`)), stdout: "ac", stderr: "b", exit: 1, hosts: 2},
		{name: "result only", spool: frame(FrameResult, `{"exit_code":0}`)},
		{name: "truncated result", spool: concat(frame(FrameResponse, response), frame(FrameResult, `{"exit_code":1,"truncated":true}`)), exit: 1, hosts: 1, truncated: true},
		{name: "no run frame", spool: frame(FrameResult, `{"exit_code":0}`), noRunFrame: true, err: "does not start with a run frame"},
		{name: "empty body", noRunFrame: true, err: ErrNoResult.Error()},
		{name: "run frame only", err: ErrNoResult.Error()},
		{name: "disconnect before result", spool: frame(FrameStdout, "partial"), stdout: "partial", err: ErrNoResult.Error()},
		{name: "disconnect between responses", spool: frame(FrameResponse, response), err: ErrNoResult.Error()},
		{name: "truncated header", spool: concat(frame(FrameStdout, "x"), []byte{FrameResult, 0, 0}), stdout: "x", err: ErrNoResult.Error()},
		{name: "truncated payload", spool: concat(header(FrameResult, 10), []byte(`{"exit`)), err: ErrNoResult.Error()},
		{name: "unknown type", spool: frame(9, "x"), err: "unknown execution frame type 9"},
		{name: "second run frame", spool: runFrame, err: "unexpected run frame"},
		{name: "oversized data frame", spool: header(FrameStdout, MaxDataFrameBytes+1), err: ErrFrameTooLarge.Error()},
		{name: "oversized response frame", spool: header(FrameResponse, MaxMessageFrameBytes+1), err: ErrFrameTooLarge.Error()},
		{name: "malformed response", spool: frame(FrameResponse, `{"host":`), err: "malformed execution response"},
		{name: "malformed result", spool: frame(FrameResult, `{"exit_code":`), err: "malformed execution result"},
		{name: "output after a response", spool: concat(frame(FrameResponse, response), frame(FrameStdout, "late")), err: "output after a response frame"},
		{name: "abrupt end after result", spool: concat(frame(FrameResult, `{"exit_code":0}`), []byte{FrameStdout, 0})},
		{name: "data after result", spool: concat(frame(FrameResult, `{"exit_code":0}`), frame(FrameStdout, "late")), err: "continues after its final frame"},
		{name: "error frame", spool: frame(FrameError, `{"code":"internal","error":"execution failed"}`), err: "execution failed"},
		{name: "malformed error frame", spool: frame(FrameError, `{}`), err: "malformed execution error frame"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := concat(runFrame, tc.spool)
			if tc.noRunFrame {
				body = tc.spool
			}
			var stream ExecStream
			got, stdout, stderr, err := read(&stream, body)
			if tc.err != "" {
				if err == nil || !strings.Contains(err.Error(), tc.err) {
					t.Fatalf("err = %v, want %q", err, tc.err)
				}
			} else if err != nil {
				t.Fatalf("err = %v", err)
			}
			if stdout != tc.stdout || stderr != tc.stderr {
				t.Fatalf("stdout %q stderr %q, want %q %q", stdout, stderr, tc.stdout, tc.stderr)
			}
			if got.ExitCode != tc.exit || len(got.Responses) != tc.hosts || got.Truncated != tc.truncated {
				t.Fatalf("result = %+v, want exit %d with %d responses, truncated %v", got, tc.exit, tc.hosts, tc.truncated)
			}
			if tc.err == "" && got.RunID != testRunID {
				t.Fatalf("run id = %q", got.RunID)
			}
		})
	}
}

// A broken stream resumes from Offset: no frame is delivered twice and the
// responses received before the break are kept.
func TestExecStreamResumesFromOffset(t *testing.T) {
	response := `{"host":"web-1","status":"completed"}`
	spool := concat(frame(FrameStdout, "one\n"), frame(FrameStdout, "two\n"), frame(FrameResponse, response), frame(FrameResponse, response), frame(FrameResult, `{"exit_code":0}`))
	// The first connection breaks inside the second response frame.
	cut := len(frame(FrameStdout, "one\n")) + len(frame(FrameStdout, "two\n")) + len(frame(FrameResponse, response)) + 3
	var stream ExecStream
	_, out1, _, err := read(&stream, concat(runFrame, spool[:cut]))
	if !errors.Is(err, ErrNoResult) || out1 != "one\ntwo\n" {
		t.Fatalf("first read: %q %v", out1, err)
	}
	if want := int64(cut - 3); stream.Offset != want {
		t.Fatalf("offset = %d, want %d (complete frames only)", stream.Offset, want)
	}
	result, out2, _, err := read(&stream, concat(runFrame, spool[stream.Offset:]))
	if err != nil || out2 != "" || len(result.Responses) != 2 || stream.Offset != int64(len(spool)) {
		t.Fatalf("resumed read: out=%q responses=%d offset=%d err=%v", out2, len(result.Responses), stream.Offset, err)
	}
	other := ExecStream{RunID: "rn_ffffffffffffffffffffffffffffffff"}
	if _, _, _, err := read(&other, concat(runFrame, spool)); err == nil || !strings.Contains(err.Error(), "instead of") {
		t.Fatalf("attached to the wrong run: %v", err)
	}
}

func TestErrorFrameIsAPIError(t *testing.T) {
	var stream ExecStream
	_, _, _, err := read(&stream, concat(runFrame, frame(FrameError, `{"code":"usage","error":"no such host"}`)))
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.Code != CodeUsage {
		t.Fatalf("err = %v, want usage APIError", err)
	}
}

func TestWriteFrameSplitsData(t *testing.T) {
	big := bytes.Repeat([]byte("x"), 2*MaxDataFrameBytes+7)
	var buf bytes.Buffer
	if err := WriteFrame(&buf, FrameStdout, big); err != nil {
		t.Fatal(err)
	}
	if int64(buf.Len()) != 3*FrameSize(0)+int64(len(big)) {
		t.Fatalf("encoded %d bytes, want three data frames", buf.Len())
	}
	buf.Write(frame(FrameResult, `{"exit_code":0}`))
	var stream ExecStream
	if _, stdout, _, err := read(&stream, concat(runFrame, buf.Bytes())); err != nil || stdout != string(big) {
		t.Fatalf("round trip: %v", err)
	}
	if err := WriteFrame(&buf, FrameResult, make([]byte, MaxMessageFrameBytes+1)); !errors.Is(err, ErrFrameTooLarge) {
		t.Fatalf("oversized result: %v", err)
	}
	if err := WriteFrame(&buf, 9, nil); err == nil {
		t.Fatal("unknown frame type accepted")
	}
}

// One target's response at the gateway's output cap fits a frame even when
// JSON escapes every output byte.
func TestCappedResponseFitsOneFrame(t *testing.T) {
	worst := strings.Repeat("<", MaxExecOutputBytes) // JSON escapes '<' as \u003c
	payload, err := json.Marshal(runner.Response{Host: "web-1", Cmd: strings.Repeat("<", 2048), Stdout: worst, Stderr: worst})
	if err != nil || len(payload) > MaxMessageFrameBytes {
		t.Fatalf("capped response is %d bytes (limit %d): %v", len(payload), MaxMessageFrameBytes, err)
	}
}

func TestValidRunID(t *testing.T) {
	for id, want := range map[string]bool{
		testRunID:                             true,
		"rn_0123456789ABCDEF0123456789abcdef": false,
		"rn_0123":                             false,
		"../../etc/passwd":                    false,
		"rn_0123456789abcdef0123456789abcdeg": false,
	} {
		if ValidRunID(id) != want {
			t.Errorf("ValidRunID(%q) = %v", id, !want)
		}
	}
}

func FuzzReadExecStream(f *testing.F) {
	f.Add(concat(runFrame, frame(FrameStdout, "out"), frame(FrameStderr, "err"), frame(FrameResponse, `{"host":"web-1","status":"completed"}`), frame(FrameResult, `{"exit_code":0}`)))
	f.Add(concat(runFrame, frame(FrameError, `{"code":"busy","error":"x"}`)))
	f.Add(concat(runFrame, header(FrameResponse, MaxMessageFrameBytes)))
	f.Add([]byte{FrameStdout, 0xff, 0xff, 0xff, 0xff})
	f.Fuzz(func(t *testing.T, data []byte) {
		var stream ExecStream
		var stdout, stderr bytes.Buffer
		_, err := stream.Read(bytes.NewReader(data), &stdout, &stderr)
		// A decoded result needs at least a run frame and a result frame.
		if err == nil && len(data) < 2*frameHeaderBytes {
			t.Fatalf("decoded a result from %d bytes", len(data))
		}
		// Output is only ever a copy of data frames from the input, and the
		// offset never passes the bytes read.
		if stdout.Len()+stderr.Len() > len(data) || stream.Offset > int64(len(data)) {
			t.Fatalf("emitted %d bytes, offset %d, from a %d byte stream", stdout.Len()+stderr.Len(), stream.Offset, len(data))
		}
	})
}
