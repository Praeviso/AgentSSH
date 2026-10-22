package remote

import (
	"bytes"
	"encoding/binary"
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

func TestReadExecStream(t *testing.T) {
	response := `{"execution_state":"finished","req_id":"r1","session_id":"s","host":"web-1","status":"failed","exit_code":3,"duration_ms":5,"stdout":"","stderr":"","output_truncated":false,"redactions":0}`
	for _, tc := range []struct {
		name           string
		stream         []byte
		stdout, stderr string
		exit           int
		hosts          int
		err            string
	}{
		{name: "output, responses, result", stream: concat(frame(FrameStdout, "a"), frame(FrameStderr, "b"), frame(FrameStdout, "c"), frame(FrameResponse, response), frame(FrameResponse, response), frame(FrameResult, `{"exit_code":1}`)), stdout: "ac", stderr: "b", exit: 1, hosts: 2},
		{name: "result only", stream: frame(FrameResult, `{"exit_code":0}`)},
		{name: "empty stream", stream: nil, err: ErrNoResult.Error()},
		{name: "disconnect before result", stream: frame(FrameStdout, "partial"), stdout: "partial", err: ErrNoResult.Error()},
		{name: "disconnect between responses", stream: frame(FrameResponse, response), err: ErrNoResult.Error()},
		{name: "truncated header", stream: concat(frame(FrameStdout, "x"), []byte{FrameResult, 0, 0}), stdout: "x", err: ErrNoResult.Error()},
		{name: "truncated payload", stream: concat(header(FrameResult, 10), []byte(`{"exit`)), err: ErrNoResult.Error()},
		{name: "unknown type", stream: frame(9, "x"), err: "unknown execution frame type 9"},
		{name: "oversized data frame", stream: header(FrameStdout, MaxDataFrameBytes+1), err: ErrFrameTooLarge.Error()},
		{name: "oversized response frame", stream: header(FrameResponse, MaxMessageFrameBytes+1), err: ErrFrameTooLarge.Error()},
		{name: "oversized result frame", stream: header(FrameResult, MaxMessageFrameBytes+1), err: ErrFrameTooLarge.Error()},
		{name: "malformed response", stream: frame(FrameResponse, `{"host":`), err: "malformed execution response"},
		{name: "malformed result", stream: frame(FrameResult, `{"exit_code":`), err: "malformed execution result"},
		{name: "output after a response", stream: concat(frame(FrameResponse, response), frame(FrameStdout, "late")), err: "output after a response frame"},
		{name: "data after result", stream: concat(frame(FrameResult, `{"exit_code":0}`), frame(FrameStdout, "late")), err: "continues after its final frame"},
		{name: "error frame", stream: frame(FrameError, `{"code":"internal","error":"execution failed"}`), err: "execution failed"},
		{name: "malformed error frame", stream: frame(FrameError, `{}`), err: "malformed execution error frame"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			got, err := ReadExecStream(bytes.NewReader(tc.stream), &stdout, &stderr)
			if tc.err != "" {
				if err == nil || !strings.Contains(err.Error(), tc.err) {
					t.Fatalf("err = %v, want %q", err, tc.err)
				}
			} else if err != nil {
				t.Fatalf("err = %v", err)
			}
			if stdout.String() != tc.stdout || stderr.String() != tc.stderr {
				t.Fatalf("stdout %q stderr %q, want %q %q", stdout.String(), stderr.String(), tc.stdout, tc.stderr)
			}
			if got.ExitCode != tc.exit || len(got.Responses) != tc.hosts {
				t.Fatalf("exit = %d with %d responses, want %d with %d", got.ExitCode, len(got.Responses), tc.exit, tc.hosts)
			}
		})
	}
}

func TestErrorFrameIsAPIError(t *testing.T) {
	_, err := ReadExecStream(bytes.NewReader(frame(FrameError, `{"code":"usage","error":"no such host"}`)), &bytes.Buffer{}, &bytes.Buffer{})
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.Code != CodeUsage {
		t.Fatalf("err = %v, want usage APIError", err)
	}
}

func TestWriteFrameSplitsDataAndRoundTrips(t *testing.T) {
	big := bytes.Repeat([]byte("x"), 2*MaxDataFrameBytes+7)
	var buf bytes.Buffer
	if err := WriteFrame(&buf, FrameStdout, big); err != nil {
		t.Fatal(err)
	}
	if buf.Len() != 3*frameHeaderBytes+len(big) {
		t.Fatalf("encoded %d bytes, want three data frames", buf.Len())
	}
	result := ExecResult{ExitCode: 6, Responses: []runner.Response{{Host: "web-1", Status: "denied"}, {Host: "web-2", Status: "completed"}}}
	if err := WriteExecResult(func(kind byte, payload []byte) error { return WriteFrame(&buf, kind, payload) }, result); err != nil {
		t.Fatal(err)
	}
	var stdout bytes.Buffer
	got, err := ReadExecStream(&buf, &stdout, &bytes.Buffer{})
	if err != nil || !bytes.Equal(stdout.Bytes(), big) || got.ExitCode != 6 || len(got.Responses) != 2 || got.Responses[1].Host != "web-2" {
		t.Fatalf("round trip: %v %+v", err, got)
	}
	if err := WriteFrame(&buf, FrameResult, make([]byte, MaxMessageFrameBytes+1)); !errors.Is(err, ErrFrameTooLarge) {
		t.Fatalf("oversized result: %v", err)
	}
	if err := WriteFrame(&buf, 9, nil); err == nil {
		t.Fatal("unknown frame type accepted")
	}
}

// A target's response at the gateway's output cap fits one frame even when
// JSON escapes every output byte, and an oversized response is refused before
// anything is written.
func TestEncodeExecResultBoundsEachResponse(t *testing.T) {
	worst := strings.Repeat("<", MaxExecOutputBytes) // JSON escapes '<' as \u003c
	fits := ExecResult{Responses: []runner.Response{{Host: "web-1", Cmd: strings.Repeat("<", 2048), Stdout: worst, Stderr: worst}}}
	if _, err := EncodeExecResult(fits); err != nil {
		t.Fatalf("capped response does not fit a frame: %v", err)
	}
	tooBig := ExecResult{Responses: []runner.Response{{Host: "web-1", Stdout: strings.Repeat("<", MaxMessageFrameBytes)}}}
	wrote := false
	err := WriteExecResult(func(byte, []byte) error { wrote = true; return nil }, tooBig)
	if !errors.Is(err, ErrFrameTooLarge) || wrote {
		t.Fatalf("oversized response: err=%v wrote=%v", err, wrote)
	}
}

func FuzzReadExecStream(f *testing.F) {
	f.Add(concat(frame(FrameStdout, "out"), frame(FrameStderr, "err"), frame(FrameResponse, `{"host":"web-1","status":"completed"}`), frame(FrameResult, `{"exit_code":0}`)))
	f.Add(frame(FrameError, `{"code":"busy","error":"x"}`))
	f.Add(header(FrameResponse, MaxMessageFrameBytes))
	f.Add([]byte{FrameStdout, 0xff, 0xff, 0xff, 0xff})
	f.Fuzz(func(t *testing.T, data []byte) {
		var stdout, stderr bytes.Buffer
		_, err := ReadExecStream(bytes.NewReader(data), &stdout, &stderr)
		// A decoded result needs at least one complete frame.
		if err == nil && len(data) < frameHeaderBytes {
			t.Fatalf("decoded a result from %d bytes", len(data))
		}
		// Output is only ever a copy of data frames from the input.
		if stdout.Len()+stderr.Len() > len(data) {
			t.Fatalf("emitted %d bytes from a %d byte stream", stdout.Len()+stderr.Len(), len(data))
		}
	})
}
