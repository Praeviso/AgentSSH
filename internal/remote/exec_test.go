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

func TestReadExecStream(t *testing.T) {
	result := `{"exit_code":1,"responses":[{"execution_state":"finished","req_id":"r1","session_id":"s","host":"web-1","status":"failed","exit_code":3,"duration_ms":5,"stdout":"","stderr":"","output_truncated":false,"redactions":0}]}`
	for _, tc := range []struct {
		name           string
		stream         []byte
		stdout, stderr string
		exit           int
		err            string
	}{
		{name: "output then result", stream: concat(frame(FrameStdout, "a"), frame(FrameStderr, "b"), frame(FrameStdout, "c"), frame(FrameResult, result)), stdout: "ac", stderr: "b", exit: 1},
		{name: "result only", stream: frame(FrameResult, `{"exit_code":0,"responses":[]}`)},
		{name: "empty stream", stream: nil, err: ErrNoResult.Error()},
		{name: "disconnect before result", stream: frame(FrameStdout, "partial"), stdout: "partial", err: ErrNoResult.Error()},
		{name: "truncated header", stream: concat(frame(FrameStdout, "x"), []byte{FrameResult, 0, 0}), stdout: "x", err: ErrNoResult.Error()},
		{name: "truncated payload", stream: concat(header(FrameResult, 10), []byte(`{"exit`)), err: ErrNoResult.Error()},
		{name: "unknown type", stream: frame(9, "x"), err: "unknown execution frame type 9"},
		{name: "oversized data frame", stream: header(FrameStdout, MaxDataFrameBytes+1), err: ErrFrameTooLarge.Error()},
		{name: "oversized result frame", stream: header(FrameResult, MaxFinalFrameBytes+1), err: ErrFrameTooLarge.Error()},
		{name: "malformed result", stream: frame(FrameResult, `{"exit_code":`), err: "malformed execution result"},
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
			if got.ExitCode != tc.exit {
				t.Fatalf("exit = %d, want %d", got.ExitCode, tc.exit)
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
	payload, _ := json.Marshal(ExecResult{ExitCode: 6, Responses: []runner.Response{{Host: "web-1", Status: "denied"}}})
	var buf bytes.Buffer
	if err := WriteFrame(&buf, FrameStdout, big); err != nil {
		t.Fatal(err)
	}
	if err := WriteFrame(&buf, FrameResult, payload); err != nil {
		t.Fatal(err)
	}
	if want := 3*frameHeaderBytes + len(big) + frameHeaderBytes + len(payload); buf.Len() != want {
		t.Fatalf("encoded %d bytes, want %d (three data frames and a result)", buf.Len(), want)
	}
	var stdout bytes.Buffer
	result, err := ReadExecStream(&buf, &stdout, &bytes.Buffer{})
	if err != nil || !bytes.Equal(stdout.Bytes(), big) || result.ExitCode != 6 || result.Responses[0].Status != "denied" {
		t.Fatalf("round trip: %v exit=%d", err, result.ExitCode)
	}
	if err := WriteFrame(&buf, FrameResult, make([]byte, MaxFinalFrameBytes+1)); !errors.Is(err, ErrFrameTooLarge) {
		t.Fatalf("oversized result: %v", err)
	}
	if err := WriteFrame(&buf, 9, nil); err == nil {
		t.Fatal("unknown frame type accepted")
	}
}

func FuzzReadExecStream(f *testing.F) {
	f.Add(concat(frame(FrameStdout, "out"), frame(FrameStderr, "err"), frame(FrameResult, `{"exit_code":0,"responses":[]}`)))
	f.Add(frame(FrameError, `{"code":"busy","error":"x"}`))
	f.Add(header(FrameResult, MaxFinalFrameBytes))
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
