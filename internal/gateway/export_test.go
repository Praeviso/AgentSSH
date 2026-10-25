package gateway

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/Praeviso/AgentSSH/internal/remote"
	"github.com/Praeviso/AgentSSH/internal/runner"
)

// FailNextClaim makes the next run claim fail with err, as a full disk would.
func FailNextClaim(err error) (restore func()) {
	original := claimRecord
	claimRecord = func(string, []byte) error {
		claimRecord = original
		return err
	}
	return func() { claimRecord = original }
}

// SetRecordLifetimes shortens how often records are aged out and how long
// cancel records and the idempotency window last.
func SetRecordLifetimes(sweep, cancelTTL, window time.Duration) (restore func()) {
	oldSweep, oldCancel, oldWindow := runSweepEvery, cancelTombstoneTTL, idempotencyWindow
	runSweepEvery, cancelTombstoneTTL, idempotencyWindow = sweep, cancelTTL, window
	return func() { runSweepEvery, cancelTombstoneTTL, idempotencyWindow = oldSweep, oldCancel, oldWindow }
}

// The reserve held per target must cover a minimal response in the worst
// case: every kept text field over the clip length, in a byte JSON escapes
// as six.
func TestMinimalResponseFitsItsReserve(t *testing.T) {
	long := strings.Repeat("<", 10*minimalFieldBytes)
	worst := minimalResponse(runner.Response{
		ExecutionState: long, NextAction: long, ReqID: long, SessionID: long, Host: long,
		CmdSHA256: long, Status: long, ExitCode: -2147483648, DurationMS: -9223372036854775808,
		PolicyAction: long, PolicyRule: long, ApprovalID: long,
		Stdout: long, Stderr: long, Cmd: long, ApprovalMatcher: long,
	})
	payload, err := json.Marshal(worst)
	if err != nil {
		t.Fatal(err)
	}
	if size := remote.FrameSize(len(payload)); size > responseReserveBytes {
		t.Fatalf("minimal response frame is %d bytes, reserve %d", size, responseReserveBytes)
	}
	final, _ := json.Marshal(remote.ExecFinal{ExitCode: -2147483648, Truncated: true})
	if size := remote.FrameSize(len(final)); size > finalReserveBytes {
		t.Fatalf("final frame is %d bytes, reserve %d", size, finalReserveBytes)
	}
}

// StopRuns cancels every live run, so a test that failed with a run still
// going (one its revoked device can no longer cancel) can end.
func (s *Server) StopRuns() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, rn := range s.runs {
		if rn.cancel != nil {
			rn.cancel(nil)
		}
	}
}

// OpenRoutes are the method and path of every route that authenticates
// itself: the token API and its OpenAPI document.
func (s *Server) OpenRoutes() []string {
	var routes []string
	for _, route := range s.tokenRoutes() {
		routes = append(routes, route.Method+" "+route.Path)
	}
	return append(routes, "GET "+remote.PathAPIOpenAPI)
}
