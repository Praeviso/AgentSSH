package gateway

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Praeviso/AgentSSH/internal/audit"
	"github.com/Praeviso/AgentSSH/internal/remote"
	"github.com/Praeviso/AgentSSH/internal/runner"
)

// FailSecurityAudit injects a file-publication failure while retaining the real
// state transaction, durable pending event, and subsequent repair paths.
func FailSecurityAudit(err error) (restore func()) {
	original := appendSecurityRecord
	appendSecurityRecord = func(string, audit.Record) error { return err }
	return func() { appendSecurityRecord = original }
}

// PauseActivationAudit models a blocked audit sink while letting concurrent
// restrictions use the real transaction and publication paths.
func PauseActivationAudit() (started <-chan struct{}, release func()) {
	original := appendSecurityRecord
	entered, resume := make(chan struct{}), make(chan struct{})
	appendSecurityRecord = func(dir string, record audit.Record) error {
		if record.Event == audit.EventDeviceActivated {
			close(entered)
			<-resume
		}
		return original(dir, record)
	}
	return entered, func() {
		close(resume)
		appendSecurityRecord = original
	}
}

// FailNextClaim makes the next run claim fail with err, as a full disk would.
func FailNextClaim(err error) (restore func()) {
	original := claimRecord
	claimRecord = func(string, []byte) error {
		claimRecord = original
		return err
	}
	return func() { claimRecord = original }
}

// FailNextSpool injects a private spool creation failure before a run's claim.
func FailNextSpool(err error) (restore func()) {
	original := openRunSpool
	openRunSpool = func(string) (*os.File, error) {
		openRunSpool = original
		return nil, err
	}
	return func() { openRunSpool = original }
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

// LiveRunCount lets tests wait for completion before injecting a new failure.
func (s *Server) LiveRunCount(deviceID string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	count := 0
	for _, rn := range s.runs {
		if rn.deviceID == deviceID {
			count++
		}
	}
	return count
}

// OpenRoutes are the method and path of the token API's routes and its
// OpenAPI document (the MCP endpoint is not part of the document).
func (s *Server) OpenRoutes() []string {
	var routes []string
	for _, op := range s.apiOperations() {
		routes = append(routes, op.method+" "+op.path)
	}
	return append(routes, "GET "+remote.PathAPIOpenAPI)
}

// SetMaxPendingClients lowers the cap on registered clients awaiting consent.
func SetMaxPendingClients(n int) (restore func()) {
	old := maxPendingClients
	maxPendingClients = n
	return func() { maxPendingClients = old }
}
