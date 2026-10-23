// Package remoteclient implements the hosted HTTPS control-plane client.
package remoteclient

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/Praeviso/AgentSSH/internal/inventory"
	"github.com/Praeviso/AgentSSH/internal/managedmode"
	"github.com/Praeviso/AgentSSH/internal/remote"
	"github.com/Praeviso/AgentSSH/internal/runner"
	"gopkg.in/yaml.v3"
)

// RequestTimeout bounds each control-plane request.
var RequestTimeout = 10 * time.Second

const (
	fileDeviceKey = "device.key"
	fileCache     = "bundle.cache.json"
)

// State is the complete enrollment record; unknown fields are rejected.
type State struct {
	ServerURL       string    `yaml:"server_url"`
	DeviceID        string    `yaml:"device_id"`
	BundlePublicKey string    `yaml:"bundle_public_key"`
	EnrolledAt      time.Time `yaml:"enrolled_at"`
	// Mode is the control plane's mode, checked on every response. Records
	// written before modes existed have none and are managed.
	Mode string `yaml:"mode,omitempty"`
}

// Gateway reports whether the device forwards commands to a gateway rather
// than running them itself under a managed configuration.
func (s State) Gateway() bool { return s.Mode == remote.ModeGateway }

// LoadMode returns the mode home is enrolled in, or "" when it is not
// enrolled.
func LoadMode(home string) (string, error) {
	if !managedmode.Enrolled(home) {
		return "", nil
	}
	state, err := LoadState(home)
	if err != nil {
		return "", err
	}
	return state.Mode, nil
}

// ModeMismatchError reports a control plane whose mode is not the one the
// device enrolled for (or asked to enroll for).
type ModeMismatchError struct {
	Want, Got string
}

func (e *ModeMismatchError) Error() string {
	return fmt.Sprintf("the control plane runs in %s mode, not %s mode", e.Got, e.Want)
}

// UnreachableError distinguishes transport failures from protocol refusals.
type UnreachableError struct{ Err error }

func (e *UnreachableError) Error() string { return fmt.Sprintf("control plane unreachable: %v", e.Err) }
func (e *UnreachableError) Unwrap() error { return e.Err }

// LoadState validates the unversioned enrollment record.
func LoadState(home string) (State, error) {
	data, err := os.ReadFile(filepath.Join(managedmode.Dir(home), managedmode.MarkerName))
	if err != nil {
		return State{}, fmt.Errorf("read remote enrollment: %w", err)
	}
	var state State
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(&state); err != nil {
		return State{}, invalidEnrollment(err)
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return State{}, invalidEnrollment(errors.New("record must contain one document"))
	}
	base, err := remote.HTTPSBaseURL(state.ServerURL)
	if err != nil || base != state.ServerURL || !validDeviceID(state.DeviceID) || state.EnrolledAt.IsZero() {
		return State{}, invalidEnrollment(errors.New("invalid URL, device ID or enrollment time"))
	}
	if _, err := remote.DecodePublicKey(state.BundlePublicKey); err != nil {
		return State{}, invalidEnrollment(err)
	}
	switch state.Mode {
	case "":
		state.Mode = remote.ModeManaged
	case remote.ModeManaged, remote.ModeGateway:
	default:
		return State{}, invalidEnrollment(fmt.Errorf("unknown mode %q", state.Mode))
	}
	return state, nil
}

func invalidEnrollment(err error) error {
	return fmt.Errorf("invalid remote enrollment; run agentssh remote leave, then re-enroll this device: %w", err)
}

// Client authenticates as one enrolled device.
type Client struct {
	State State
	http  *http.Client
	// stream shares http's signing transport without a whole-request
	// timeout, for executions that run as long as their command.
	stream *http.Client
}

// NewClient loads the device key and uses ordinary HTTPS trust.
func NewClient(home string) (*Client, error) {
	state, err := LoadState(home)
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(filepath.Join(managedmode.Dir(home), fileDeviceKey))
	if err != nil {
		return nil, fmt.Errorf("read device key: %w", err)
	}
	block, rest := pem.Decode(data)
	if block == nil || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("invalid HTTPS device key")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, errors.New("invalid HTTPS device key")
	}
	key, ok := parsed.(ed25519.PrivateKey)
	if !ok {
		return nil, errors.New("HTTPS device key must be Ed25519")
	}
	client := signedHTTPClient(key, state.DeviceID, remote.DeviceSignatureTag, state.Mode)
	stream := *client
	stream.Timeout = 0
	return &Client{State: state, http: client, stream: &stream}, nil
}

// Status reports the device's standing; a revoked device gets an APIError.
func (c *Client) Status(ctx context.Context) (remote.StatusResponse, error) {
	var out remote.StatusResponse
	err := c.call(ctx, http.MethodGet, remote.PathStatus, nil, &out)
	return out, err
}

// FetchBundle downloads the signed configuration bundle.
func (c *Client) FetchBundle(ctx context.Context) (remote.BundleResponse, error) {
	var out remote.BundleResponse
	err := c.call(ctx, http.MethodGet, remote.PathBundle, nil, &out)
	return out, err
}

// Hosts lists the hosts and groups a gateway runs commands on for this
// device.
func (c *Client) Hosts(ctx context.Context) (inventory.PublicInventory, error) {
	var out inventory.PublicInventory
	err := c.call(ctx, http.MethodGet, remote.PathHosts, nil, &out)
	return out, err
}

// RequestStatus reads a gateway's audit status of one of this device's
// requests.
func (c *Client) RequestStatus(ctx context.Context, reqID string) (runner.Response, error) {
	var out runner.Response
	err := c.call(ctx, http.MethodPost, remote.PathRequestStatus, remote.RequestStatusRequest{ReqID: reqID}, &out)
	return out, err
}

// ApprovalStatus reads one of this device's approval requests on a gateway.
func (c *Client) ApprovalStatus(ctx context.Context, id string) (remote.ApprovalStatusResponse, error) {
	var out remote.ApprovalStatusResponse
	err := c.call(ctx, http.MethodPost, remote.PathApprovalStatus, remote.ApprovalStatusRequest{ApprovalID: id}, &out)
	return out, err
}

// PlanStatus reads one of this device's plans on a gateway.
func (c *Client) PlanStatus(ctx context.Context, id string) (remote.PlanStatusResponse, error) {
	var out remote.PlanStatusResponse
	err := c.call(ctx, http.MethodPost, remote.PathPlanStatus, remote.PlanStatusRequest{PlanID: id}, &out)
	return out, err
}

// SubmitPlan submits a plan for approval on a gateway without running it.
func (c *Client) SubmitPlan(ctx context.Context, req remote.PlanSubmitRequest) (remote.PlanSubmitResult, error) {
	var out remote.PlanSubmitResult
	err := c.call(ctx, http.MethodPost, remote.PathPlanSubmit, req, &out)
	return out, err
}

// Authorize asks a gateway how each check would be authorized now.
func (c *Client) Authorize(ctx context.Context, checks []remote.AuthorizeCheck) (remote.AuthorizeResponse, error) {
	var out remote.AuthorizeResponse
	err := c.call(ctx, http.MethodPost, remote.PathAuthorize, remote.AuthorizeRequest{Checks: checks}, &out)
	return out, err
}

// Sign asks the control plane to sign SSH userauth data for host.
func (c *Client) Sign(ctx context.Context, host string, data []byte) (remote.SignResponse, error) {
	var out remote.SignResponse
	err := c.call(ctx, http.MethodPost, remote.PathSign, remote.SignRequest{Host: host, Data: data}, &out)
	return out, err
}

// ReattachTimeout bounds how long Exec keeps reattaching to a run without
// making progress after its stream breaks.
var ReattachTimeout = 2 * time.Minute

// cancelTimeout bounds the explicit cancel sent when Exec's context ends.
const cancelTimeout = 5 * time.Second

// Exec starts one command on a gateway, copying streamed output to stdout and
// stderr. A broken connection does not stop the command: Exec reattaches and
// continues where it left off. The run ID is chosen here, so even a lost first
// response is recovered by repeating the request, which joins the run rather
// than starting it twice. Cancelling ctx sends an explicit cancel, which ends
// the remote command, and returns the context's error.
func (c *Client) Exec(ctx context.Context, req remote.ExecRequest, stdout, stderr io.Writer) (remote.ExecResult, error) {
	return c.ExecNotify(ctx, req, nil, stdout, stderr)
}

// ExecNotify is Exec that also calls onRun with each run frame, before the
// output that follows it, so a caller can attribute streamed output to the
// run's request ID.
func (c *Client) ExecNotify(ctx context.Context, req remote.ExecRequest, onRun func(remote.ExecRun), stdout, stderr io.Writer) (remote.ExecResult, error) {
	if req.RunID == "" {
		req.RunID = remote.NewRunID()
	}
	stream := remote.ExecStream{RunID: req.RunID, OnRun: onRun}
	start := func() (remote.ExecResult, error) {
		return c.openStream(ctx, remote.PathExec, req, &stream, stdout, stderr)
	}
	result, err := start()
	return c.follow(ctx, &stream, start, result, err, stdout, stderr)
}

// Attach replays a run of this device from the start and follows it to its
// result, reattaching like Exec.
func (c *Client) Attach(ctx context.Context, runID string, stdout, stderr io.Writer) (remote.ExecResult, error) {
	stream := remote.ExecStream{RunID: runID}
	start := func() (remote.ExecResult, error) {
		return c.openStream(ctx, remote.PathExecAttach, remote.ExecAttachRequest{RunID: runID}, &stream, stdout, stderr)
	}
	result, err := start()
	return c.follow(ctx, &stream, start, result, err, stdout, stderr)
}

// Cancel stops a run of this device. It reports false when nothing was
// running under the ID; a request with that ID that has not arrived yet is
// then refused.
func (c *Client) Cancel(ctx context.Context, runID string) (bool, error) {
	var out remote.ExecCancelResponse
	err := c.call(ctx, http.MethodPost, remote.PathExecCancel, remote.ExecCancelRequest{RunID: runID}, &out)
	return out.Cancelled, err
}

// follow retries a broken stream: start again until a run frame has arrived,
// then reattach from the offset of the frames already consumed.
func (c *Client) follow(ctx context.Context, stream *remote.ExecStream, start func() (remote.ExecResult, error), result remote.ExecResult, err error, stdout, stderr io.Writer) (remote.ExecResult, error) {
	backoff := 200 * time.Millisecond
	deadline := time.Now().Add(ReattachTimeout)
	offset := stream.Offset
	for err != nil {
		if ctx.Err() != nil {
			return remote.ExecResult{}, c.cancelRun(stream.RunID, ctx.Err())
		}
		var unreachable *UnreachableError
		if !errors.Is(err, remote.ErrNoResult) && !errors.As(err, &unreachable) {
			return remote.ExecResult{}, err
		}
		if stream.Offset != offset {
			// Progress since the last break: restart the patience window.
			offset, backoff, deadline = stream.Offset, 200*time.Millisecond, time.Now().Add(ReattachTimeout)
		}
		if time.Now().After(deadline) {
			return remote.ExecResult{}, fmt.Errorf("lost run %s and could not reattach within %s; it may still be running: %w", stream.RunID, ReattachTimeout, err)
		}
		select {
		case <-time.After(backoff):
		case <-ctx.Done():
			return remote.ExecResult{}, c.cancelRun(stream.RunID, ctx.Err())
		}
		backoff = min(2*backoff, 5*time.Second)
		if !stream.Started {
			result, err = start()
			continue
		}
		result, err = c.openStream(ctx, remote.PathExecAttach, remote.ExecAttachRequest{RunID: stream.RunID, Offset: stream.Offset}, stream, stdout, stderr)
	}
	return result, nil
}

// cancelRun turns a cancelled context into an explicit cancel of the run, so a
// local Ctrl-C still stops the remote command.
func (c *Client) cancelRun(runID string, cause error) error {
	ctx, done := context.WithTimeout(context.Background(), cancelTimeout)
	defer done()
	if _, err := c.Cancel(ctx, runID); err != nil {
		return fmt.Errorf("%w; run %s may still be running (cancel failed: %v)", cause, runID, err)
	}
	return cause
}

func (c *Client) openStream(ctx context.Context, path string, body any, stream *remote.ExecStream, stdout, stderr io.Writer) (remote.ExecResult, error) {
	data, err := json.Marshal(body)
	if err != nil {
		return remote.ExecResult{}, err
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.State.ServerURL+path, bytes.NewReader(data))
	if err != nil {
		return remote.ExecResult{}, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	resp, err := c.stream.Do(httpReq)
	if err != nil {
		return remote.ExecResult{}, transportError(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode/100 != 2 {
		data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		if err != nil {
			return remote.ExecResult{}, &UnreachableError{Err: err}
		}
		return remote.ExecResult{}, statusError(resp.StatusCode, data)
	}
	if resp.Header.Get("Content-Type") != remote.ExecContentType {
		return remote.ExecResult{}, fmt.Errorf("control plane answered %s with %q, not an execution stream", path, resp.Header.Get("Content-Type"))
	}
	return stream.Read(resp.Body, stdout, stderr)
}

func (c *Client) call(ctx context.Context, method string, path string, body any, out any) error {
	return doJSON(ctx, c.http, method, c.State.ServerURL+path, body, out)
}

func doJSON(ctx context.Context, client *http.Client, method string, endpoint string, body any, out any) error {
	ctx, cancel := context.WithTimeout(ctx, RequestTimeout)
	defer cancel()
	var reader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(data)
	}
	req, err := http.NewRequestWithContext(ctx, method, endpoint, reader)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := client.Do(req)
	if err != nil {
		return transportError(err)
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(io.LimitReader(resp.Body, (16<<20)+1))
	if err != nil {
		return &UnreachableError{Err: err}
	}
	if len(data) > 16<<20 {
		return errors.New("control plane response is too large")
	}
	if resp.StatusCode/100 != 2 {
		return statusError(resp.StatusCode, data)
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(data, out); err != nil {
		return fmt.Errorf("decode control plane response: %w", err)
	}
	return nil
}

// transportError classifies a failed round trip. Refusals the transport
// raises itself (a redirect, a control plane of another mode) are not network
// failures, so they never permit falling back to cached state.
func transportError(err error) error {
	var apiErr *remote.APIError
	if errors.As(err, &apiErr) {
		return apiErr
	}
	var mismatch *ModeMismatchError
	if errors.As(err, &mismatch) {
		return mismatch
	}
	return &UnreachableError{Err: err}
}

// statusError classifies a non-2xx response body.
func statusError(status int, data []byte) error {
	var apiErr remote.ErrorResponse
	if json.Unmarshal(data, &apiErr) != nil || apiErr.Code == "" || apiErr.Error == "" {
		// An ingress cannot report device standing when its backend is
		// unavailable. Keep actual protocol refusals distinct from gateway
		// failures so only the latter permit an unexpired cached bundle.
		if ingressFailure(status) {
			return &UnreachableError{Err: fmt.Errorf("HTTPS ingress returned HTTP %d", status)}
		}
		return &remote.APIError{Status: status, Code: remote.CodeInternal, Message: fmt.Sprintf("HTTP %d", status)}
	}
	return &remote.APIError{Status: status, Code: apiErr.Code, Message: apiErr.Error}
}

// Leave removes the device credentials and cached bundle, returning home to
// local mode. The marker goes first so a partial failure still exits remote mode.
func Leave(home string) error {
	dir := managedmode.Dir(home)
	if err := os.Remove(filepath.Join(dir, managedmode.MarkerName)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return os.RemoveAll(dir)
}
