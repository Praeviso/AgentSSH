package gateway

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/Praeviso/AgentSSH/internal/approval"
	"github.com/Praeviso/AgentSSH/internal/audit"
	"github.com/Praeviso/AgentSSH/internal/controlplane"
	"github.com/Praeviso/AgentSSH/internal/inventory"
	"github.com/Praeviso/AgentSSH/internal/policy"
	"github.com/Praeviso/AgentSSH/internal/remote"
	"github.com/Praeviso/AgentSSH/internal/runner"
	"github.com/Praeviso/AgentSSH/internal/session"
	"gopkg.in/yaml.v3"
)

// maxPlanSubmitBody fits MaxPlanCommands commands at the command size limit
// only if most are short; a plan near the cap is refused as too large.
const maxPlanSubmitBody = 8 << 20

// maxReviewTextBytes bounds a plan review's free-text fields.
const maxReviewTextBytes = 16 << 10

// DefaultMaxPendingApprovals is Server.MaxPendingApprovals's default.
const DefaultMaxPendingApprovals = 1000

func (s *Server) maxPendingApprovals() int {
	if s.MaxPendingApprovals > 0 {
		return s.MaxPendingApprovals
	}
	return DefaultMaxPendingApprovals
}

// approvals are deviceID's approval stores for its own requests: what the
// device creates is capped, since it stays on the gateway's disk until an
// operator decides.
func (s *Server) approvals(deviceID string) approvalStores {
	stores := deviceApprovals(s.Dir, deviceID)
	stores.Pending.MaxPending = s.maxPendingApprovals()
	return stores
}

// approvalStores are one device's approval state on the gateway.
type approvalStores struct {
	Pending  approval.PendingStore
	Sessions approval.SessionStore
}

func deviceApprovals(dir, deviceID string) approvalStores {
	base := filepath.Join(dir, "devices", deviceID, "approval")
	return approvalStores{
		Pending: approval.PendingStore{
			PendingDir:   filepath.Join(base, "pending"),
			ResponsesDir: filepath.Join(base, "responses"),
			PlansDir:     filepath.Join(base, "plans"),
		},
		Sessions: approval.SessionStore{Dir: filepath.Join(base, "sessions")},
	}
}

// approvalRoutes let a device submit and query approvals. None resolves
// one: decisions are the gateway operator's (DecideApproval, DecidePlan).
func (s *Server) approvalRoutes() []controlplane.Route {
	return []controlplane.Route{
		{Method: "POST", Path: remote.PathApprovalStatus, Handler: s.handleApprovalStatus},
		{Method: "POST", Path: remote.PathPlanSubmit, Handler: s.handlePlanSubmit, MaxBody: maxPlanSubmitBody},
		{Method: "POST", Path: remote.PathPlanStatus, Handler: s.handlePlanStatus},
		{Method: "POST", Path: remote.PathAuthorize, Handler: s.handleAuthorize, MaxBody: maxPlanSubmitBody},
	}
}

// deviceRuntime is the approval settings of deviceID's pushed policy, or the
// defaults when it has none.
func (s *Server) deviceRuntime(deviceID string) approval.RuntimeConfig {
	_, pol, err := s.loadDeviceConfig(deviceID)
	if err != nil {
		return approvalRuntime(deviceID, policy.Approval{})
	}
	return approvalRuntime(deviceID, pol.Approval)
}

func (s *Server) loadDeviceConfig(deviceID string) (inventory.Inventory, policy.Config, error) {
	cfg, err := s.Store.Config(deviceID)
	if err != nil {
		return inventory.Inventory{}, policy.Config{}, err
	}
	return remote.ParseManaged(cfg.InventoryYAML, cfg.PolicyYAML, nil)
}

// writeApprovalError answers a lookup the CLI rejects as a usage error with
// the same message.
func writeApprovalError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, approval.ErrInvalidID), errors.Is(err, approval.ErrPendingNotFound),
		errors.Is(err, approval.ErrInvalidPlanID), errors.Is(err, approval.ErrPlanNotFound),
		errors.Is(err, approval.ErrPlanDigest):
		controlplane.WriteError(w, http.StatusNotFound, remote.CodeUsage, err.Error())
	default:
		controlplane.WriteError(w, http.StatusInternalServerError, remote.CodeInternal, "approval store unavailable")
	}
}

func (s *Server) handleApprovalStatus(w http.ResponseWriter, _ *http.Request, device controlplane.Device, body []byte) {
	var req remote.ApprovalStatusRequest
	if controlplane.DecodeBody(body, &req) != nil {
		controlplane.WriteError(w, http.StatusBadRequest, remote.CodeBadRequest, "malformed approval status query")
		return
	}
	status, err := s.approvals(device.ID).Pending.Status(req.ApprovalID)
	if err != nil {
		writeApprovalError(w, err)
		return
	}
	controlplane.WriteJSON(w, http.StatusOK, remote.ApprovalStatusResponse{Status: status, WaitTimeoutMS: s.deviceRuntime(device.ID).WaitTimeout.Milliseconds()})
}

func (s *Server) handlePlanStatus(w http.ResponseWriter, _ *http.Request, device controlplane.Device, body []byte) {
	var req remote.PlanStatusRequest
	if controlplane.DecodeBody(body, &req) != nil {
		controlplane.WriteError(w, http.StatusBadRequest, remote.CodeBadRequest, "malformed plan status query")
		return
	}
	status, err := s.approvals(device.ID).Pending.PlanStatus(req.PlanID)
	if err != nil {
		writeApprovalError(w, err)
		return
	}
	controlplane.WriteJSON(w, http.StatusOK, remote.PlanStatusResponse{Status: status, WaitTimeoutMS: s.deviceRuntime(device.ID).WaitTimeout.Milliseconds()})
}

func (s *Server) handlePlanSubmit(w http.ResponseWriter, _ *http.Request, device controlplane.Device, body []byte) {
	var req remote.PlanSubmitRequest
	if controlplane.DecodeBody(body, &req) != nil {
		controlplane.WriteError(w, http.StatusBadRequest, remote.CodeBadRequest, "malformed plan submission")
		return
	}
	if err := validatePlanSubmit(req); err != nil {
		controlplane.WriteError(w, http.StatusBadRequest, remote.CodeUsage, err.Error())
		return
	}
	inv, pol, ok := s.deviceConfig(w, device.ID)
	if !ok {
		return
	}
	resolved, err := inventory.NewResolver(inv).Resolve(req.Host)
	if err != nil {
		controlplane.WriteError(w, http.StatusBadRequest, remote.CodeUsage, fmt.Sprintf("%v\n  list all hosts: agentssh hosts", err))
		return
	}
	if resolved.Kind != inventory.TargetKindHost || len(resolved.Targets) != 1 {
		controlplane.WriteError(w, http.StatusBadRequest, remote.CodeUsage, "plan submit targets a single host; submit one plan per host")
		return
	}
	// Plan IDs are the device's; one another device holds is refused, so an
	// operator's decision by ID cannot be steered onto this device's plan.
	if taken, err := planIDTaken(s.Dir, device.ID, req.PlanID); err != nil || taken {
		if err != nil {
			controlplane.WriteError(w, http.StatusInternalServerError, remote.CodeInternal, "approval store unavailable")
		} else {
			controlplane.WriteError(w, http.StatusConflict, remote.CodeUsage, "plan id is already in use; submit again")
		}
		return
	}
	runtime := approvalRuntime(device.ID, pol.Approval)
	if !runtime.Enabled {
		controlplane.WriteError(w, http.StatusBadRequest, remote.CodeUsage, "plan submit requires the async approval channel\n  approvals are disabled in this device's policy on the gateway; ask the gateway's administrator")
		return
	}
	commands := make([]runner.PlanCommand, 0, len(req.Commands))
	for _, command := range req.Commands {
		commands = append(commands, runner.PlanCommand{
			ID: command.ID, Name: command.Name, Phase: command.Phase, OnFailure: command.OnFailure, Cmd: command.Cmd,
			Stdin: runner.Stdin{SHA256: command.StdinSHA256, Bytes: command.StdinBytes}, PayloadRef: command.PayloadRef,
		})
	}
	stores := s.approvals(device.ID)
	lock, _ := s.submits.LoadOrStore(device.ID, new(sync.Mutex))
	lock.(*sync.Mutex).Lock()
	defer lock.(*sync.Mutex).Unlock()
	// Refuse a plan that cannot fit before it creates any request, so a
	// refusal leaves nothing half submitted. A gray-zone run creating a
	// request meanwhile can still make a plan stop part way; the cap holds
	// either way, since every request is counted as it is created.
	waiting, err := stores.Pending.Unresolved()
	if err != nil {
		controlplane.WriteError(w, http.StatusInternalServerError, remote.CodeInternal, "approval store unavailable")
		return
	}
	if waiting+len(commands) > stores.Pending.MaxPending {
		writeTooManyPending(w)
		return
	}
	env := runner.Env{
		Policy:    pol,
		Inventory: inv,
		Approval:  runtime,
		Sessions:  stores.Sessions,
		Pending:   stores.Pending,
		Audit:     s.deviceAudit(device.ID),
	}
	target := resolved.Targets[0].Name
	response, exitCode, err := runner.SubmitPlan(env, runner.PlanSubmitRequest{
		PlanID:   req.PlanID,
		Host:     target,
		Session:  session.Context{ID: req.Session, Host: target, Label: req.SessionLabel},
		Commands: commands,
		Review:   req.Review,
	})
	var usage runner.UsageError
	switch {
	case errors.As(err, &usage):
		controlplane.WriteError(w, http.StatusBadRequest, remote.CodeUsage, usage.Error())
		return
	case errors.Is(err, approval.ErrTooManyPending):
		writeTooManyPending(w)
		return
	case err != nil:
		controlplane.WriteError(w, http.StatusInternalServerError, remote.CodeInternal, "plan submission failed")
		return
	}
	controlplane.WriteJSON(w, http.StatusOK, remote.PlanSubmitResult{Response: response, ExitCode: exitCode})
}

func writeTooManyPending(w http.ResponseWriter) {
	controlplane.WriteError(w, http.StatusTooManyRequests, remote.CodeBusy, approval.ErrTooManyPending.Error())
}

func validatePlanSubmit(req remote.PlanSubmitRequest) error {
	switch {
	case !approval.ValidPlanID(req.PlanID):
		return approval.ErrInvalidPlanID
	case req.Session == "":
		return errors.New("a session must be declared for plan submit")
	case len(req.Commands) == 0:
		return errors.New("plan submit requires at least one command")
	case len(req.Commands) > remote.MaxPlanCommands:
		return fmt.Errorf("a plan has at most %d commands", remote.MaxPlanCommands)
	case len(req.SessionLabel) > remote.MaxExecLabelBytes:
		return fmt.Errorf("session label must be at most %d bytes", remote.MaxExecLabelBytes)
	}
	for name, value := range map[string]string{"host": req.Host, "session": req.Session, "execution id": req.Review.ExecutionID} {
		if len(value) > remote.MaxExecFieldBytes || strings.IndexFunc(value, unicode.IsControl) >= 0 {
			return fmt.Errorf("%s must be at most %d bytes without control characters", name, remote.MaxExecFieldBytes)
		}
	}
	// The review is shown to the operator; its text is the device's and must
	// not carry control characters (terminal escapes) or crowd the manifest.
	meta := req.Review.Metadata
	for _, value := range []string{meta.Description, meta.Impact, meta.Recovery} {
		if len(value) > maxReviewTextBytes || strings.IndexFunc(value, func(r rune) bool { return unicode.IsControl(r) && r != '\n' && r != '\t' }) >= 0 {
			return fmt.Errorf("plan description, impact and recovery must be at most %d bytes without control characters other than newlines and tabs", maxReviewTextBytes)
		}
	}
	review := []string{meta.Title, meta.Version, meta.Revision}
	if len(req.Review.Steps) > remote.MaxPlanCommands {
		return fmt.Errorf("a plan has at most %d steps", remote.MaxPlanCommands)
	}
	for _, step := range req.Review.Steps {
		review = append(review, step.ID, step.Name, step.Phase, step.OnFailure, step.Status, step.PolicyRule, step.ApprovalID, step.StdinSHA256, step.PayloadRef)
		if len(step.Cmd) > remote.MaxExecCommandBytes {
			return fmt.Errorf("command is %d bytes; the limit is %d bytes (128 KiB)", len(step.Cmd), remote.MaxExecCommandBytes)
		}
	}
	for _, value := range review {
		if len(value) > remote.MaxExecLabelBytes || strings.IndexFunc(value, unicode.IsControl) >= 0 {
			return fmt.Errorf("plan review fields must be at most %d bytes without control characters", remote.MaxExecLabelBytes)
		}
	}
	for _, command := range req.Commands {
		if strings.TrimSpace(command.Cmd) == "" {
			return errors.New("plan commands must not be empty")
		}
		if len(command.Cmd) > remote.MaxExecCommandBytes {
			return fmt.Errorf("command is %d bytes; the limit is %d bytes (128 KiB)", len(command.Cmd), remote.MaxExecCommandBytes)
		}
		if err := validStdinIdentity(command.StdinSHA256, command.StdinBytes); err != nil {
			return err
		}
		for _, value := range []string{command.ID, command.Name, command.Phase, command.OnFailure, command.PayloadRef} {
			if len(value) > remote.MaxExecLabelBytes || strings.IndexFunc(value, unicode.IsControl) >= 0 {
				return fmt.Errorf("plan step fields must be at most %d bytes without control characters", remote.MaxExecLabelBytes)
			}
		}
	}
	return nil
}

// emptySHA256 is the hash of an empty stdin.
const emptySHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

// validStdinIdentity checks that a stated stdin hash and size can describe
// one payload: a well-formed hash, a size within the stdin limit, no size
// without a hash, and size zero only for the empty payload's hash. The
// gateway cannot check the size against content it never receives at
// submit; grants bind it and execution compares it (CheckGrantedStdin).
func validStdinIdentity(sha string, bytes int64) error {
	switch {
	case sha == "" && bytes == 0:
		return nil
	case sha == "":
		return errors.New("a stdin size needs its sha256")
	case len(sha) != 64 || strings.Trim(sha, "0123456789abcdef") != "":
		return errors.New("stdin sha256 must be 64 lowercase hex characters")
	case bytes < 0 || bytes > remote.MaxExecStdinBytes:
		return fmt.Errorf("stdin is %d bytes; the limit is %d bytes (32 MiB)", bytes, remote.MaxExecStdinBytes)
	case bytes == 0 && sha != emptySHA256:
		return errors.New("a stdin of zero bytes has the empty payload's sha256")
	}
	return nil
}

func (s *Server) handleAuthorize(w http.ResponseWriter, _ *http.Request, device controlplane.Device, body []byte) {
	var req remote.AuthorizeRequest
	if controlplane.DecodeBody(body, &req) != nil || len(req.Checks) == 0 || len(req.Checks) > remote.MaxPlanCommands {
		controlplane.WriteError(w, http.StatusBadRequest, remote.CodeBadRequest, "malformed authorization query")
		return
	}
	inv, pol, ok := s.deviceConfig(w, device.ID)
	if !ok {
		return
	}
	runtime := approvalRuntime(device.ID, pol.Approval)
	sessions := s.approvals(device.ID).Sessions
	out := remote.AuthorizeResponse{ApprovalEnabled: runtime.Enabled, Results: make([]approval.AuthorizationStatus, 0, len(req.Checks))}
	for _, check := range req.Checks {
		auth, err := approval.PreflightAuthorize(pol, inv, sessions, runtime, check.Session, check.Host, check.Cmd, check.StdinSHA256)
		if err != nil {
			controlplane.WriteError(w, http.StatusBadRequest, remote.CodeUsage, fmt.Sprintf("policy is invalid: %v", err))
			return
		}
		auth, _ = approval.CheckGrantedStdin(auth, check.StdinBytes)
		out.Results = append(out.Results, auth.Status)
	}
	controlplane.WriteJSON(w, http.StatusOK, out)
}

// DeviceApproval is a pending request and the device that made it.
type DeviceApproval struct {
	DeviceID string `json:"device_id"`
	approval.PendingRequest
}

// deviceIDs lists the devices that have approval state.
func deviceIDs(dir string) ([]string, error) {
	entries, err := os.ReadDir(filepath.Join(dir, "devices"))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var ids []string
	for _, entry := range entries {
		if entry.IsDir() {
			ids = append(ids, entry.Name())
		}
	}
	sort.Strings(ids)
	return ids, nil
}

// ListApprovals returns every device's pending requests, oldest first.
func ListApprovals(dir string) ([]DeviceApproval, error) {
	ids, err := deviceIDs(dir)
	if err != nil {
		return nil, err
	}
	var out []DeviceApproval
	for _, id := range ids {
		requests, err := deviceApprovals(dir, id).Pending.List()
		if err != nil {
			return nil, err
		}
		for _, req := range requests {
			out = append(out, DeviceApproval{DeviceID: id, PendingRequest: req})
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].TS < out[j].TS })
	return out, nil
}

// ErrAmbiguousID refuses a lookup by an ID that more than one device holds.
// Devices mint plan IDs, so a device could reuse another's to have a decision
// meant for that plan land on its own.
var ErrAmbiguousID = errors.New("more than one device holds this ID; name the device with --device")

// findDevice returns the one device whose store holds an ID, as found reports
// it; deviceID, when set, limits the search to that device.
func findDevice(dir, deviceID string, found func(approvalStores) error) (string, error) {
	ids, err := deviceIDs(dir)
	if err != nil {
		return "", err
	}
	var match string
	notFound := approval.ErrPendingNotFound
	for _, id := range ids {
		if deviceID != "" && id != deviceID {
			continue
		}
		err := found(deviceApprovals(dir, id))
		switch {
		case err == nil && match != "":
			return "", ErrAmbiguousID
		case err == nil:
			match = id
		case errors.Is(err, approval.ErrPendingNotFound), errors.Is(err, approval.ErrPlanNotFound):
			notFound = err
		default:
			return "", err
		}
	}
	if match == "" {
		return "", notFound
	}
	// Reread the match: the scan may have overwritten what found recorded.
	return match, found(deviceApprovals(dir, match))
}

// ApprovalStatus finds an approval request, on deviceID when set, and reports
// its device and status.
func ApprovalStatus(dir, deviceID, id string) (string, approval.StatusResult, error) {
	var status approval.StatusResult
	deviceID, err := findDevice(dir, deviceID, func(stores approvalStores) (err error) {
		status, err = stores.Pending.Status(id)
		return err
	})
	return deviceID, status, err
}

// PlanStatus finds a plan, on deviceID when set, and reports its device and
// status.
func PlanStatus(dir, deviceID, id string) (string, approval.PlanStatus, error) {
	if !approval.ValidPlanID(id) {
		return "", approval.PlanStatus{}, approval.ErrInvalidPlanID
	}
	var status approval.PlanStatus
	deviceID, err := findDevice(dir, deviceID, func(stores approvalStores) (err error) {
		status, err = stores.Pending.PlanStatus(id)
		return err
	})
	if errors.Is(err, approval.ErrPendingNotFound) {
		err = approval.ErrPlanNotFound
	}
	return deviceID, status, err
}

// planIDTaken reports whether a device other than deviceID holds planID.
func planIDTaken(dir, deviceID, planID string) (bool, error) {
	ids, err := deviceIDs(dir)
	if err != nil {
		return false, err
	}
	for _, id := range ids {
		if id == deviceID {
			continue
		}
		_, err := deviceApprovals(dir, id).Pending.GetPlan(planID)
		if err == nil {
			return true, nil
		}
		if !errors.Is(err, approval.ErrPlanNotFound) {
			return false, err
		}
	}
	return false, nil
}

// Decider is who decides and, when an ID is ambiguous, the device it belongs
// to.
type Decider struct {
	// Operator is recorded in the decision's audit record.
	Operator string
	// DeviceID, when set, limits the lookup to that device.
	DeviceID string
}

// decisionOptions applies decisions for deviceID with its policy's grant
// lifetimes, recording them in the gateway's audit chain. A host-scope grant
// appends its rule to the device's policy and pushes it as a new
// configuration version.
func decisionOptions(dir string, store *controlplane.Store, deviceID, operator string, now time.Time) approval.ApplyOptions {
	server := &Server{Dir: dir, Store: store}
	runtime := server.deviceRuntime(deviceID)
	stores := deviceApprovals(dir, deviceID)
	opts := approval.ApplyOptions{
		Pending:    stores.Pending,
		Sessions:   stores.Sessions,
		Audit:      audit.NewStore(filepath.Join(dir, FileAudit)),
		SessionTTL: runtime.SessionTTL,
		TaskTTL:    runtime.TaskTTL,
		Channel:    approval.ChannelGateway,
		DeviceID:   deviceID,
		Operator:   operator,
	}
	cfg, err := store.Config(deviceID)
	var inv inventory.Inventory
	var pol policy.Config
	if err == nil {
		inv, pol, err = remote.ParseManaged(cfg.InventoryYAML, cfg.PolicyYAML, nil)
	}
	if err != nil {
		opts.SavePolicy = func(policy.Config) error {
			return fmt.Errorf("host scope needs the device's configuration: %w", err)
		}
		return opts
	}
	opts.Bundle = policy.Bundle{Policy: pol, Inventory: inv}
	// The rule is added to the policy as read here; if another push lands
	// first, the decision fails rather than overwrite it (the request stays
	// approved without a rule, so the device's rerun asks again).
	opts.SavePolicy = func(next policy.Config) error {
		if next.Version == 0 {
			next.Version = 1
		}
		data, err := yaml.Marshal(&next)
		if err != nil {
			return err
		}
		_, err = controlplane.ReplaceConfig(store, deviceID, cfg.Version, cfg.InventoryYAML, string(data), now)
		return err
	}
	return opts
}

// DecideApproval resolves one approval request of the device that made it.
func DecideApproval(dir string, store *controlplane.Store, by Decider, id string, verdict approval.Verdict, scope approval.Scope) (string, approval.ApplyResult, error) {
	deviceID, _, err := ApprovalStatus(dir, by.DeviceID, id)
	if err != nil {
		return "", approval.ApplyResult{}, err
	}
	result, err := approval.ApplyDecision(decisionOptions(dir, store, deviceID, by.Operator, time.Now()), id, verdict, scope)
	return deviceID, result, err
}

// DecidePlan resolves every pending member of a plan with one verdict; host
// scope is not offered for a whole plan.
func DecidePlan(dir string, store *controlplane.Store, by Decider, id string, verdict approval.Verdict, scope approval.Scope) (string, []approval.ApplyResult, error) {
	deviceID, _, err := PlanStatus(dir, by.DeviceID, id)
	if err != nil {
		return "", nil, err
	}
	results, err := approval.ApplyPlanDecision(decisionOptions(dir, store, deviceID, by.Operator, time.Now()), id, verdict, scope)
	return deviceID, results, err
}
