// Package gateway is the gateway-mode control plane. Devices enroll and
// authenticate exactly as with a managed control plane, but inventory, policy,
// identities and SSH stay here: devices send commands to /exec, and there is no
// signing or bundle endpoint, so no request path hands a device an identity
// signature or its policy.
package gateway

import (
	"net/http"
	"path/filepath"
	"slices"
	"sync"
	"time"

	"github.com/Praeviso/AgentSSH/internal/controlplane"
	"github.com/Praeviso/AgentSSH/internal/executor"
	"github.com/Praeviso/AgentSSH/internal/inventory"
	"github.com/Praeviso/AgentSSH/internal/remote"
	"golang.org/x/crypto/ssh"
)

// FileDatabase is the gateway's database file. It differs from the managed
// control plane's, so a managed binary pointed at a gateway directory finds no
// devices or identities to sign for.
const FileDatabase = "gateway.db"

// ScryptWorkFactor is the production master-passphrase cost; tests lower it.
var ScryptWorkFactor = controlplane.DefaultScryptWorkFactor

// Init generates encrypted keys and initializes a gateway data directory.
func Init(dir, master string) error {
	return controlplane.Init(dir, master, controlplane.InitOptions{
		Mode:       remote.ModeGateway,
		WorkFactor: ScryptWorkFactor,
		InitStore: func(dir string) error {
			store, err := OpenStore(filepath.Join(dir, FileDatabase))
			if err != nil {
				return err
			}
			return store.Close()
		},
	})
}

// OpenStore opens (creating if needed) the gateway database at path.
func OpenStore(path string) (*controlplane.Store, error) {
	return controlplane.OpenStore(path, operatorSchema+activationSchema+tokenSchema+oauthSchema)
}

// Server is the gateway HTTP API.
type Server struct {
	// Dir is the data directory: the audit chain, known_hosts, and per-device
	// approval state live here.
	Dir   string
	Store *controlplane.Store
	Keys  *controlplane.Keys
	Now   func() time.Time
	// ExecTimeout and MaxConcurrentPerDevice bound executions; RunRetention,
	// RunMaxBytes and RunQuotaBytes (per device) bound their spooled output.
	// Zero values use the defaults.
	ExecTimeout            time.Duration
	MaxConcurrentPerDevice int
	RunRetention           time.Duration
	RunMaxBytes            int64
	RunQuotaBytes          int64
	// RunRecords caps the run records one device keeps.
	RunRecords int
	// MaxPendingApprovals caps one device's requests awaiting a decision, and
	// separately its plans awaiting one.
	MaxPendingApprovals int
	// Executor, when set, replaces SSH with the gateway's identities for a
	// device's inventory. Tests use it to drive a fake target.
	Executor func(inventory.Inventory) executor.Executor
	// WebOrigin is the Web UI's origin. When set, the gateway is an OAuth
	// authorization server for its MCP endpoint, with the authorization
	// endpoint there.
	WebOrigin string

	mu        sync.Mutex
	running   map[string]int
	signers   map[string]ssh.Signer
	runs      map[string]*run
	nextSweep time.Time
	// deviceRecords counts each device's records (live and stored) since its
	// last sweep; deviceSweeps says when that device is next aged out.
	deviceRecords map[string]int
	deviceSweeps  map[string]time.Time
	// submits serializes each device's plan submissions, so a plan's
	// precheck against the approval cap holds while it is submitted.
	submits sync.Map // device ID → *sync.Mutex
	// oauth is the authorization server when WebOrigin is set; registerMu
	// serializes registrations, so the cap on pending clients holds.
	oauth      *OAuth
	registerMu sync.Mutex
}

// NewServer wires a data directory, its store and unlocked keys into an API
// server.
func NewServer(dir string, store *controlplane.Store, keys *controlplane.Keys) *Server {
	return &Server{Dir: dir, Store: store, Keys: keys, Now: time.Now}
}

func (s *Server) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// Handler serves enrollment, /status, /hosts, /requests/status and the /exec endpoints under the public
// HTTPS base, with the same trust requirements as the managed handler.
func (s *Server) Handler(publicURL string) (http.Handler, error) {
	api := controlplane.API{
		Mode:           remote.ModeGateway,
		Store:          func() *controlplane.Store { return s.Store },
		Keys:           func() *controlplane.Keys { return s.Keys },
		Now:            s.now,
		DescribeStatus: s.describeStatus,
	}
	base, err := remote.HTTPSBaseURL(publicURL)
	if err != nil {
		return nil, err
	}
	openAPI, err := openAPIRoute(base)
	if err != nil {
		return nil, err
	}
	if s.WebOrigin != "" {
		oauth, err := NewOAuth(publicURL, s.WebOrigin)
		if err != nil {
			return nil, err
		}
		s.oauth = &oauth
	}
	api.Open = append(s.tokenRoutes(), openAPI)
	if s.oauth != nil {
		api.Open = append(api.Open, s.oauthRoutes()...)
	}
	routes := slices.Concat(s.execRoutes(), s.deviceRoutes(), s.approvalRoutes())
	for i := range routes {
		// Cancelling only stops a run, so a device whose window ended can
		// still stop its own.
		if routes[i].Path != remote.PathExecCancel {
			routes[i].Handler = s.requireActive(routes[i].Handler)
		}
	}
	return api.Handler(publicURL, routes...)
}

// requireActive refuses a device outside its activation window. Enrollment
// and /status are not wrapped, so a device can enroll before it is activated
// and see its state.
func (s *Server) requireActive(next controlplane.DeviceHandler) controlplane.DeviceHandler {
	return func(w http.ResponseWriter, r *http.Request, device controlplane.Device, body []byte) {
		_, active, err := deviceActive(s.Dir, s.Store, device.ID, s.now())
		if err != nil {
			controlplane.WriteError(w, http.StatusInternalServerError, remote.CodeInternal, "activation state unavailable")
			return
		}
		if !active {
			controlplane.WriteError(w, http.StatusForbidden, remote.CodeDeviceInactive, "this device is not activated; an operator must activate it on the gateway")
			return
		}
		next(w, r, device, body)
	}
}

func (s *Server) describeStatus(device controlplane.Device, status *remote.StatusResponse) {
	now := s.now()
	if a, _, err := deviceActive(s.Dir, s.Store, device.ID, now); err == nil {
		status.Activation = ActivationStatus(a, now)
	}
}
