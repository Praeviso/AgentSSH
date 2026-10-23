package gateway

import (
	"errors"
	"fmt"
	"net/http"
	"path/filepath"

	"github.com/Praeviso/AgentSSH/internal/audit"
	"github.com/Praeviso/AgentSSH/internal/controlplane"
	"github.com/Praeviso/AgentSSH/internal/inventory"
	"github.com/Praeviso/AgentSSH/internal/policy"
	"github.com/Praeviso/AgentSSH/internal/remote"
	"github.com/Praeviso/AgentSSH/internal/runner"
)

// deviceRoutes answer the device's read-only questions that a local CLI
// answers from its own inventory and audit.
func (s *Server) deviceRoutes() []controlplane.Route {
	return []controlplane.Route{
		{Method: "GET", Path: remote.PathHosts, Handler: s.handleHosts},
		{Method: "POST", Path: remote.PathRequestStatus, Handler: s.handleRequestStatus},
	}
}

func (s *Server) handleHosts(w http.ResponseWriter, _ *http.Request, device controlplane.Device, _ []byte) {
	inv, _, ok := s.deviceConfig(w, device.ID)
	if !ok {
		return
	}
	controlplane.WriteJSON(w, http.StatusOK, inventory.NewResolver(inv).Public())
}

// deviceConfig loads the inventory and policy pushed for deviceID, answering
// the request itself when there are none.
func (s *Server) deviceConfig(w http.ResponseWriter, deviceID string) (inventory.Inventory, policy.Config, bool) {
	inv, pol, err := s.loadDeviceConfig(deviceID)
	switch {
	case errors.Is(err, controlplane.ErrNotFound):
		controlplane.WriteError(w, http.StatusNotFound, remote.CodeNoConfig, "no configuration has been pushed for this device")
	case err != nil:
		controlplane.WriteError(w, http.StatusInternalServerError, remote.CodeInternal, "this device's configuration is unavailable")
	default:
		return inv, pol, true
	}
	return inventory.Inventory{}, policy.Config{}, false
}

func (s *Server) handleRequestStatus(w http.ResponseWriter, _ *http.Request, device controlplane.Device, body []byte) {
	var req remote.RequestStatusRequest
	if controlplane.DecodeBody(body, &req) != nil || req.ReqID == "" || len(req.ReqID) > remote.MaxExecFieldBytes {
		controlplane.WriteError(w, http.StatusBadRequest, remote.CodeBadRequest, "malformed request status query")
		return
	}
	records, err := audit.NewStore(filepath.Join(s.Dir, FileAudit)).ReadAll()
	if err != nil {
		controlplane.WriteError(w, http.StatusInternalServerError, remote.CodeInternal, "audit unavailable")
		return
	}
	// Only this device's records answer, so request IDs reveal nothing about
	// other devices.
	own := records[:0]
	for _, record := range records {
		if record.DeviceID == device.ID {
			own = append(own, record)
		}
	}
	response, ok := runner.RequestStatus(own, req.ReqID)
	if !ok {
		controlplane.WriteError(w, http.StatusNotFound, remote.CodeRequestNotFound, fmt.Sprintf("audit request %q not found", req.ReqID))
		return
	}
	controlplane.WriteJSON(w, http.StatusOK, response)
}
