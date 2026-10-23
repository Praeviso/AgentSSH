package gateway

import (
	"errors"
	"fmt"
	"net/http"
	"path/filepath"

	"github.com/Praeviso/AgentSSH/internal/audit"
	"github.com/Praeviso/AgentSSH/internal/controlplane"
	"github.com/Praeviso/AgentSSH/internal/inventory"
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
	inv, ok := s.deviceInventory(w, device.ID)
	if !ok {
		return
	}
	controlplane.WriteJSON(w, http.StatusOK, inventory.NewResolver(inv).Public())
}

// deviceInventory loads the inventory pushed for deviceID, answering the
// request itself when there is none.
func (s *Server) deviceInventory(w http.ResponseWriter, deviceID string) (inventory.Inventory, bool) {
	cfg, err := s.Store.Config(deviceID)
	if errors.Is(err, controlplane.ErrNotFound) {
		controlplane.WriteError(w, http.StatusNotFound, remote.CodeNoConfig, "no configuration has been pushed for this device")
		return inventory.Inventory{}, false
	}
	if err != nil {
		controlplane.WriteError(w, http.StatusInternalServerError, remote.CodeInternal, "configuration lookup failed")
		return inventory.Inventory{}, false
	}
	inv, _, err := remote.ParseManaged(cfg.InventoryYAML, cfg.PolicyYAML, nil)
	if err != nil {
		controlplane.WriteError(w, http.StatusInternalServerError, remote.CodeInternal, "stored configuration is unreadable")
		return inventory.Inventory{}, false
	}
	return inv, true
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
