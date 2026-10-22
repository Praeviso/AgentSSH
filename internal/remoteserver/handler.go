package remoteserver

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/Praeviso/AgentSSH/internal/controlplane"
	"github.com/Praeviso/AgentSSH/internal/remote"
)

// Handler is the managed control-plane API. publicURL is trusted deployment
// configuration (including a possible plugin path prefix), never a forwarded
// header. It can sit behind a TLS terminator without client certificates.
// HTTP origins must be reachable only through that trusted HTTPS ingress.
func (s *Server) Handler(publicURL string) (http.Handler, error) {
	api := controlplane.API{
		Mode:  remote.ModeManaged,
		Store: func() *controlplane.Store { return s.Store.Store },
		Keys:  func() *controlplane.Keys { return s.Keys },
		Now:   s.now,
	}
	return api.Handler(publicURL,
		controlplane.Route{Method: "GET", Path: remote.PathBundle, Handler: s.handleBundle},
		controlplane.Route{Method: "POST", Path: remote.PathSign, Handler: s.handleSign, Revoked: s.logRevokedSign},
	)
}

// logRevokedSign records a revoked device's signing attempt; without the log
// entry the refusal is not sent.
func (s *Server) logRevokedSign(deviceID string, body []byte, now time.Time) error {
	var req remote.SignRequest
	_ = json.Unmarshal(body, &req)
	if err := s.Store.AppendSign(SignEntry{SignID: "sg_" + controlplane.RandomHex(8), TS: now, DeviceID: deviceID, Host: req.Host, Result: SignRejected, Reason: "device revoked"}); err != nil {
		return errors.New("signing log unavailable")
	}
	return nil
}
