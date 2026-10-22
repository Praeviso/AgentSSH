// Package gateway is the gateway-mode control plane. Devices enroll and
// authenticate exactly as with a managed control plane, but inventory, policy,
// identities and SSH stay here: there is no signing or bundle endpoint, so no
// request path hands a device an identity signature or its policy.
package gateway

import (
	"net/http"
	"path/filepath"
	"time"

	"github.com/Praeviso/AgentSSH/internal/controlplane"
	"github.com/Praeviso/AgentSSH/internal/remote"
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
	return controlplane.OpenStore(path, "")
}

// Server is the gateway HTTP API.
type Server struct {
	Store *controlplane.Store
	Keys  *controlplane.Keys
	Now   func() time.Time
}

// NewServer wires a store and unlocked keys into an API server.
func NewServer(store *controlplane.Store, keys *controlplane.Keys) *Server {
	return &Server{Store: store, Keys: keys, Now: time.Now}
}

func (s *Server) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// Handler serves enrollment and authenticated device requests under the public
// HTTPS base, with the same trust requirements as the managed handler.
func (s *Server) Handler(publicURL string) (http.Handler, error) {
	api := controlplane.API{
		Mode:  remote.ModeGateway,
		Store: func() *controlplane.Store { return s.Store },
		Keys:  func() *controlplane.Keys { return s.Keys },
		Now:   s.now,
	}
	return api.Handler(publicURL)
}
