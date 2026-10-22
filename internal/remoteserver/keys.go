package remoteserver

import (
	"crypto/ed25519"
	"path/filepath"
	"time"

	"filippo.io/age"
	"github.com/Praeviso/AgentSSH/internal/controlplane"
	"github.com/Praeviso/AgentSSH/internal/remote"
)

// FileDatabase is the managed control plane's database file.
const FileDatabase = "server.db"

// ScryptWorkFactor is the production master-passphrase cost; tests lower it.
var ScryptWorkFactor = controlplane.DefaultScryptWorkFactor

var ErrWrongMaster = controlplane.ErrWrongMaster

// Keys contains only the unlocked signing and storage keys.
type Keys = controlplane.Keys

func Initialized(dir string) bool {
	return controlplane.Initialized(dir)
}

// Init generates encrypted signing keys and initializes a managed
// control-plane store.
func Init(dir, master string) error {
	return controlplane.Init(dir, master, controlplane.InitOptions{
		Mode:       remote.ModeManaged,
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

func Unlock(dir, master string) (*Keys, error) {
	return controlplane.Unlock(dir, master)
}

// LoadBundlePublicKey reads the public bundle-verification key without unlocking
// private keys. Enrollment-token creation needs only this public information.
func LoadBundlePublicKey(dir string) (ed25519.PublicKey, error) {
	return controlplane.LoadBundlePublicKey(dir)
}

// LoadRecipient reads the public age recipient. Creating identities needs only
// this, so it works without the master password.
func LoadRecipient(dir string) (age.Recipient, error) {
	return controlplane.LoadRecipient(dir)
}

// NewIdentity generates an ed25519 SSH identity encrypted to recipient.
func NewIdentity(name string, recipient age.Recipient, now time.Time) (Identity, error) {
	return controlplane.NewIdentity(name, recipient, now)
}
