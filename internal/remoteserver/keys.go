package remoteserver

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"golang.org/x/crypto/ssh"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"filippo.io/age"
	"github.com/Praeviso/AgentSSH/internal/fileutil"
)

const (
	fileMaster    = "master.age"
	fileRecipient = "recipient"
	fileBundlePub = "bundle.pub"
	fileBundleKey = "bundle.key.age"
	FileDatabase  = "server.db"
)

// ScryptWorkFactor is the production master-passphrase cost; tests lower it.
var ScryptWorkFactor = 18
var ErrWrongMaster = errors.New("wrong master password or corrupt master key")

// Keys contains only the unlocked signing and storage keys.
type Keys struct {
	identity  *age.X25519Identity
	BundleKey ed25519.PrivateKey
}

func Initialized(dir string) bool {
	_, err := os.Stat(filepath.Join(dir, fileMaster))
	return err == nil
}

// Init generates encrypted signing keys and initializes the control-plane store.
func Init(dir, master string) error {
	if master == "" {
		return errors.New("master password must not be empty")
	}
	if Initialized(dir) {
		return fmt.Errorf("control plane already initialized in %s", dir)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		return err
	}
	recipient := identity.Recipient()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	scrypt, err := age.NewScryptRecipient(master)
	if err != nil {
		return err
	}
	scrypt.SetWorkFactor(ScryptWorkFactor)
	masterBlob, err := encryptTo(scrypt, []byte(identity.String()))
	if err != nil {
		return err
	}
	keyBlob, err := encryptPrivateKey(recipient, key)
	if err != nil {
		return err
	}
	for _, f := range []struct {
		name string
		data []byte
		perm os.FileMode
	}{
		{fileRecipient, []byte(recipient.String() + "\n"), 0o644},
		{fileBundlePub, []byte(base64.StdEncoding.EncodeToString(pub) + "\n"), 0o644},
		{fileBundleKey, keyBlob, 0o600},
	} {
		if err := fileutil.WriteFileAtomic(filepath.Join(dir, f.name), f.data, f.perm, f.name+"-*"); err != nil {
			return err
		}
	}
	store, err := OpenStore(filepath.Join(dir, FileDatabase))
	if err != nil {
		return err
	}
	if err := store.Close(); err != nil {
		return err
	}
	// Commit initialization last so an interrupted initialization can be retried.
	return fileutil.WriteFileAtomic(filepath.Join(dir, fileMaster), masterBlob, 0o600, fileMaster+"-*")
}

func Unlock(dir, master string) (*Keys, error) {
	blob, err := os.ReadFile(filepath.Join(dir, fileMaster))
	if err != nil {
		return nil, err
	}
	scrypt, err := age.NewScryptIdentity(master)
	if err != nil {
		return nil, err
	}
	plain, err := decryptWith(scrypt, blob)
	if err != nil {
		return nil, ErrWrongMaster
	}
	identity, err := age.ParseX25519Identity(strings.TrimSpace(string(plain)))
	if err != nil {
		return nil, ErrWrongMaster
	}
	keys := &Keys{identity: identity}
	decoded, err := keys.readPrivateKey(filepath.Join(dir, fileBundleKey))
	if err != nil {
		return nil, err
	}
	key, ok := decoded.(ed25519.PrivateKey)
	if !ok {
		return nil, errors.New("bundle key is not Ed25519")
	}
	keys.BundleKey = key
	return keys, nil
}

func (k *Keys) BundlePublicKey() string {
	return base64.StdEncoding.EncodeToString(k.BundleKey.Public().(ed25519.PublicKey))
}

// DecryptIdentity returns the SSH signer for an identity's encrypted key.
func (k *Keys) DecryptIdentity(blob []byte) (ssh.Signer, error) {
	key, err := k.decryptPrivateKey(blob)
	if err != nil {
		return nil, err
	}
	return ssh.NewSignerFromKey(key)
}

// LoadRecipient reads the public age recipient. Creating identities needs only
// this, so it works without the master password.
func LoadRecipient(dir string) (age.Recipient, error) {
	data, err := os.ReadFile(filepath.Join(dir, fileRecipient))
	if err != nil {
		return nil, fmt.Errorf("read recipient (run agentssh-server init first): %w", err)
	}
	return age.ParseX25519Recipient(strings.TrimSpace(string(data)))
}

// NewIdentity generates an ed25519 SSH identity encrypted to recipient.
func NewIdentity(name string, recipient age.Recipient, now time.Time) (Identity, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return Identity{}, err
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		return Identity{}, err
	}
	blob, err := encryptPrivateKey(recipient, priv)
	if err != nil {
		return Identity{}, err
	}
	line := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshPub))) + " agentssh:" + name
	return Identity{Name: name, PublicKey: line, PrivateKey: blob, Status: IdentityActive, CreatedAt: now}, nil
}

func (k *Keys) readPrivateKey(path string) (any, error) {
	blob, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return k.decryptPrivateKey(blob)
}

func (k *Keys) decryptPrivateKey(blob []byte) (any, error) {
	plain, err := decryptWith(k.identity, blob)
	if err != nil {
		return nil, err
	}
	return x509.ParsePKCS8PrivateKey(plain)
}

func encryptPrivateKey(recipient age.Recipient, key any) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	return encryptTo(recipient, der)
}

func encryptTo(recipient age.Recipient, plain []byte) ([]byte, error) {
	var out bytes.Buffer
	w, err := age.Encrypt(&out, recipient)
	if err != nil {
		return nil, err
	}
	if _, err := w.Write(plain); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

func decryptWith(identity age.Identity, blob []byte) ([]byte, error) {
	r, err := age.Decrypt(bytes.NewReader(blob), identity)
	if err != nil {
		return nil, err
	}
	return io.ReadAll(r)
}
