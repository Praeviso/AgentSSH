package remoteclient

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/Praeviso/AgentSSH/internal/fileutil"
	"github.com/Praeviso/AgentSSH/internal/managedmode"
	"github.com/Praeviso/AgentSSH/internal/remote"
	"gopkg.in/yaml.v3"
)

// Enroll proves ownership of a fresh device key and commits local state last.
func Enroll(ctx context.Context, home, serverURL, rawToken string, now time.Time) (State, error) {
	if managedmode.Enrolled(home) {
		return State{}, errors.New("this AgentSSH home is already enrolled; run agentssh remote leave first")
	}
	token, err := remote.ParseEnrollToken(rawToken)
	if err != nil {
		return State{}, err
	}
	base, err := remote.HTTPSBaseURL(serverURL)
	if err != nil || base != token.ServerURL {
		return State{}, errors.New("control plane URL does not match the HTTPS enrollment token")
	}
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return State{}, err
	}
	client := signedHTTPClient(key, token.ID, remote.EnrollSignatureTag)
	var response remote.EnrollResponse
	if err := doJSON(ctx, client, http.MethodPost, base+remote.PathEnroll, remote.EnrollRequest{
		TokenID: token.ID, TokenSecret: token.Secret, PublicKey: base64.StdEncoding.EncodeToString(pub)}, &response); err != nil {
		return State{}, err
	}
	bundlePub, err := remote.DecodeDevicePublicKey(response.BundlePublicKey)
	if err != nil || remote.PublicKeyFingerprint(bundlePub) != token.BundleFingerprint {
		return State{}, errors.New("bundle public key does not match the enrollment token")
	}
	if !validDeviceID(response.DeviceID) {
		return State{}, errors.New("control plane returned an invalid device id")
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return State{}, err
	}
	state := State{ServerURL: base, DeviceID: response.DeviceID, BundlePublicKey: response.BundlePublicKey, EnrolledAt: now.UTC()}
	encoded, err := yaml.Marshal(state)
	if err != nil {
		return State{}, err
	}
	dir := managedmode.Dir(home)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return State{}, err
	}
	// The marker commits enrollment last; failures never activate partial state.
	if err := fileutil.WriteFileAtomic(filepath.Join(dir, fileDeviceKey), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600, fileDeviceKey+"-*"); err != nil {
		return State{}, err
	}
	if err := fileutil.WriteFileAtomic(filepath.Join(dir, managedmode.MarkerName), encoded, 0o600, managedmode.MarkerName+"-*"); err != nil {
		return State{}, err
	}
	return state, nil
}

func validDeviceID(id string) bool {
	if len(id) < 5 || len(id) > 80 || id[:4] != "dev_" {
		return false
	}
	for _, c := range id[4:] {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '_', c == '-':
		default:
			return false
		}
	}
	return true
}
