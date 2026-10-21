package remoteclient

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/Praeviso/AgentSSH/internal/fileutil"
	"github.com/Praeviso/AgentSSH/internal/managedmode"
	"github.com/Praeviso/AgentSSH/internal/remote"
	"gopkg.in/yaml.v3"
)

type proofTransport struct {
	base       http.RoundTripper
	key        ed25519.PrivateKey
	keyID, tag string
}

func (t *proofTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	var body []byte
	if req.Body != nil {
		var err error
		body, err = io.ReadAll(req.Body)
		_ = req.Body.Close()
		if err != nil {
			return nil, err
		}
	}
	signed := req.Clone(req.Context())
	if len(body) > 0 {
		signed.Body = io.NopCloser(bytes.NewReader(body))
	}
	if err := remote.SignHTTPRequest(signed, body, t.keyID, t.tag, t.key, time.Now()); err != nil {
		return nil, err
	}
	return t.base.RoundTrip(signed)
}

func httpsHTTPClient(key ed25519.PrivateKey, keyID, tag string) *http.Client {
	// Use ordinary system trust, including an operator's system trust settings.
	// No private control-plane CA or client certificate is installed in v2.
	transport := http.DefaultTransport.(*http.Transport).Clone()
	roots := transport.TLSClientConfig
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS13}
	if roots != nil {
		transport.TLSClientConfig.RootCAs = roots.RootCAs
	}
	return &http.Client{Timeout: RequestTimeout, Transport: &proofTransport{base: transport, key: key, keyID: keyID, tag: tag},
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return &remote.APIError{Status: http.StatusForbidden, Code: remote.CodeUnauthenticated, Message: "control plane redirects are not permitted"}
		}}
}

func newHTTPSClient(home string, state State) (*Client, error) {
	base, err := remote.HTTPSBaseURL(state.ServerURL)
	if err != nil || base != state.ServerURL {
		return nil, errors.New("invalid HTTPS enrollment URL")
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
	return &Client{State: state, http: httpsHTTPClient(key, state.DeviceID, remote.DeviceSignatureTag)}, nil
}

func enrollHTTPS(ctx context.Context, home, serverURL, rawToken string, now time.Time) (State, error) {
	token, err := remote.ParseHTTPSEnrollToken(rawToken)
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
	client := httpsHTTPClient(key, token.ID, remote.EnrollSignatureTag)
	var response remote.HTTPSEnrollResponse
	if err := doJSON(ctx, client, http.MethodPost, base+remote.PathEnrollV2, remote.HTTPSEnrollRequest{
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
	state := State{Protocol: remote.HTTPSProtocol, ServerURL: base, DeviceID: response.DeviceID, BundlePublicKey: response.BundlePublicKey, EnrolledAt: now.UTC()}
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
