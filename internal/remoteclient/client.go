// Package remoteclient is the AgentSSH side of remote control: device
// enrollment, mTLS/v2 HTTPS API clients, the signed configuration bundle cache, and
// the SSH signer whose private key lives only on the control plane.
package remoteclient

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Praeviso/AgentSSH/internal/fileutil"
	"github.com/Praeviso/AgentSSH/internal/managedmode"
	"github.com/Praeviso/AgentSSH/internal/remote"
	"gopkg.in/yaml.v3"
)

// RequestTimeout bounds every control-plane call.
var RequestTimeout = 10 * time.Second

const (
	fileCACert     = "ca.crt"
	fileDeviceKey  = "device.key"
	fileDeviceCert = "device.crt"
	fileCache      = "bundle.cache.json"
)

// State is the enrollment record stored in remote/remote.yaml.
type State struct {
	Protocol        string    `yaml:"protocol,omitempty"`
	ServerURL       string    `yaml:"server_url"`
	DeviceID        string    `yaml:"device_id"`
	CAFingerprint   string    `yaml:"ca_fingerprint"`
	BundlePublicKey string    `yaml:"bundle_public_key"`
	EnrolledAt      time.Time `yaml:"enrolled_at"`
}

// UnreachableError wraps a transport-level failure talking to the control
// plane. Unlike remote.APIError it says nothing about the device's standing.
type UnreachableError struct {
	Err error
}

func (e *UnreachableError) Error() string {
	return fmt.Sprintf("control plane unreachable: %v", e.Err)
}

func (e *UnreachableError) Unwrap() error { return e.Err }

// LoadState reads the enrollment record for home.
func LoadState(home string) (State, error) {
	data, err := os.ReadFile(filepath.Join(managedmode.Dir(home), managedmode.MarkerName))
	if err != nil {
		return State{}, fmt.Errorf("read remote enrollment: %w", err)
	}
	var state State
	if err := yaml.Unmarshal(data, &state); err != nil {
		return State{}, fmt.Errorf("parse remote enrollment: %w", err)
	}
	if state.ServerURL == "" || state.DeviceID == "" || state.BundlePublicKey == "" {
		return State{}, errors.New("remote enrollment record is incomplete; run agentssh remote leave and enroll again")
	}
	if state.Protocol != "" && state.Protocol != remote.HTTPSProtocol {
		return State{}, errors.New("unsupported remote enrollment protocol")
	}
	return state, nil
}

// Client talks to the control plane as an enrolled device.
type Client struct {
	State State
	http  *http.Client
}

// NewClient uses the protocol explicitly recorded at enrollment.
func NewClient(home string) (*Client, error) {
	state, err := LoadState(home)
	if err != nil {
		return nil, err
	}
	if state.Protocol == remote.HTTPSProtocol {
		return newHTTPSClient(home, state)
	}
	dir := managedmode.Dir(home)
	caPEM, err := os.ReadFile(filepath.Join(dir, fileCACert))
	if err != nil {
		return nil, fmt.Errorf("read control plane CA: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, errors.New("control plane CA certificate is unreadable")
	}
	cert, err := tls.LoadX509KeyPair(filepath.Join(dir, fileDeviceCert), filepath.Join(dir, fileDeviceKey))
	if err != nil {
		return nil, fmt.Errorf("load device certificate: %w", err)
	}
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			MinVersion:   tls.VersionTLS13,
			RootCAs:      pool,
			Certificates: []tls.Certificate{cert},
		},
	}
	return &Client{State: state, http: &http.Client{Transport: transport, Timeout: RequestTimeout}}, nil
}

// Status reports the device's standing; a revoked device gets an APIError.
func (c *Client) Status(ctx context.Context) (remote.StatusResponse, error) {
	var out remote.StatusResponse
	err := c.call(ctx, http.MethodGet, remote.PathStatus, nil, &out)
	return out, err
}

// FetchBundle downloads the signed configuration bundle.
func (c *Client) FetchBundle(ctx context.Context) (remote.BundleResponse, error) {
	var out remote.BundleResponse
	err := c.call(ctx, http.MethodGet, remote.PathBundle, nil, &out)
	return out, err
}

// Sign asks the control plane to sign SSH userauth data for host.
func (c *Client) Sign(ctx context.Context, host string, data []byte) (remote.SignResponse, error) {
	var out remote.SignResponse
	err := c.call(ctx, http.MethodPost, remote.PathSign, remote.SignRequest{Host: host, Data: data}, &out)
	return out, err
}

func (c *Client) call(ctx context.Context, method string, path string, body any, out any) error {
	if c.State.Protocol == remote.HTTPSProtocol {
		switch path {
		case remote.PathStatus:
			path = remote.PathStatusV2
		case remote.PathBundle:
			path = remote.PathBundleV2
		case remote.PathSign:
			path = remote.PathSignV2
		default:
			return errors.New("unsupported HTTPS control-plane operation")
		}
	}
	return doJSON(ctx, c.http, method, strings.TrimRight(c.State.ServerURL, "/")+path, body, out)
}

func doJSON(ctx context.Context, client *http.Client, method string, endpoint string, body any, out any) error {
	ctx, cancel := context.WithTimeout(ctx, RequestTimeout)
	defer cancel()
	var reader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(data)
	}
	req, err := http.NewRequestWithContext(ctx, method, endpoint, reader)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := client.Do(req)
	if err != nil {
		var apiErr *remote.APIError
		if errors.As(err, &apiErr) {
			return apiErr
		}
		return &UnreachableError{Err: err}
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(io.LimitReader(resp.Body, (16<<20)+1))
	if err != nil {
		return &UnreachableError{Err: err}
	}
	if len(data) > 16<<20 {
		return errors.New("control plane response is too large")
	}
	if resp.StatusCode/100 != 2 {
		var apiErr remote.ErrorResponse
		if json.Unmarshal(data, &apiErr) != nil || apiErr.Code == "" {
			return &remote.APIError{Status: resp.StatusCode, Code: remote.CodeInternal, Message: fmt.Sprintf("HTTP %d", resp.StatusCode)}
		}
		return &remote.APIError{Status: resp.StatusCode, Code: apiErr.Code, Message: apiErr.Error}
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(data, out); err != nil {
		return fmt.Errorf("decode control plane response: %w", err)
	}
	return nil
}

// Enroll redeems token with the control plane at serverURL and stores the
// device credentials under home. The marker file is written last, so a failed
// enrollment never leaves the home half in remote mode.
func Enroll(ctx context.Context, home string, serverURL string, rawToken string, now time.Time) (State, error) {
	if managedmode.Enrolled(home) {
		return State{}, errors.New("this AgentSSH home is already enrolled; run agentssh remote leave first")
	}
	if strings.HasPrefix(strings.TrimSpace(rawToken), remote.HTTPSTokenPrefix) {
		return enrollHTTPS(ctx, home, serverURL, rawToken, now)
	}
	token, err := remote.ParseEnrollToken(rawToken)
	if err != nil {
		return State{}, err
	}
	parsed, err := url.Parse(strings.TrimRight(serverURL, "/"))
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" {
		return State{}, fmt.Errorf("control plane URL must be https://host[:port], got %q", serverURL)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return State{}, err
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "agentssh-device"},
	}, key)
	if err != nil {
		return State{}, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return State{}, err
	}

	client := &http.Client{Timeout: RequestTimeout, Transport: &http.Transport{TLSClientConfig: pinnedTLS(token.CAFingerprint, parsed.Hostname())}}
	var resp remote.EnrollResponse
	err = doJSON(ctx, client, http.MethodPost, parsed.String()+remote.PathEnroll, remote.EnrollRequest{
		TokenID:     token.ID,
		TokenSecret: token.Secret,
		CSRPEM:      string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})),
	}, &resp)
	if err != nil {
		return State{}, err
	}
	caBlock, _ := pem.Decode([]byte(resp.CAPEM))
	if caBlock == nil || remote.CertFingerprint(caBlock.Bytes) != token.CAFingerprint {
		return State{}, errors.New("control plane returned a CA that does not match the enrollment token")
	}
	if pub, err := base64.StdEncoding.DecodeString(resp.BundlePublicKey); err != nil || len(pub) != 32 {
		return State{}, errors.New("control plane returned an invalid bundle public key")
	}
	if !strings.HasPrefix(resp.DeviceID, "dev_") {
		return State{}, errors.New("control plane returned an invalid device id")
	}

	dir := managedmode.Dir(home)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return State{}, fmt.Errorf("create remote state directory: %w", err)
	}
	state := State{
		ServerURL:       parsed.String(),
		DeviceID:        resp.DeviceID,
		CAFingerprint:   token.CAFingerprint,
		BundlePublicKey: resp.BundlePublicKey,
		EnrolledAt:      now.UTC(),
	}
	stateYAML, err := yaml.Marshal(state)
	if err != nil {
		return State{}, err
	}
	files := []struct {
		name string
		data []byte
		perm os.FileMode
	}{
		{fileCACert, []byte(resp.CAPEM), 0o644},
		{fileDeviceKey, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600},
		{fileDeviceCert, []byte(resp.CertPEM), 0o644},
		{managedmode.MarkerName, stateYAML, 0o600},
	}
	for _, f := range files {
		if err := fileutil.WriteFileAtomic(filepath.Join(dir, f.name), f.data, f.perm, f.name+"-*"); err != nil {
			return State{}, fmt.Errorf("write %s: %w", f.name, err)
		}
	}
	return state, nil
}

// pinnedTLS trusts exactly the CA whose fingerprint came with the enrollment
// token. The server sends that CA in its chain; system roots play no part.
func pinnedTLS(fingerprint string, serverName string) *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS13,
		// Verification is done in VerifyConnection against the pinned CA.
		InsecureSkipVerify: true, //nolint:gosec // replaced by fingerprint pinning below
		VerifyConnection: func(cs tls.ConnectionState) error {
			var ca *x509.Certificate
			for _, cert := range cs.PeerCertificates {
				if remote.CertFingerprint(cert.Raw) == fingerprint {
					ca = cert
					break
				}
			}
			if ca == nil || len(cs.PeerCertificates) == 0 {
				return errors.New("control plane certificate chain does not contain the pinned CA")
			}
			pool := x509.NewCertPool()
			pool.AddCert(ca)
			_, err := cs.PeerCertificates[0].Verify(x509.VerifyOptions{DNSName: serverName, Roots: pool})
			return err
		},
	}
}

// Leave removes the device credentials and cached bundle, returning home to
// local mode. The marker goes first so a partial failure still exits remote mode.
func Leave(home string) error {
	dir := managedmode.Dir(home)
	if err := os.Remove(filepath.Join(dir, managedmode.MarkerName)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return os.RemoveAll(dir)
}
