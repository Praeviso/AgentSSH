// Package remoteclient implements the hosted HTTPS control-plane client.
package remoteclient

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Praeviso/AgentSSH/internal/managedmode"
	"github.com/Praeviso/AgentSSH/internal/remote"
	"gopkg.in/yaml.v3"
)

// RequestTimeout bounds each control-plane request.
var RequestTimeout = 10 * time.Second

const (
	fileDeviceKey = "device.key"
	fileCache     = "bundle.cache.json"
)

// State is the complete enrollment record; unknown fields are rejected.
type State struct {
	ServerURL       string    `yaml:"server_url"`
	DeviceID        string    `yaml:"device_id"`
	BundlePublicKey string    `yaml:"bundle_public_key"`
	EnrolledAt      time.Time `yaml:"enrolled_at"`
}

// UnreachableError distinguishes transport failures from protocol refusals.
type UnreachableError struct{ Err error }

func (e *UnreachableError) Error() string { return fmt.Sprintf("control plane unreachable: %v", e.Err) }
func (e *UnreachableError) Unwrap() error { return e.Err }

// LoadState validates the unversioned enrollment record.
func LoadState(home string) (State, error) {
	data, err := os.ReadFile(filepath.Join(managedmode.Dir(home), managedmode.MarkerName))
	if err != nil {
		return State{}, fmt.Errorf("read remote enrollment: %w", err)
	}
	var state State
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(&state); err != nil {
		return State{}, fmt.Errorf("invalid remote enrollment; re-enroll this device: %w", err)
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return State{}, errors.New("remote enrollment must contain one document")
	}
	base, err := remote.HTTPSBaseURL(state.ServerURL)
	if err != nil || base != state.ServerURL || !validDeviceID(state.DeviceID) || state.EnrolledAt.IsZero() {
		return State{}, errors.New("invalid remote enrollment; re-enroll this device")
	}
	if _, err := remote.DecodeDevicePublicKey(state.BundlePublicKey); err != nil {
		return State{}, err
	}
	return state, nil
}

// Client authenticates as one enrolled device.
type Client struct {
	State State
	http  *http.Client
}

// NewClient loads the device key and uses ordinary HTTPS trust.
func NewClient(home string) (*Client, error) {
	state, err := LoadState(home)
	if err != nil {
		return nil, err
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
	return &Client{State: state, http: signedHTTPClient(key, state.DeviceID, remote.DeviceSignatureTag)}, nil
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

// Leave removes the device credentials and cached bundle, returning home to
// local mode. The marker goes first so a partial failure still exits remote mode.
func Leave(home string) error {
	dir := managedmode.Dir(home)
	if err := os.Remove(filepath.Join(dir, managedmode.MarkerName)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return os.RemoveAll(dir)
}
