package remoteclient

import (
	"bytes"
	"crypto/ed25519"
	"crypto/tls"
	"io"
	"net/http"
	"time"

	"github.com/Praeviso/AgentSSH/internal/remote"
)

type proofTransport struct {
	base       http.RoundTripper
	key        ed25519.PrivateKey
	keyID, tag string
	// mode is the control-plane mode every response must name.
	mode string
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
	// A proof is single-use even for GET. A non-rewindable body (including an
	// empty body) prevents Transport's internal retries from resending its nonce
	// after the server accepted a request but the response was lost. Let the
	// caller observe the transport failure and apply the bounded cache policy.
	signed.Body = io.NopCloser(bytes.NewReader(body))
	signed.GetBody = nil
	if err := remote.SignHTTPRequest(signed, body, t.keyID, t.tag, t.key, time.Now()); err != nil {
		return nil, err
	}
	resp, err := t.base.RoundTrip(signed)
	if err != nil {
		return nil, err
	}
	if err := checkMode(resp, t.mode); err != nil {
		_ = resp.Body.Close()
		return nil, err
	}
	return resp, nil
}

// checkMode fails closed on a response from a control plane of another mode,
// including its refusals, so talking to the wrong plane never reads as an
// ordinary error. An ingress reporting its backend unavailable answers for no
// control plane, so it is left to be classified as unreachable.
func checkMode(resp *http.Response, want string) error {
	header := resp.Header.Get(remote.HeaderMode)
	if header == "" && ingressFailure(resp.StatusCode) {
		return nil
	}
	if got := remote.ResponseMode(header); got != want {
		return &ModeMismatchError{Want: want, Got: got}
	}
	return nil
}

func ingressFailure(status int) bool {
	switch status {
	case http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		return true
	}
	return false
}

func signedHTTPClient(key ed25519.PrivateKey, keyID, tag, mode string) *http.Client {
	return controlPlaneClient(&proofTransport{base: baseTransport(), key: key, keyID: keyID, tag: tag, mode: mode})
}

// baseTransport uses ordinary system trust, including an operator's system
// trust settings. Device authentication uses request signatures.
func baseTransport() *http.Transport {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	if transport.TLSClientConfig == nil {
		transport.TLSClientConfig = &tls.Config{}
	}
	transport.TLSClientConfig.MinVersion = max(transport.TLSClientConfig.MinVersion, tls.VersionTLS13)
	return transport
}

func controlPlaneClient(transport http.RoundTripper) *http.Client {
	return &http.Client{Timeout: RequestTimeout, Transport: transport,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return &remote.APIError{Status: http.StatusForbidden, Code: remote.CodeUnauthenticated, Message: "control plane redirects are not permitted"}
		}}
}
