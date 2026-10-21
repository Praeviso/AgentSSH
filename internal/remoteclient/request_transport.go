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

func signedHTTPClient(key ed25519.PrivateKey, keyID, tag string) *http.Client {
	// Use ordinary system trust, including an operator's system trust settings.
	// Device authentication uses request signatures.
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
