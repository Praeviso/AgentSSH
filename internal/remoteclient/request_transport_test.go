package remoteclient

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/Praeviso/AgentSSH/internal/remote"
)

func TestSignedGETDoesNotReplayAfterLostResponse(t *testing.T) {
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	seen := map[string]bool{}
	requests := 0
	var endpoint string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
			return
		}
		proof, err := remote.VerifyHTTPRequest(r, body, endpoint, "dev_fixture", remote.DeviceSignatureTag, pub, time.Now())
		if err != nil {
			t.Errorf("invalid proof: %v", err)
			w.WriteHeader(401)
			return
		}
		mu.Lock()
		requests++
		n := requests
		replayed := seen[proof.Nonce]
		seen[proof.Nonce] = true
		mu.Unlock()
		if replayed {
			w.WriteHeader(403)
			_, _ = io.WriteString(w, `{"code":"unauthenticated","error":"request replayed"}`)
			return
		}
		if n == 2 {
			// Consume the proof on the reused connection, then lose the response.
			conn, _, err := w.(http.Hijacker).Hijack()
			if err != nil {
				t.Error(err)
				return
			}
			_ = conn.Close()
			return
		}
		_, _ = io.WriteString(w, `{}`)
	}))
	defer server.Close()
	endpoint = server.URL + remote.PathBundle
	client := signedHTTPClient(key, "dev_fixture", remote.DeviceSignatureTag, remote.ModeManaged)
	transport := client.Transport.(*proofTransport).base.(*http.Transport)
	transport.TLSClientConfig.RootCAs = server.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs
	defer transport.CloseIdleConnections()

	if err := doJSON(context.Background(), client, "GET", endpoint, nil, nil); err != nil {
		t.Fatal(err)
	}
	var unreachable *UnreachableError
	if err := doJSON(context.Background(), client, "GET", endpoint, nil, nil); !errors.As(err, &unreachable) {
		t.Fatalf("lost response should remain a transport failure, got %v", err)
	}
	mu.Lock()
	count := requests
	mu.Unlock()
	if count != 2 {
		t.Fatalf("transport resent the consumed proof: %d requests", count)
	}
	// An explicit new operation gets a new proof and remains usable.
	if err := doJSON(context.Background(), client, "GET", endpoint, nil, nil); err != nil {
		t.Fatal(err)
	}
}
