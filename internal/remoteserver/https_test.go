package remoteserver

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Praeviso/AgentSSH/internal/remote"
)

const testHTTPSBase = "https://config.example/v1/plugins/agentssh"

type httpsFixture struct {
	dir     string
	store   *Store
	server  *Server
	handler http.Handler
	key     ed25519.PrivateKey
	now     time.Time
}

func newHTTPSFixture(t *testing.T) *httpsFixture {
	t.Helper()
	dir, store := newTestStore(t)
	keys, err := Unlock(dir, "master")
	if err != nil {
		t.Fatal(err)
	}
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	f := &httpsFixture{dir: dir, store: store, server: NewServer(store, keys), key: key, now: time.Unix(1700000000, 0)}
	f.server.Now = func() time.Time { return f.now }
	f.handler, err = f.server.HTTPSHandler(testHTTPSBase)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *httpsFixture) token(t *testing.T) remote.HTTPSEnrollToken {
	t.Helper()
	token, err := f.store.CreateHTTPSEnrollToken("laptop", testHTTPSBase, remote.PublicKeyFingerprint(f.server.Keys.BundleKey.Public().(ed25519.PublicKey)), time.Minute, f.now)
	if err != nil {
		t.Fatal(err)
	}
	return token
}

func (f *httpsFixture) request(t *testing.T, method, path, id, tag string, body []byte) *http.Request {
	t.Helper()
	r := httptest.NewRequest(method, testHTTPSBase+path, bytes.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	if err := remote.SignHTTPRequest(r, body, id, tag, f.key, f.now); err != nil {
		t.Fatal(err)
	}
	return r
}

func serve(handler http.Handler, r *http.Request) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	return w
}

func (f *httpsFixture) enroll(t *testing.T, token remote.HTTPSEnrollToken) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(remote.HTTPSEnrollRequest{TokenID: token.ID, TokenSecret: token.Secret, PublicKey: base64.StdEncoding.EncodeToString(f.key.Public().(ed25519.PublicKey))})
	if err != nil {
		t.Fatal(err)
	}
	return serve(f.handler, f.request(t, "POST", remote.PathEnrollV2, token.ID, remote.EnrollSignatureTag, body))
}

func (f *httpsFixture) device(t *testing.T) string {
	t.Helper()
	w := f.enroll(t, f.token(t))
	if w.Code != 200 {
		t.Fatalf("enroll: %d %s", w.Code, w.Body.String())
	}
	var response remote.HTTPSEnrollResponse
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	return response.DeviceID
}

func TestHTTPSEnrollProofBeforeSingleUseRedemption(t *testing.T) {
	f := newHTTPSFixture(t)
	token := f.token(t)
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	correct := f.key
	f.key = other
	// A claimed public key different from the signing key cannot burn the token.
	body, _ := json.Marshal(remote.HTTPSEnrollRequest{TokenID: token.ID, TokenSecret: token.Secret, PublicKey: base64.StdEncoding.EncodeToString(correct.Public().(ed25519.PublicKey))})
	w := serve(f.handler, f.request(t, "POST", remote.PathEnrollV2, token.ID, remote.EnrollSignatureTag, body))
	if w.Code != 401 {
		t.Fatalf("wrong proof: %d %s", w.Code, w.Body.String())
	}
	f.key = correct
	if w := f.enroll(t, token); w.Code != 200 {
		t.Fatalf("good proof after bad: %d %s", w.Code, w.Body.String())
	}
	if w := f.enroll(t, token); w.Code != 403 {
		t.Fatalf("reused token: %d", w.Code)
	}
	if _, err := f.store.RedeemEnrollToken(token.ID, token.Secret, f.now); err != ErrTokenInvalid {
		t.Fatalf("v2 token used via v1: %v", err)
	}
}

func TestHTTPSEnrollWrongSecretExpiryAndOrigin(t *testing.T) {
	f := newHTTPSFixture(t)
	token := f.token(t)
	wrong := token
	wrong.Secret = "wrong"
	if w := f.enroll(t, wrong); w.Code != 403 {
		t.Fatalf("wrong secret: %d", w.Code)
	}
	other, err := f.store.CreateHTTPSEnrollToken("wrong origin", "https://other.example", token.BundleFingerprint, time.Minute, f.now)
	if err != nil {
		t.Fatal(err)
	}
	if w := f.enroll(t, other); w.Code != 403 {
		t.Fatalf("wrong origin: %d", w.Code)
	}
	f.now = f.now.Add(2 * time.Minute)
	if w := f.enroll(t, token); w.Code != 403 {
		t.Fatalf("expired token: %d", w.Code)
	}
}

func TestHTTPSReplayProtectionSurvivesRestart(t *testing.T) {
	f := newHTTPSFixture(t)
	id := f.device(t)
	req := f.request(t, "GET", remote.PathStatusV2, id, remote.DeviceSignatureTag, nil)
	if w := serve(f.handler, req.Clone(req.Context())); w.Code != 200 {
		t.Fatalf("first: %d %s", w.Code, w.Body.String())
	}
	if err := f.store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err := OpenStore(filepath.Join(f.dir, FileDatabase))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	f.server.Store = store
	if w := serve(f.handler, req.Clone(req.Context())); w.Code != 403 {
		t.Fatalf("replay after reopen: %d", w.Code)
	}
	f.store = store
	f.now = f.now.Add(time.Second)
	if w := serve(f.handler, f.request(t, "GET", remote.PathStatusV2, id, remote.DeviceSignatureTag, nil)); w.Code != 200 {
		t.Fatalf("fresh proof: %d", w.Code)
	}
}

func TestHTTPSConcurrentReplayHasOneWinner(t *testing.T) {
	f := newHTTPSFixture(t)
	id := f.device(t)
	req := f.request(t, "GET", remote.PathStatusV2, id, remote.DeviceSignatureTag, nil)
	var winners atomic.Int32
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if serve(f.handler, req.Clone(req.Context())).Code == 200 {
				winners.Add(1)
			}
		}()
	}
	wg.Wait()
	if winners.Load() != 1 {
		t.Fatalf("successful replays: %d", winners.Load())
	}
}

func TestHTTPSRejectsExpiredTamperedAndAmbiguousRequests(t *testing.T) {
	f := newHTTPSFixture(t)
	id := f.device(t)
	for _, tc := range []struct {
		name   string
		mutate func(*http.Request)
	}{
		{"method", func(r *http.Request) { r.Method = "POST" }},
		{"missing signature", func(r *http.Request) { r.Header.Del("Signature") }},
		{"duplicate signature", func(r *http.Request) { r.Header.Add("Signature", r.Header.Get("Signature")) }},
		{"query", func(r *http.Request) { r.URL.RawQuery = "x=1" }},
		{"escaped path", func(r *http.Request) { r.URL.RawPath = "/v1/plugins/agentssh/v2/%73tatus" }},
		{"body", func(r *http.Request) { r.Body = http.NoBody; r.Header.Set("Content-Digest", "sha-256=:wrong:") }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := f.request(t, "GET", remote.PathStatusV2, id, remote.DeviceSignatureTag, nil)
			tc.mutate(r)
			if w := serve(f.handler, r); w.Code == 200 {
				t.Fatal("invalid request accepted")
			}
		})
	}
	r := f.request(t, "GET", remote.PathStatusV2, id, remote.DeviceSignatureTag, nil)
	f.now = f.now.Add(2 * time.Minute)
	if w := serve(f.handler, r); w.Code != 401 {
		t.Fatalf("expired proof: %d", w.Code)
	}
}
