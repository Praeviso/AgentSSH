package remoteserver

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Praeviso/AgentSSH/internal/remote"
)

func TestRevocationDuringAuthenticationIsDefinitive(t *testing.T) {
	for _, path := range []string{remote.PathStatus, remote.PathBundle, remote.PathSign} {
		t.Run(path, func(t *testing.T) {
			f := newHTTPSFixture(t)
			id := f.device(t)
			method := "GET"
			var body []byte
			if path == remote.PathSign {
				method, body = "POST", []byte(`{"host":"web-1","data":""}`)
			}
			req := f.request(t, method, path, id, remote.DeviceSignatureTag, body)
			var once sync.Once
			// The clock boundary is reached after key lookup and before nonce
			// admission: simulate an operator revoking the already loaded device.
			f.server.Now = func() time.Time {
				once.Do(func() {
					if err := f.store.RevokeDevice(id, f.now); err != nil {
						t.Error(err)
					}
				})
				return f.now
			}
			w := serve(f.handler, req)
			var refusal remote.ErrorResponse
			if err := json.Unmarshal(w.Body.Bytes(), &refusal); err != nil {
				t.Fatal(err)
			}
			if w.Code != 403 || refusal.Code != remote.CodeDeviceRevoked || !remote.IsRevoked(&remote.APIError{Code: refusal.Code}) {
				t.Fatalf("ambiguous revocation: %d %s", w.Code, w.Body.String())
			}
			if path == remote.PathSign {
				logs, err := f.store.SignLog(SignLogFilter{DeviceID: id})
				if err != nil || len(logs) != 1 || logs[0].Result != SignRejected || logs[0].Host != "web-1" || logs[0].Reason != "device revoked" {
					t.Fatalf("missing rejection audit: %+v, %v", logs, err)
				}
			}
		})
	}
}

func TestClockFailuresAreDiagnosedOnlyAfterAuthentication(t *testing.T) {
	f := newHTTPSFixture(t)
	id := f.device(t)
	for _, drift := range []time.Duration{-35 * time.Second, time.Minute} {
		t.Run(drift.String(), func(t *testing.T) {
			now := f.now
			r := f.request(t, "GET", remote.PathStatus, id, remote.DeviceSignatureTag, nil)
			f.now = now.Add(drift)
			w := serve(f.handler, r)
			var refusal remote.ErrorResponse
			if err := json.Unmarshal(w.Body.Bytes(), &refusal); err != nil {
				t.Fatal(err)
			}
			if w.Code != 401 || refusal.Code != "clock_skew" || !strings.Contains(refusal.Error, "synchronize") || !strings.Contains(refusal.Error, f.now.UTC().Format(time.RFC3339)) {
				t.Fatalf("opaque clock error: %d %s", w.Code, w.Body.String())
			}
			r.Header.Set("Signature", "agentssh=:AAAA:")
			w = serve(f.handler, r)
			if !strings.Contains(w.Body.String(), `"code":"unauthenticated"`) {
				t.Fatalf("forged proof diagnosed as clock skew: %s", w.Body.String())
			}
			f.now = now
		})
	}
	// Enrollment uses the same diagnostics and a stale proof does not burn its token.
	token := f.token(t)
	f.server.Now = func() time.Time { return f.now.Add(-35 * time.Second) }
	w := f.enroll(t, token)
	if w.Code != 401 || !strings.Contains(w.Body.String(), `"code":"clock_skew"`) {
		t.Fatalf("enroll clock: %d %s", w.Code, w.Body.String())
	}
	f.server.Now = func() time.Time { return f.now }
	if w := f.enroll(t, token); w.Code != 200 {
		t.Fatalf("clock error consumed token: %s", w.Body.String())
	}
}

func TestConcurrentControlPlaneWrites(t *testing.T) {
	f := newHTTPSFixture(t)
	id := f.device(t)
	// A second store models CLI operations while the serving process polls.
	other, err := OpenStore(f.dir + "/" + FileDatabase)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = other.Close() }()
	const count = 24
	tokens := make([]remote.EnrollToken, count)
	requests := make([]*http.Request, count)
	for i := range count {
		tokens[i] = f.token(t)
		requests[i] = f.request(t, "GET", remote.PathStatus, id, remote.DeviceSignatureTag, nil)
	}
	start := make(chan struct{})
	errs := make(chan error, count*3)
	versions := make(chan int64, count)
	var wg sync.WaitGroup
	for i := range count {
		wg.Add(3)
		go func() {
			defer wg.Done()
			<-start
			version, err := other.PutConfig(id, "hosts: {}", "version: 1", f.now)
			if err != nil {
				errs <- fmt.Errorf("config: %w", err)
			} else {
				versions <- version
			}
		}()
		go func(i int) {
			defer wg.Done()
			<-start
			token := tokens[i]
			_, err := other.RedeemEnrollToken(token.ID, token.Secret, token.ServerURL, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", f.now)
			if err != nil {
				errs <- fmt.Errorf("enroll: %w", err)
			}
		}(i)
		go func(i int) {
			defer wg.Done()
			<-start
			if w := serve(f.handler, requests[i]); w.Code != 200 {
				errs <- fmt.Errorf("poll: %d %s", w.Code, w.Body.String())
			}
		}(i)
	}
	close(start)
	wg.Wait()
	close(errs)
	close(versions)
	for err := range errs {
		t.Error(err)
	}
	seen := map[int64]bool{}
	for v := range versions {
		seen[v] = true
	}
	for v := int64(1); v <= count; v++ {
		if !seen[v] {
			t.Errorf("missing configuration revision %d", v)
		}
	}
}

func TestNonceRetentionAndAmortizedPruning(t *testing.T) {
	f := newHTTPSFixture(t)
	id := f.device(t)
	request := func() {
		t.Helper()
		if w := serve(f.handler, f.request(t, "GET", remote.PathStatus, id, remote.DeviceSignatureTag, nil)); w.Code != 200 {
			t.Fatalf("status: %d %s", w.Code, w.Body.String())
		}
	}
	request() // First maintenance pass.
	if _, err := f.store.db.Exec(`INSERT INTO request_nonces VALUES (?,?,?)`, id, "expired", f.now.Unix()-1); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.db.Exec(`INSERT INTO request_nonces VALUES (?,?,?)`, id, "still-live", f.now.Unix()+120); err != nil {
		t.Fatal(err)
	}
	assertNonce := func(nonce string, want int) {
		t.Helper()
		var count int
		if err := f.store.db.QueryRow(`SELECT COUNT(*) FROM request_nonces WHERE device_id=? AND nonce=?`, id, nonce).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != want {
			t.Fatalf("nonce %s: got %d rows, want %d", nonce, count, want)
		}
	}
	request()
	assertNonce("expired", 1) // No cleanup scan in the intervening hot-path request.
	f.now = f.now.Add(time.Minute)
	request()
	assertNonce("expired", 0)
	assertNonce("still-live", 1)
}

func TestAuthenticatedBodiesHaveOneBoundedStrictDecoder(t *testing.T) {
	f := newHTTPSFixture(t)
	id := f.device(t)
	for _, path := range []string{remote.PathEnroll, remote.PathSign} {
		for _, body := range []string{strings.Repeat("x", (64<<10)+1), `{} {}`, `{"unknown":true}`} {
			r := f.request(t, "POST", path, id, remote.DeviceSignatureTag, []byte(body))
			if w := serve(f.handler, r); w.Code != 400 {
				t.Fatalf("%s malformed body: %d %s", path, w.Code, w.Body.String())
			}
		}
	}
}

func TestProofExpiringBeforeAdmissionIsRejected(t *testing.T) {
	f := newHTTPSFixture(t)
	id := f.device(t)
	r := f.request(t, "GET", remote.PathStatus, id, remote.DeviceSignatureTag, nil)
	calls := 0
	f.server.Now = func() time.Time {
		calls++
		if calls == 1 {
			return f.now
		}
		return f.now.Add(time.Minute)
	}
	w := serve(f.handler, r)
	if w.Code != 401 || !strings.Contains(w.Body.String(), `"code":"clock_skew"`) {
		t.Fatalf("expired proof admitted after waiting: %d %s", w.Code, w.Body.String())
	}
}
