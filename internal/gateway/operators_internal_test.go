package gateway

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"regexp"
	"sync"
	"testing"
	"time"

	"github.com/Praeviso/AgentSSH/internal/audit"
	"github.com/Praeviso/AgentSSH/internal/controlplane"
	"github.com/Praeviso/AgentSSH/internal/remote"
)

// RFC 6238 appendix B: the SHA-1 secret "12345678901234567890" at T=59 is
// 94287082; six digits keep the last six.
func TestTOTPMatchesRFC6238(t *testing.T) {
	secret := []byte("12345678901234567890")
	for _, tc := range []struct {
		unix int64
		want string
	}{{59, "287082"}, {1111111109, "081804"}, {1234567890, "005924"}, {2000000000, "279037"}} {
		if got := TOTPCode(secret, time.Unix(tc.unix, 0)); got != tc.want {
			t.Fatalf("T=%d: %s, want %s", tc.unix, got, tc.want)
		}
	}
	now := time.Unix(1234567890, 0)
	if matchTOTP(secret, "005924", now) < 0 || matchTOTP(secret, "005924", now.Add(31*time.Second)) < 0 {
		t.Fatal("a code was refused within one step of drift")
	}
	if matchTOTP(secret, "005924", now.Add(91*time.Second)) >= 0 || matchTOTP(secret, "12345", now) >= 0 {
		t.Fatal("a stale or malformed code was accepted")
	}
}

func TestPasswordHashesVerify(t *testing.T) {
	PasswordParams.Time, PasswordParams.MemoryKiB = 1, 64
	hash := hashPassword("correct horse battery")
	if !checkPassword(hash, "correct horse battery") || checkPassword(hash, "correct horse batterY") || checkPassword("$argon2id$garbage", "x") {
		t.Fatal("password check")
	}
	if hashPassword("correct horse battery") == hash {
		t.Fatal("hashes are not salted")
	}
}

func operatorStore(t *testing.T) (*controlplane.Store, *controlplane.Keys, int64) {
	t.Helper()
	ScryptWorkFactor = 10
	dir := t.TempDir()
	if err := Init(dir, "master"); err != nil {
		t.Fatal(err)
	}
	store, err := OpenStore(filepath.Join(dir, FileDatabase))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	keys, err := controlplane.Unlock(dir, "master")
	if err != nil {
		t.Fatal(err)
	}
	PasswordParams.Time, PasswordParams.MemoryKiB = 1, 64
	if err := AddOperator(store, "alice", "correct horse battery", time.Now()); err != nil {
		t.Fatal(err)
	}
	op, err := checkOperatorPassword(context.Background(), store, "alice", "correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	return store, keys, op.ID
}

// Each of revocation's two guards holds on its own: the revoked operator's
// sessions are deleted, and a session row that survived is still refused.
func TestRevocationGuardsHoldEachOnTheirOwn(t *testing.T) {
	store, _, id := operatorStore(t)
	now := time.Now()
	if _, err := newSession(store, id, StageActive, now); err != nil {
		t.Fatal(err)
	}
	if err := RevokeOperator(store, "alice", now); err != nil {
		t.Fatal(err)
	}
	var rows int
	if err := store.DB().QueryRow(`SELECT count(*) FROM web_sessions WHERE operator_id = ?`, id).Scan(&rows); err != nil || rows != 0 {
		t.Fatalf("sessions left after revocation: %d, %v", rows, err)
	}
	// A session written for the revoked operator (as by a request racing the
	// revocation) is refused by the status check alone.
	token, err := newSession(store, id, StageActive, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := lookupSession(store, token, now); ok {
		t.Fatal("a revoked operator's session was accepted")
	}
}

// A code is accepted once, and an older step is refused after a newer one.
func TestTOTPCodesAreAcceptedOnce(t *testing.T) {
	store, keys, id := operatorStore(t)
	now := time.Unix(1_800_000_000, 0)
	secret, _ := NewTOTPSecret()
	if err := enrollTOTP(store, keys, id, secret, TOTPCode(secret, now), now); err != nil {
		t.Fatal(err)
	}
	if err := checkTOTP(store, keys, id, TOTPCode(secret, now), now); err == nil {
		t.Fatal("the enrollment code was accepted again")
	}
	later := now.Add(30 * time.Second)
	code := TOTPCode(secret, later)
	if err := checkTOTP(store, keys, id, code, later); err != nil {
		t.Fatal(err)
	}
	if err := checkTOTP(store, keys, id, code, later); err == nil {
		t.Fatal("a code was accepted twice")
	}
}

// A host grant adds its rule to the policy it read; if another push lands
// first, the grant fails instead of overwriting that push.
func TestHostGrantNeverOverwritesANewerPush(t *testing.T) {
	store, _, _ := operatorStore(t)
	now := time.Now()
	if _, err := store.DB().Exec(`INSERT INTO devices (id, name, public_key, status, created_at) VALUES ('dev_test', 'vm', 'k', 'active', ?)`, controlplane.FormatTime(now)); err != nil {
		t.Fatal(err)
	}
	inv := "hosts:\n  web-1: {addr: 10.0.0.1, user: deploy, identity: web}\n"
	if _, err := store.DB().Exec(`INSERT INTO identities (name, public_key, private_key, status, created_at) VALUES ('web', 'p', x'00', 'active', ?)`, controlplane.FormatTime(now)); err != nil {
		t.Fatal(err)
	}
	if _, err := controlplane.PushConfig(store, "dev_test", inv, "version: 1\n", now); err != nil {
		t.Fatal(err)
	}
	opts := decisionOptions(t.TempDir(), store, "dev_test", "web:alice", now)
	admin := "version: 1\nrules:\n  - {name: admin, match: {cmd_regex: '^uptime$'}, action: allow}\n"
	if _, err := controlplane.PushConfig(store, "dev_test", inv, admin, now); err != nil {
		t.Fatal(err)
	}
	if err := opts.SavePolicy(opts.Bundle.Policy); !errors.Is(err, controlplane.ErrConfigChanged) {
		t.Fatalf("save over a newer push: %v", err)
	}
	if cfg, _ := store.Config("dev_test"); cfg.Version != 2 || cfg.PolicyYAML != admin {
		t.Fatalf("config after the refused save: v%d\n%s", cfg.Version, cfg.PolicyYAML)
	}
}

// Concurrent enrollment pages (two tabs) all show the one key the session
// keeps, so a code from any of them verifies.
func TestConcurrentEnrollmentPagesShowOneKey(t *testing.T) {
	store, keys, id := operatorStore(t)
	for round := 0; round < 20; round++ {
		token, err := newSession(store, id, StagePassword, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		const pages = 8
		secrets := make([][]byte, pages)
		var start, done sync.WaitGroup
		start.Add(1)
		for i := range secrets {
			done.Add(1)
			go func() {
				defer done.Done()
				start.Wait()
				secrets[i], _ = pendingTOTP(store, keys, token)
			}()
		}
		start.Done()
		done.Wait()
		kept, err := pendingTOTP(store, keys, token)
		if err != nil {
			t.Fatal(err)
		}
		for i, secret := range secrets {
			if !bytes.Equal(secret, kept) {
				t.Fatalf("round %d: page %d shows a key the session did not keep", round, i)
			}
		}
	}
}

// takePasswordChecks occupies every password check, as concurrent sign-ins
// would, and returns a function that frees one; the test's end frees the
// rest.
func takePasswordChecks(t *testing.T) (free func()) {
	t.Helper()
	held := cap(passwordChecks)
	for range held {
		passwordChecks <- struct{}{}
	}
	free = func() {
		if held > 0 {
			held--
			<-passwordChecks
		}
	}
	t.Cleanup(func() {
		for held > 0 {
			free()
		}
	})
	return free
}

// At most cap(passwordChecks) argon2id checks run at once; a check waits for
// a free one only until its context ends.
func TestPasswordChecksAreBoundedAtOnce(t *testing.T) {
	store, _, _ := operatorStore(t)
	free := takePasswordChecks(t)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := checkOperatorPassword(ctx, store, "alice", "correct horse battery"); !errors.Is(err, ErrPasswordsBusy) {
		t.Fatalf("check with every slot taken: %v", err)
	}
	free()
	if _, err := checkOperatorPassword(context.Background(), store, "alice", "correct horse battery"); err != nil {
		t.Fatalf("check with a free slot: %v", err)
	}
}

// A sign-in refused as busy never had its password checked, so it does not
// count against the account: more busy refusals than the failure limit
// still leave the operator able to sign in.
func TestBusySignInsAreNotFailures(t *testing.T) {
	store, keys, _ := operatorStore(t)
	web, err := NewWebUI(t.TempDir(), store, keys)
	if err != nil {
		t.Fatal(err)
	}
	site := httptest.NewTLSServer(web.Handler())
	t.Cleanup(site.Close)
	client := *site.Client()
	client.Jar, _ = cookiejar.New(nil)
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	csrf := regexp.MustCompile(`name="csrf" value="([0-9a-f]+)"`)
	login := func() int {
		t.Helper()
		resp, err := client.Get(site.URL + "/login")
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		m := csrf.FindSubmatch(body)
		if m == nil {
			t.Fatalf("no CSRF token:\n%.300s", body)
		}
		resp, err = client.PostForm(site.URL+"/login", url.Values{"csrf": {string(m[1])}, "name": {"alice"}, "password": {"correct horse battery"}})
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		return resp.StatusCode
	}
	defer func(wait time.Duration) { passwordWait = wait }(passwordWait)
	passwordWait = 20 * time.Millisecond
	free := takePasswordChecks(t)
	for i := 0; i <= accountFailures; i++ {
		if status := login(); status != http.StatusServiceUnavailable {
			t.Fatalf("busy sign-in %d answered %d", i, status)
		}
	}
	for range cap(passwordChecks) {
		free()
	}
	if status := login(); status != http.StatusSeeOther {
		t.Fatalf("sign-in once checks were free answered %d", status)
	}
}

// Two requests that both find the same window ended record its end once.
func TestAnEndedWindowFoundTwiceIsRecordedOnce(t *testing.T) {
	store, _, _ := operatorStore(t)
	dir := t.TempDir()
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	token, err := store.CreateEnrollToken("agent", "https://gw.example/agentssh", remote.PublicKeyFingerprint(pub), time.Minute, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	device, err := store.RedeemEnrollToken(token.ID, token.Secret, "https://gw.example/agentssh", base64.StdEncoding.EncodeToString(pub), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	a, err := ActivateDevice(dir, store, device.ID, time.Minute, "local:alice", "", time.Now().Add(-time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	// Both finders read the window before either claims it.
	for range 2 {
		if err := recordActivationEnd(dir, store, a, time.Now()); err != nil {
			t.Fatal(err)
		}
	}
	records, err := activationAudit(dir).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	ended := 0
	for _, record := range records {
		if record.Event == audit.EventDeviceActivationEnded {
			ended++
		}
	}
	if ended != 1 {
		t.Fatalf("the end was recorded %d times", ended)
	}
}

func TestRemaining(t *testing.T) {
	now := time.Now()
	for d, want := range map[time.Duration]string{
		20 * time.Second: "under 1m", 45 * time.Minute: "45m", 2 * time.Hour: "2h", 90 * time.Minute: "1h30m", 24 * time.Hour: "24h",
	} {
		if got := Remaining(now.Add(d), now); got != want {
			t.Errorf("Remaining(%s) = %q, want %q", d, got, want)
		}
	}
}

func TestAPIWait(t *testing.T) {
	ms := func(v int64) *int64 { return &v }
	for _, tc := range []struct {
		in   *int64
		want time.Duration
	}{
		{nil, 20 * time.Second}, {ms(0), 0}, {ms(-5), 0}, {ms(1500), 1500 * time.Millisecond}, {ms(3_600_000), 50 * time.Second},
	} {
		if got := apiWait(tc.in); got != tc.want {
			t.Errorf("apiWait(%v) = %s, want %s", tc.in, got, tc.want)
		}
	}
}
