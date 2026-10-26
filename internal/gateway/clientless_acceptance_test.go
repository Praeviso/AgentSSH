package gateway_test

import (
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Praeviso/AgentSSH/internal/audit"
	"github.com/Praeviso/AgentSSH/internal/gateway"
	"github.com/Praeviso/AgentSSH/internal/remote"
)

// The same credential, never rotated or replaced, crosses each standing
// boundary through both clientless transports. Refusals create no extra run;
// every durable run and execution audit record names the token's device.
func TestClientlessTokenActivationLifecycle(t *testing.T) {
	for _, transport := range []string{"JSON", "MCP"} {
		t.Run(transport, func(t *testing.T) {
			f, _ := execGateway(t)
			device := tokenDevice(t, f)
			clock := &clock{now: time.Now().UTC().Truncate(time.Second)}
			f.server.Now = clock.Now
			client := &mcpClient{t: t, f: f, token: device.Token}
			args := map[string]any{"host": "web-1", "command": "uptime", "session": "s_lifecycle"}
			refusal := func(code string) {
				t.Helper()
				if transport == "JSON" {
					got := apiCall(t, f, device.Token, remote.PathAPIRun, args)
					if got.status != http.StatusForbidden || got.body.Code != code {
						t.Fatalf("JSON refusal: %d %s, want %s", got.status, got.raw, code)
					}
					return
				}
				for _, got := range []mcpReply{mcpInit(client), client.request("tools/call", map[string]any{"name": "run", "arguments": args})} {
					if got.status != http.StatusForbidden || !strings.Contains(string(got.raw), code) {
						t.Fatalf("MCP refusal: %d %s, want %s", got.status, got.raw, code)
					}
				}
			}
			run := func() {
				t.Helper()
				var result remote.APIRun
				if transport == "JSON" {
					result = runOf(t, apiCall(t, f, device.Token, remote.PathAPIRun, args))
				} else {
					if r := mcpInit(client); r.status != http.StatusOK {
						t.Fatalf("initialize inside window: %d %s", r.status, r.raw)
					}
					tool := client.call("run", args)
					data, _ := json.Marshal(tool.Structured)
					if tool.IsError || json.Unmarshal(data, &result) != nil {
						t.Fatalf("MCP run: %+v", tool)
					}
				}
				if result.State != remote.APIRunFinished || result.Result != remote.APIResultOK || result.ExitCode == nil || *result.ExitCode != 0 {
					t.Fatalf("run inside window: %+v", result)
				}
				verifyRunDevice(t, f, device.DeviceID, result.RunID, result.ReqID)
			}
			activate := func(duration time.Duration, by string) {
				t.Helper()
				if _, err := gateway.ActivateDevice(f.dir, f.store, device.DeviceID, duration, by, "acceptance", clock.Now()); err != nil {
					t.Fatal(err)
				}
			}

			refusal(remote.CodeDeviceInactive)
			activate(time.Minute, "local:alice")
			run()
			clock.Add(time.Minute) // The exact end, not a grace period after it.
			refusal(remote.CodeDeviceInactive)
			if err := gateway.RecordEndedActivations(f.dir, f.store, clock.Now()); err != nil {
				t.Fatal(err)
			}
			activate(time.Hour, "local:bob")
			run()
			clock.Add(10 * time.Second)
			if changed, err := gateway.DeactivateDevice(f.dir, f.store, device.DeviceID, "local:carol", clock.Now()); err != nil || !changed {
				t.Fatalf("deactivate: %v, %v", changed, err)
			}
			refusal(remote.CodeDeviceInactive)
			activate(time.Hour, "local:dave")
			run()
			clock.Add(time.Second)
			if err := gateway.RevokeDevice(f.dir, f.store, device.DeviceID, "local:erin", clock.Now()); err != nil {
				t.Fatal(err)
			}
			refusal(remote.CodeDeviceRevoked)
			if err := gateway.RevokeDevice(f.dir, f.store, device.DeviceID, "local:retrier", clock.Now().Add(time.Minute)); err != nil {
				t.Fatal(err)
			}
			paths, err := filepath.Glob(filepath.Join(f.dir, "runs", device.DeviceID, "rn_*.json"))
			if err != nil || len(paths) != 3 {
				t.Fatalf("three admitted runs, no refused ones: %v, %v", paths, err)
			}
			var lifecycle []string
			executions := 0
			records, err := audit.NewStore(filepath.Join(f.dir, gateway.FileAudit)).ReadAll()
			if err != nil {
				t.Fatal(err)
			}
			for _, record := range records {
				if record.DeviceID != device.DeviceID {
					continue
				}
				switch record.Event {
				case audit.EventDeviceActivated, audit.EventDeviceActivationEnded, audit.EventDeviceDeactivated, audit.EventDeviceRevoked:
					lifecycle = append(lifecycle, string(record.Event)+":"+record.Operator)
				case audit.EventStarted, audit.EventCompleted:
					if record.TokenID != device.TokenID {
						t.Fatalf("execution missing its token: %+v", record)
					}
					executions++
				}
			}
			want := "device_activated:local:alice,device_activation_expired:local:alice,device_activated:local:bob,device_deactivated:local:carol,device_activated:local:dave,device_revoked:local:erin"
			if strings.Join(lifecycle, ",") != want || executions != 6 {
				t.Fatalf("lifecycle %v; execution records %d", lifecycle, executions)
			}
			if result, err := audit.NewStore(filepath.Join(f.dir, gateway.FileAudit)).Verify(); err != nil || !result.OK {
				t.Fatalf("audit chain: %+v, %v", result, err)
			}
		})
	}
}

func verifyRunDevice(t *testing.T, f *fixture, deviceID, runID, reqID string) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(f.dir, "runs", deviceID, runID+".json"))
	if err != nil {
		t.Fatal(err)
	}
	var record struct {
		DeviceID string `json:"device_id"`
		RunID    string `json:"run_id"`
		ReqID    string `json:"req_id"`
		State    string `json:"state"`
	}
	if err := json.Unmarshal(data, &record); err != nil || record.DeviceID != deviceID || record.RunID != runID || record.ReqID != reqID || record.State != "finished" {
		t.Fatalf("run's device attribution: %s, %v", data, err)
	}
}

// Consent is performed through the operator UI. Both issuance and use obey
// the chosen device's window; an inactive refusal spends neither the code
// nor the refresh token. Revoking the device ends every client's grant.
func TestOAuthBrowserConsentObeysTheDevicesWindow(t *testing.T) {
	w := newWebFixture(t)
	o := webOAuth(t, w)
	device := tokenDevice(t, w.fixture)
	b := w.browser(t)
	csrf := b.signIn("alice")
	w.server.Now = w.clock.Now
	client := publicClient(t, w.fixture)
	verifier, challenge := pkce("acceptance")
	path := remote.PathOAuthAuthorize + "?" + authorizationQuery(o, client, "https://agent.example/callback", challenge).Encode()
	consent := func() string {
		t.Helper()
		p := b.do(http.MethodPost, path, url.Values{"csrf": {csrf}, "decision": {"authorize"}, "device": {device.DeviceID}})
		callback, err := url.Parse(p.location)
		if err != nil || p.status != http.StatusSeeOther || callback.Query().Get("code") == "" {
			t.Fatalf("browser consent: %+v", p)
		}
		return callback.Query().Get("code")
	}
	activate := func(duration time.Duration) gateway.Activation {
		t.Helper()
		a, err := gateway.ActivateDevice(w.dir, w.store, device.DeviceID, duration, "local:operator", "acceptance", w.clock.Now())
		if err != nil {
			t.Fatal(err)
		}
		return a
	}
	code := consent()
	refused(t, tokenRequest(t, w.fixture, exchange(client, code, verifier)), "invalid_grant", "not activated")
	firstWindow := activate(time.Minute)
	first := issued(t, tokenRequest(t, w.fixture, exchange(client, code, verifier)))
	if first.ExpiresIn > 60 {
		t.Fatalf("access token outlives the window: %+v", first)
	}
	c := &mcpClient{t: t, f: w.fixture, token: first.AccessToken}
	if r := mcpInit(c); r.status != http.StatusOK {
		t.Fatalf("active OAuth client: %d %s", r.status, r.raw)
	}
	args := map[string]any{"host": "web-1", "command": "uptime", "session": "s_oauth_acceptance"}
	if run := c.call("run", args); run.IsError || run.Structured["result"] != remote.APIResultOK {
		t.Fatalf("run inside window: %+v", run)
	}
	w.clock.Add(firstWindow.Until.Sub(w.clock.Now()))
	if r := mcpInit(c); r.status != http.StatusUnauthorized {
		t.Fatalf("access token at the exact window end: %d %s", r.status, r.raw)
	}
	refused(t, tokenRequest(t, w.fixture, refreshWith(client, first.RefreshToken)), "invalid_grant", "not activated")
	secondCode := consent()
	refused(t, tokenRequest(t, w.fixture, exchange(client, secondCode, verifier)), "invalid_grant", "not activated")
	activate(time.Hour)
	second := issued(t, tokenRequest(t, w.fixture, exchange(client, secondCode, verifier)))
	refreshed := issued(t, tokenRequest(t, w.fixture, refreshWith(client, first.RefreshToken)))
	if r := mcpInit(&mcpClient{t: t, f: w.fixture, token: refreshed.AccessToken}); r.status != http.StatusOK {
		t.Fatalf("refresh after reactivation: %d %s", r.status, r.raw)
	}
	if err := gateway.RevokeDevice(w.dir, w.store, device.DeviceID, "local:operator", w.clock.Now()); err != nil {
		t.Fatal(err)
	}
	for _, tk := range []tokens{second, refreshed} {
		if r := mcpInit(&mcpClient{t: t, f: w.fixture, token: tk.AccessToken}); r.status != http.StatusForbidden || !strings.Contains(string(r.raw), remote.CodeDeviceRevoked) {
			t.Fatalf("grant after device revocation: %d %s", r.status, r.raw)
		}
		refused(t, tokenRequest(t, w.fixture, refreshWith(client, tk.RefreshToken)), "invalid_grant", "device is revoked")
	}
	page := b.do(http.MethodGet, "/audit?"+url.Values{"device": {device.DeviceID}}.Encode(), nil)
	if page.status != http.StatusOK || !strings.Contains(page.body, "Hash chain intact") || !strings.Contains(page.body, "device_revoked") || !strings.Contains(page.body, "local:operator") {
		t.Fatalf("revocation in operator audit page: %d %.1200s", page.status, page.body)
	}
}
