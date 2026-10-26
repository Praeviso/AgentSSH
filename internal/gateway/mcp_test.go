package gateway_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/Praeviso/AgentSSH/internal/approval"
	"github.com/Praeviso/AgentSSH/internal/audit"
	"github.com/Praeviso/AgentSSH/internal/gateway"
	"github.com/Praeviso/AgentSSH/internal/remote"
)

// mcpClient speaks MCP's Streamable HTTP transport to the gateway: one
// JSON-RPC message per POST.
type mcpClient struct {
	t     *testing.T
	f     *fixture
	token string
	next  int
}

type mcpReply struct {
	status int
	raw    []byte
	Result json.RawMessage `json:"result"`
	Error  *struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

func (c *mcpClient) post(message map[string]any, header ...string) mcpReply {
	c.t.Helper()
	data, _ := json.Marshal(message)
	req, err := http.NewRequest(http.MethodPost, c.f.base+remote.PathMCP, bytes.NewReader(data))
	if err != nil {
		c.t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	for i := 0; i+1 < len(header); i += 2 {
		req.Header.Set(header[i], header[i+1])
	}
	got := send(c.t, req)
	r := mcpReply{status: got.status, raw: got.raw}
	_ = json.Unmarshal(got.raw, &r)
	return r
}

func (c *mcpClient) request(method string, params any) mcpReply {
	c.t.Helper()
	c.next++
	return c.post(map[string]any{"jsonrpc": "2.0", "id": c.next, "method": method, "params": params})
}

type toolResult struct {
	Content []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	} `json:"content"`
	Structured map[string]any `json:"structuredContent"`
	IsError    bool           `json:"isError"`
}

// call runs a tool and returns its result, failing on a protocol error.
func (c *mcpClient) call(name string, arguments map[string]any) toolResult {
	c.t.Helper()
	r := c.request("tools/call", map[string]any{"name": name, "arguments": arguments})
	var result toolResult
	if r.status != http.StatusOK || r.Error != nil || json.Unmarshal(r.Result, &result) != nil || len(result.Content) != 1 {
		c.t.Fatalf("%s: %d %s", name, r.status, r.raw)
	}
	return result
}

// The agent's workflow over MCP: initialize, list tools, hosts, a session,
// an allowed run, a deny, a gray zone that an operator approves, the rerun.
func TestMCPAgentWorkflow(t *testing.T) {
	f, _ := execGateway(t)
	issued := activeTokenDevice(t, f)
	c := &mcpClient{t: t, f: f, token: issued.Token}
	init := c.request("initialize", map[string]any{"protocolVersion": "2025-06-18", "capabilities": map[string]any{}, "clientInfo": map[string]any{"name": "test", "version": "1"}})
	var info struct {
		ProtocolVersion string         `json:"protocolVersion"`
		Capabilities    map[string]any `json:"capabilities"`
		Instructions    string         `json:"instructions"`
	}
	if init.Error != nil || json.Unmarshal(init.Result, &info) != nil || info.ProtocolVersion != "2025-06-18" || info.Capabilities["tools"] == nil {
		t.Fatalf("initialize: %s", init.raw)
	}
	for _, lesson := range []string{"new_session", "denied", "pending is not approved", "next_offset"} {
		if !strings.Contains(info.Instructions, lesson) {
			t.Errorf("instructions do not mention %q", lesson)
		}
	}
	if r := c.post(map[string]any{"jsonrpc": "2.0", "method": "notifications/initialized"}); r.status != http.StatusAccepted {
		t.Fatalf("initialized notification: %d %s", r.status, r.raw)
	}
	var list struct {
		Tools []struct {
			Name        string         `json:"name"`
			Description string         `json:"description"`
			InputSchema map[string]any `json:"inputSchema"`
		} `json:"tools"`
	}
	if r := c.request("tools/list", map[string]any{}); r.Error != nil || json.Unmarshal(r.Result, &list) != nil {
		t.Fatalf("tools/list: %s", r.raw)
	}
	names := map[string]map[string]any{}
	for _, tool := range list.Tools {
		if tool.Description == "" || tool.InputSchema["type"] != "object" {
			t.Errorf("tool %s: %+v", tool.Name, tool)
		}
		names[tool.Name] = tool.InputSchema
	}
	for _, want := range []string{"status", "hosts", "new_session", "run", "run_output", "cancel_run", "request_status", "approval_status"} {
		if names[want] == nil {
			t.Errorf("no %s tool", want)
		}
	}
	if required, _ := names["run"]["required"].([]any); len(required) != 3 {
		t.Fatalf("run's input schema: %v", names["run"])
	}

	if hosts := c.call("hosts", nil); !strings.Contains(hosts.Content[0].Text, `"web-1"`) {
		t.Fatalf("hosts: %+v", hosts)
	}
	session := c.call("new_session", nil).Structured["session_id"]
	ok := c.call("run", map[string]any{"host": "web-1", "command": "uptime", "session": session})
	if ok.IsError || ok.Structured["result"] != "ok" || !strings.Contains(ok.Content[0].Text, "up 3 days") {
		t.Fatalf("allowed run: %+v", ok)
	}
	// A denial and a pending approval are results the agent acts on, not
	// tool failures.
	denied := c.call("run", map[string]any{"host": "web-1", "command": "reboot", "session": session})
	if denied.IsError || denied.Structured["result"] != "denied" || denied.Structured["exit_code"] != 6.0 {
		t.Fatalf("deny: %+v", denied)
	}
	gray := c.call("run", map[string]any{"host": "web-1", "command": "hostname", "session": session})
	if gray.IsError || gray.Structured["result"] != "approval_required" {
		t.Fatalf("gray zone: %+v", gray)
	}
	approvalID := gray.Structured["responses"].([]any)[0].(map[string]any)["approval_id"].(string)
	if pending := c.call("approval_status", map[string]any{"approval_id": approvalID, "wait_ms": 0}); pending.Structured["status"] != "pending" {
		t.Fatalf("approval status: %+v", pending)
	}
	if _, _, err := gateway.DecideApproval(f.dir, f.store, gateway.Decider{Operator: "web:alice"}, approvalID, approval.VerdictApproved, approval.ScopeSession); err != nil {
		t.Fatal(err)
	}
	if approved := c.call("approval_status", map[string]any{"approval_id": approvalID}); approved.Structured["status"] != "approved" {
		t.Fatalf("after the decision: %+v", approved)
	}
	if rerun := c.call("run", map[string]any{"host": "web-1", "command": "hostname", "session": session}); rerun.Structured["result"] == "approval_required" {
		t.Fatalf("rerun after approval: %+v", rerun)
	}
	// Every record the device's own calls caused names its token; the
	// operator's decision names the operator instead.
	var tokenRecords int
	for _, r := range auditRecords(t, f) {
		switch r.Event {
		case audit.EventStarted, audit.EventCompleted, audit.EventFailed, audit.EventDenied, audit.EventApprovalRequested:
		default:
			continue
		}
		if r.DeviceID == issued.DeviceID {
			if r.TokenID != issued.TokenID {
				t.Fatalf("record without its token: %+v", r)
			}
			tokenRecords++
		}
	}
	if tokenRecords == 0 {
		t.Fatal("no audit records of the MCP runs")
	}
}

// An inactive or revoked device's token is refused at initialization and on
// every call.
func TestMCPRefusesInactiveAndRevokedDevices(t *testing.T) {
	f, _ := execGateway(t)
	issued := tokenDevice(t, f)
	c := &mcpClient{t: t, f: f, token: issued.Token}
	init := map[string]any{"protocolVersion": "2025-06-18", "capabilities": map[string]any{}, "clientInfo": map[string]any{"name": "test", "version": "1"}}
	if r := c.request("initialize", init); r.status != http.StatusForbidden || !strings.Contains(string(r.raw), remote.CodeDeviceInactive) {
		t.Fatalf("initialize while inactive: %d %s", r.status, r.raw)
	}
	if _, err := gateway.ActivateDevice(f.dir, f.store, issued.DeviceID, time.Hour, "local:alice", "", time.Now()); err != nil {
		t.Fatal(err)
	}
	if r := c.request("initialize", init); r.status != http.StatusOK {
		t.Fatalf("initialize while active: %d %s", r.status, r.raw)
	}
	if _, err := gateway.DeactivateDevice(f.dir, f.store, issued.DeviceID, "local:alice", time.Now()); err != nil {
		t.Fatal(err)
	}
	for _, method := range []string{"tools/list", "tools/call", "ping"} {
		if r := c.request(method, map[string]any{"name": "hosts"}); r.status != http.StatusForbidden || !strings.Contains(string(r.raw), remote.CodeDeviceInactive) {
			t.Fatalf("%s while inactive: %d %s", method, r.status, r.raw)
		}
	}
	if err := f.store.RevokeDevice(issued.DeviceID, time.Now()); err != nil {
		t.Fatal(err)
	}
	if r := c.request("initialize", init); r.status != http.StatusForbidden || !strings.Contains(string(r.raw), remote.CodeDeviceRevoked) {
		t.Fatalf("initialize while revoked: %d %s", r.status, r.raw)
	}
	c.token = ""
	if r := c.request("initialize", init); r.status != http.StatusUnauthorized {
		t.Fatalf("initialize without a token: %d %s", r.status, r.raw)
	}
}

func TestMCPProtocolEdges(t *testing.T) {
	f, _ := execGateway(t)
	issued := activeTokenDevice(t, f)
	c := &mcpClient{t: t, f: f, token: issued.Token}
	for _, method := range []string{http.MethodGet, http.MethodDelete} {
		req, _ := http.NewRequest(method, f.base+remote.PathMCP, nil)
		if got := send(t, req); got.status != http.StatusMethodNotAllowed {
			t.Errorf("%s /mcp: %d", method, got.status)
		}
	}
	if r := c.request("resources/list", nil); r.Error == nil || r.Error.Code != -32601 {
		t.Errorf("unknown method: %s", r.raw)
	}
	if r := c.request("tools/call", map[string]any{"name": "rm"}); r.Error == nil || r.Error.Code != -32602 {
		t.Errorf("unknown tool: %s", r.raw)
	}
	if r := c.post(map[string]any{"jsonrpc": "1.0", "id": 1, "method": "ping"}); r.Error == nil || r.Error.Code != -32600 {
		t.Errorf("jsonrpc 1.0: %s", r.raw)
	}
	if r := c.post(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "ping"}, "MCP-Protocol-Version", "1999-01-01"); r.status != http.StatusBadRequest {
		t.Errorf("unsupported protocol version: %d %s", r.status, r.raw)
	}
	if r := c.request("initialize", map[string]any{"protocolVersion": "2099-01-01"}); !strings.Contains(string(r.Result), `"protocolVersion":"2025-11-25"`) {
		t.Errorf("an unknown version gets the newest: %s", r.raw)
	}
	// A refusal by the API is a tool result with isError, so the agent sees it.
	refused := c.call("run", map[string]any{"host": "db-9", "command": "uptime", "session": "s_x"})
	if !refused.IsError || refused.Structured["code"] != remote.CodeUsage {
		t.Errorf("unknown host: %+v", refused)
	}
	if bad := c.call("run", map[string]any{"host": "web-1", "command": "uptime", "session": "s_x", "unknown": 1}); !bad.IsError {
		t.Errorf("an unknown argument: %+v", bad)
	}
}

// The MCP endpoint takes only the bearer token, never the Web UI's session
// cookie, and the Web UI never takes the token.
func TestMCPAndTheWebUIShareNoCredentials(t *testing.T) {
	w := newWebFixture(t)
	issued := activeTokenDevice(t, w.fixture)
	b := w.browser(t)
	b.signIn("alice")
	site, _ := url.Parse(w.site.URL)
	var cookies []string
	for _, cookie := range b.client.Jar.Cookies(site) {
		cookies = append(cookies, cookie.Name+"="+cookie.Value)
	}
	if len(cookies) == 0 {
		t.Fatal("no Web UI session cookie")
	}
	c := &mcpClient{t: t, f: w.fixture}
	if r := c.post(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "ping"}, "Cookie", strings.Join(cookies, "; ")); r.status != http.StatusUnauthorized {
		t.Fatalf("the Web UI's cookie on /mcp: %d %s", r.status, r.raw)
	}
	anonymous := w.browser(t)
	if p := anonymous.do(http.MethodGet, "/approvals", nil, "Authorization", "Bearer "+issued.Token); p.status != http.StatusSeeOther || p.location != "/login" {
		t.Fatalf("the token on the Web UI: %+v", p)
	}
}
