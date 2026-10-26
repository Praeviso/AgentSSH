package gateway

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"strings"

	"github.com/Praeviso/AgentSSH/internal/controlplane"
	"github.com/Praeviso/AgentSSH/internal/remote"
)

// The MCP endpoint offers the token API as MCP tools over Streamable HTTP,
// for agent platforms that connect to remote MCP servers. It is a minimal
// server: each POST carries one JSON-RPC message, requests are answered with
// application/json, and there is no server-initiated stream or session. A
// tool runs the same handler as its /api route, so its result is the same
// JSON. Every request authenticates as a token device that must be active,
// initialization included.

// mcpVersions are the protocol revisions the endpoint speaks, newest first.
var mcpVersions = []string{"2025-11-25", "2025-06-18", "2025-03-26"}

// mcpInstructions is what skills/agentssh-usage teaches, for the agent.
const mcpInstructions = `Run commands on servers through this AgentSSH gateway. The gateway authorizes, runs and audits every command under this device's policy.
- One session per task: call new_session once and pass its session_id to every run of the task.
- Use hosts to find targets. Prefer bounded output (journalctl -n 100 --no-pager, logs --tail 100).
- result "denied": policy forbids the command. Stop that operation; never retry it reworded or in another form.
- result "approval_required": an operator must decide. Wait with approval_status on the approval_id (pending is not approved), then run the same command again, unchanged, in the same session.
- result "ssh_error": the command may or may not have run. Find out what ran before retrying.
- state "running": the run outlived the wait and keeps running; continue with run_output from next_offset. Do not start it again.
- A refusal saying the device is not activated or is revoked: stop and tell the user; only the gateway's operator can fix it.`

// JSON-RPC 2.0 error codes.
const (
	rpcParseError     = -32700
	rpcInvalidRequest = -32600
	rpcMethodNotFound = -32601
	rpcInvalidParams  = -32602
)

type rpcMessage struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method,omitempty"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type rpcReply struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

type mcpTool struct {
	Name        string          `json:"name"`
	Title       string          `json:"title,omitempty"`
	Description string          `json:"description"`
	InputSchema json.RawMessage `json:"inputSchema"`
	op          apiOperation
}

// mcpTools describes each API operation as a tool, from the OpenAPI document:
// its summary and description, and its request schema as the input schema.
func (s *Server) mcpTools() ([]mcpTool, error) {
	var doc map[string]any
	if err := json.Unmarshal(openAPIDocument, &doc); err != nil {
		return nil, err
	}
	schemas, _ := doc["components"].(map[string]any)["schemas"].(map[string]any)
	var tools []mcpTool
	for _, op := range s.apiOperations() {
		spec, _ := doc["paths"].(map[string]any)[op.path].(map[string]any)[strings.ToLower(op.method)].(map[string]any)
		if spec == nil {
			return nil, fmt.Errorf("%s %s is not in the OpenAPI document", op.method, op.path)
		}
		description, _ := spec["summary"].(string)
		if more, ok := spec["description"].(string); ok {
			description += " " + more
		}
		input := any(map[string]any{"type": "object", "properties": map[string]any{}, "additionalProperties": false})
		if body, ok := spec["requestBody"].(map[string]any); ok {
			schema := body["content"].(map[string]any)["application/json"].(map[string]any)["schema"].(map[string]any)
			if ref, ok := schema["$ref"].(string); ok {
				input = schemas[strings.TrimPrefix(ref, "#/components/schemas/")]
			}
		}
		raw, err := json.Marshal(input)
		if err != nil {
			return nil, err
		}
		tools = append(tools, mcpTool{Name: op.tool, Title: strings.ReplaceAll(op.tool, "_", " "), Description: description, InputSchema: raw, op: op})
	}
	return tools, nil
}

// mcpRoutes are the MCP endpoint: POST for messages; GET (a server stream)
// and DELETE (a session) are not offered.
func (s *Server) mcpRoutes() []controlplane.OpenRoute {
	refuse := func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Allow", "POST")
		controlplane.WriteError(w, http.StatusMethodNotAllowed, remote.CodeBadRequest, "this MCP endpoint takes POST only: no server stream, no session")
	}
	return []controlplane.OpenRoute{
		s.tokenRoute("POST", remote.PathMCP, tokenOptions{needsActive: true, oauth: true, maxBody: maxExecBody, respondWithin: respondWithin}, s.handleMCP),
		{Method: "GET", Path: remote.PathMCP, Handler: refuse},
		{Method: "DELETE", Path: remote.PathMCP, Handler: refuse},
	}
}

func (s *Server) handleMCP(w http.ResponseWriter, r *http.Request, device controlplane.Device, cred credential, body []byte) {
	if v := r.Header.Get("MCP-Protocol-Version"); v != "" && !slices.Contains(mcpVersions, v) {
		controlplane.WriteError(w, http.StatusBadRequest, remote.CodeBadRequest, "unsupported MCP-Protocol-Version "+v)
		return
	}
	var msg rpcMessage
	if err := json.Unmarshal(body, &msg); err != nil {
		reply(w, nil, nil, &rpcError{rpcParseError, "the body is not one JSON-RPC message"})
		return
	}
	if msg.JSONRPC != "2.0" {
		reply(w, msg.ID, nil, &rpcError{rpcInvalidRequest, "jsonrpc must be 2.0"})
		return
	}
	// A notification or a response to the server: nothing to answer.
	if len(msg.ID) == 0 || msg.Method == "" {
		w.WriteHeader(http.StatusAccepted)
		return
	}
	switch msg.Method {
	case "initialize":
		var params struct {
			ProtocolVersion string `json:"protocolVersion"`
		}
		_ = json.Unmarshal(msg.Params, &params)
		version := mcpVersions[0]
		if slices.Contains(mcpVersions, params.ProtocolVersion) {
			version = params.ProtocolVersion
		}
		reply(w, msg.ID, map[string]any{
			"protocolVersion": version,
			"capabilities":    map[string]any{"tools": map[string]any{"listChanged": false}},
			"serverInfo":      map[string]any{"name": "agentssh-gateway", "title": "AgentSSH gateway", "version": "1"},
			"instructions":    mcpInstructions,
		}, nil)
	case "ping":
		reply(w, msg.ID, map[string]any{}, nil)
	case "tools/list":
		tools, err := s.mcpTools()
		if err != nil {
			controlplane.WriteError(w, http.StatusInternalServerError, remote.CodeInternal, "tool list unavailable")
			return
		}
		reply(w, msg.ID, map[string]any{"tools": tools}, nil)
	case "tools/call":
		s.callTool(w, r, device, cred, msg)
	default:
		reply(w, msg.ID, nil, &rpcError{rpcMethodNotFound, "unknown method " + msg.Method})
	}
}

// callTool runs a tool's API handler and answers its JSON as the tool
// result. Every answer the API gives with 200 is a result, denied,
// approval_required and ssh_error runs included (their result field says
// so); a refusal (usage, inactive, not found) is a result with isError set,
// so the agent sees why.
func (s *Server) callTool(w http.ResponseWriter, r *http.Request, device controlplane.Device, cred credential, msg rpcMessage) {
	var params struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
	}
	if err := json.Unmarshal(msg.Params, &params); err != nil || params.Name == "" {
		reply(w, msg.ID, nil, &rpcError{rpcInvalidParams, "tools/call needs a tool name"})
		return
	}
	tools, err := s.mcpTools()
	if err != nil {
		controlplane.WriteError(w, http.StatusInternalServerError, remote.CodeInternal, "tool list unavailable")
		return
	}
	i := slices.IndexFunc(tools, func(t mcpTool) bool { return t.Name == params.Name })
	if i < 0 {
		reply(w, msg.ID, nil, &rpcError{rpcInvalidParams, "unknown tool " + params.Name})
		return
	}
	arguments := params.Arguments
	if len(arguments) == 0 || string(arguments) == "null" {
		arguments = []byte("{}")
	}
	answer := &capturedAnswer{header: http.Header{}, status: http.StatusOK}
	tools[i].op.handler(answer, r, device, cred, arguments)
	text := strings.TrimSpace(answer.body.String())
	result := map[string]any{"content": []map[string]any{{"type": "text", "text": text}}, "isError": answer.status != http.StatusOK}
	var structured map[string]any
	if json.Unmarshal(answer.body.Bytes(), &structured) == nil {
		result["structuredContent"] = structured
	}
	reply(w, msg.ID, result, nil)
}

func reply(w http.ResponseWriter, id json.RawMessage, result any, rpcErr *rpcError) {
	if len(id) == 0 {
		id = json.RawMessage("null")
	}
	controlplane.WriteJSON(w, http.StatusOK, rpcReply{JSONRPC: "2.0", ID: id, Result: result, Error: rpcErr})
}

// capturedAnswer keeps what an API handler writes, for a tool result.
type capturedAnswer struct {
	header http.Header
	status int
	body   bytes.Buffer
}

func (a *capturedAnswer) Header() http.Header         { return a.header }
func (a *capturedAnswer) Write(p []byte) (int, error) { return a.body.Write(p) }
func (a *capturedAnswer) WriteHeader(status int)      { a.status = status }
