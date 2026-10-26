# A remote MCP endpoint on the gateway (#43)

> Status: done · Issue: [#43](https://github.com/Praeviso/AgentSSH/issues/43) · Epic: [#35](https://github.com/Praeviso/AgentSSH/issues/35)

## Goal and acceptance

Agent platforms that connect to remote MCP servers use the gateway directly:
the token API as MCP tools over Streamable HTTP, authenticated as a token
device.

Done when:

- A test with an MCP client initializes, lists tools, and runs the agent
  workflow (hosts, allowed run, deny, pending, approval, rerun) against a test
  gateway.
- An inactive or revoked device's token is refused at initialization and on
  every call.
- Checked with at least one real MCP client.

## Decisions (the issue's preparation)

- **Specification and SDK.** Streamable HTTP as in revisions 2025-06-18 and
  2025-11-25 (2025-03-26 also negotiated), implemented as a minimal JSON-RPC
  server, not the official Go SDK: `initialize`, `ping`, `tools/list`,
  `tools/call`, JSON answers, no session and no server stream need no new
  dependency.
- **Results versus errors.** A run that is denied, needs approval or fails
  over SSH is a normal tool result whose `result` field says so: the agent
  must act on it (stop, wait for the operator, check what ran), and a tool
  error can read as transient. A refusal from the API (usage, inactive, not
  found, a malformed argument) is a result with `isError`.

## Approach

- `apiOperations` (api.go): one table of method, path, tool name, options and
  handler. `tokenRoutes` registers the HTTP routes from it; `mcpTools` turns
  each into a tool with the OpenAPI document's summary, description and
  request schema.
- `POST /mcp` is a token route (authenticated before and after the body) that
  needs the device active for every request. `GET` and `DELETE` answer 405.
  `MCP-Protocol-Version` is checked; `initialize` echoes a supported version or
  offers the newest, and carries instructions from the agent skill.
- `tools/call` runs the operation's handler into a captured response and
  answers its JSON as text and `structuredContent`, with `isError` when the
  status was not 200. Audit records of tool calls carry `token_id`, as for
  `/api`.

## Progress

- [x] Operation table; MCP endpoint.
- [x] Tests (`internal/gateway/mcp_test.go`): the workflow (initialize with
  version negotiation and instructions, the initialized notification answered
  202, the tool list with schemas, hosts, session, allowed run, deny as a
  result with exit 6, gray zone, approval status pending then approved after
  an operator decides, the rerun, audit records with the token); inactive and
  revoked devices refused at initialize and on `tools/list`, `tools/call`,
  `ping`, and no token at all; protocol edges (GET and DELETE 405, unknown
  method -32601, unknown tool -32602, jsonrpc 1.0 -32600, unsupported version
  header 400, an unknown proposed version answered with the newest, an API
  refusal and an unknown argument as `isError`); the Web UI's cookie refused on
  `/mcp` and the token refused by the Web UI.
- [x] Real client: the official TypeScript SDK (`@modelcontextprotocol/sdk`
  1.32.2, installed outside the repository) against real binaries behind a TLS
  ingress and a real SSH target.
- [x] Docs: README, remote-control.md, gateway-mode.md.
- [x] Final validation.

## Validation

```
gofmt -l .
go vet ./...
golangci-lint run
go test -race ./...
scripts/e2e_tui_audit_run_summary.sh --no-tui
```

Mutation checks, each failing its test: the endpoint open to inactive devices;
refusals not marked `isError`; a denial marked `isError`; the client's
protocol version ignored; a notification answered like a request.

Real client (2026-10-26): `Client` with `StreamableHTTPClientTransport` and the
bearer header connected, negotiated 2025-11-25, read the instructions and the
eight tools, then: hosts; a session; `uptime` → `ok`; `rm -rf` → `denied`,
exit 6, not an error; `whoami` → `approval_required`; the operator granted it
from the CLI; `approval_status` → `approved` (session); `whoami` again → `ok`;
an unknown host → `isError` (`usage`). The SDK's GET for a server stream got
405 and carried on.
