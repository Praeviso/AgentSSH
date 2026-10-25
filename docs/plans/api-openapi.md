# The rest of the JSON API and its OpenAPI document (#42)

> Status: done · Issue: [#42](https://github.com/Praeviso/AgentSSH/issues/42) · Parent: [#39](https://github.com/Praeviso/AgentSSH/issues/39) · Epic: [#35](https://github.com/Praeviso/AgentSSH/issues/35)

## Goal and acceptance

The token API covers the agent's other commands, and an OpenAPI 3.1 document
describes every JSON endpoint (#41's and these), served by the gateway with the
bearer scheme, kept honest by a test.

Done when:

- Each endpoint answers like its CLI counterpart for the same device state.
- The document validates and every documented operation succeeds against a
  test gateway with example payloads.
- The README documents the JSON API.

## Approach

- **Endpoints.** `POST /api/request/status {req_id}` (the signed route's
  handler: `runner.RequestStatus` over the device's own audit records),
  `POST /api/approval/status {approval_id, wait_ms?}` (the device's
  `approval.StatusResult`, polling every 250 ms while pending up to the wait,
  answering at once on a decision), `POST /api/session` (`session.NewID`).
  `GET /api/hosts` came with #40. All need the device active.
- **Document.** `internal/gateway/openapi.json`, embedded, served at
  `GET /api/openapi.json` without a token, with `servers` set to the gateway's
  public base. Written by hand (no generator dependency) with descriptions for
  the agents that read them: what `denied`, `approval_required` and
  `ssh_error` mean for the next step. Schemas use a small JSON Schema subset:
  `$ref`, `type`, `properties`, `required`, `additionalProperties`, `items`,
  `enum`.
- **Drift test.** The routes served (`Server.OpenRoutes`, test-only) must equal
  the operations documented; every `$ref` resolves; every example fits its
  request schema; every operation, sent with its example (live IDs in place of
  the examples'), answers 200 and fits its response schema, and every
  operation is exercised; a refusal fits the Error schema. A unit test makes
  sure the validator refuses each kind of violation.
- **CLI parity test.** `/api/hosts` equals the public inventory of the pushed
  configuration (`hosts --json`); `/api/request/status` equals
  `runner.RequestStatus` over the device's records (`status --json`);
  `/api/approval/status` equals `gateway.ApprovalStatus` (`approval status`),
  before and after an operator decides during a wait, which returns well
  before the wait ends; sessions are `s_` and eight hex characters, fresh each
  time.

## Progress

- [x] Endpoints, embedded document and its route.
- [x] Tests: `internal/gateway/openapi_test.go`.
- [x] Docs: README (endpoint table, OpenAPI URL), remote-control.md,
  gateway-mode.md.
- [x] Final validation.

## Validation

```
gofmt -l .
go vet ./...
golangci-lint run
go test -race ./...
scripts/e2e_tui_audit_run_summary.sh --no-tui
```

Results (2026-10-25, final code): gofmt clean, `go vet` and `golangci-lint`
(0 issues) pass, `go test -race ./...` passes, the e2e script exits 0.

Mutation checks, each failing its test: a route left out of the document; an
undocumented route served; the document disagreeing with an answer
(`next_offset` as a string); an example that fits no schema; an approval wait
that ignores a decision (it ran the full ten seconds).

Live, with real binaries behind a TLS ingress and curl: `openapi.json` without
a token (3.1.0, the gateway's public base, nine paths); a session; a gray-zone
command answered `approval_required` with its approval ID; an approval status
call with a 20 s wait answered `approved` (session scope) two seconds in, when
the operator granted it from the CLI; the rerun in the same session answered
`ok`; the request status answered for its request ID; the chain verified.
