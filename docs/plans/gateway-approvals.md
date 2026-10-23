# Approval state and grants on the gateway (#19)

> Status: done · Issue: [#19](https://github.com/Praeviso/AgentSSH/issues/19) · Parent: [#18](https://github.com/Praeviso/AgentSSH/issues/18) · Epic: [#11](https://github.com/Praeviso/AgentSSH/issues/11)

## Goal and acceptance

For gateway devices, pending requests, resolutions, session/task grants and
plan manifests live only on `agentssh-gateway` (`devices/<id>/approval/`,
already written by the gateway's runner since #15), and only the gateway
authorizes. A device can submit and query, never decide.

Done when:

- A device can `approval status|wait`, `plan submit|status|wait`, and use
  `run --wait-approval` and `plan run|resume --wait-approval`, with the same
  output and exit codes as local mode.
- The gateway host decides with `agentssh-gateway approval ls|show|grant|deny`
  and `agentssh-gateway plan show|grant|deny`; decisions are appended to the
  gateway's audit chain with the device's `device_id`.
- Test: no device request can adjudicate (no such route; a device's signed
  request to one is refused and nothing is resolved).
- Test: after a session grant on the gateway, a rerun in the same session
  matches it, another session does not, and an explicit deny still wins.
- Test: after a whole plan is approved, running its steps one by one creates
  no new approval requests.

Out of scope: the Web UI (#20); host-scope grants on the gateway (they would
rewrite the device's pushed policy; the operator edits and pushes it instead,
as in managed mode).

## Approach

Gateway device endpoints (read and submit only):

- `POST /approvals/status {approval_id}` → `{status, wait_timeout_ms}`.
- `POST /plans/submit` → `{response, exit_code}`: the same preflight as local
  `plan submit` (`runner.SubmitPlan`) against the device's pushed policy and
  gateway-side grants. Commands carry their stdin identity (sha256, size) only;
  stdin data stays on the device until its step runs. The client mints the
  plan ID (it keys local payload pins); the gateway validates it, and plan
  manifests are created exclusively in the device's own directory.
- `POST /plans/status {plan_id}` → `{status, wait_timeout_ms}`.
- `POST /authorize {host, session, commands}` → per-command preflight status,
  for the readiness checks `run --wait-approval` and `plan run` make after an
  approval (a resolution is written before its grant). No side effects.
- Waiting is client-side polling of the status endpoints; the default timeout
  is the device policy's `approval.wait_timeout`, returned with each status.

Gateway admin (`internal/gateway/approvals.go`, `cmd/agentssh-gateway`): find a
request or plan by ID across `devices/*/approval`, then `approval.ApplyDecision`
/ `ApplyPlanDecision` with that device's stores, its policy's TTLs, channel
`gateway`, and an audit store that stamps `device_id`
(`ApplyOptions.DeviceID`). Host scope is refused before anything is written.

Client: one seam per question, local or gateway — approval status, plan
status, plan submit, preflight — used by the existing commands and wait loops.

## Progress

- [x] Protocol (`internal/remote/approvals.go`) and gateway device endpoints
  (`internal/gateway/approvals.go`): approval status, plan submit, plan status,
  authorize; per-device stores (`deviceApprovals`), shared by `/exec`.
- [x] Gateway admin: `ListApprovals`, `ApprovalStatus`, `PlanStatus`,
  `DecideApproval`, `DecidePlan` (device found by ID across
  `devices/*/approval`; device policy TTLs; `ApplyOptions.DeviceID` stamps the
  audit record; channel `gateway`; host scope refused first), and
  `agentssh-gateway approval ls|show|grant|deny`, `plan show|grant|deny`.
- [x] Client seams (`cmd/agentssh/gateway.go`): `approvalStatus`,
  `planStatus`, `preflight`, `gatewaySubmitPlan`, `waitFor` (backoff 200ms to
  2s; ticker 1s for gateway readiness loops). Used by `approval status|wait`,
  `plan submit|status|wait`, `run --wait-approval`, `plan run|resume` (plan
  approval is now submitted to the gateway as locally) and execution
  `next_action`. The #17 refusals are lifted.
- [x] Executions record `approval_on_gateway`; a plan kept in the store the
  device no longer uses is superseded and the remaining steps resubmitted.
  This also covers the #28 review comment that #29 fixed in isolation (#29
  would have dropped gateway plans once approvals moved to the gateway).
- [x] Security review follow-up: a plan's review text is the device's and is
  shown to the gateway's operator. `plan show` quotes it, and `/plans/submit`
  refuses control characters in review and step fields (newlines and tabs
  stay allowed in description, impact and recovery, at most 16 KiB each), so a
  device cannot write terminal escapes to the operator's screen.
  Test: `TestPlanReviewTextCannotCarryControlCharacters` (mutation-checked).
- [x] Tests: see Validation.
- [x] Docs: `docs/architecture/remote-control.md` (approvals table, admin
  commands, superseded plans).
- [x] Final validation.

## Validation

```
gofmt -l .
go vet ./...
go build ./cmd/...
golangci-lint run
go test -race ./...
go test -run '^$' -fuzz FuzzReadExecStream -fuzztime 30s ./internal/remote
scripts/e2e_tui_audit_run_summary.sh --no-tui
```

Results (2026-10-23, final code):

- `gofmt -l .` clean; `go vet ./...`, `go build ./cmd/...` pass;
  `golangci-lint run` 0 issues; `go test -race ./...` all packages pass;
  `FuzzReadExecStream` 30 s no failures; e2e script exit 0.
- Acceptance tests:
  - `TestDevicesCannotDecideApprovals`: a device signing its own requests to
    nine plausible decision routes gets 404 for each; its request stays
    pending and the rerun is still exit 7.
  - `TestGatewaySessionGrantScopeAndDenyPrecedence`: the granted session reruns
    (twice), another session gets a new request, and a deny pushed later wins.
  - `TestGatewayPlanIsApprovedOnceThenRunsStepByStep`: plan run submits two
    gray-zone steps for one review; after `plan grant --session` the resume runs
    all three steps with no new approval request, keeps the gateway's plan, and
    streams `request_id`s.
- Parity: `TestGatewayApprovalWorkflowMatchesLocal` (12 steps: pending run,
  status, wait 0s, decision, wait, status, rerun; then the deny path; unknown
  ID) gives identical output and exit codes in both modes.
- Also: `run --wait-approval` waits for a gateway decision and runs once; waits
  without `--timeout` use the gateway policy's `wait_timeout`; decisions are
  audited with the device and channel; another device cannot read a request;
  host scope is refused before anything is resolved; gateway CLI wiring.
- Mutation checks, each failing exactly its test: approval status read
  locally; preflight answered locally; no `device_id` on decisions; host scope
  allowed; plan submitted locally; default wait not from the device policy
  (the wait then runs the default 10 minutes); no `approval_on_gateway` marker
  (the gateway's plan is superseded); no supersede step (a local plan blocks a
  gateway device).
