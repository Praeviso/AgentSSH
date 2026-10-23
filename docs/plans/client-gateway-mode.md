# Client gateway mode (#17)

> Status: done · Issue: [#17](https://github.com/Praeviso/AgentSSH/issues/17) · Parent: [#13](https://github.com/Praeviso/AgentSSH/issues/13) · Epic: [#11](https://github.com/Praeviso/AgentSSH/issues/11)

## Goal and acceptance

A device enrolls with `--mode managed|gateway` (default `managed`) and the
mode is stored in `remote.yaml`. In gateway mode the agent-facing commands
(`hosts`, `run`, `status`, `plan run|resume|execution`, `session new`) go through
`agentssh-gateway`; the local inventory, policy, approval and audit files are
ignored, and commands that read or change them are refused. The agent and
`skills/agentssh-usage/SKILL.md` do not need to know the mode.

Done when:

- Enrolling with `--mode gateway` against `agentssh-server`, or with
  `--mode managed` against `agentssh-gateway`, fails with a clear message and
  leaves the home unenrolled; a token is not spent on the wrong control plane.
- Every response is checked against the enrolled mode; a mismatch fails closed.
- The same CLI cases (allowed, failing, denied, gray zone, SSH error, group,
  stdin, unknown host, missing session, `hosts`, `status`) under local and under
  gateway (in-process test gateway) give identical stdout, stderr and exit
  codes, apart from minted IDs.
- In gateway mode, editing the local `policy.yaml` does not change results.
- `plan run/resume` runs each step through `/exec` (reauthorized on the
  gateway), stdin files stay on the client until their step's request.
- `agentssh diagnostics` reports the mode.

Out of scope (#19): approval state on the gateway, so `approval status|wait`,
`plan submit|status|wait`, `run --wait-approval` and `plan run --wait-approval`
are refused in gateway mode for now; the operator UI (#20); docs for choosing a
mode (#21).

## Approach

Protocol (`internal/remote`, `internal/controlplane`):

- Every control-plane response carries `AgentSSH-Mode` (managed or gateway);
  a missing header means managed, as older `agentssh-server` releases send
  none. The client's signing transport compares it with the enrolled mode on
  every response, so a mismatch fails closed even on error responses (a 404
  from the wrong plane reads as a mode mismatch, not "HTTP 404").
- Enrollment first sends an unsigned `GET /status`; the 401 still carries the
  header, so the mode is checked before `/enroll` spends the token. The signed
  `/enroll` and a signed `/status` with the new key check it again before the
  enrollment record is committed.
- Gateway: `GET /hosts` (the device's public inventory) and
  `POST /requests/status {req_id}` (the device's latest audit record for that
  request, as `status --json` prints it). The run frame gains `req_id` for a
  single-host run (minted before the run, kept in the run record) so streamed
  plan events carry it as locally; the result frame gains `target_kind` so
  `run --json` prints an object for a host and an array for a group.

Client:

- `remoteclient.State.Mode`; `Enroll(..., mode, ...)`; `Client.Hosts`,
  `Client.RequestStatus`; `Open` (managed bundle) refuses a gateway home.
- `config.Load` in gateway mode returns `Config.Gateway` (a client) and no
  inventory or policy.
- CLI: a guard on every leaf command allows only the gateway command set in
  gateway mode, with a message naming where that state lives. `run` renders
  the gateway's per-target responses through the same printers as local
  (streamed output, footers, deny/pending/not-run notices, `--json`), and
  merges `truncated` into a warning. `plan run/resume` skip the client-side
  plan-approval round in gateway mode.
- Shared texts: the no-session usage message and the unknown-host hints come
  from one place so both modes print them identically.

Test seam: `gateway.Server.Executor` replaces the SSH executor, so the parity
test drives the same fake executor in both modes.

## Progress

- [x] Protocol: `AgentSSH-Mode` on every response (`internal/controlplane`),
  unsigned mode probe before `/enroll`, gateway `/hosts` and
  `/requests/status` (`internal/gateway/device.go`), run-frame `req_id` (minted
  before the run, kept in the run record), result `target_kind`.
- [x] Client: `State.Mode` (missing = managed), `Enroll(..., mode, ...)`,
  mode check in the signing transport (an ingress 502/503/504 without the
  header stays "unreachable", so reattach keeps working; a mismatch is never
  "unreachable", so no cached bundle replaces it), `Client.Hosts`,
  `Client.RequestStatus`, `Client.ExecNotify`; `Open` refuses a gateway home.
- [x] `config.Load`/`LoadPaths` attach `Config.Gateway`. CLI: leaf-command
  guard (`cmd/agentssh/gateway.go`) that runs before any operator prompt;
  `run` → `runGateway` (same printers, streamed footer, deny/pending/not-run
  notices, `--json` object vs array, truncation warning, Ctrl-C → cancel);
  `hosts`, `status`, `plan run|resume|execution` (no client-side plan approval
  round; `next_action` says resume after the operator decides);
  `remote enroll --mode`, `remote status` (mode line, no bundle/local lines),
  `remote refresh` refused; `diagnostics` reports `mode`.
- [x] Shared texts: `runner.ErrNoSession`, `runner.ResolveUsage`,
  `runner.RequestStatus`; the gateway checks the session after the target, as
  the CLI does, and never falls back to its own `AGENTSSH_SESSION`.
- [x] Tests: `cmd/agentssh/gateway_test.go` (parity suite of 21 cases plus no
  session, unknown host without session, and `status`; local configuration
  ignored; refused commands with no operator prompt; plan run through the
  gateway with per-step audit, stdin and streamed `request_id`; `remote enroll`
  mode check and `remote status`), `internal/remoteclient` (wrong-mode
  enrollment does not spend the token; a control plane of another mode fails
  closed instead of using the cache), `internal/gateway` (managed enrollment
  refused before the token is spent; hosts and request status are the device's
  own; run frame names the request on `/exec` and on replay).
- [x] Docs: `docs/architecture/remote-control.md` (mode header, enrollment
  probe, device endpoints, gateway devices).
- [x] Final validation.

Decisions:

- Mode on every response as a header rather than a `/status` call per
  command: no extra round trip, and it also covers refusals (a managed
  server's 404 for `/exec` reads as a mode mismatch).
- Remediation hints are the one intended difference from local output: a
  deny says the policy belongs to the control plane's administrator, and an
  SSH failure says the cause is in the gateway's log (the gateway now logs
  it), since the device sees no transport details. The parity test maps
  exactly these lines.
- The CLI treats a single-host run with `stream` as streamed: the gateway's
  executor always streams. The test seam `gateway.Server.Executor` uses the
  CLI tests' streaming fake.

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
  `golangci-lint run` 0 issues.
- `go test -race ./...`: all packages pass.
- `FuzzReadExecStream` 30 s: no failures.
- `scripts/e2e_tui_audit_run_summary.sh --no-tui`: exit 0.
- Mutation checks, each failing exactly its test: no transport mode check; no
  enrollment probe; a mismatch classified as unreachable; no `target_kind`;
  no pre-minted request ID; session checked before the target; no command
  guard; request status not filtered by device; no ingress exemption (reattach
  test); client-side plan approval in gateway mode; gateway output not
  treated as streamed.
