# Device activation windows (#37)

> Status: done · Issue: [#37](https://github.com/Praeviso/AgentSSH/issues/37) · Parent: [#36](https://github.com/Praeviso/AgentSSH/issues/36) · Epic: [#35](https://github.com/Praeviso/AgentSSH/issues/35)

## Goal and acceptance

A gateway device is usable only inside an activation window an operator
chooses each time. It is inactive by default and inactive again when the window
ends. Activation is separate from revocation, which stays terminal. This holds
for every gateway device; token devices (#40) reuse it.

Done when:

- A new device is refused with `device_inactive` until activated. Inside the
  window it runs; after the end it is refused again with no operator action.
  Reactivating works; a revoked device cannot be activated.
- `device activate <id> --for <d>` needs `--for`, from 1m to 24h; activating an
  active device sets a new end. `device deactivate <id>` takes effect on the next request.
- Activation, deactivation and expiry are records in the gateway's audit chain
  with the operator and note; the chain verifies.
- On a signed device the CLI prints a hint that an operator must activate it,
  and `agentssh remote status` shows the state.
- Every device starts inactive, including devices enrolled before this change
  (gateway mode has no deployments yet, so there is no migration path).

Examples:

- Enroll, push config, `run` → refused, `device_inactive`, hint names the
  gateway's operator. `/status` still answers (inactive).
- `device activate dev_x --for 2h --note "deploy"` → `run` succeeds;
  `remote status` shows "active until …".
- Clock passes the end → `run` refused; one `device_activation_expired` audit
  record, not one per refused request.
- `device activate dev_x` (no `--for`) → usage error; `--for 48h` → refused
  with the cap in the message.
- `device revoke dev_x` then `device activate dev_x` → refused: revoked.

## Approach

- **State.** A gateway-only table (`device_activations`: device ID, active
  until, set by, note, set at, expiry recorded), created with the gateway's
  schema fragment like `operators`. The shared `devices` table and the managed
  database stay unchanged. No row, or an end in the past, is inactive.
- **Enforcement.** `gateway.Server.Handler` wraps every gateway route's
  handler: an inactive device gets 403 `device_inactive`. Enrollment and
  `/status` (registered by `internal/controlplane`) are not wrapped, so a device
  can be enrolled before activation and see its state. The check reads the
  store with the gateway's clock on every request; nothing is cached.
- **`/status`.** `controlplane.API` gets an optional hook that adds the
  activation state to `StatusResponse` (`activation: {state, until}`,
  omitted by the managed server).
- **Expiry audit.** The first time a request or a periodic sweep in `serve`
  finds a window ended and not yet recorded, one `device_activation_expired`
  record is appended and the row marked, in one guarded update so concurrent
  requests record it once.
- **Audit records.** New events `device_activated`, `device_deactivated`,
  `device_activation_expired`, with `device_id`, `operator`, and two new
  omitempty fields (`active_until`, `note`) appended to `Record` and its
  canonical form, so older records keep their hashes.
- **CLI.** `agentssh-gateway device activate|deactivate`; `device ls` gains
  state and remaining time.
- **Cap.** A fixed 24h maximum (`gateway.MaxActivation`), checked by the store
  function that activates, so the CLI and the Web UI (#38) share one rule.
  Deviation from the issue's `serve --max-activation`: `device activate` runs
  in its own process and cannot read `serve`'s flags, so a serve-only cap
  would disagree with what the CLI wrote and `device ls` shows. A configurable
  cap would live in the data directory; not needed yet.
- **Client.** `remote.CodeDeviceInactive`; `agentssh` maps it to a hint
  ("an operator must activate this device on the gateway") with the same exit
  behavior as other control-plane refusals; `remote status` prints the state.

## Progress

- [x] Store and enforcement (`internal/gateway/activation.go`, the route
  wrapper in `gateway.go`). `/exec/cancel` is exempt besides enrollment and
  `/status`: cancelling only stops a run, so a device whose window just ended
  can still stop its own.
- [x] Audit records: `device_activated`, `device_deactivated`,
  `device_activation_expired`, new omitempty fields `active_until` and `note`.
  An activation is audited before it is stored and a deactivation after, so a
  failed write leaves the device inactive. An ended window is claimed with a
  guarded update, then recorded, so concurrent finders record it once.
- [x] Admin commands: `device activate <id> --for <d> [--note]`,
  `device deactivate <id>`, an `ACTIVATION` column in `device ls` (through an
  optional `admin.Program` column, so the managed server is unchanged), and a
  30-second sweep in `serve`.
- [x] Client: `remote.CodeDeviceInactive`; `agentssh` adds "only the gateway's
  operator can activate this device" (exit 1, as other refusals);
  `remote status` prints an `access` line, and a gateway device's standing reads
  "enrolled" instead of "active", so it is not confused with activation.
- [x] Tests: the existing gateway fixtures activate the devices they enroll; the
  helpers that count audit records skip activation records. New tests cover
  every acceptance item; see Validation for the mutation checks.
- [x] Docs: README gateway section, remote-control.md (activation paragraph,
  threat model rows), gateway-mode.md (trust boundary, design, limits); the
  skill's "stop" row names "not activated".
- [x] PR review follow-up (review of 1031606):
  - Reactivating a device whose window had ended unnoticed (no request or
    sweep since, or `serve` stopped) replaced the row and lost that end.
    `ActivateDevice` now records an unrecorded ended window before replacing
    it. Test: `TestReactivatingRecordsTheEndOfAnUnnoticedWindow`.
  - The end was claimed (`end_recorded = 1`) before its audit append, so a
    failed append lost it for good. The audit chain now decides whether an end
    is recorded: `audit.Store.AppendUnless` checks for the same end (device and
    `active_until`) under the chain's lock, and the flag is set only after the
    record is in the chain, so a failed append is retried and concurrent
    finders still record it once. Windows last at least a minute, so two
    windows of a device never end in the same second. Tests:
    `TestAnEndThatFailedToRecordIsRetried`, `TestAppendUnlessAddsAFactOnce`,
    and the existing two-finders test.
  - Mutation checks, each failing its test: no record before replacing; the
    flag set before the append; no dedupe in the chain; `AppendUnless`
    ignoring its predicate; no minimum duration.
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

Mutation checks, each failing its test: no activation check on routes;
`/exec/cancel` not exempt; no 24h cap; a revoked device activatable;
deactivation leaving the window's end unrecorded (a later sweep recorded an
expiry); the end recorded without the guarded claim (an internal test has two
finders hold the same ended window; eight concurrent requests alone did not
reveal the race).

Live, with real binaries behind a TLS ingress and a test SSH target: a new
device's run is refused with the hint and `remote status` shows
`access inactive`; `device ls` shows `inactive`; after
`device activate --for 1m` the run succeeds and `device ls` shows the time
left; with no further requests the sweep in `serve` recorded the end 24 s after
the window closed, the next run was refused, and the chain verified with one
expiry record.
