# Stop runs whose device lost standing (#34)

> Status: done · Issue: [#34](https://github.com/Praeviso/AgentSSH/issues/34) · Parent: [#36](https://github.com/Praeviso/AgentSSH/issues/36) · Epic: [#35](https://github.com/Praeviso/AgentSSH/issues/35)

## Goal and acceptance

A run the gateway already started stops when its device may no longer act:
revoked, deactivated, its activation window ended, or (at little cost, so
included) an identity it connects with disabled. Managed mode already cancels
a revoked device's command within 30 seconds; gateway mode matches it.

Done when:

- Revoking, deactivating, and letting a window end, each mid-run: the remote
  command receives `SIGTERM` within the check interval, and the run ends with
  the reason in its record and its audit record.
- Other devices' runs, and runs in good standing, keep going; the audit chain
  verifies.
- The threat-model row "A device is revoked" and gateway-mode.md's limits are
  updated.

## Approach

- **Cause.** A run's context is `WithCancelCause` under its timeout. The
  device's own cancel passes no cause; a standing check passes the reason.
  `runner.interruption` writes `cancelled: <cause>` when a cause is set, and
  plain `cancelled` otherwise, so the CLI's records are unchanged.
- **Check.** `Server.CancelRunsWithoutStanding` reads each live run's device
  (revoked? `deviceActive`?) and the identities its targets use, once per
  device and identity per round, from the store, and stops the runs that lost
  standing. `serve` runs it every 30 s (`gateway.StandingCheckEvery`) with the
  ended-window sweep from #37. A store error is returned and logged and stops
  nothing: only a definitive answer stops a run, as in managed mode.
- **Reason.** `deactivated_by` in `device_activations` tells a deactivation
  from a window that ended on its own (the table is unreleased and gateway mode
  has no deployments, so no migration). The run record gains `cancel_reason`.
- **Identities.** Each run keeps the identity names of its resolved targets.

## Progress

- [x] Cause through the run context and the runner's audit text.
- [x] Standing check, `deactivated_by`, `cancel_reason`, identities per run.
- [x] `serve`: one 30-second loop records ended windows and checks standing.
- [x] Tests (`internal/gateway/standing_test.go`): revoked, deactivated (with
  another device's run unaffected), window ended (the check runs with the
  server clock two hours later), identity disabled, and a run in good standing
  untouched; each checks `SIGTERM`, the run record, the audit record and the
  chain.
- [x] The device is told why: a stopped run ends with an error frame
  (`device_revoked`, `device_inactive` or `identity_disabled`,
  "the gateway stopped this command: <reason>") instead of its responses. The
  first live check showed the device an SSH failure and the hint "the gateway
  could not connect to this host", which was wrong.
- [x] Docs: README gateway section, remote-control.md (runs paragraph, threat
  model), gateway-mode.md (design section, limits).
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

Mutation checks, each failing its test: revocation not checked; identities
not kept per run; `deactivated_by` not written (the reason read "activation
ended"); no cause passed when stopping; the runner ignoring the cause; every
run stopped regardless of standing (the other device's and the good-standing
run ended); the device not told why (it got a result instead of the refusal).
At first these failures hung until the test timeout, because the fixture's
ingress waited on the run that was never stopped; the tests now stop leftover
runs at cleanup (`Server.StopRuns`, test-only), since a revoked device cannot
cancel its own.

Live, with real binaries behind a TLS ingress and a test SSH target: a
`sleep 300` run, then `device deactivate`; serve's check stopped it 28 s later
(within the 30-second interval). The device printed
"the gateway stopped this command: the device was deactivated" with the hint
that only the gateway's operator can activate it (exit 1); the audit record
read `cancelled: the device was deactivated` and the run record its
`cancel_reason`.
