# Run commands over the JSON API (#41)

> Status: done · Issue: [#41](https://github.com/Praeviso/AgentSSH/issues/41) · Parent: [#39](https://github.com/Praeviso/AgentSSH/issues/39) · Epic: [#35](https://github.com/Praeviso/AgentSSH/issues/35)

## Goal and acceptance

A token device (#40) runs commands with JSON in and out. Hosted platforms time
out calls, often within a minute, so a call waits a bounded time and a longer
run is continued from offsets.

Done when:

- A short command returns its output in one call; a long one returns
  `running` and is completed by reading from offsets, with every byte once;
  cancel stops it.
- Deny, gray zone and an SSH error give the same responses as `run --json`.
- A repeated request with the same run ID does not run the command twice.

## Approach

- **Paths.** `POST /api/run`, `POST /api/run/output`, `POST /api/run/cancel`,
  with JSON bodies: the control plane refuses query strings, and the shape
  mirrors `/exec`, `/exec/attach`, `/exec/cancel`.
- **One start path.** `handleExec`'s start-or-join logic becomes
  `Server.exec`/`execAs` with a `serve` callback: `/exec` streams frames from
  the run, the API answers JSON (`answerRun`). `joinRun` becomes
  `serveExisting`. So both have the same validation, limits, idempotency,
  pipeline and audit; the API's audit records carry `token_id`.
- **Answer.** `remote.APIRun`: state, result (named from the exit code),
  exit code, truncated, target kind, stdout and stderr since the offset (data
  frames), the `run --json` objects since the offset (response frames), an
  error for an error frame, and `next_offset` (a frame boundary). A run that
  ended without a final frame answers `error`.
- **Waiting.** `wait_ms`: absent 20 s, 0 none, capped at 50 s; the wait ends
  as soon as the run finishes. The route extends its response deadline past
  the server's 30 s.
- **Identity.** A run is identified for `run_id` by the canonical
  `ExecRequest` (what it runs), not the request body, so a repeat with another
  `wait_ms` joins it.
- **Body after auth.** Open routes now read their own body
  (`controlplane.ReadBody`): a token route authenticates first, then reads up
  to its limit with the long upload deadline when the limit is large.

## Progress

- [x] Shared start path, API handlers, remote types.
- [x] Open routes read the body after authentication.
- [x] Tests (`internal/gateway/api_test.go`): one-call answer (fast, with the
  token audited); offsets (running, then the rest, every byte once; re-reading
  the end adds nothing; reading from 0 replays it); cancel; deny, gray zone and
  SSH error compared field by field with `/exec`'s `run --json` objects;
  repeated run ID runs once and a different request with it is refused;
  refusals (usage, offsets beyond, inside a frame and negative, another
  device's run, inactive); a wait past the server's one-second response
  deadline in the fixture; `apiWait`.
- [x] Docs: README, remote-control.md, gateway-mode.md.
- [x] PR review follow-up (review of the first commit): polling a finished
  run from its last `next_offset` read no frames, so the answer reported
  `error` ("output is incomplete") for a run that had succeeded. A run's
  outcome now comes from its final frame whatever the offset: when the frames
  read do not include it, `finalFrame` finds it by walking the spool's frame
  headers. The offsets test and the cancel test now poll once more from the
  end and require the same result, exit code and error; both failed on the old
  code.
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

Mutation checks, each failing its test: the response deadline not extended
(the connection broke on a 2 s wait); the wait ignoring progress (a finished
run answered only when its wait ended); output not streamed (nothing arrived
before the result); the wait counted in the run's identity (a repeat got 409);
the token not audited on runs; offsets not bounded. Three of these first hung
until the test timeout; requests in tests now time out after 15 s, and the
tests stop leftover runs and release the fake target at cleanup.

Live, with real binaries behind a TLS ingress, a real SSH target and curl:
`uptime` finished in one call (`ok`, one response); a three-second loop with
`wait_ms` 1000 answered `running` with "tick 1", and `/api/run/output` from
`next_offset` returned "tick 2", "tick 3" and `ok`; `rm -rf` answered `denied`
with exit 6; the same `run_id` twice answered the same run and request ID, and
the audit holds one started and one completed record for it, with `token_id`.
