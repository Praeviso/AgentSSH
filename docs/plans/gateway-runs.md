# Gateway runs survive disconnects and can be reattached (#16)

> Status: done · Issue: [#16](https://github.com/Praeviso/AgentSSH/issues/16) · Parent: [#13](https://github.com/Praeviso/AgentSSH/issues/13) · Epic: [#11](https://github.com/Praeviso/AgentSSH/issues/11)

## Goal and acceptance

A cloud agent can lose its network mid-command. A dropped connection must not
kill a half-finished deployment: the command keeps running on the gateway, its
frames are spooled to disk, and the device reattaches and continues from where
it left off. Only an explicit cancel stops the command.

Done when:

- Cutting the connection mid-run: the client reattaches on its own, receives
  the complete output and exit code, and the remote command ran exactly once.
- A different device reattaching with the same ID is refused.
- Reattaching after retention returns a clear error. Output beyond the
  per-run cap marks the result `truncated` with a non-zero exit code; a partial
  result is never presented as complete.
- Explicit cancel still terminates the remote command (TERM) and the audit
  says `cancelled`.

Out of scope: the CLI flag surface and `--json` rendering (#17 consumes
`remoteclient.Client.Exec` and `ExecResult.Truncated`).

### Naming

The codebase already uses `execution_id` for reviewable plan executions
(`ExecRequest.ExecutionID`, audit `execution_id`). The issue's "execution ID"
is therefore a **run ID** here: `rn_` + 32 hex characters, minted by the
gateway per `/exec`.

### Disconnect vs. cancel (the issue's preparation question)

The request is half duplex (#15), so there is no in-band cancel frame. A
dropped connection now only detaches the device; an explicit cancel is a
separate signed `POST /exec/cancel {run_id}`. `remoteclient.Client.Exec`
sends it when its context is cancelled (Ctrl-C), and keeps reattaching when the
stream breaks for any other reason.

## Approach

Wire (`internal/remote`):

- Every `/exec` and `/exec/attach` response starts with a run frame (6,
  `{run_id}`); the bytes after it are the run's spool from the requested
  offset: data, response and result/error frames, unchanged.
- The result frame gains `truncated`; `ExecResult` exposes `RunID` and
  `Truncated`.
- `POST /exec/attach {run_id, offset}` (streaming) and
  `POST /exec/cancel {run_id}`; `run_not_found` (404) covers unknown, another
  device's, and expired runs alike (no existence oracle); `run_interrupted`
  (410) for a run the gateway lost to a restart.
- `ExecStream` keeps the run ID, the byte offset of complete frames consumed,
  and the responses collected so far across reconnects, so output is written
  exactly once.

Gateway (`internal/gateway/runs.go`):

- `runs/<id>/meta.json` (owner, created, finished) and `runs/<id>/frames`.
  The runner executes in a goroutine with its own context (`--exec-timeout`),
  writing frames to the spool; `/exec` and `/exec/attach` tail the spool
  (in-memory wakeups while running, plain file reads after). The concurrency
  slot is held until the run finishes, not until the request ends.
- Per-run cap (`serve --run-max-bytes`, default 64 MiB): a reserve of 16 KiB per
  target is kept back; data frames that do not fit are dropped and full
  responses that do not fit are sent with their output removed
  (`output_truncated`); the result then has `truncated: true` and the exit
  code merged with 1.
- Retention (`serve --run-retention`, default 24 h after a run finishes):
  attach refuses expired runs; a sweep (at most once a minute, on `/exec`)
  deletes them, and runs left unfinished by a restart once they are older than
  retention plus the execution timeout.

Client (`internal/remoteclient`): `Exec` reattaches with backoff for up to
`ReattachTimeout` (default 2 min) on stream breaks and transport errors;
protocol refusals end it. On context cancellation it sends `/exec/cancel`
(5 s budget) and returns the context error.

## Progress

- [x] Read #15 code paths; settle naming and the cancel signal.
- [x] Wire: run frame, attach/cancel messages, `ExecFinal.truncated`,
  `ExecStream` (offset of complete frames, responses kept across reads).
- [x] Gateway (`internal/gateway/runs.go`): run registry and spool, detached
  execution, `/exec/attach`, `/exec/cancel`, cap with per-target reserve,
  retention check on attach plus a once-a-minute sweep, `serve
  --run-retention --run-max-bytes`.
- [x] Client: `Exec` reattaches with backoff (patience window restarts when
  the offset advances) and turns context cancellation into `/exec/cancel`;
  `Attach` replays a run; `Cancel`.
- [x] Tests (`internal/gateway/runs_test.go`, `internal/remote/exec_test.go`):
  connections cut mid-run, then the client reattaches with each chunk once,
  exit 0, and the command run exactly once, plus a full replay; another
  device's attach and cancel are 404; expiry is 404 with an explanation and
  the spool is removed; cap → truncated, exit 1, output removed, spool within
  the cap, same on replay; restart leftovers → 410; an unreachable gateway
  ends Exec with "may still be running" after `ReattachTimeout`; stream
  offsets count complete frames only. Existing cancellation, timeout and
  concurrency tests pass with cancel now explicit.
- [x] Docs: `docs/architecture/remote-control.md` (runs, reattach, cancel,
  retention, cap).
- [x] Final validation.

- [x] Security review follow-up (PR #26): retention alone left an enrolled
  device free to fill the gateway's disk by running large-output commands back
  to back (64 MiB each, kept 24 h), which would also break the audit and
  database. Runs now live under `runs/<device-id>/<run-id>/`, and before each
  new run the device's oldest stored runs are evicted until a full run fits
  `--run-quota-bytes` (default 512 MiB); the sweep also runs on attach. Test:
  four capped runs under a 128 KiB quota keep the device's spool within it,
  the oldest run is `run_not_found` and the newest still replays; without the
  eviction the same test keeps 195 KiB.

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

Results (2026-10-22, final code):

- `gofmt -l .` clean; `go vet ./...`, `go build ./cmd/...` pass;
  `golangci-lint run` 0 issues.
- `go test -race -count=3` on `internal/gateway`, `internal/remote`,
  `internal/remoteclient`: pass.
- `go test -race -count=1 ./...`: every package passes except one run of
  `internal/approval` `TestApplyDecisionAtomicClaimBeforeHostSideEffects`
  ("corrupt approval resolution"). This branch does not touch
  `internal/approval`; the test passes 100/100 alone. Cause (pre-existing):
  `PendingStore.Resolve` creates the response file with `O_EXCL` and writes it
  afterwards, so a concurrent reader can see an empty file. To be fixed in its
  own change.
- `FuzzReadExecStream` 30 s: no failures.
- `scripts/e2e_tui_audit_run_summary.sh --no-tui`: exit 0.
