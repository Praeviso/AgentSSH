# Gateway execution API (#15)

> Status: done · Issue: [#15](https://github.com/Praeviso/AgentSSH/issues/15) · Parent: [#13](https://github.com/Praeviso/AgentSSH/issues/13) · Epic: [#11](https://github.com/Praeviso/AgentSSH/issues/11)

## Goal and acceptance

`agentssh-gateway` authorizes and executes a device's command with the shared
pipeline (`internal/runner`) against that device's pushed inventory and policy,
connects with its own identities (keys never leave the process), streams
output back, and keeps the authoritative audit chain.

Done when:

- Integration test (in-process test sshd, real HTTPS + signed requests):
  allowed commands stream output chunk by chunk; stdin reaches the remote
  command byte for byte; explicit deny → exit 6; gray zone → exit 7 with a
  pending request when the device's policy enables approvals.
- Client cancellation (dropping the request) ends the remote session (the
  gateway sends `signal TERM` and closes the connection) and the audit records
  the run as failed with a cancellation error.
- The gateway audit chain verifies; tampering with any field, including
  `device_id`, fails verification.
- Frame codec: table-driven tests and a fuzz target (malformed frames,
  oversized frames, stream ending before a result).
- Per-device concurrency limit (429 `busy`) and a command timeout.

Out of scope: execution IDs and reattaching to output after a disconnect
(#16); the client `--mode gateway` path that renders results like local mode
(#17); operator approval decisions (#19/#20; this change only creates pending
requests in per-device stores).

### Deviation from the issue text: no full-duplex stream

The issue (written before #10) asks for full-duplex HTTP/2 on the mTLS
listener with stdin/cancel frames. After #10 the gateway is a private HTTP
origin behind a TLS-terminating ingress, and every request is signed over a
`Content-Digest` of its whole body. Full duplex would need h2c to the origin,
an ingress that streams request bodies (nginx buffers them by default), and a
new per-frame signature scheme. Stdin is already a bounded file (≤ 32 MiB,
read fully by the CLI), so:

- The request is one signed JSON body carrying the command and stdin.
- The response is a stream of frames: stdout, stderr, then exactly one
  result (or error) frame.
- Cancellation is the client dropping the request; the request context ends
  and the executor terminates the remote session. There is no cancel frame.

## Approach

Wire (`internal/remote`):

- `POST /exec`, `ExecRequest{host, cmd, stdin, session, session_label,
  execution_id, step_id, review_sha256, stream}`. `stdin` is base64 (`null` =
  no stdin, `""` = empty stdin); the gateway computes its SHA-256 itself.
- Frames: `type:1 | length:4 (big endian) | payload`. Types: stdout, stderr,
  result (`ExecResult{exit_code, responses[]}` where responses are the
  `run --json` objects), error (`ErrorResponse`). Data frames ≤ 64 KiB (the
  writer splits), result/error ≤ 16 MiB. `ReadExecStream` copies data frames
  to writers and fails with `ErrNoResult` if the stream ends first.
- New codes: `usage` (400; client maps to exit 2), `busy` (429).

Shared HTTP layer (`internal/controlplane`):

- `Route.MaxBody` (default 64 KiB) and `Route.Streaming`: a streaming route gets
  a longer read deadline for its body, then no read/write deadline while the
  handler streams.

Gateway (`internal/gateway/exec.go`):

- Validate (session required, ≤ 256 bytes; stdin ≤ 32 MiB), load the device's
  config, parse with `remote.ParseManaged`, resolve the target, build the
  output filter and approval runtime from the device's policy (no environment
  override).
- Env: per-device approval stores under `devices/<id>/approval/`, the gateway
  audit (`audit.jsonl`) stamped with `device_id`, and a native executor whose
  only auth method is the in-process identity signer (identity must still be
  active at dial time), `known_hosts` in the data directory, no connection
  reuse, host-key policy from the device inventory.
- Response frames are written lazily: an error before the first frame becomes
  a normal HTTP error; after it, an error frame.
- Per-device semaphore and `context.WithTimeout`; flags on `serve`.

Executor: on cancellation send `signal TERM` before closing the connection, so
OpenSSH (≥ 7.9) terminates a non-pty command instead of leaving it running.
This also improves local Ctrl-C.

Audit: `device_id` appended to `Record` and `canonicalRecord` (`omitempty`), so
existing records keep their hashes. `agentssh-gateway audit verify`.

Client: `remoteclient.Client.Exec` (no whole-request timeout) so the
integration test exercises the real signed transport; #17 builds on it.

## Progress

- [x] Read runner, executor (native, cancellation), audit, approval stores,
  session resolution, signing transport.
- [x] Wire types and frame codec (`internal/remote/exec.go`).
- [x] `Route.MaxBody`/`Route.Streaming`; gateway `/exec`
  (`internal/gateway/exec.go`); `device_id` in audit; `signal TERM` on
  cancellation; `remoteclient.Client.Exec`; `serve --exec-timeout
  --max-concurrent`; `agentssh-gateway audit verify`.
- [x] Found during testing: the runner never recorded why a run failed, so a
  cancelled run looked like any transport failure. A `failed` record whose
  context ended now carries `error: cancelled` or `error: timed out` (local
  Ctrl-C too).
- [x] Tests: frame codec table + fuzz (`internal/remote`); gateway integration
  against an in-process sshd through a TLS ingress with 1 s read/write
  timeouts (streaming chunk by chunk past those timeouts, stdin byte for byte,
  gateway-side redaction, deny → 6, gray zone → 7 with a per-device pending
  request, cancellation → TERM + `cancelled` audit, timeout → TERM + 9 +
  `timed out`, 429 busy, usage errors not audited, audit chain with
  `device_id` and tamper detection, disabled identity → 9); runner
  interrupted-run audit; `audit verify` CLI.
- [x] Docs: `docs/architecture/remote-control.md` (gateway execution),
  `docs/architecture/overview.md` (§6 `error` and `device_id`).

- [x] Security review follow-up (PR #24): the first version granted `/exec`'s
  5-minute upload deadline and ~44 MiB body cap before authenticating, so an
  unauthenticated client could hold both. Routes above the default body size
  now verify the signature over the headers first
  (`remote.VerifyHTTPRequestHeaders`; the signature covers `Content-Digest`),
  refuse a declared `Content-Length` above the cap with 413, answer pre-auth
  refusals with `Connection: close` so Go's server does not drain the unread
  body first, and only then extend the deadline, read the body and check it
  against the digest (`remote.ContentDigestMatches`). Test: a hand-written
  request whose body never arrives is refused at once (401 unsigned, 413
  oversized); against the previous handler it hangs until the read timeout.

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

Known limits: a request must arrive within the 60 s signature lifetime, so
very large stdin over a slow link is refused (`clock_skew`); ingresses must not
buffer responses (the gateway sends `X-Accel-Buffering: no`).

Results (2026-10-22, final code):

- `gofmt -l .` clean; `go vet ./...`, `go build ./cmd/...` pass;
  `golangci-lint run` 0 issues.
- `go test -race -count=1 -timeout=20m ./...`: every package passes except one
  run of `internal/executor`'s
  `TestNativeExecutorNewSessionTimesOutAndClosesPooledClient`, which uses a
  30 ms connect timeout and saw the handshake itself time out under full-suite
  load. That path (dial / new session) is untouched here; the test passes 20/20
  alone and the package passes 3/3 under `-race`.
- Regression check: with the streaming-deadline reset removed, the chunked
  streaming test fails (`tls: bad record MAC` when the 1 s write timeout cuts
  the stream); with it, it passes.
- Fuzz: `FuzzReadExecStream` 30 s, no failures.
- `scripts/e2e_tui_audit_run_summary.sh --no-tui`: exit 0.
