# Security enforcement during audit failures (#57)

> Status: done · Issue: [#57](https://github.com/Praeviso/AgentSSH/issues/57)

## Goal and acceptance

Confirmed OAuth replay revokes the grant even when audit publication fails.
Activation expiry and deactivation still stop live SSH commands within the
30-second standing interval. Pending revocation, replay-refusal, deactivation,
and expiry records survive restarts and concurrent repair with their original
identity, actor, time, and reason. State-store errors remain distinct from
audit-publication errors. Permission-granting operations retain their existing
audit requirements. Run admission/publication work in #58 is out of scope.

## Approach

1. Add a gateway-only durable audit outbox. Commit pending facts with state
   changes, publish after commit, and deduplicate under the audit-file lock
   using stable event IDs. Preserve old audit canonical forms.
2. Make standing evaluation read-only. Requests independently collect an
   observed expiry; enforcement and audit repair run on separate timers.
   Replacing an expired activation preserves its event transactionally.
3. Commit OAuth replay refusal and revocation together, and report committed
   restrictions with pending audit repair separately from failed commits.
4. Add public-interface regressions for unwritable/corrupt audit storage,
   restart/concurrent recovery, state-store failure, real SSH cancellation,
   concurrent replay, and unchanged permission-expansion behavior.
5. Update architecture documentation, run consolidated validation, verify the
   original defects on the baseline, and deliver an English PR closing #57.

## Progress

- Confirmed main and origin/main at `52722ad`; clean starting worktree.
- Created branch `fix/gateway-security-audit`.
- Read the issue, lifecycle implementation, CLI/Web UI callers, existing
  recovery tests, and CI commands. Reusing the `docs/plans` convention.
- Implemented a SQLite outbox for these security events, stable audit event
  IDs, hash-chain validation and synced append before acknowledging delivery.
  Existing device-revocation recovery remains in place.
- State-only standing evaluation and separate enforcement/repair timers avoid
  audit I/O on the cancellation path. Expiry requests only collect facts.
- Added transactional replay revocation/deactivation, preservation of old
  expiry facts during reactivation, and committed-but-pending error reporting.
- Added enforcement, restart/concurrent repair, failed-completion, transaction
  rollback, ENOSPC, state-store error, and concurrent refresh regressions.
- Activation publishes outside the database write transaction and rechecks
  its snapshot before committing; blocked audit I/O cannot hold up a later
  restriction or let stale activation overwrite it.
- Added CLI/Web UI reporting tests and blocked-activation concurrency coverage.
- Updated gateway architecture and remote-control documentation. Implementation
  and consolidated local validation are complete; delivery is through a PR
  closing #57, with remote CI evidence attached to the published PR head.

## Validation

Planned acceptance examples: replay with failed auditing invalidates all grant
tokens across restart; expired/deactivated live runs receive SIGTERM despite
audit failure; a state-read error leaves existing runs alone and refuses new
requests; concurrent/restarted repair emits each pending fact once; activation
does not succeed while its audit cannot be published.

Planned final commands:

- `gofmt` and `git diff --check`.
- `go test -race -count=1 -timeout=20m ./...`.
- `go vet ./...`, `go build ./cmd/...`, and `golangci-lint run --timeout=5m`.
- `node scripts/verify_https_vectors.mjs`.
- `scripts/e2e_tui_audit_run_summary.sh --no-tui` with an isolated CLI home.
- Baseline regression checks in an isolated copy and remote final-head CI.

Results (2026-10-27, Go 1.25.5, writable caches under
`/tmp/agentssh-issue57`, `GOFLAGS=-p=2`):

- `go test -race -count=1 -timeout=20m ./...`: all 27 packages with tests pass.
- `go vet ./...`, builds of every command, and `golangci-lint run --timeout=5m`
  pass; lint reports zero issues. Formatting and `git diff --check` are clean.
- HTTPS vectors pass. The noninteractive audit smoke passes and verifies its
  14-record chain using the compiled CLI and an isolated home.
- The same core regression file copied into an archive of `52722ad` fails for
  both original defects: replay leaves the grant usable, and failed expiry
  auditing becomes unknown standing. No new production API is needed to compile
  that file against the baseline.
- Unwritable/corrupt audit recovery passes after reopening the database and
  handler, including concurrent repair from six independent store handles.
  The first actor/time/reason and one event per fact survive. ENOSPC injection,
  failed completion markers, atomic rollback, concurrent refresh replay, and
  CLI/Web UI reporting are covered by durable regression tests.
- The local integration overlay runs the compiled gateway as a separate
  process behind the TLS fixture and against its SSH test target. With audit
  repair demonstrably waiting on an exclusive lock in `/proc/locks`, the next
  standing cycle still sends SIGTERM about 15 seconds after expiry. Releasing
  the lock lets the run finish with its durable expiry cancellation reason.
- Blocked activation publication neither holds the database writer lock nor
  overwrites a concurrent deactivation or revocation; the focused race tests
  and final full suite pass.

The first validation pass exposed test-fixture issues: one helper needed an
existing configuration, and a clock-advanced cleanup request violated the
signed-request time window. The fixtures were corrected and the complete
validation was rerun. The first live integration assertion also assumed a
stream would remain attached after expiry; the final check observes SIGTERM
and the durable run record, since expiry legitimately refuses reattachment.

The live evidence is local: no production HTTPS ingress, production SSH host,
or external MCP platform was exercised. A corrupt chain requires operator
repair before pending publication can resume. Per-command audit recovery keeps
its existing semantics; the outbox covers the scoped lifecycle facts.
