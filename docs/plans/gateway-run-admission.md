# Complete run admission and publication (#58)

> Status: done · Issue: [#58](https://github.com/Praeviso/AgentSSH/issues/58)

## Goal and acceptance

New runs are fully initialized before any standing sweep can observe them.
Requests rejected for record capacity, duplicate IDs, or storage failures do
not evict protected retained output or leak concurrency slots/private spools.
Keep the existing durable record authority, early-cancel/idempotency/restart
semantics, record reclamation policy, and quota plus in-flight space bound.

Concrete checks: with one protected record and a quota equal to the per-run
cap, another request returns 429 while the first result remains attachable;
concurrent standing sweeps and run starts have no identity race; a failed
spool or claim leaves existing output unchanged and allows the same request
to retry once; concurrent admission cannot exceed record/concurrency limits.

## Approach

1. Give `startRun` a complete creation specification, including identities
   and cancellation. It owns record/concurrency admission, spool creation,
   exclusive claim, output-space arrangement, and live publication under
   `s.mu`. Identity metadata is privately copied and immutable after publish.
2. Treat a successful exclusive durable-record claim as the commit point.
   Before it, only private attempt resources and the existing independent
   TTL/eligible-record reclamation rules may change. Move request-specific
   output eviction after commit. Return all pre-commit failures without
   charging a concurrency slot or leaving a spool.
3. Settle the live map, concurrency accounting, and finished-output quota
   together when a run ends. Document lock ordering and ownership; exclusive
   file claims retain cross-process ID arbitration, while live scheduling and
   resource accounting belong to the single serving process.
4. Add behavioral admission/fault/race regressions and reuse existing
   reconnect, cancellation, restart, cap, TTL, and device-isolation tests.
   Update architecture documentation and deliver an English PR closing #58.

## Progress

- Confirmed #59 merged at `1907e8c`; synchronized main and created
  `fix/gateway-run-admission` from that commit with a clean worktree.
- Read #58, run storage/admission/reclamation, standing snapshots, public
  execution routes, existing regressions, and CI requirements.
- Implemented the complete creation specification, privately owned immutable
  identities, post-claim slot charging/output eviction, and unified completion.
  The file-backed record remains the only durable authority.
- Added public-route record rejection/fault/capacity/idempotency regressions,
  concurrent standing coverage, metadata ownership, exclusive-claim races, and
  duplicate-completion accounting tests. Reused existing lifecycle coverage.
- Updated run storage, architecture, and the prior run plan. Implementation,
  final diff review, and consolidated local validation are complete. Delivery
  is through a PR closing #58, with CI evidence on its exact published head.

## Validation

Planned consolidated validation:

- `gofmt` and `git diff --check`.
- `go test -race -count=1 -timeout=20m ./...`.
- `go vet ./...`, all command builds, and
  `golangci-lint run --timeout=5m`.
- HTTPS Web Crypto vectors and the noninteractive audit smoke with an isolated
  home and the compiled CLI.
- Core regressions against an isolated archive of the pre-fix main, then
  remote CI on the exact published PR head.

Results (2026-10-27, Go 1.25.5, writable module/build/lint caches under
`/tmp/agentssh-issue57`, logs under `/tmp/agentssh-issue58`, `GOFLAGS=-p=2`):

- `go test -race -count=1 -timeout=20m ./...`: all 27 packages with tests pass.
- `go vet ./...`, all command builds, and `golangci-lint run --timeout=5m`
  pass; lint reports zero issues. Formatting and `git diff --check` are clean.
- HTTPS vectors pass. The noninteractive audit smoke using the compiled CLI
  and an isolated home passes and verifies its 14-record audit chain.
- The unchanged public-route regression file copied into an archive of
  `1907e8c` fails for both original defects: record rejection removes retained
  output, and continuous standing sweeps report identity slice races in
  `execAs` / `CancelRunsWithoutStanding`. The same tests pass on the fix.
- New regressions cover byte-identical retained results after record rejection,
  concurrent record admission, ENOSPC before spool/claim with capacity-one
  retries, repeat/conflict/cancel handling at a full concurrency limit, first
  standing-check identity ownership, exclusive claims from independent server
  instances, restart authority, and duplicate completion accounting.
- Existing reconnect, early cancellation, caps, quota, TTL, idempotency-window
  reclamation, device isolation, and identity-disable cancellation tests pass
  as part of the full suite.

An initial lint pass flagged a defer inside a closed-channel range in a new
claim-race test. Cleanup was moved outside the loop, then the complete suite
and required static checks were rerun successfully.

The behavior tests exercise local TLS and SSH fixtures, not production hosts,
production ingress, or an external MCP platform. Existing independent TTL and
eligible-record reclamation retain their documented rules; resource accounting
and live execution scheduling remain owned by a single serving process.
