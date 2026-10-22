# Run pipeline extraction (#12)

> Status: done · Issue: [#12](https://github.com/Praeviso/AgentSSH/issues/12) · Epic: [#11](https://github.com/Praeviso/AgentSSH/issues/11) (gateway mode)

## Goal and acceptance

Move the run execution pipeline (session binding → authorization → approval
request → audit → execution → output filtering → exit-code merge) out of
`cmd/agentssh` into a package that has no cobra or terminal dependency, so the
gateway control plane (#15) can run exactly the same decisions. No behavior
change for the CLI.

Done when:

- `go test -race ./...` passes with no edits to existing `cmd/agentssh` tests.
- The new package imports neither `cobra` nor writes to `os.Stdout`/`os.Stderr`.
- Package tests cover, through its public API: explicit deny → 6; gray zone →
  7 with a pending request; execution after a grant match; a group where any
  member needs approval executes no member; a once grant consumed exactly once
  under concurrent reruns.

Out of scope: plan execution orchestration (checkpoints, event journal,
resume) stays in the CLI — #17 drives plan steps from the client, one execution
call per step. `policy test` display logic stays in the CLI.

## Approach

New package `internal/runner`:

- `Env` — loaded policy, inventory, approval runtime, session/pending stores, an
  `AuditLog` interface, an `executor.Executor`, an `output.Filter`, and optional
  hooks (`HostOS` for the CLI's inventory OS refresh, `NewReqID` for tests).
- `Run(ctx, env, Request) (Outcome, error)` — the former `runDirect` body:
  per-target session binding, group preflight when approvals are enabled,
  per-target `Authorize`, deny/pending audit, started/completed audit, streaming
  or buffered execution, once-grant settlement, response finalization, merged
  exit code. Presentation goes through an `Observer` (deny / pending / not-run /
  finished / warning callbacks); streaming output goes to caller-supplied
  writers. Responses are always collected and returned finalized.
- `SubmitPlan(env, PlanSubmitRequest)` — the per-command preflight loop of
  `plan submit` (pending creation, review manifest, `approval_requested` audit).
  Target/session resolution and payload pinning stay in the CLI.
- `Response` and `PlanSubmitResponse` move to the package; the CLI
  keeps type aliases so JSON and tests are untouched. `UsageError` moves too and
  the CLI's `usageError` becomes an alias, so exit 2 mapping is unchanged.

Key decisions:

- Finalization (`execution_state`, `next_action`, `cmd_sha256`, cmd echo
  truncation) happens once inside `Run`. It is not idempotent (the hash must be
  of the full command), so `writeRunResponses` no longer finalizes.
- Usage-error text stays byte-identical (including `~/.agentssh` hints); a
  future gateway may wrap it.
- `captureRun` keeps calling `runDirect` (JSON round trip) to avoid touching
  plan-run behavior in this change.
- The three "is every command authorized now?" readiness loops (run wait, plan
  wait, plan resume) stay in the CLI. They are not part of #12's scope, and one
  of them (`executionAuthorizationReady`) stops at the first unready command
  while the others keep looking for a deny, so merging them would change
  behavior.

## Progress

- [x] Read pipeline call sites: `runDirect`, `buildRunPlans`,
  `handleApprovalPreflightBlock`, `submitPlanInputsWithOptions`,
  `waitForRunApproval`, `waitPlanReady`, `executionAuthorizationReady`.
- [x] Implement `internal/runner` (`runner.go`, `response.go`, `plan.go`) and
  switch `runDirect` and `plan submit` over. `cmd/agentssh` keeps presentation
  (`runObserver`, stream writer wiring, JSON/`--fields` output) and loses ~680
  lines of pipeline code.
- [x] Package tests (`internal/runner/runner_test.go`): allowed execution and
  audit; explicit deny → 6; gray zone → 7 with a pending request; approvals
  disabled → 6; session grant scoped to its session; group needing approval
  executes no member; once grant consumed exactly once across 8 concurrent
  reruns; once grant restored after a transport failure; remote/transport exit
  mapping; streamed output redacted; missing session is a usage error with no
  side effects; exit-code merge order; plan submit classification and shared
  pending for duplicate lines.
- [x] Final validation.

## Validation

Planned (from `.github/workflows/ci.yml`):

```
gofmt -l .
go vet ./...
go build ./cmd/...
golangci-lint run
go test -race ./...
```

Results (2026-10-22, final code):

- `gofmt -l .` — clean.
- `go vet ./...` — pass.
- `go build ./cmd/...` — pass.
- `golangci-lint run` — 0 issues.
- `go test -race -count=1 -timeout=20m ./...` — all packages pass, including
  `cmd/agentssh` with no test file modified and the new `internal/runner`.
- `scripts/e2e_tui_audit_run_summary.sh --no-tui` against a fresh build — exit 0.

No managed host was contacted; executors are faked in tests.
