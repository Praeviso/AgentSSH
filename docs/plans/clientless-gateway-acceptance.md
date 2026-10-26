# Clientless gateway acceptance (#35, #44)

> Status: done · Epic: [#35](https://github.com/Praeviso/AgentSSH/issues/35) · OAuth: [#44](https://github.com/Praeviso/AgentSSH/issues/44)

## Goal and acceptance

Complete the Epic's acceptance on main after #55 (2ce8303): no agent-side
binary for JSON/MCP, operator-controlled activation, OAuth consent and standing,
device-attributed runs, and a verifiable gateway audit chain for activation,
expiry, deactivation and revocation. Existing signed, managed and local modes
must continue to pass. Saved plan execution/resume over JSON/MCP remains the
Epic's explicitly deferred work.

Acceptance audit found a concrete gap: the shared `device revoke` command
updates the device row but appends no gateway audit record. Existing activation
CLI coverage even expects only activation and deactivation in the chain after
revocation. The missing event prevents completing #35's second acceptance item.

## Approach

1. Add a gateway-specific audited revocation operation and a small mode hook in
   the shared command scaffolding. Managed mode retains its store operation.
2. Persist the first operator/time and revocation together in a gateway-only
   table, then append `device_revoked`. Revocation must take effect even when
   audit storage fails. Retrying or the serve sweep repairs the record, with
   the original actor/time, exactly once under the audit lock. Unknown devices
   create neither state nor records. Repeated revocation remains idempotent.
3. Add public-interface coverage: real command dispatch for signed and token
   devices, audit failure and restart/concurrent recovery, JSON/MCP token
   lifecycle at the exact window boundary, run records naming their device,
   OAuth browser consent before activation and issuance/use/refusal across its
   window. Reuse existing workflow and standing tests instead of duplicating
   the full SDK/browser harness from #55.
4. Update the README and threat model, map each Epic acceptance item to durable
   tests and existing live-client evidence, and deliver a PR closing #35/#44
   only when all scoped acceptance and final checks pass.

## Progress

- #55 merged and #46 closed; code and security review report no findings.
- Workspace clean; main synchronized to 2ce8303. Branch:
  `fix/gateway-device-revocation-audit`.
- Reusing the repository's `docs/plans` mechanism and implement workflow.
- Implemented transactional revocation metadata, the mode-specific command
  hook, deduplicated audit publication and recovery in the standing sweep.
- Added signed/token CLI coverage, cross-process retry/sweep recovery under
  audit failure, JSON/MCP credential lifecycles and OAuth consent/window checks.

## Acceptance evidence map

| Epic acceptance | Durable evidence |
| --- | --- |
| No agent binary: hosts, allow, deny, pending, Web UI decision and rerun over JSON/MCP | `TestAgentApprovalWorkflowThroughWebUI` (JSON, MCP, OAuth MCP); real Chromium and official SDK evidence in [#55](https://github.com/Praeviso/AgentSSH/pull/55) and [web-oauth-consent.md](web-oauth-consent.md) |
| Same token before activation, at expiry and after revocation; full lifecycle audit and device-attributed runs | `TestClientlessTokenActivationLifecycle`; `TestDeviceRevokeCommandAuditsSignedAndTokenDevices`; `TestDeviceRevocationAuditRecoversWithTheOriginalOperator` |
| OAuth operator consent and issue/use only inside the device window | `TestOAuthBrowserConsentObeysTheDevicesWindow`; `TestOAuthConsentReturnsThroughPasswordAndTOTP`; `TestOAuthRefreshRotation`; `TestOAuthRevocation` |
| Signed gateway, managed and local modes keep working | Full repository race tests, including `remoteclient`, `remoteserver`, runner and CLI packages |
| README, gateway architecture and threat model | README gateway section; `docs/architecture/gateway-mode.md`; `docs/architecture/remote-control.md` |

The existing standing tests also verify cancellation on revocation,
deactivation and expiry, while other devices' runs remain unaffected.

## Validation

Passed on the final code, Go 1.25.5 with `GOFLAGS=-p=2` and writable build/lint
caches under `/tmp/agentssh-issue35`:

- Formatting and `git diff --check`.
- `go vet ./...` and `go build ./cmd/...`.
- `go test -race -count=1 -timeout=20m ./...`: all 27 packages with tests pass.
- `golangci-lint run --timeout=5m`: zero issues.
- `node scripts/verify_https_vectors.mjs`: independent request, bundle and SSH
  signatures pass.
- `scripts/e2e_tui_audit_run_summary.sh --no-tui` with the compiled CLI and an
  isolated data directory: passes, audit chain verifies with 14 records.
- The unchanged new CLI regression test copied into an isolated archive of
  main at 2ce8303 fails with zero revocation records where one is required;
  the same test passes on the final code. No new production helper or enum is
  needed to compile the test against the old tree.
- The compiled `agentssh-gateway` binary, using a fresh production-format data
  directory, creates/activates/revokes a token device, repeats revocation, and
  handles a second device's revocation while its audit path is unwritable.
  A separate command sees the second device revoked; after restoring the log,
  a new command repairs its event. Both devices have exactly one revocation
  record, and the five-record chain verifies.
- New targeted race tests cover separate store handles recovering one failed
  audit concurrently, through both a command retry and the periodic sweep,
  preserving the first operator/time; unknown devices add nothing. JSON and
  MCP each reuse one token through all activation states and verify three
  device-attributed run files and all lifecycle/execution audit records. The
  OAuth HTTP integration test performs operator consent before activation,
  checks the exact window boundary, resumes unused codes/refresh tokens after
  reactivation, and refuses both grants after device revocation; the operator
  Audit page shows the event and an intact chain.

This change does not alter the browser UI or MCP/OAuth wire formats; the real
browser/official SDK checks from #55 remain linked separately above and were
not rerun as new live-client evidence. No required validation is blocked.
The sandbox emits a nonfatal read-only module metadata-cache warning during
successful builds. Logs and the isolated regression/CLI fixtures are under
`/tmp/agentssh-issue35-acceptance/`. Remote CI and artifacts are verified on the
final PR head after publishing.
