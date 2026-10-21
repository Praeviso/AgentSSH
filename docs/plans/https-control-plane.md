# Execution plan — hosted HTTPS control plane

## Goal and acceptance

Support a single hosted config-center service through one unversioned HTTPS
control-plane protocol. Remove certificate enrollment, private-CA management,
protocol selection, compatibility endpoints/tables and numbered wire identifiers.
Keep signed device requests, one-time enrollment, bundle verification, monotonic
configuration versions, remote SSH signing, revocation and local deny overlays.

Acceptance: a real client enrolls through a path prefix, verifies configuration
and connects to an SSH target. Device and identity revocation, replay, expiry,
tampering, wrong pins and redirects fail closed. Enrollment records have only the
service URL, device ID, bundle public key and enrollment time. No certificate or
protocol selector is persisted. Existing enrollment/state is deliberately not
migrated; operators create a fresh server data directory and re-enroll devices.

## Approach

1. Consolidate endpoint/message/token definitions and client/server handlers;
   remove protocol dispatch and certificate code. Use /enroll, /status, /bundle,
   /sign, unversioned token and signature tags, and an unversioned bundle envelope.
2. Retain one device/token/nonce schema and signing-key-only server initialization.
   The reference server runs a private HTTP origin behind its configured public
   HTTPS ingress. No certificate or HTTP-mode switches are needed.
3. Convert all lifecycle tests to the retained protocol, regenerate independent
   Web Crypto fixtures and rewrite documentation around the final behavior.
4. Review for obsolete paths, fields, flags and dead code; run consolidated
   formatting, vet, builds, full race tests, lint and Web Crypto verification.
   Update the existing PR #10 and inspect CI on the actual final head.

## Progress

- Working in an isolated /tmp checkout, feat/https-control-plane.
- User requested a clean replacement rather than parallel protocol support.
- Consolidation complete: one handler/client/token schema; numbered protocol
  identifiers, certificate lifecycle, mode flags and compatibility storage removed.
- All original remote lifecycle tests now exercise the single HTTPS protocol.
- Canonical protocol documentation replaces duplicate and superseded documents;
  independently signed Web Crypto fixtures use the final unversioned contract.
- Original local checkouts remain untouched. Updating the existing PR #10.

## PR review follow-up

Review against PR head 3a1309b and base 6c95ab2. Confirmed: ingress gateway
failures lose cache grace; automatic GET retries reuse proofs; signature time
failures lack diagnostics; deferred SQLite write transactions can fail on snapshot
upgrade; nonce admission conflates revocation and replay; invalid enrollment
guidance omits leave; nonce pruning runs for every request; handlers buffer bodies
twice; the CLI duplicates bundle-key storage details. The final nit is partly
incorrect: configured TLS roots are used by embedders/tests, and bundle key
decoding supplies bytes required by verification.

Acceptance and approach:

- Classify non-protocol gateway 502/503/504 as unreachable, retaining cache expiry
  and fail-closed protocol refusals; verify through Open with a real TLS ingress.
- Make signed requests non-rewindable so Transport cannot resend a consumed
  proof. Exercise a reused connection lost after server-side acceptance.
- Keep the 60s/30s proof limits. Authenticate first, then return clock_skew with
  server UTC time and explicit clock synchronization guidance, including enroll.
- Acquire SQLite write intent at transaction start. Atomically distinguish
  revoked devices from replay at nonce admission, sharing the rejection/audit
  path; prune expired indexed nonces at most once per minute per store.
- Decode the already authenticated bounded request bytes once; centralize the
  bundle public-key loader; restore leave-then-enroll guidance for all invalid
  state; simplify redundant URL handling while retaining TLS trust settings.
- Add regression coverage, run it against the old head where feasible, then run
  full race tests, vet, build, lint, Web Crypto fixtures and CI on the pushed head.

Progress: implementation complete in /tmp/agentssh-config-center-review.
Nonce admission also checks expiration after obtaining the SQLite writer lock.
Original checkouts remain untouched. New regression tests were copied unchanged
into an isolated checkout of 3a1309b and reproduced nine failing cases: connection
retry/replay, ingress cache classification, incomplete recovery guidance, client
clock diagnostics, revocation classification/audit, server/enrollment clock
diagnostics, concurrent writes (including SQLite code 517), per-request pruning,
and proof expiry before admission. Those same tests pass on the revised code.
Body decoding and token-key loading have retained behavioral coverage; they were
refactors supported by source inspection, rather than failing functional cases.

Final local validation passed on the implementation above (Go 1.25.5,
GOFLAGS=-p=2, writable /tmp build cache):

- go test -race -count=1 -timeout=20m ./... (entire repository, including real
  SSH lifecycle, replay, clock, cache, revocation and concurrent storage tests).
- go vet ./... and go build ./cmd/...; build returned zero with a nonfatal
  read-only module metadata-cache warning.
- golangci-lint run --timeout=5m (2.5.0), zero issues; gofmt and git diff --check.
- node scripts/verify_https_vectors.mjs, all independent Web Crypto vectors.
- Python CI-selection tests, all 21 passed.
- Removal scan found the retired enrollment field only in its intentional
  rejection regression fixture; no compatibility code or versioned protocol.

Delivery: update PR #10 and verify its exact final head's CI. Remote results are
reported in the PR and delivery message independently from the local checks.

## Previous validation

Passed on the final implementation with Go 1.25.5, a writable /tmp build cache
and GOFLAGS=-p=2:

- gofmt and git diff --check.
- go vet ./... and go build ./cmd/....
- go test -race -count=1 -timeout=20m ./... (entire repository).
- golangci-lint run --timeout=5m (local 2.5.0; GitHub CI uses 2.12.2).
- node scripts/verify_https_vectors.mjs (request, bundle and SSH signatures).
- Repository-wide removal scan found no retired protocol identifiers, certificate
  APIs, mode flags or compatibility tables. State tests require exactly the four
  retained enrollment fields and reject unexpected fields.

The final full pass follows removal of an unused test import. Build succeeded
with a nonfatal read-only module metadata cache warning. GitHub Actions on the
final PR head records remote CI independently of these local results. This run
supersedes earlier protocol validation; no config-center implementation or
deployment is included.
