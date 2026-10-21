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

- Working in /tmp/agentssh-config-center-adapter, feat/https-control-plane.
- User requested a clean replacement rather than parallel protocol support.
- Consolidation complete: one handler/client/token schema; numbered protocol
  identifiers, certificate lifecycle, mode flags and compatibility storage removed.
- All original remote lifecycle tests now exercise the single HTTPS protocol.
- Canonical protocol documentation replaces duplicate and superseded documents;
  independently signed Web Crypto fixtures use the final unversioned contract.
- Original local checkouts remain untouched. Updating the existing PR #10.

## Validation

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
