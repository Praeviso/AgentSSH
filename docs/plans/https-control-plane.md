# Execution plan — HTTPS control-plane adapter

## Goal and acceptance

Allow a hosted control plane such as a config-center Worker to serve AgentSSH
without a separate Go service or private-CA TLS termination. Add an explicit v2
HTTPS/device-public-key protocol, a Go server reference implementation, client
support and a language-neutral wire contract. Existing v1 mTLS enrollments remain
supported; no negotiation or automatic downgrade is allowed.

Acceptance: a real enrolled v2 client fetches/verifies its bundle and connects to
the in-process SSH target using remote signatures; revocation, identity disable,
tampering, replay, expiry and wrong enrollment pins fail closed. A URL prefix is
preserved through enrollment and every request. Redirects never forward enrollment
secrets or signed requests. Public protocol fixtures can be verified independently
with Web Crypto. Existing SSH/policy/cache behavior remains covered.

## Approach

1. Define a narrow RFC 9421 Ed25519 request-signature profile and origin/path-bound
   v2 enrollment token pinning the bundle public key. Reuse existing bundle and
   SSH signature envelopes.
2. Add SQLite-backed device public keys, single-use v2 enrollment tokens and
   durable replay protection; expose a prefix-aware HTTPS handler and optional
   HTTP origin behind a TLS proxy. Reuse current configuration/signing handlers.
3. Adapt the client based only on its explicit token/enrollment protocol. Keep
   v1 mTLS state, native SSH signing and local-only tightening unchanged.
4. Add behavioral tests, independent interoperability fixtures and protocol/user
   documentation, then perform one consolidated validation and publish a PR.

## Progress

- Inspected current main `6c95ab2`, repository CI and remote-control architecture.
- Working in `/tmp/agentssh-config-center-adapter`, branch
  `feat/https-control-plane`; original checkout remains unchanged.
- Implemented the explicit v2 token/signature profile, prefix-aware reference
  handler, durable replay store, CLI flags and client protocol dispatch.
- Added real SSH lifecycle coverage, rejection/concurrency/restart tests and
  independently generated Web Crypto fixtures. Documented the hosted wire contract.
- Implementation and consolidated validation complete. Delivery branch:
  `feat/https-control-plane` in `Praeviso/AgentSSH`.

## Validation

Passed with Go 1.25.5 and writable `/tmp/agentssh-adapter-go-cache`:

- gofmt and `git diff --check`.
- `go vet ./...` and `go build ./cmd/...`.
- `go test -race -count=1 -timeout=20m ./...` (with `GOFLAGS=-p=2`).
- `golangci-lint run --timeout=5m` (local v2.5.0; CI uses v2.12.2).
- `node scripts/verify_https_vectors.mjs` verifies request, bundle and SSH vectors.

The final race run includes both existing v1 and new v2 paths. V2 tests cover
real SSH authentication, fresh signing on consecutive connections, device and
identity revocation, in-flight cancellation, URL and key pins, redirect refusal,
expiry, altered messages, concurrent replay and durable replay after reopening
SQLite. An initial name collision and a missing test certificate SAN were fixed
before the final full pass. The build emitted a nonfatal read-only module metadata
cache warning; its command exited successfully.

Remote CI is recorded by GitHub Actions on the pull request, separately from these
local results. No config-center implementation, deployed Worker interoperability
or production deployment is included in this PR.
