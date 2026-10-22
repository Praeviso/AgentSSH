# agentssh-gateway binary (#14)

> Status: done · Issue: [#14](https://github.com/Praeviso/AgentSSH/issues/14) · Parent: [#13](https://github.com/Praeviso/AgentSSH/issues/13) · Epic: [#11](https://github.com/Praeviso/AgentSSH/issues/11) (gateway mode)

## Goal and acceptance

Add `cmd/agentssh-gateway`, the gateway-mode control plane: it enrolls and
authenticates devices and manages identities and per-device configuration, but
has no signing or bundle endpoint, so no request path hands identity
signatures or a policy bundle to a client. Managed mode stays the job of
`agentssh-server`; one data directory belongs to exactly one mode.

Done when:

- A device enrolls with `agentssh-gateway`; after `device revoke` its next
  request is refused with `device_revoked`.
- Signed `POST /sign` and `GET /bundle` requests to the gateway return 404, and
  the gateway's dependency graph does not contain `internal/remoteserver` (the
  only package with sign/bundle handlers).
- `/status` reports the control-plane mode (`gateway`, and `managed` for
  `agentssh-server`).
- Each binary refuses a data directory initialized by the other.
- Existing `agentssh-server`, `remoteserver` and `remoteclient` tests pass
  unmodified, and the `agentssh-server` database schema is unchanged.

Out of scope: the execution API, server-side audit, and using identity keys for
SSH connections (#15); client `--mode` (#17); Web UI (#20); adding the gateway
to release archives (once #13 is usable end to end).

### Deviation from the issue text

The issue predates #10, which replaced mTLS with signed HTTPS requests behind a
TLS-terminating ingress. There is no CA or client certificate any more, so
"mTLS" becomes "the same signed-request device authentication as
`agentssh-server`", `tls renew` is dropped, and there is no CA/TLS code to
share. Paths are unversioned (`/status`, not `/v1/status`).

## Approach

New shared package `internal/controlplane` (moved from `internal/remoteserver`
with no semantic change):

- Keys: master-password-protected age key, the Ed25519 control-plane key
  (bundle signing in managed mode; pinned by enrollment tokens in both modes),
  age-encrypted identity keys. `Init` takes the mode, scrypt work factor, and a
  database initializer, and records the mode in a `mode` file; a missing file
  means `managed` (directories created before this change).
- Store: devices, enrollment tokens, identities, configs, request nonces. An
  extra schema fragment lets `remoteserver` add `sign_log` with the exact same
  DDL, so the managed database is unchanged and the gateway database has no
  signing table.
- HTTP: canonical-target guard, enrollment, signed device-request middleware
  (revocation + replay check on every request), `/status` with the mode, and
  per-route hooks (managed uses one to log a revoked device's sign attempt).
  Store and clock are read through accessors at request time, as before.
- `PushConfig` validation (direct addr/user/identity hosts; the gateway connects
  with the same rules).
- `internal/controlplane/admin`: cobra scaffolding shared by both binaries —
  `--data`, master-password prompt, data-directory mode check, `init`,
  `device token create|ls|revoke`, `identity create|ls|disable`,
  `config push`, and the serve loop.

`internal/remoteserver` keeps its exported API through type aliases, wrapper
functions and an embedding `Store` (which adds the sign log), so its tests and
`remoteclient`'s e2e tests compile unchanged.

New `internal/gateway`: `Init`/`Unlock`/`OpenStore` over `gateway.db` and a
`Server` whose handler registers only the shared routes. New
`cmd/agentssh-gateway`: `init`, `serve`, `device`, `identity`, `config`.

Key decisions:

- Distinct database file (`gateway.db`) plus the `mode` marker: even an older
  `agentssh-server` binary pointed at a gateway directory sees no devices or
  identities, so it cannot sign for gateway devices.
- The token-creation hint prints `agentssh remote enroll <url> --mode gateway`;
  the flag arrives with #17.

## Progress

- [x] Read `remoteserver`, `remote`, `remoteclient`, `cmd/agentssh-server`, and
  the related issues (#13, #15, #17).
- [x] Extract `internal/controlplane` (keys, store, HTTP layer, `PushConfig`)
  and `internal/controlplane/admin`; `remoteserver` keeps its API through
  aliases/wrappers and a `Store` that embeds the shared one and adds the sign
  log; `agentssh-server` uses the shared commands (help and output unchanged).
- [x] Add `internal/gateway` and `cmd/agentssh-gateway`.
- [x] Tests: `internal/gateway` (real client enrolls through a TLS ingress,
  `/status` reports gateway mode, revoked device refused; sign and bundle are
  404), `admin` (each binary refuses the other's directory; legacy directories
  are managed), `cmd/agentssh-gateway` (enroll hint names `--mode gateway`;
  binary does not depend on `internal/remoteserver`), `remoteserver` (`/status`
  reports managed mode).
- [x] Docs: `docs/architecture/remote-control.md` (gateway section, `mode` file,
  status mode), `docs/architecture/overview.md` package tree.
- [x] Final validation.

Small visible changes to `agentssh-server`: `/status` gains `"mode":"managed"`
(old clients ignore unknown fields); `init` also writes `mode`; the
"read recipient / bundle public key" errors no longer name the binary (both are
only reachable after the initialization check).

## Validation

Planned (from `.github/workflows/ci.yml`):

```
gofmt -l .
go vet ./...
go build ./cmd/...
golangci-lint run
go test -race ./...
scripts/e2e_tui_audit_run_summary.sh --no-tui
```

Plus: diff the `sqlite_master` DDL of a database created by `agentssh-server
init` on `main` and on this branch.

Results (2026-10-22, final code):

- `gofmt -l .` — clean; `go vet ./...` — pass; `go build ./cmd/...` — pass.
- `golangci-lint run` — 0 issues.
- `go test -race -count=1 -timeout=20m ./...` — all packages pass. No existing
  test file was modified (`remoteserver`, `remoteclient`, `cmd/agentssh-server`
  included); new tests in `internal/gateway`, `internal/controlplane/admin`,
  `cmd/agentssh-gateway`, and `internal/remoteserver/mode_test.go`.
- `scripts/e2e_tui_audit_run_summary.sh --no-tui` against a fresh build — exit 0.
- Schema: `sqlite_master` of a database from `agentssh-server init` on `main`
  and on this branch are identical (9 statements); the only directory
  difference is the new `mode` file.
- Manual: `agentssh-gateway init` / `identity create` / `device token create` /
  `device ls` work, and `agentssh-server --data <gateway dir> device ls` is
  refused ("holds a gateway control plane").
