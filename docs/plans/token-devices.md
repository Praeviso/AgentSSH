# Token devices (#40)

> Status: done · Issue: [#40](https://github.com/Praeviso/AgentSSH/issues/40) · Parent: [#39](https://github.com/Praeviso/AgentSSH/issues/39) · Epic: [#35](https://github.com/Praeviso/AgentSSH/issues/35)

## Goal and acceptance

A token device is a gateway device whose credential is a long-lived bearer
token instead of an enrolled Ed25519 key, for agents that cannot run
`agentssh`. It starts inactive (#37), can be revoked for good, and its token can
be rotated. Tokens and signatures never stand in for each other.

Done when:

- A created token authenticates only while its device is active; after
  revocation or rotation the old token is refused; the token is not stored in
  clear.
- A token on a signed route and a signature on a token route are both refused.
- Audit records carry the device and token ID.

## Approach

- **Model.** A token device is a row in the shared `devices` table with an
  empty public key; the kind is derived from that (`gateway.DeviceKind`). The
  signed middleware refuses a device with no key (`401 unknown device key`,
  where decoding an empty key used to give 500). Tokens live in the gateway's
  `device_tokens` table: ID, device, SHA-256 of the secret, created, revoked.
- **Token.** `agt_<16 hex id>_<43 base64url>` (256 random bits); the ID finds
  the row, the secret's hash is compared in constant time.
- **Routes.** `controlplane.API.Open`: routes that authenticate themselves,
  under the same public base and wrapper (canonical target, no query, mode
  header), bounded bodies, never the signature check. The gateway registers
  `GET /api/status` (answers while inactive) and `GET /api/hosts` (needs the
  device active), the first of the JSON API (#41, #42 add the rest).
- **Answers.** Any token failure is one `401 unauthenticated`; a revoked
  device `403 device_revoked`; inactive `403 device_inactive`.
- **CLI.** `device create --name <n> --kind token` (prints the token once,
  never `device token create`, which makes enrollment tokens),
  `device rotate <id>`, and a `KIND` column in `device ls` (the admin hook
  becomes a list of columns). The Web UI's Devices page names the kind,
  deferred from #38.
- **Audit.** `token_id` added to records (omitempty); `device_token_issued`
  and `device_token_revoked` with the operator.
- **Rate limiting** (the issue's open question): not per token. The secret
  cannot be guessed, and a lockout keyed by the token ID, which is part of the
  token and in audit records, would let anyone who saw it lock the device out.

## Progress

- [x] Store, token format, authentication, open routes.
- [x] CLI, `device ls` kind, Web UI kind.
- [x] Tests: `internal/gateway/tokens_test.go` (active only; rotation; not in
  clear: the secret is in no file of the data directory, WAL included; tokens
  and signatures never stand in for each other, including a signature claiming
  the token device's ID; bad tokens refused alike and never in a URL),
  `cmd/agentssh-gateway` (`create`, `rotate`, `ls`, audit), Web UI kind.
- [x] Docs: README, remote-control.md (token devices, API routes, threat-model
  row), gateway-mode.md (design and trade-offs).
- [x] PR review follow-up (review of 0a38823): the not-in-clear test took
  the secret as the text after the token's last "_", but "_" is in the
  base64url alphabet, so a secret containing it left a short suffix that could
  occur in the data files and fail the test spuriously (11 false reports in 300
  runs). The test now splits on the two fixed separators and checks the secret
  is 43 characters (300 of 300 runs pass). The gateway's parser was not
  affected: it matches the whole token with an anchored pattern, and the ID is
  hex.
- [x] Final validation.

## Validation

```
gofmt -l .
go vet ./...
golangci-lint run
go test -race ./...
scripts/e2e_tui_audit_run_summary.sh --no-tui
```

Results (2026-10-25, final code): gofmt clean, `go vet` and `golangci-lint`
(0 issues) pass, `go test -race ./...` passes, the e2e script exits 0.

Mutation checks, each failing its test: the secret not compared (a wrong
secret was accepted); a rotated-out token accepted; rotation keeping the old
token; a keyless device reaching the signature check (500 instead of 401);
activation not checked on token routes; the token ID not audited.

Live, with real binaries behind a TLS ingress and curl: `device create --kind
token` printed the token once; `/api/status` answered while inactive,
`/api/hosts` gave `403 device_inactive` until `device activate`, then the
hosts; the token on the signed `/status` gave `401`; after `device rotate` the
old token gave `401 invalid bearer token` and the new one worked; `device ls`
showed `KIND token` with the window; the audit chain verified.
