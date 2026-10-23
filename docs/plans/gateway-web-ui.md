# Operator Web UI on the gateway (#20)

> Status: done · Issue: [#20](https://github.com/Praeviso/AgentSSH/issues/20) · Parent: [#18](https://github.com/Praeviso/AgentSSH/issues/18) · Epic: [#11](https://github.com/Praeviso/AgentSSH/issues/11)

## Goal and acceptance

Operators away from the agent's machine decide gateway devices' approvals in a
browser. `agentssh-gateway serve --web-listen` serves a Web UI from assets
embedded in the binary (Go `html/template`, `embed`, a little vanilla JS, no
Node build), on its own listener, never on the device API's.

Done when:

- End to end: a gateway device's gray-zone command exits 7, an operator approves
  it in the browser, `approval wait` on the device returns 0, and the rerun
  succeeds.
- Tests: device credentials and unauthenticated requests cannot reach decision
  endpoints; a decision without the CSRF token is refused; an operator without
  TOTP cannot decide; revoking an operator ends their sessions at once; logins
  beyond the failure threshold are rate limited; cookies are `HttpOnly; Secure;
  SameSite=Strict`.
- Every decision's audit record names the operator (Web UI and CLI alike).
- Approvals and Audit pages checked in a browser at desktop and phone widths.

Decisions taken with the user (2026-10-23):

- Host scope is offered (Web UI and `agentssh-gateway approval grant --host`):
  approving appends the host rule to the device's policy and pushes it as a new
  configuration version. The policy YAML is re-rendered from its structure, so
  comments and formatting of the pushed file are not kept; the UI says so.
- TOTP enrollment shows a QR code from an in-repository encoder (byte mode, EC
  level M, versions 1–10), no new dependency. It is checked against jsQR during
  development.

## Approach

Accounts (`internal/gateway/operators.go`, tables in `gateway.db`):

- `operators`: name (unique), argon2id password hash (PHC string), TOTP secret
  sealed to the gateway's age recipient (unsealed only by `serve`), the last
  accepted TOTP step (no code replay), status (`active`/`revoked`).
- `web_sessions`: SHA-256 of a random token, operator, stage (`password` →
  `active`), CSRF token, created/last-seen/expiry. Every request rechecks the
  operator's status, and revocation deletes their sessions.
- `agentssh-gateway operator add|ls|revoke` (password read twice from the TTY,
  or `AGENTSSH_GATEWAY_OPERATOR_PASSWORD` for scripts).
- TOTP: RFC 6238, SHA-1, 6 digits, 30 s, ±1 step. Enrolled at first login: the
  password-stage session can only see the enrollment page until a code verifies.

Web (`internal/gateway/web`):

- Routes: `/login` (password, then TOTP or enrollment), `/logout`,
  `/approvals`, `/approvals/<id>` POST, `/plans/<id>` POST, `/audit`, `/static/`.
- Cookies: session `HttpOnly; Secure; SameSite=Strict; Path=/`; the login form
  uses a double-submit token. Every POST after login needs the session's CSRF
  token. Headers: strict CSP (`default-src 'none'`, self scripts/styles),
  `frame-ancestors 'none'`, `no-store`, `no-referrer`, `nosniff`.
- Rate limit: in memory, per account and per client address, 5 failures in 15
  minutes lock out for the rest of the window (password and TOTP failures).
- Decisions go through `gateway.DecideApproval`/`DecidePlan` with the operator
  in `ApplyOptions.Operator` → `audit.Record.Operator`.
- Approvals page: plans first (members with a per-row deny; approve the rest
  once/session/task, no host), then single requests (device, host, session,
  command, matcher, stdin, offered scopes; once/session/task/host/deny); a
  shell-metacharacter warning on commands.
- Audit page: filter by device, host, session; newest first, latest 200; chain
  verification banner.

## Progress

- [x] QR encoder (`internal/qr`): byte mode, level M, versions 1–10, mask
  chosen by penalty, SVG output. Checked with jsQR: 427 inputs (1–213 bytes,
  random and repeated, every version) decode; with 1 % of data modules flipped
  all still decode, so the Reed-Solomon codewords correct real errors. Unit
  tests: the standard worked example's EC codewords, capacity per version,
  finder/timing/format structure. The page's own QR (taken from the browser)
  decodes to the otpauth URI with the key the page shows.
- [x] Operators (`internal/gateway/operators.go`): accounts, argon2id, TOTP
  (RFC 6238 vectors), sealed keys (`Keys.Seal/Open`), server-side sessions with
  a password stage, revocation deleting sessions plus a status recheck,
  `operator add|ls|revoke`.
- [x] `audit.Record.Operator` and `ApplyOptions.Operator`; `gateway.Decider`
  (operator, optional device); host scope pushes the device's policy as a new
  version; `approval grant --host`.
- [x] Web UI (`internal/gateway/web.go`, `webui/`): login, TOTP enrollment and
  verification, approvals (plans and singles), audit; security headers, CSRF,
  same-origin check, login limiter; `serve --web-listen [--web-cert --web-key]`
  binding before it reports success.
- [x] Browser check (playwright-cli, Chromium): login, enrollment, approvals,
  a decision and its notice, audit, at 1280×800 and 390×844, light and dark.
  Found and fixed: `Referrer-Policy: no-referrer` made Chromium send
  `Origin: null` on form posts, which the origin check refused (now
  `same-origin`, and a test covers `Origin: null`); host and device names broke
  at their hyphens in the audit table; filter controls had uneven heights; the
  TOTP key wrapped inside a group; no favicon.
- [x] Commit security review follow-up (bb3d186):
  - The login limiter checked the limit and recorded a failure in separate
    steps, so a burst of concurrent TOTP or password attempts all passed the
    check. `loginLimiter.begin` now counts an attempt as a failure when it
    starts, under the same lock as the check, and takes it back on success.
    Test: `TestConcurrentLoginsCannotPassTheLimit` (30 concurrent wrong
    passwords, at most 5 checked; a mutation reopening the gap fails it).
  - A host grant re-read the configuration only for the inventory and pushed
    the policy derived from what it read earlier, so an admin push in between
    was overwritten. `controlplane.ReplaceConfig` writes only if the version
    is still the one read (`ErrConfigChanged` otherwise; the decision fails
    without a rule). Test: `TestHostGrantNeverOverwritesANewerPush`
    (mutation-checked).
- [x] Docs: `docs/architecture/remote-control.md`.
- [x] Final validation.

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

Plus: jsQR decodes the encoder's output for every version; playwright-cli
screenshots of Login, Approvals and Audit at 1280×800 and 390×844.

Results (2026-10-23, final code): see the PR. Mutation checks, each failing its
test: CSRF token check, origin check, stage check, rate limiter, SameSite
Strict, operator on decisions, TOTP replay guard; revocation's two guards
(session deletion, status recheck) each failing their own unit test. A redundant
TOTP pre-check that only duplicated the atomic guard was removed.
