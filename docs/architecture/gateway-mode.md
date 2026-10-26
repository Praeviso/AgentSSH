# Gateway mode

> Status: implemented (Epic [#11](https://github.com/Praeviso/AgentSSH/issues/11): #12, #14–#17, #19, #20) · Wire contract: [remote-control.md](remote-control.md#gateway-mode) · Choosing a mode: [README](../../README.md#choose-a-mode)

In gateway mode the client only forwards. `agentssh-gateway` holds each
device's inventory, policy, approvals, SSH identities and audit; it authorizes,
runs and audits every command. This document records the design as built and
the trade-off each part made. The endpoints, frames and limits are specified in
`remote-control.md`; the plans in `docs/plans/` hold each change's validation.

## Why a third mode

In managed mode (`agentssh-server`) the control plane signs SSH logins, and the
client enforces policy, approvals, output filtering and audit. A process running
as the agent's OS user can read `device.key`, request login signatures, and
connect to target hosts with them, so nothing the client enforces constrains it.
Managed mode therefore suits supervised agents on trusted machines, not
cloud-hosted or unattended ones.

Gateway mode treats the device as untrusted. Whatever a stolen device key or a
modified client sends, the gateway runs only what that device's policy and
grants authorize, and records it where the device cannot reach.

## Components

```
agent ──argv──▶ agentssh (device)          agentssh-gateway                target hosts
                 hosts/run/status/plan ──▶  /hosts /exec /exec/attach  ──SSH──▶  sshd
                 approval status|wait      /approvals/status /plans/*            (trust the
                 signed HTTPS requests     /authorize /requests/status            gateway's
                 device.key, remote.yaml   inventory, policy, approvals,          identities)
                 plan snapshots, payloads  identities, runs, audit.jsonl
                                           operator CLI · Web UI (own listener)
```

What stays on the device is only what concerns the device itself: its
enrollment (`device.key`, `remote.yaml`), saved plan executions and their stdin
payloads, and session IDs. Plan executions are orchestrated on the device, but
every step is a separate `/exec` that the gateway authorizes again, so a device
that lies about its plan state gains nothing.

## Trust boundaries

- **Device → gateway.** Every request is signed with the device key (RFC 9421
  profile, single-use nonce, 60 s lifetime) and checked for revocation. The
  device's identity selects its own inventory, policy, approval directory and
  runs; another device's IDs are not found.
- **Gateway → targets.** The gateway connects with its own identities,
  in-process: no ssh-agent, no local keys, no ssh_config, no connection reuse,
  host keys in its own `known_hosts`. Identity private keys are encrypted to
  the gateway's age identity, which only the master password unlocks.
- **Operator → gateway.** Decisions come from the gateway host's CLI, which
  reads the data directory, or from the Web UI, which uses accounts of its own
  (argon2id passwords and mandatory TOTP) on a listener the device API never
  shares. No device endpoint can resolve an approval.
- **When a device may act.** Only inside an activation window an operator
  opened for a chosen duration (1 min to 24 h); outside it every device endpoint
  but cancel refuses it, so a stolen device key is useless while the device is
  inactive. Revocation stays separate and permanent.
- **MCP client → gateway (OAuth).** Registration is open and grants nothing;
  only an operator's explicit consent after password and TOTP creates a grant,
  for one chosen token device. Client names are self-reported; the consent page
  shows the client ID and callback as well as the requested access. Consent and
  revocation require the Web UI's session, CSRF token and same-origin checks;
  a device credential cannot authorize a client. Login returns only to the
  local consent endpoint, where the client request is revalidated. Access
  tokens are bound to `/mcp`, last at most an hour or to the end of the
  activation window, and are refused once the grant or device is revoked; a
  refresh token used twice, or a code used twice with its PKCE verifier,
  revokes its grant.
- **What a device still controls.** Inside its window, it chooses which allowed
  commands to run and when, and it receives their filtered output. It can submit approval
  requests and plans, bounded per device, which only an operator can decide.

## Design and trade-offs by part

### Shared run pipeline (#12)

The run pipeline (session binding, authorization, approval request, audit,
execution, output filtering, exit-code merge) moved from `cmd/agentssh` into
`internal/runner`, which has no cobra or terminal dependency. The gateway calls
the same `runner.Run`, so a command gets the same decision in both places.

Trade-offs: plan orchestration (checkpoints, event journal, resume) stayed in
the CLI, so the gateway authorizes plans one step at a time rather than running
them itself; the three readiness loops of the waits stayed in the CLI because
merging them would have changed behavior.

### Separate binary and data directory (#14)

`agentssh-gateway` is its own binary. It shares enrollment, request signatures,
revocation, identities and configuration storage with `agentssh-server`
through `internal/controlplane`, but registers no `/sign` or `/bundle` route
and does not link `internal/remoteserver`. Its database is `gateway.db`, and a
`mode` file marks the data directory; each binary refuses the other's.

Trade-offs: two binaries to deploy instead of one with a mode switch, in
exchange for a gateway that cannot hand out signatures or bundles by
misconfiguration. The issue predates the switch from mTLS to signed HTTPS
(#10), so there is no client certificate or `tls renew`.

### Execution API (#15)

`POST /exec` is one signed JSON body (command, session, optional stdin up to
32 MiB) answered by a stream of frames: stdout and stderr data, one `run --json`
response per target, then a result or error frame. The signature over the
headers (covering `Content-Digest`) is verified before the body is read.
Output is capped per stream (1 MiB, or the policy's `output.max_bytes` if
lower) before auditing, so the audit hash covers exactly what is returned.

Trade-offs: no full-duplex stream. Full duplex would have needed h2c to the
origin, an ingress that streams request bodies, and a per-frame signature
scheme. Stdin is a bounded file the CLI reads whole anyway, and cancellation is
a separate signed request. On cancellation the gateway sends `SIGTERM` before
closing the SSH connection, so a non-pty command does not keep running (local
Ctrl-C gained the same).

### Runs that outlive the connection (#16)

Each `/exec` is a run (`rn_` + 32 hex) whose frames are spooled to disk; the
connection only attaches to it. A device whose connection drops reattaches
from the byte offset it has consumed (`/exec/attach`), so every frame arrives
once and the command runs once. The client mints the run ID and sends it as an
idempotency key, so a repeated request whose first response was lost joins the
existing run. `/exec/cancel`, `--exec-timeout`, or the device losing standing
(#34, below) stops a run.

Trade-offs: the gateway now stores output, so it is bounded on every axis
(spool per run, finished output per device, run records per device, retention)
and a partial result is marked `truncated` with a non-zero exit code. A run
live when the gateway restarts cannot be recovered; it reports
`run_interrupted` and its outcome must be read from the audit.

### Client gateway mode (#17)

A device enrolls with `agentssh remote enroll --mode gateway`. Every response
carries `AgentSSH-Mode`, and the client checks it on every response, so a
control plane of the other mode fails closed and is never mistaken for an
unreachable one. Enrollment probes `/status` unsigned first, so the wrong mode
is refused before the token is spent. In gateway mode the CLI renders the
gateway's responses with the printers local mode uses, so output and exit codes
match local mode; a guard refuses (exit 2) every command for state the device
no longer keeps.

Trade-offs: remediation hints differ by mode on purpose (they name the gateway's
administrator, not local files). Optional inspection commands that read local
state (`policy test`, `session grants`, `audit`) are unavailable on a gateway
device rather than proxied; the agent workflow does not depend on them.

### Approvals on the gateway (#19)

Pending requests, resolutions, session and task grants and plan manifests live
under `devices/<id>/approval/` on the gateway. Devices submit and query
(`/approvals/status`, `/plans/submit`, `/plans/status`, `/authorize`); the
gateway's operator decides with `agentssh-gateway approval|plan`. Each decision
is appended to the gateway's audit chain with the device and operator.

Trade-offs:

- Waiting is client-side polling (backing off to every 2 s), not a push channel.
- Plan IDs are minted by devices, because they key the device's payload pins.
  The gateway refuses an ID another device holds, and a decision by an ambiguous
  ID needs `--device`.
- What a device leaves pending is capped per device (`--max-pending-approvals`),
  since only an operator removes it.
- A grant binds the stdin size the request stated as well as its hash, because
  the size is what the operator reads.

### Operator Web UI (#20)

`serve --web-listen` serves server-rendered pages from assets embedded in the
binary (`html/template`, a few lines of vanilla JS, no build step). Operators
sign in with a password and TOTP enrolled from a QR code at first login.
Sessions are server side, revocation applies on the next request, and every
POST needs a CSRF token and a same-origin request. The Approvals page decides
plans and single requests; the Devices page activates and deactivates devices
(#38); the Audit page browses and verifies the chain.

Trade-offs:

- Accounts are local to the gateway: there is no SSO or external identity
  provider.
- The sign-in limiter is in memory, per process. Password checks are bounded to
  two at a time so argon2id cannot exhaust memory.
- Behind a proxy that rewrites `Host`, the browser-facing origin must be given
  (`--web-origin`); forwarded headers are not trusted.
- Host scope, offered here and in `approval grant --host`, appends a rule to the
  device's policy and pushes it as a new version. That rewrites the policy YAML
  from its structure, losing comments and formatting, and it is written only
  if the policy is still the version it was derived from.
- The QR encoder is in the repository (byte mode, level M, versions 1–10)
  rather than a new dependency.

### Activation windows (#37)

Every gateway device starts inactive. `device activate <id> --for <duration>`
opens a window, `device deactivate` closes it early, and the window ends on its
own. The state is a gateway-only table and every device route checks it on each
request, except enrollment, `/status` and `/exec/cancel`. Activation,
deactivation and the end of a window are audit records with the operator.

Trade-offs:

- The cap is a fixed 24 h checked where a window is stored, not a `serve` flag:
  `device activate` runs in its own process and could not see `serve`'s flags,
  so a serve-only cap would disagree with what the CLI wrote.
- An ended window is recorded by the first request or the 30-second sweep that
  finds it, or by the activation that replaces it, so its record can come up to
  that long after the window ended; the record's `active_until` says when it
  did. The audit chain, not the table's flag, decides whether an end is already
  recorded, so a failed append is retried and never duplicated; this is why a
  window lasts at least a minute, so two windows of a device never end in the
  same second.
- When the window ends or the device is deactivated or revoked, its running
  commands are stopped too (#34, below).

### Token devices (#40)

For agents that cannot install a client, a token device authenticates with a
bearer token instead of an enrolled key. It is an ordinary device row with no
public key, so activation, revocation, configuration, approvals and audit all
apply unchanged, and the signed routes refuse it; its tokens, stored only as
the SHA-256 of their secret, authenticate the routes below `/api/`, which a
signature never does.

Trade-offs:

- A bearer token can be replayed while it is valid, unlike a signed request
  with its single-use nonce. Activation windows bound that to the time an
  operator chose, rotation replaces a token at once, and TLS (the ingress) is
  the only transport; tokens are never accepted in a URL.
- No lockout after failed tokens: a 256-bit secret cannot be guessed, and a
  lockout keyed by the token ID (part of the token, and in audit records)
  would let anyone who saw it lock the device out. A failed check costs one
  SHA-256.
- One live token per device: rotation revokes the previous one in the same
  transaction, so there is never a moment with two or none.

### Running commands over the API (#41)

`POST /api/run` starts the same run `/exec` does (one shared start-or-join
path; `/exec` streams frames from it, the API answers JSON) and waits a
bounded time for it. A run that outlives the wait is read from offsets into
its spool with `/api/run/output`, exactly as a device reattaches.

Trade-offs:

- Bounded waits and polling instead of a stream: hosted platforms end tool
  calls and HTTP actions within about a minute, so no call outlasts 50 s, and
  the spool and offsets (#16) make polling lossless.
- Output is returned as text. A chunk boundary can split a multi-byte
  character, which then reads as U+FFFD; the final `run --json` objects carry
  the complete filtered output, as for `run --json`.
- Responses are returned as they are written, not held until the end, so an
  offset never skips one.
- The rest of the agent's commands follow the CLI's answers (#42): hosts,
  request status, approval status with a bounded wait, and a new session, all
  described by an OpenAPI 3.1 document served at `/api/openapi.json` for
  platforms that import an API. The document is checked against the live
  handlers in tests, not generated from code: no generator dependency, and the
  descriptions (what to do on `denied` or `approval_required`) are written for
  the agents that read them.

### A remote MCP endpoint (#43)

Agent platforms that connect to remote MCP servers use `/mcp`: the token API's
operations as tools, over Streamable HTTP. One table of operations registers
both the HTTP routes and the tools, and each tool's schema and description
come from the OpenAPI document, so the two surfaces cannot disagree.

Trade-offs:

- A minimal JSON-RPC implementation instead of the official Go SDK: four
  methods and JSON answers need no dependency, and the server stays
  stateless (no session ID, no server stream). Checked with the official
  TypeScript SDK's client, which negotiated 2025-11-25 and ran the workflow.
- Denied, approval required and SSH errors are results, not tool errors: the
  agent must act on them (stop, wait, check), and some clients treat tool
  errors as transient. Refusals are tool errors.
- Every MCP request needs the device active, so an inactive device is refused
  at initialization; cancelling while inactive goes through `/api/run/cancel`.

### OAuth for MCP clients (#45, #46)

Platforms that connect to remote MCP servers only through OAuth 2.1 get
tokens from the gateway itself, which is the authorization server for its
`/mcp` endpoint when `serve` knows the Web UI's origin (`--web-origin`). A
client registers itself, an operator's consent on the Web UI binds it to
one token device as a grant, and the grant's access tokens act as that device
on `/mcp`. The grant is the long-lived, revocable part; access tokens last an
hour and never past the device's activation window, and are issued and
accepted only while the device is active.

Trade-offs:

- Open dynamic registration, because every OAuth-capable MCP client falls
  back to it and pre-registration needs a setup step per platform. A client
  is only a name and redirect URIs (HTTPS, or HTTP on loopback), so
  registering grants nothing; unconsented clients are capped (1000) and
  deleted after an hour. Client ID metadata documents are not offered: the
  gateway would fetch URLs anyone names.
- Opaque tokens stored hashed, like device tokens: revocation and the
  device's standing take effect on the next request, which signed tokens
  would need a lookup for anyway.
- Token and registration endpoints under the public URL, which the platform's
  servers reach; the authorization endpoint on the Web UI, which only the
  operator's browser needs to reach.
- An inactive device's code or refresh token is refused without being
  consumed, so the client continues once an operator activates the device;
  a reused one revokes the grant, since someone else holds it.
- Access tokens are for `/mcp` only (RFC 8707 resource), not `/api`.

The Web UI's `/oauth/authorize` page preserves the client's request through
password and TOTP sign-in, including retries. It shows the client's name, ID,
callback and the requested access, then requires an explicit choice of an
available token device; signed and revoked devices are excluded. Deny needs no
device and returns `access_denied`, with the client's state and issuer. The
request is validated again on POST, and an unknown client or unregistered
callback is refused without redirecting. Consent may bind an inactive device,
but never activates it: tokens still cannot be issued or used until activation.
The consent page's CSP allows the validated callback's origin for form redirects;
other pages retain `form-action 'self'`. Consent forms still post to the Web UI
and must pass its same-origin and CSRF checks.

The Devices page lists each token device's OAuth grants, with the client ID,
who consented and when, and a revoke action. Revoked grants remain visible as
history. A grant can be revoked only under the device it belongs to. Consent
and revocation use the same authenticated operator, CSRF and same-origin
checks as approval decisions, and their audit records name `web:<operator>`,
the client, device and grant. Revoking a grant refuses both access and refresh
tokens from the next request; other clients' grants and the static device
token continue to work within the device's activation window.

### Stopping runs that lost standing (#34)

Every 30 s, `serve` checks each live run's device and the identities its
targets connect with, reading them from the store because the CLI changes them
from another process. A run whose device was revoked or deactivated, whose
window ended, or which connects with a disabled identity is cancelled as
`/exec/cancel` cancels it: `SIGTERM`, then the connection closes. The run ends
with an error frame naming the reason, so the device sees why (and the matching
hint) instead of an SSH failure, and the reason is recorded in the run record
and in the run's audit record; the run's context carries it as its
cancellation cause, which the shared runner writes as `cancelled: <reason>`.

Trade-offs:

- One sweep over the live runs, not a timer per run: one store read per device
  and per identity each round, so a run stops up to 30 s after the change, as
  in managed mode.
- Only a definitive answer stops a run. A store error is logged and the run
  continues, as managed mode cancels only on a definitive revocation.
- The stopped run's per-target responses are replaced by the error frame, so
  output already streamed stays with the device but the final responses (and
  their request IDs) do not reach it; the audit keeps them.

## Limits and what is not provided

- **Single point of execution.** If the gateway is down, no gateway device runs
  anything; if it is compromised, every target host trusting its identities is
  exposed. There is no high availability or horizontal scaling.
- **Reachability.** The gateway, not the device, must reach every target host.
- **Stopping is not immediate.** A run of a device that lost standing stops
  within the 30-second check, not at once.
- **Plans** run on one host; multi-host and group plans are not supported.
- **Notifications.** Operators learn of pending approvals from `approval ls` or
  the Web UI; there is no push to IM or mobile.
- **OAuth discovery with a path prefix.** Clients look for the metadata at
  the origin's root (`/.well-known/oauth-protected-resource/<prefix>/mcp`,
  `/.well-known/oauth-authorization-server/<prefix>`), so an ingress that
  forwards only the prefix must route those two paths to the gateway too.
- **TUI.** The operator TUI does not decide gateway approvals; use the CLI on
  the gateway host or the Web UI.

The threat model for all three modes is the table in
[remote-control.md](remote-control.md#threat-model).
