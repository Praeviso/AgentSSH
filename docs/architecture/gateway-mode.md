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
- **What a device still controls.** It chooses which allowed commands to run
  and when, and it receives their filtered output. It can submit approval
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
existing run. Only `/exec/cancel` or `--exec-timeout` stops a run.

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
plans and single requests; the Audit page browses and verifies the chain.

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

## Limits and what is not provided

- **Single point of execution.** If the gateway is down, no gateway device runs
  anything; if it is compromised, every target host trusting its identities is
  exposed. There is no high availability or horizontal scaling.
- **Reachability.** The gateway, not the device, must reach every target host.
- **Revocation and running commands.** Revoking a device refuses its next
  request, but a run the gateway already started continues until it finishes or
  `--exec-timeout` (30 minutes by default); the device can no longer attach to
  its output.
- **Plans** run on one host; multi-host and group plans are not supported.
- **Notifications.** Operators learn of pending approvals from `approval ls` or
  the Web UI; there is no push to IM or mobile.
- **TUI.** The operator TUI does not decide gateway approvals; use the CLI on
  the gateway host or the Web UI.

The threat model for all three modes is the table in
[remote-control.md](remote-control.md#threat-model).
