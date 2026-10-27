# Hosted HTTPS control plane

A control plane manages device enrollment, published inventory/policy and remote
SSH signing. A hosted implementation such as a config-center Worker can provide
all of these inside one service. `agentssh-server` is the Go reference
implementation. AgentSSH has one HTTPS device-signature protocol, with no protocol
selector or numbered endpoint, token, signature tag or bundle-format marker.

## Responsibilities and trust

The client authenticates the service with ordinary HTTPS and pins the bundle
public key from its enrollment token. The service authenticates the device using
Ed25519 request signatures. Device keys remain local; SSH identity keys remain in
the service. Target hosts trust the identity public key in `authorized_keys`.

The service checks device standing and identity status on every login-signature
request. Clients verify bundles, enforce policy, apply local deny rules first,
filter output and maintain their local execution audit. A signing log proves a
login was signed or refused, not which commands a device actually ran.

The signer checks RFC 4252 authentication structure, login user, algorithm and
identity public key. The SSH session hash does not prove the actual remote host
to the service; identities should be scoped to the hosts that share trust in them.
Command-level policy and in-flight cancellation are enforced by the client and
cannot constrain a modified client binary.

## Threat model

What each mode does against each threat. "Same-user process" means code
running as the agent's OS user outside the CLI, such as a compromised tool or a
modified `agentssh`.

| Threat | Local | Managed (`agentssh-server`) | Gateway (`agentssh-gateway`) |
| --- | --- | --- | --- |
| An injected agent asks the CLI for a destructive command | Deny rules on the device refuse it (exit 6) | Deny rules from the bundle and local deny rules refuse it | The gateway's policy for the device refuses it |
| The agent reads credentials | Never in its output, but keys and `secrets.enc` are on the device | SSH keys are not on the device; `device.key` is | Neither SSH keys nor policy are on the device; `device.key` is |
| A same-user process bypasses the CLI | Uses the keys and `ssh` directly; nothing constrains it | Requests login signatures with `device.key` and runs anything as the identity's user on its assigned hosts; only the signing log records the logins | Can only call the gateway, which runs what the device's policy and grants authorize and audits it |
| The agent approves its own request | Decisions need operator authentication; a same-user process can edit the approval files | As local | No device endpoint decides; operators decide on the gateway host or in its Web UI |
| Audit records are altered | The hash chain shows edits, but a same-user process can rewrite the whole file | As local for commands; the control plane's signing log is out of reach | The chain is on the gateway, out of the device's reach |
| A device key is stolen | No device key | Logins to assigned hosts until the device is revoked | Commands the device's policy allows, only inside an activation window an operator opened, until it is revoked |
| A token device's token leaks | No tokens | No tokens | It works only inside an activation window, until the token is rotated or the device revoked; unlike a signature it can be replayed within that time |
| A device is revoked | No device | Its next login is refused; running commands check standing every 30 s and are cancelled | Its next request is refused, as when it is deactivated or its window ends; within 30 s its running commands are stopped (`SIGTERM`), with the reason in the audit |
| The control plane is down | Not involved | Cached bundle until expiry, but no new logins: commands fail closed | Nothing runs: the gateway is the single point of execution |
| The control plane is compromised | Not involved | Every host trusting its identities | Every host trusting its identities, and every device's policy and audit |
| Target hosts must trust | Your keys | The control plane's identities | The gateway's identities, and the gateway must reach them |

## Endpoint base and deployment

An administrator chooses a canonical HTTPS base, for example
`https://config.example/plugins/agentssh`. Prefix segments contain only unreserved
ASCII letters, digits and `-._~`. No credentials, query, fragment, escaped path,
dot segments or empty path segments are allowed. Trailing slashes are removed.
Append these literal endpoint paths:

| Method | Suffix | Authentication / response |
| --- | --- | --- |
| POST | `/enroll` | Single-use token and the new device key's proof of possession |
| GET | `/status` | Device proof; device ID, active/revoked standing and control-plane mode (`managed`) |
| GET | `/bundle` | Device proof; signed configuration bundle |
| POST | `/sign` | Device proof; SSH authentication signature and signing-log ID |

Every response, including a refusal of an unauthenticated request, carries
`AgentSSH-Mode: managed` or `AgentSSH-Mode: gateway`; a response without it is
from a managed control plane that predates the header (or, for 502/503/504, an
ingress whose backend is down). A device is enrolled for one mode, stored as
`mode` in `remote.yaml` (a record without it is managed), and its client checks
the header on every response: a control plane of another mode fails the request
closed and is never mistaken for an unreachable one, so no cached configuration
is used in its place.

Queries and redirects are refused. A terminating deployment configures the
verifier with its external HTTPS base; never derive the signature target from
client-supplied forwarding headers. The reference server mounts the full prefix,
so its HTTPS ingress preserves the request path and keeps the HTTP origin private.

```sh
agentssh-server init
agentssh-server identity create web
agentssh-server serve --public-url https://cp.example/agentssh
# Private origin defaults to 127.0.0.1:8080; --listen changes that address.
agentssh-server device token create --name laptop \
  --public-url https://cp.example/agentssh
agentssh remote enroll https://cp.example/agentssh --token '<token>'
agentssh-server config push --device <id> --inventory inventory.yaml --policy policy.yaml
agentssh-server device revoke <id>
agentssh-server identity disable web
agentssh-server log
```

The reference server owns encrypted signing keys and SQLite state. Its initialization
creates `master.age`, `recipient`, `bundle.pub`, `bundle.key.age`, `mode` and
`server.db`. `mode` records which control plane owns the directory (a missing file
means `managed`); `agentssh-server` and `agentssh-gateway` each refuse the other's
directory.
The master passphrase protects an age X25519 identity; bundle and SSH identity
private keys are encrypted to that identity. Creating SSH identities needs only
the public age recipient. The public HTTPS ingress owns transport certificates.

### Gateway mode

`agentssh-gateway` shares this enrollment, request-signature, revocation, identity
and configuration machinery (`internal/controlplane`), but from the table above
registers only `/enroll` and `/status` (mode `gateway`), plus its own device
endpoints, `/exec` and those below:
`/bundle` and `/sign` return 404, and the binary does not link
`internal/remoteserver`. Its database is `gateway.db`, so a managed binary pointed
at a gateway directory has no devices or identities to sign for.

`POST /exec` carries one signed JSON body: target, command (at most 128 KiB, the
local argv limit), session and optional stdin (base64, at most 32 MiB); host,
session and plan identifiers are at most 256 bytes and the session label 1 KiB,
so no audit record nears the reader's 8 MiB line limit. The gateway runs it
through the same pipeline as the CLI (`internal/runner`) against the device's
pushed inventory and policy, connecting with its own identities in-process (no
agent, local keys or ssh_config; no connection reuse; `known_hosts` in the data
directory). Because its body is
larger than other endpoints', the gateway verifies the signature over the
request headers (which cover `Content-Digest`) before reading the body, refuses
an oversized `Content-Length` with 413, and then checks the body against the
digest. Requests the CLI would reject as usage errors return 400 `usage`; a device over its
concurrency limit (`serve --max-concurrent`, default 4) gets 429 `busy`.

Each `/exec` is a run with an ID (`rn_` + 32 hex). The client mints it and
sends it as `run_id`, an idempotency key: repeating the same request (same body
digest) with the same ID joins the existing run instead of starting the command
again, so a client whose first response was lost recovers without running the
command twice; reusing the ID for a different request is `409 run_conflict`.
The gateway mints an ID when none is sent.

A run's frames, `type:1 | length:4 big-endian | payload`, are: stdout (1) and
stderr (2) data frames of at most 64 KiB, sent only when the request asks to
stream a single-host run; then one response frame (5) per target with its
`run --json` object; then a result frame (3, `{exit_code, truncated}`). An
error frame (4, `ErrorResponse`) may replace everything after the data frames.
Response, result and error frames are at most 16 MiB: the gateway caps each
stream's output at 1 MiB unless the policy's `output.max_bytes` is lower
(applied before auditing, so the audit hash covers what is returned), which
keeps a response within one frame even when JSON escapes every byte.

Every `/exec` and `POST /exec/attach {run_id, offset}` response starts with a
run frame (6, `{run_id}`) followed by the run's frames from the offset,
following a live run until its final frame. The run does not depend on the
connection: a dropped request only detaches the device, and the client
reattaches from the byte offset of the complete frames it has consumed, so
every frame arrives exactly once and the command runs once. A run stops on
`POST /exec/cancel {run_id}`, on `serve --exec-timeout` (default 30m), or when
its device loses standing: every 30 s `serve` reads each live run's device and
identities from the store, and stops the runs of a device that was revoked or
deactivated or whose activation window ended, and the runs connecting with a
disabled identity. Only a definitive answer stops a run; a store error is
logged and the run left alone. In every case the gateway sends the remote
command `SIGTERM` before closing the SSH connection. A run stopped for lost
standing ends with an error frame instead of its responses, so the device is
told why rather than seeing a transport failure: `device_revoked`,
`device_inactive` or `identity_disabled`, with the message
`the gateway stopped this command: <reason>`. The reason is also in the run
record (`cancel_reason`) and in its audit record
(`cancelled: the device was revoked`, for example). A device's concurrency slot is held until its run finishes.

**Run records.** Each run ID has one record, `runs/<device-id>/<run-id>.json`,
which is the single source of truth; the frames live beside it in a spool the
record names. A record appears whole or not at all, and publishing it
exclusively is the only way to claim an ID, so a start and a cancel that
overtook its own request race on the same publish and the first wins, durably
across restarts. Everything an attempt writes before its claim is private and
removed if the claim fails. States:

| State | Meaning | Answer to attach / a repeated `/exec` |
| --- | --- | --- |
| `running` (live) | in progress | streams it |
| `running` (not live after a restart) | outcome unknown, see the audit | `410 run_interrupted` |
| `finished` | output kept for `serve --run-retention` (default 24h) | streams it |
| `evicted` | output deleted (retention or quota); record kept for the idempotency window | `404 run_not_found`, never re-run |
| `cancelled` | a cancel arrived first; kept 10 minutes | `409 run_cancelled` |

Runs belong to the device that started them; another device's and unknown IDs
are `404 run_not_found` too, and a cancel of an ID that is not live answers
`cancelled: false` either way.

A run ID deduplicates repeats of its request for at least the idempotency
window, one hour after the run starts (clients repeat a request only while
recovering a lost first response). Records are a resource of their own: a
device keeps at most `serve --run-records` (default 10000) in any state. Every
new record, a run's or a cancel's, is admitted against that limit; when the
device is at it, the oldest finished or evicted runs past the window are
reclaimed, and if none are, the start or the cancel is refused with
`429 busy` (a refused cancel was not recorded, so the client reports that the
run may still be running). Each device's records are aged out at least once a
minute, by whichever request needs a record.

**Space.** A run's spool is hard-capped at `serve --run-max-bytes` (default
64 MiB). Space is reserved up front for each target's response in a minimal
form (32 KiB, a proven bound) and for the result frame, so a group with more
targets than the cap can hold is refused as a usage error, before any room is
made for it. Output beyond the
cap is dropped; a response that no longer fits is sent without its output, or
in its minimal form (`output_truncated`); the result then says
`truncated: true` with the exit code raised to at least 1, so a partial result
never passes for a complete one. A device keeps at most
`serve --run-quota-bytes` (default 512 MiB) of finished output: before a run
starts and again when one finishes, its oldest finished runs are evicted. One
device therefore occupies at most quota + `--max-concurrent` ×
`--run-max-bytes`. The request must arrive within the 60 s proof lifetime;
ingresses must stream responses (the gateway sends `X-Accel-Buffering: no`).

Every run is recorded in one hash chain per gateway, `audit.jsonl`, with
`device_id` on each record (`agentssh-gateway audit verify`).

**Approvals.** A gateway device's pending requests, resolutions, session and
task grants and plan manifests live only on the gateway, under
`devices/<id>/approval/`, and only the gateway authorizes. Devices submit and
query, and no device endpoint resolves anything:

| Method | Suffix | Answer |
| --- | --- | --- |
| POST | `/approvals/status` | `{status, wait_timeout_ms}`: the request as `approval status` prints it, and the device policy's default wait |
| POST | `/plans/submit` | `{response, exit_code}`: `plan submit`'s preflight against the device's policy and grants; commands carry their stdin identity only, and the device mints the plan ID |
| POST | `/plans/status` | `{status, wait_timeout_ms}`, as `plan status` prints it |
| POST | `/authorize` | how each `{host, session, cmd, stdin_sha256}` would be authorized now, with no side effects |

Waits (`approval wait`, `plan wait`, `--wait-approval`) poll these, backing off
to every 2 s, and after an approval check `/authorize` before rerunning, since a
resolution is written before its grant. Another device's IDs are not found.
The gateway's operator decides on the gateway host, from the data directory:

```sh
agentssh-gateway approval ls [--json]
agentssh-gateway approval show <approval-id> [--device <id>]
agentssh-gateway approval grant <approval-id> --once|--session|--task|--host [--device <id>]
agentssh-gateway approval deny <approval-id> [--device <id>]
agentssh-gateway plan show <plan-id> [--json] [--device <id>]
agentssh-gateway plan grant <plan-id> --once|--session|--task [--device <id>]
agentssh-gateway plan deny <plan-id> [--device <id>]
```

What a device leaves awaiting a decision stays on the gateway's disk until an
operator acts, so it is capped per device (`serve --max-pending-approvals`,
default 1000): unresolved requests, and separately plans that still have one
(plans with none left are reaped after a day, like resolved requests). A plan
that does not fit is refused before it creates anything, and a request beyond
the cap is `429 busy`, on `/exec` and `/plans/submit` alike. Counting and
creating are one step under a lock beside the device's approval directory, so
concurrent requests cannot pass the cap together, and a device's plan
submissions are serialized.

A grant records the stdin size its request stated, and a run whose stdin
differs in size is refused (`approval/stdin-size-mismatch`, exit 6); zero is a
size like any other, not "unchecked", so a grant recorded before sizes were
bound needs approving again for a non-empty stdin. The hash already pins the
content; the size a device states when submitting a plan is what the operator
reads, so a misstated one can never authorize the real payload. `/plans/submit`
also refuses a hash and size that cannot describe one payload (a malformed
hash, a size without a hash, a size beyond the stdin limit, or zero bytes with
any hash but the empty payload's).

Plan IDs are minted by devices, so the gateway refuses a submitted plan ID that
another device already holds (`409`), and a decision by an ID that more than
one device holds (two submissions racing past that check) is refused until
`--device` names the device. A decision by ID therefore never lands on another
device's plan.

Grant lifetimes come from the device's policy; each decision is appended to the
gateway's audit chain with the device's `device_id`, channel `gateway` and the
deciding `operator` (`local:<user>` from the CLI, `web:<name>` from the Web UI).
A host-scope grant appends an allow rule for the request's matcher to the
device's policy and pushes it as a new configuration version; the policy YAML is
re-rendered from its structure, so comments and formatting in the pushed file are
not kept. The new version is written only if the policy it was derived from is
still current; if another push landed first the decision fails without a rule
(the request stays approved without one, so the device's rerun asks again) and
the other push is kept. A whole plan is approved once, for the session or for the task, never
for the host. `plan show` lists the commands of the plan's requests, which are
what a grant authorizes, before the steps as the device described them.

**Operator Web UI.** `serve --web-listen <addr>` serves a Web UI for operators
away from the gateway host, from assets embedded in the binary, on its own
listener: never the device API's, so no device request reaches it and no
operator request reaches the device API. It speaks TLS with
`--web-cert/--web-key`, or plain HTTP behind a TLS-terminating proxy. A proxy
may rewrite `Host` to its upstream address, so plain HTTP requires
`--web-origin`, the HTTPS origin browsers use (`https://ops.example`); posts must
come from it. With TLS and no `--web-origin`, a post's `Origin` must match its
`Host`.

```sh
agentssh-gateway operator add <name>     # password from the TTY, or AGENTSSH_GATEWAY_OPERATOR_PASSWORD
agentssh-gateway operator ls
agentssh-gateway operator revoke <name>  # ends their sessions at once
agentssh-gateway serve --public-url https://gw.example/agentssh \
  --web-listen 127.0.0.1:8443 --web-origin https://ops.example
```

Operators are accounts of their own (`operators` in `gateway.db`): argon2id
password hashes, and TOTP that is mandatory and enrolled at the first sign-in
from a QR code (RFC 6238, SHA-1, six digits, 30 s; the key sealed to the
gateway's age recipient; each code accepted once). A password alone opens only a
ten-minute session for the TOTP step. Sessions are server side (`web_sessions`,
keyed by the SHA-256 of a random cookie token, 12 h, 30 min idle) and every
request rechecks the operator, so revocation takes effect on the next request.
Cookies are `HttpOnly; Secure; SameSite=Strict`; every POST needs the session's
CSRF token (the login form a double-submit token) and must not come from another
origin; POST bodies are URL-encoded and at most 64 KiB, checked before any
field is read; pages send a CSP without inline script, `frame-ancestors 'none'`,
`no-store` and `Referrer-Policy: same-origin`. Failed passwords and codes are
limited per account (5 in 15 minutes) and per client address (20; behind a
proxy that is the proxy's), after which sign-in is refused until the window
passes. An attempt is counted when it starts and taken back if it succeeds, so
concurrent attempts cannot pass the limit together. At most two password
checks (argon2id, 64 MiB each) run at once across all clients; a sign-in waits
up to five seconds for one, then is refused as busy without counting as a
failure. The Approvals page lists plans (approve the remaining steps as a whole
after denying single ones) and single requests (once, session, task, host,
deny), warning about commands that use shell syntax; the Devices page shows
each device's activation (active with the time left and who activated it,
inactive, or revoked) and last activity, and activates a device for a duration
chosen from 30 minutes to 24 hours (with an optional note) or deactivates it,
both audited as `web:<name>`; the Audit page browses the chain by device, host
and session, newest first, with its verification result. The Web UI opens and
closes windows at the system clock, which the device API checks them against.
The design and its trade-offs are in [gateway-mode.md](gateway-mode.md).

The other device endpoints answer what a local CLI reads from its own files:
`GET /hosts` returns the device's hosts and groups as `agentssh hosts --json`
prints them, and `POST /requests/status {req_id}` the device's latest audit
record for that request as `agentssh status --json` prints it (another
device's request is `404 request_not_found`). A single-host run's request ID
is minted before it starts and sent in its run frame (`{run_id, req_id}`), so
output streamed into plan events carries it; the result frame's `target_kind`
(`host` or `group`) decides whether `run --json` prints an object or an array.
Transport failures reach the device only as `ssh_error`; their cause is in the
gateway's log.

**Activation.** A gateway device is usable only inside an activation window.
It starts inactive; `agentssh-gateway device activate <id> --for <duration>`
opens a window of that length (1 min to 24 h, checked when it is stored), and
activating an active device sets a new end. `device deactivate <id>` closes it
at once. Windows live in the gateway's `device_activations` table, not in the
shared `devices` table, so the managed database is unchanged. Every device
endpoint except `/exec/cancel` refuses a device outside its window with
`403 device_inactive`, checked against the store with the gateway's clock on
each request; enrollment, `/status` and `/exec/cancel` still answer, so a device
can enroll before it is activated, see its state and stop its own runs.
`/status` reports `activation: {state: active|inactive, until}`. Activation,
deactivation and the end of a window are records in the audit chain
(`device_activated`, `device_deactivated`, `device_activation_expired`, with
`operator`, `active_until` and `note`). An ended window is recorded once, by the
first request or the 30-second audit sweep in `serve` that finds it, and before
a new activation replaces it. The gateway durably collects each expiry before
marking its window collected; publication deduplicates by stable `event_id`
under the audit-file lock. Pending expiry facts survive replacement windows,
concurrent retries, and process restarts. Deactivation and OAuth grant
revocation commit state and pending audit facts together, so audit failure
cannot leave access enabled. A failed publication reports that the restriction
is effective and audit repair is pending. Activation still requires successful
audit publication before opening access. Standing enforcement uses a separate
30-second loop with no audit-file I/O, so audit failure cannot prevent confirmed
expiry/deactivation from cancelling live runs. See
[gateway-mode.md](gateway-mode.md#security-state-and-audit-publication-57) for
recovery and error semantics. Revocation is separate and permanent: a revoked
device cannot be activated. On a gateway, `device revoke` appends `device_revoked`
with the device ID, operator and original revocation time. Revocation and its
actor/time are committed together before appending: an audit write failure
still leaves the device revoked, and a retry or the 30-second serve sweep
repairs the record. The hash-chain lock prevents duplicate records, and the
first operator/time survive concurrent retries and process restarts.

**Token devices.** A token device is a gateway device whose credential is a
bearer token instead of an enrolled key, for agents that cannot run
`agentssh`. `agentssh-gateway device create --name <n> --kind token` adds one
(the name avoids `device token create`, which makes enrollment tokens) and
prints its token once: `agt_<16 hex id>_<43 base64url characters>`, 256 random
bits of secret. The device is a row in the shared `devices` table with no
public key, so the signed routes refuse it (`401 unknown device key`); its
tokens live in the gateway's `device_tokens` table, which keeps only the
SHA-256 of the secret, compared in constant time. `device rotate <id>` issues
a new token and revokes the old one in one transaction; `device revoke`
revokes the device and with it its token. Issuing and revoking a token are
audit records (`device_token_issued`, `device_token_revoked`) with the device,
`token_id` and operator.

Token routes live under the same public base, below `/api/`, and are
registered as routes that authenticate themselves: they get the same
canonical-target checks (so a token in a query string is refused with 400) and
headers, never the signature check, and a signature never authenticates them.
A request carries `Authorization: Bearer <token>`. A malformed, unknown,
rotated-out or wrong token gets one answer, `401 unauthenticated`
("invalid bearer token"), whatever was wrong; a revoked device's token gets
`403 device_revoked`; outside its activation window every route but
`GET /api/status` answers `403 device_inactive`. `GET /api/status` answers like
`/status`; `GET /api/hosts` like `/hosts`. Failed tokens are not rate limited
per token: the secret cannot be guessed, and a lockout keyed by the token ID,
which is part of the token and appears in audit records, would let anyone who
saw it lock its device out.

A token route authenticates before it reads the body, so an unauthenticated
client never holds a large upload; a route admitting a large body then gets
the same upload time as `/exec`. Once the body has arrived it checks the token
and the device's standing again, as the signed routes check after the body, so
a token rotated or a device revoked or deactivated during a slow upload runs
nothing.

Token devices run commands with JSON in and out, for callers that cannot read
`/exec`'s frames or keep a stream open (hosted platforms time out tool calls,
often within a minute):

| Method | Suffix | Body → answer |
| --- | --- | --- |
| POST | `/api/run` | `{host, command, session, session_label?, stdin? (base64), run_id?, wait_ms?}` → the run |
| POST | `/api/run/output` | `{run_id, offset, wait_ms?}` → the run from `offset` |
| POST | `/api/run/cancel` | `{run_id}` → `{run_id, cancelled}` (also while inactive) |
| POST | `/api/request/status` | `{req_id}` → the request as `agentssh status --json` prints it |
| POST | `/api/approval/status` | `{approval_id, wait_ms?}` → the request as `agentssh approval status` prints it, after waiting while it is pending |
| POST | `/api/session` | → `{session_id}`, as `agentssh session new` mints one |
| GET | `/api/openapi.json` | the OpenAPI 3.1 document of these routes, no token needed |

The run is the same as an `/exec` run (the same pipeline, spool, idempotency,
limits and audit, with `token_id` on its records): `/api/run` is `/exec` with
streaming on, and a call waits up to `wait_ms` (absent: 20 s; 0: not at all;
at most 50 s, past the server's own response deadline) for it to finish. The
answer is `{run_id, req_id, state, result, exit_code, truncated, target_kind,
stdout, stderr, responses, error, next_offset}`: `state` is `running` or
`finished`; `stdout` and `stderr` are the output streamed since the offset, as
text (bytes that are not valid UTF-8 read as U+FFFD); `responses` are the
`run --json` objects written since the offset, which together carry the
complete filtered output; once finished, `exit_code` has the CLI's meaning
and `result` names it (`ok`, `failed`, `denied`, `approval_required`,
`ssh_error`, `usage`), or `result` is `error` with `error` when the run ended
without a result (the gateway stopped it, for example). `next_offset` is where
the next read continues, so every byte arrives once; an offset the API did not
answer is refused with 400. A run's identity for `run_id` is what it runs, not
how long a call waits. Requests the CLI would reject are `400 usage`, before a
run starts. An approval status call waits like a run call (`wait_ms`), polling
the device's approval store, and answers as soon as an operator decides; a
wait that ends while pending answers `pending`, which is not an approval.

**MCP.** `POST /mcp` serves the same operations as MCP tools over Streamable
HTTP: one JSON-RPC message per POST, a request answered with
`application/json`, a notification or response accepted with 202, and no
server stream or session (`GET` and `DELETE` are `405`). It negotiates
protocol revisions 2025-11-25, 2025-06-18 and 2025-03-26 (an unknown request
gets the newest), refuses an unsupported `MCP-Protocol-Version` header with
400, and implements `initialize` (with instructions drawn from the agent
skill), `ping`, `tools/list` and `tools/call`. Each tool runs its `/api`
operation's handler, so its result is that operation's JSON (as text and as
`structuredContent`); a tool's input schema, summary and description come from
the OpenAPI document. A run that is denied, needs approval or fails over SSH
is a normal result whose `result` says so, because the agent must act on it;
a refusal (usage, inactive, not found) is a result with `isError`. The
endpoint is a token route like the others (authenticated before and after the
body) and needs the device active for every request, initialization included,
so a device cannot cancel over MCP while inactive (the `/api` cancel can). It
takes only the bearer token: the Web UI's session cookie authenticates nothing
here, and the token nothing in the Web UI.

**OAuth.** With `--web-origin`, the gateway is an OAuth 2.1 authorization
server for `/mcp`. A request to `/mcp` without a valid token is answered 401
with `WWW-Authenticate: Bearer resource_metadata="..."`, naming the protected
resource metadata (RFC 9728) at
`<origin>/.well-known/oauth-protected-resource<path>/mcp`; it lists the public
URL as the authorization server, whose metadata (RFC 8414) is at
`<origin>/.well-known/oauth-authorization-server<path>`. Clients register at
`/oauth/register` (RFC 7591; `none`, `client_secret_basic` or
`client_secret_post`; secrets kept hashed) and get tokens at `/oauth/token`
(authorization code with PKCE S256 only, and refresh tokens). The
authorization endpoint is the Web UI's `/oauth/authorize`; it answers with
`code`, `state` and `iss` (RFC 9207). The one scope is `agentssh`, and the
only resource (RFC 8707) is `/mcp`. Codes (`agc_`), access tokens (`ago_`) and
refresh tokens (`agr_`) are opaque, and only their SHA-256 is stored. Codes
last 5 minutes and redeem once; access tokens an hour, capped at the end of
the device's activation window; refresh tokens 30 days, replaced on every
use. A refresh token presented after it was used revokes the grant, and so
does a used code presented with its PKCE verifier; without the verifier a
used code is only refused, since it was in a redirect URL and proves nothing.
The token endpoint refuses (`invalid_grant`) while the grant's device is
inactive or revoked, without consuming the code or refresh token; `/mcp`
refuses an inactive device's access token with 403 `device_inactive`, which
does not send a client back through authorization. Audit records of runs
through a grant carry `grant_id` instead of `token_id`; the gateway's chain
records `oauth_grant_created` (the consenting operator, the client),
`oauth_refresh_refused` (a refresh token it issued, refused, with the reason)
and `oauth_grant_revoked` (by an operator, or for a reused code or refresh
token). `agentssh-gateway oauth ls` and `oauth revoke <grant>` list and revoke
grants.

The OpenAPI document is embedded in the binary and served with the gateway's
public base as its server and the bearer scheme. A test keeps it from drifting:
the routes it documents must be exactly the routes served, every example must
fit its schema, and every operation, sent with its example (live IDs in place
of the examples'), must succeed and answer what its schema says.

**Gateway devices.** `agentssh remote enroll <url> --token <t> --mode gateway`
(the default is `managed`) enrolls a device for a gateway. In gateway mode
`hosts`, `run`, `status` and `plan run|resume` go through these endpoints: the
gateway resolves, authorizes, runs and audits every command, and the device's
local `inventory.yaml`, `policy.yaml`, approvals and audit are ignored. The CLI
renders the gateway's per-target responses with the same printers as a local
run, so output and exit codes match local mode; only remediation hints name the
gateway's administrator instead of the local files. `plan run` keeps its saved
execution on the device and sends each step as its own `/exec`, so the gateway
reauthorizes every step, and a step's stdin file is read only when that step is
sent. `approval status|wait`, `plan submit|status|wait` and `--wait-approval`
work as locally, against the gateway's approvals (below). A saved execution
records whether its approval plan is on a gateway (`approval_on_gateway`); one
whose plan is kept where the device no longer runs commands (a local plan after
enrolling with a gateway, or the reverse) marks it `superseded` and submits the
remaining steps again. Commands that read or
change state the device no longer keeps (inventory, policy, secret, approval
decisions, audit, sessions, TUI) are refused with exit 2.

## Enrollment

The token format is:

```text
agentssh-enroll.<id>.<secret>.<bundle_fingerprint>.<encoded_base>
```

- `id`: 1–80 ASCII letters, digits, `_` or `-`; reference token IDs start with `et_`.
- `secret`: unpadded base64url of 32 random bytes. Persist only its SHA-256 digest.
- `bundle_fingerprint`: lowercase hex SHA-256 of the raw 32-byte Ed25519 bundle key.
- `encoded_base`: unpadded base64url of the UTF-8 canonical public HTTPS base.

The supplied enrollment URL must match the token before sending anything. The
client first sends an unsigned `GET /status`: its 401 still names the control
plane's mode, so enrolling for the wrong mode is refused before the token is
spent. It then generates an Ed25519 key and sends JSON:

```json
{"token_id":"et_...","token_secret":"...","public_key":"<standard padded base64 raw Ed25519 public key>"}
```

Sign with the new device key, token ID as `keyid` and enrollment tag below.
Verify proof before consuming the token. Atomically consume a valid nonexpired
token bound to the configured public base, create the device and store its public
key. Tokens are single-use and expire after 10 minutes by default. Return:

```json
{"device_id":"dev_...","bundle_public_key":"<standard padded base64 raw Ed25519 bundle key>"}
```

The client checks the returned bundle-key fingerprint, then writes `device.key`
(PKCS#8 PEM, 0600) and `remote.yaml` (0600). The enrollment marker commits last and
has exactly `server_url`, `device_id`, `bundle_public_key`, `enrolled_at`, `mode`. Failed
pin validation never activates remote mode. If a response or local write is lost,
issue a fresh token instead of automatically reusing a consumed one.

## Request signatures

Use this narrow profile of [RFC 9421](https://www.rfc-editor.org/rfc/rfc9421.html).
Sign the raw body bytes, including an empty body for GET. `Content-Digest` uses
the RFC 9530 SHA-256 form:

```text
Content-Digest: sha-256=:<standard padded base64 SHA-256 of raw body>:
Signature-Input: agentssh=("@method" "@target-uri" "content-digest");created=<unix>;expires=<unix>;nonce="<nonce>";keyid="<id>";alg="ed25519";tag="agentssh-device"
Signature: agentssh=:<standard padded base64 Ed25519 signature>:
```

Require exactly those three covered components and that parameter order, one
value of each header, and no additional labels or algorithm choices. `keyid` is
the token ID for enrollment and device ID afterwards. `tag` is `agentssh-enroll`
only at enrollment, and `agentssh-device` for other operations.

`nonce` is unpadded base64url of 32 fresh random bytes. `expires > created`, lifetime
is at most 60 seconds, expiration is strictly after server time, and creation is
no more than 30 seconds ahead of server time. Synchronize device and service clocks.
An otherwise authentic but out-of-window proof returns HTTP 401 `clock_skew`,
with synchronization guidance and server UTC time. Verify the signature before
diagnosing time drift; do not automatically adjust the clock or widen the window.
This applies to enrollment and device requests.

The UTF-8 signature base has four lines and no final newline:

```text
"@method": POST
"@target-uri": https://config.example/plugins/agentssh/sign
"content-digest": sha-256=:...:
"@signature-params": ("@method" "@target-uri" "content-digest");created=...;expires=...;nonce="...";keyid="dev_...";alg="ed25519";tag="agentssh-device"
```

The target is the full configured public URI including its prefix. Every raw JSON
byte is authenticated; do not reserialize before digesting. Verify the signature,
check device standing and atomically claim `(device_id, nonce)` in durable storage,
rechecking active status. Keep that nonce until expiry. Enrollment uses its
single-use token transaction instead. An unavailable replay store refuses requests.
The reference server bounds bodies at 64 KiB and authenticates and decodes the
same bytes. Its SQLite write transactions acquire write intent before reading;
nonce admission authoritatively distinguishes revocation from replay. Expired
nonces are removed using the expiry index at most once per minute per store, in
the same transaction as admission. Live nonces remain protected until expiry.

Signed requests are single-use even for GET: the client supplies non-rewindable
bodies, including empty bodies, so HTTP Transport cannot automatically resend a
consumed proof after losing a response on a reused connection. A subsequent
explicit operation generates a fresh proof. Enrollment and signing are never
retried automatically because their outcome may already have been committed.

## Configuration and SSH signatures

`GET /bundle` returns `{"bundle":"<base64 raw JSON>","signature":"<base64>"}`.
Bundle JSON contains `version`, `device_id`, `issued_at`, `not_after`,
`inventory_yaml`, `policy_yaml`, and `identities` (names mapped to SSH public keys).
Sign the exact JSON bytes prefixed with `agentssh-bundle\0`. No format selector is
present. `version` is the per-device, monotonically increasing configuration
revision; restoring historical content must advance it. This is configuration
ordering, not a protocol version.

The client rejects incorrect signatures/device IDs, configuration rollback and
expired bundles. A fresh cache is reused for 60 seconds; a network failure may
use a cached bundle only until its expiry (10 minutes by default). An authenticated
refusal never uses cached configuration. A non-protocol HTTPS ingress 502, 503 or
504 counts as unreachable, allowing only the same unexpired cache grace. A valid
protocol error (nonempty `code` and `error`) remains a refusal regardless of HTTP
status; other invalid responses fail closed. Cache grace does not provide offline
SSH signatures. Managed hosts require `addr`, `user`,
`identity` and native transport. Local inventory edits, discovery, local SSH
credentials and connection reuse are disabled. Local policy contributes deny
rules only; once/session approvals remain local.

`POST /sign` accepts `{"host":"web-1","data":"<base64 RFC 4252 userauth bytes>"}`.
Validate the assigned host, user, identity key, algorithm and complete authentication
structure. Refuse revoked devices and disabled identities. Return
`{"sign_id":"sg_...","format":"ssh-ed25519","blob":"<base64 raw signature>"}`.
Commit signing audit before returning a signature; logging failure refuses signing.
Each SSH command needs a new connection and signature. Running commands check
device standing every 30 seconds and cancel on definitive revocation.

Use error responses `{"code":"...","error":"..."}`; revoked devices return
`device_revoked`. Device status and replay state must use authoritative storage.
Concurrent revocation and authentication are ordered by the authorization
transaction; already authorized signatures cannot be recalled.

For config-center, resolve an assignment/channel to one fixed published release
per operation, read both YAML files from it and maintain the device's configuration
revision. Never sign from drafts. This repository provides the protocol and
reference implementation; it does not implement or deploy the config-center plugin.

## State replacement and interoperability

Existing enrollment records, tokens and server databases are not migrated. Create
a fresh reference-server data directory, initialize it and reinstall its identity
public keys as appropriate. Operators run `remote leave`, then enroll with a fresh
token. Unexpected enrollment fields are rejected. No fallback paths remain.

`internal/remote/testdata/https.json` contains independently generated Web Crypto
vectors for request, bundle and SSH authentication signatures, using a public
RFC 8032 test seed. Go tests verify all three. Independently verify with Node >=20:

```sh
node scripts/verify_https_vectors.mjs
```

Acceptance covers real HTTPS enrollment and SSH connections, pins, redirects,
configuration signature/expiry/rollback, device and identity revocation, in-flight
cancellation, and durable replay rejection under concurrency and database reopen.
Execution and verification are recorded in [the execution plan](../plans/https-control-plane.md).
