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
registers only `/enroll` and `/status` (mode `gateway`), plus its own `/exec`:
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
The gateway mints an ID when none is sent. Its frames,
`type:1 | length:4 big-endian | payload`, are spooled under `runs/<device-id>/<id>/`:
stdout (1) and stderr (2) data frames of at most 64 KiB, sent only when the
request asks to stream a single-host run; then one response frame (5) per
target with its `run --json` object; then a result frame (3,
`{exit_code, truncated}`). An error frame (4, `ErrorResponse`) may replace
everything after the data frames. Response, result and error frames are at most
16 MiB: the gateway caps each stream's output at 1 MiB unless the policy's
`output.max_bytes` is lower (applied before auditing, so the audit hash covers
what is returned), which keeps a response within one frame even when JSON
escapes every byte.

Every `/exec` and `POST /exec/attach {run_id, offset}` response starts with a
run frame (6, `{run_id}`) followed by the spool from the offset, following a
live run until its final frame. The run does not depend on the connection: a
dropped request only detaches the device, and the client reattaches from the
byte offset of the complete frames it has consumed, so every frame arrives
exactly once and the command runs once. Only `POST /exec/cancel {run_id}` or
`serve --exec-timeout` (default 30m) stops a run. A cancel for an ID the
gateway has not seen answers `cancelled: false` and refuses that request for
10 minutes (`409 run_cancelled`), since a cancel can overtake its own request; the gateway then sends the
remote command `SIGTERM` before closing the SSH connection. A device's
concurrency slot is held until its run finishes.

Runs belong to the device that started them; another device's, unknown, and
expired runs are all `404 run_not_found`. Finished runs stay reattachable for
`serve --run-retention` (default 24h); a run left unfinished by a gateway
restart is `410 run_interrupted` (its outcome is in the audit). Each run keeps
at most `serve --run-max-bytes` (default 64 MiB) of frames, holding back 16 KiB
per target: output beyond it is dropped, responses that no longer fit lose
their output (`output_truncated`), and the result says `truncated: true` with
the exit code raised to at least 1, so a partial result never passes for a
complete one. A device keeps at most `serve --run-quota-bytes` (default
512 MiB) of finished runs: before a new run starts and again when one finishes (runs that start
together each see the same free space), its oldest runs are evicted
(and then answer `run_not_found`). With the concurrency limit, one device
occupies at most quota + `--max-concurrent` × `--run-max-bytes` on disk. The request must arrive within the 60 s proof lifetime;
ingresses must stream responses (the gateway sends `X-Accel-Buffering: no`).

Every run is recorded in one hash chain per gateway, `audit.jsonl`, with
`device_id` on each record (`agentssh-gateway audit verify`). Pending approval
requests live under `devices/<id>/approval/`; operator decisions, the client
side and the full design follow in #17, #19, #20 and
`docs/architecture/gateway-mode.md`.

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
client generates an Ed25519 key and sends JSON:

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
has exactly `server_url`, `device_id`, `bundle_public_key`, `enrolled_at`. Failed
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
