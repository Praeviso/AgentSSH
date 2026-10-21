# Hosted HTTPS control-plane protocol (v2)

This protocol lets a hosted service (including a config-center Worker) implement
the AgentSSH control plane without running the Go server or terminating a private
CA's mTLS. The Go server is a reference implementation. The client authenticates
the service with ordinary HTTPS and pins the bundle key from its enrollment token.
The service authenticates each device through an Ed25519 HTTP message signature.
TLS remains mandatory on the public endpoint. The existing v1 private-CA/mTLS
protocol stays separate: no discovery, fallback or automatic downgrade occurs.

## Deployment and endpoint base

An administrator chooses a canonical public HTTPS base, for example
`https://config.example/v1/plugins/agentssh`. The base may include a path prefix;
it must not include credentials, a query, fragment, escaped path, dot segments or
empty path segments. Prefix segments use unreserved ASCII letters, digits,
`-._~`. Trailing slashes are removed. Append these literal paths:

| Method | Suffix | Authentication / response |
| --- | --- | --- |
| POST | `/v2/enroll` | Single-use token + new device key's proof of possession |
| GET | `/v2/status` | Device proof; existing status response |
| GET | `/v2/bundle` | Device proof; existing signed bundle envelope |
| POST | `/v2/sign` | Device proof; existing SSH userauth request/response |

Query parameters and redirects are not supported. A TLS-terminating deployment
must configure its verifier with its external HTTPS base; never derive the
signature target from client-supplied `Forwarded` / `X-Forwarded-*` headers. Keep
the origin private to the HTTPS ingress. The reference handler mounts the full
prefix, so the reverse proxy preserves the request path.

Reference server behind an ordinary HTTPS reverse proxy:

```sh
agentssh-server serve --listen 127.0.0.1:8080 --http \
  --public-url https://cp.example/agentssh
agentssh-server device token create --name laptop \
  --public-url https://cp.example/agentssh
agentssh remote enroll https://cp.example/agentssh --token '<token>'
```

Use `init`, `identity create`, `config push` and `device revoke` as before. In v2
mode the server exposes only the v2 endpoints; HTTP never exposes the v1 APIs.
Without `--public-url`, `serve` keeps the existing mTLS behavior. `--http` requires
`--public-url`. Serving the reference API directly over TLS is also possible but
its certificate must be trusted by the client's system trust store.

## Enrollment token and messages

```text
agentssh-enroll.v2.<id>.<secret>.<bundle_fingerprint>.<encoded_base>
```

- `id`: 1–80 ASCII letters, digits, `_` or `-` (reference IDs start with `et_`).
- `secret`: unpadded base64url of 32 random bytes. Store only its SHA-256 digest.
- `bundle_fingerprint`: lowercase hex SHA-256 of the raw 32-byte Ed25519 bundle
  public key. This is a bundle-key pin, not a TLS certificate fingerprint.
- `encoded_base`: unpadded base64url of the UTF-8 canonical public HTTPS base.

The supplied enrollment URL must match the token's base before sending anything.
The client generates an Ed25519 device key and sends JSON:

```json
{"token_id":"et_...","token_secret":"...","public_key":"<standard padded base64 raw 32-byte Ed25519 public key>"}
```

Sign this request using the new device private key, the token ID as `keyid`, and
the enrollment tag below. Verify this proof before consuming the token. Atomically
consume a nonexpired token bound to this exact public base, create the device and
persist its public key. Return:

```json
{"device_id":"dev_...","bundle_public_key":"<standard padded base64 raw 32-byte Ed25519 key>"}
```

The client checks the returned bundle-key fingerprint against the token, then
stores the device key (PKCS#8 PEM, 0600) and an enrollment marker (0600), written
last. No device certificate or private CA is needed. A failed pin check never
activates remote mode; a consumed token is not reused automatically. Issue a new
token if enrollment must be repeated after a lost response or local write failure.

## Request signature profile

Use the following narrow profile of [RFC 9421](https://www.rfc-editor.org/rfc/rfc9421.html),
not a general-purpose signature negotiation mechanism. Sign the raw body bytes,
including an empty body on GET. `Content-Digest` uses the RFC 9530 SHA-256 form:

```text
Content-Digest: sha-256=:<standard padded base64 SHA-256 of raw body>:
Signature-Input: agentssh=("@method" "@target-uri" "content-digest");created=<unix>;expires=<unix>;nonce="<nonce>";keyid="<id>";alg="ed25519";tag="agentssh-device-v2"
Signature: agentssh=:<standard padded base64 Ed25519 signature>:
```

The three covered components and the parameter order above are exact. Require
one value of each header; reject additional signature labels, duplicate headers,
unsupported parameters and algorithm choices. `keyid` uses the token ID at
enrollment and the device ID afterwards. `tag` is `agentssh-enroll-v2` only for
enrollment; all other operations require `agentssh-device-v2`.

`nonce` is unpadded base64url of 32 fresh random bytes. `expires > created`, the
lifetime is at most 60 seconds, `expires` must be strictly after server time, and
`created` may be no more than 30 seconds ahead of server time. Synchronize clocks.

The UTF-8 signature base has exactly four lines and no final newline:

```text
"@method": POST
"@target-uri": https://config.example/v1/plugins/agentssh/v2/sign
"content-digest": sha-256=:...:
"@signature-params": ("@method" "@target-uri" "content-digest");created=...;expires=...;nonce="...";keyid="dev_...";alg="ed25519";tag="agentssh-device-v2"
```

The target is the full configured public HTTPS URI, including prefix. HTTP method,
target, body digest and all signature parameters are authenticated. JSON key order
is irrelevant to parsing but changing any raw JSON byte invalidates its signature.

After verification, check device standing on every request and atomically claim
`(device_id, nonce)` in durable storage, rechecking active status in that write.
Keep the nonce until `expires`; process-local caches are insufficient. Enrollment
uses the token's single-use transaction instead. An unavailable replay store must
refuse requests. The reference server bounds bodies at 64 KiB and deletes expired
nonces. Hosted implementations must enforce equivalent bounds and cleanup.

## Reused behavior and consistency

Bundle `format: 1`, its `agentssh-bundle-v1\0` domain separator, standard-base64
envelope, YAML strings, per-device monotonic version and pin verification remain
unchanged. Sign the exact transmitted JSON bytes; clients never reserialize before
verification. Keep the existing 10-minute bundle TTL, 60-second cache window,
deny-only local overlay, no local credential fallback, fresh SSH connection per
command and device-revocation watchdog.

The SSH signing endpoint still accepts only RFC 4252 publickey authentication
data matching the device's assigned host user, identity public key and Ed25519
algorithm. Reject disabled identities. Return `sign_id`, `format: ssh-ed25519`
and standard-base64 raw signature bytes. Commit the signing log before returning
the signature; failure to log must fail closed. Signing is not command execution
audit and cannot prove the actual target beyond the existing identity trust scope.

Use existing error envelopes (`code`, `error`); revoked devices return
`device_revoked`. A protocol refusal, invalid signature or replay never permits
cached-config fallback. Only transport unavailability can use a still-valid
cached bundle. Configure active/revoked state from authoritative storage, not a
stale edge cache. Concurrent revocation and authentication are ordered by the
authorization transaction; they cannot recall a signature already authorized.

For config-center, map the assignment to a fixed published release (or resolve a
channel to one fixed release for each operation), read both YAML files from that
release, and allocate a monotonically increasing device configuration version.
Restoring historical content must advance that version. Never sign from drafts.
The v2 protocol does not implement config-center storage, UI or deployment.

## Migration and interoperability

Existing enrollment markers without `protocol` remain v1. V2 writes
`protocol: https-signatures-v2`. Unknown protocols are rejected. Moving an existing
device between protocols requires operator-controlled `remote leave` and a fresh
token/enrollment; replacing just the server URL is insufficient.

`internal/remote/testdata/https-v2.json` contains independently generated Web Crypto
vectors for a request signature, signed bundle and SSH authentication signature.
The public key uses the published RFC 8032 test seed; these are public test keys.
Go tests verify all three. Independently verify with Node >=20:

```sh
node scripts/verify_https_vectors.mjs
```

A hosted implementation must additionally test atomic token redemption, durable
replay under concurrency/restart, device and identity revocation, audit failure,
bundle rollback/expiry and the actual AgentSSH-to-SSH connection path.
