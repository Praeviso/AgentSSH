# An OAuth 2.1 authorization server for token devices (#45)

> Status: done · Issue: [#45](https://github.com/Praeviso/AgentSSH/issues/45) · Canto: [#44](https://github.com/Praeviso/AgentSSH/issues/44) · Epic: [#35](https://github.com/Praeviso/AgentSSH/issues/35)

## Goal and acceptance

MCP clients that connect only through OAuth 2.1 get access tokens for the
gateway's MCP endpoint from the gateway itself. An operator's consent binds
the client to one token device (the grant); access tokens are short-lived and
are issued and accepted only while that device is active.

Done when:

- A test runs the authorization code flow with PKCE, refresh rotation (a
  reused refresh token revokes the grant), revocation, and refusal while the
  device is inactive.
- A test checks the discovery metadata is what an MCP client needs to start
  the flow.

The consent page and browser flow are tracked in
[#46](web-oauth-consent.md): here the authorization request is parsed and
validated, and consent is a function the page calls.

## Decisions (the issue's preparation)

- **Client registration: dynamic (RFC 7591), open.** Every MCP client that
  supports OAuth falls back to dynamic registration when the server offers it,
  and platforms such as hosted agents use it; pre-registration would need a
  per-platform setup step. Registration is unauthenticated, as MCP clients
  expect, so it grants nothing: a client is only a name and redirect URIs,
  and only an operator's consent creates a grant. Redirect URIs must be HTTPS,
  or HTTP on a loopback address (any port, RFC 8252); no custom schemes. A
  client no grant was made for is deleted an hour after it registered, and at
  most 1000 such clients exist at once, so open registration cannot fill the
  database. Client ID metadata documents are not offered: they would make
  the gateway fetch URLs that anyone names.
- **Token format: opaque, stored hashed.** As device tokens: a random secret
  with a recognizable prefix (`agc_` codes, `ago_` access tokens, `agr_`
  refresh tokens), only its SHA-256 stored. Revocation and the device's
  standing apply at once, which a signed token would not give without a lookup
  anyway.
- **Lifetimes.** Authorization codes 5 minutes, single use. Access tokens one
  hour, never past the device's activation window. Refresh tokens 30 days,
  rotated on every use; a reused one revokes the grant. The grant itself does
  not expire: it is the long-lived, revocable part.
- **Where the endpoints live.** The issuer is the gateway's public URL. The
  token and registration endpoints are under it, since the platform's servers
  call them; the authorization endpoint is the Web UI's `/oauth/authorize`,
  since only the operator's browser visits it. OAuth is offered only when the
  gateway knows the Web UI's origin (`--web-origin`).
- **Audience.** Access tokens are for the MCP endpoint (RFC 8707 resource
  `<public-url>/mcp`) and accepted only there, not on `/api`.
- **Inactive device.** The token endpoint refuses (`invalid_grant`, saying the
  device is not activated) without consuming the code or refresh token, so the
  client can try again once an operator activates the device; `/mcp` answers
  403 `device_inactive`, as for device tokens, which does not send a client
  back through authorization.

## Approach

- Schema (`oauth.go`): `oauth_clients`, `oauth_grants` (client, device,
  scope, who consented, revocation), `oauth_tokens` (code, access and refresh,
  hashed, with expiry and use; a code keeps its redirect URI and PKCE
  challenge).
- Discovery: `<public-url>/.well-known/...` is not where clients look, so the
  well-known URIs are served at the origin's root with the path inserted
  (RFC 9728 for the protected resource, RFC 8414 for the authorization
  server); a 401 from `/mcp` names the resource metadata in
  `WWW-Authenticate`. `controlplane.OpenRoute` gains `Root`.
- `/oauth/register`, `/oauth/token` are open routes. Public clients
  (`none`) and confidential ones (`client_secret_basic`/`_post`, secret
  hashed); PKCE S256 for all.
- `ParseAuthorization` validates an authorization request (client and
  redirect URI first, refused without redirecting when wrong; the rest
  answered as redirects); `Authorize` records the grant for a token device
  and returns the redirect with code, state and `iss`; `Deny` returns the
  `access_denied` redirect.
- Bearer check: an `ago_` token on `/mcp` authenticates as its grant's
  device; audit records carry `grant_id` (new field) instead of `token_id`.
- Audit (gateway chain): `oauth_grant_created` (consent),
  `oauth_refresh_refused` (a known refresh token refused: inactive device,
  reuse, revoked grant), `oauth_grant_revoked` (operator, reuse of a code or
  refresh token).
- CLI: `agentssh-gateway oauth ls` and `oauth revoke <grant>`.

## Progress

- [x] Store, metadata, registration, token endpoint, bearer check.
- [x] Authorization request parsing and consent functions; CLI.
- [x] Tests (`internal/gateway/oauth_test.go`): discovery from the first 401
  through both metadata documents, with the base's path inserted, and none of
  it without `--web-origin`; the code flow with PKCE (wrong verifier, another
  client, another redirect URI or resource, an unknown client refused; a
  resource with another case or a trailing slash accepted), a run through the
  access token audited with the grant, the access token refused on `/api`, a
  reused code revoking the grant only with its verifier (without it, refused
  and nothing changes); refresh rotation and reuse revoking every
  token of the grant; revocation by an operator and of the device; refusal
  while inactive without consuming the code or refresh token, and the access
  token capped at the window; expiry of codes and access tokens;
  registration (redirect URI rules, confidential clients by Basic and form,
  loopback ports, the cap and ageing of unconsented clients); authorization
  request refusals with and without redirect, and denial.
- [x] Mutation checks: skipping PKCE, accepting access tokens on `/api`,
  issuing while inactive, no window cap, accepting a revoked grant's token,
  accepting any redirect URI each fail a test; ignoring refresh token reuse
  fails a test once the used-token guard in the rotation is removed too
  (either one alone catches it).
- [x] Live check with the official TypeScript SDK 1.32.2 through a TLS ingress
  with a path prefix: it discovered the metadata from the 401, registered,
  built the authorization request (PKCE, state, resource, scope), and, after
  consent by `Authorize` (standing in for #46's page), exchanged the code,
  negotiated 2025-11-25 and ran a command; its refresh rotated the tokens; a
  reused refresh token revoked the grant and the SDK went back to
  authorization. `audit verify` passed, and `oauth ls`/`revoke` showed and
  revoked grants.
