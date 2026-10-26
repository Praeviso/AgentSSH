# Operators authorize OAuth clients in the Web UI (#46)

> Status: done · Issue: [#46](https://github.com/Praeviso/AgentSSH/issues/46) · Canto: [#44](https://github.com/Praeviso/AgentSSH/issues/44) · Epic: [#35](https://github.com/Praeviso/AgentSSH/issues/35)

## Goal and acceptance

An OAuth-only MCP client reaches the authorization endpoint, an operator signs
in with password and TOTP, reviews the client and requested access, and chooses
one token device. Consent returns the authorization code to the registered
callback; denial returns `access_denied`. No grant exists before explicit
consent. Devices lists each device's grants and lets an operator revoke one;
the client's next request is refused. All mutations need the existing session,
CSRF and same-origin checks and are audited as `web:<operator>`.

The device's activation remains separate: consent never activates it. Unknown,
signed and revoked devices cannot be selected. Invalid clients or callbacks
never redirect; valid OAuth errors follow the validated callback. Login may
return only to the authorization endpoint, never to an arbitrary URL.

## Approach

1. Wire the existing OAuth descriptor into the Web UI. Reuse `ParseAuthorization`,
   `Authorize`, `Deny`, `Grants` and `RevokeGrant` from #45.
2. Carry a bounded, local authorization return path through password and TOTP,
   including retry pages. Revalidate the OAuth request on consent POST.
3. Add consent and per-device grant controls. Keep the current visual system:
   background #f7f7f5, surface #ffffff, text #1d1f21, muted #5f6368,
   action #1f5fbf, danger #b3261e; system sans for forms, existing monospace
   for identifiers. Left-align client identity, access, then the required device
   choice and Authorize/Deny actions. Grant rows sit inside their device, with
   wrapping identifiers and stacked phone controls. This extends the existing
   operator workflow without introducing another dashboard or navigation item.
4. Test through HTTP: password/TOTP continuation, consent and denial, CSRF and
   origin failures, request/device validation, grant ownership and revocation,
   and the MCP/JSON approval workflow with actual Web UI decisions. Document
   setup and the trust boundary. Check actual browser forms and redirects at
   desktop and phone widths, with an OAuth MCP client.

## Progress

- Confirmed #36, #39, #43 and #45 are complete on main at 748fd1c; #46 is the
  remaining implementation item. No existing consent page or return-path
  mechanism exists. Workspace started clean; no repository agent guide exists.
- Design review: reuse the established Devices page and form hierarchy; the
  meaningful distinction is the client-to-device binding, not new decoration.
- Implemented consent, safe sign-in continuation and per-device grant history
  and revocation. CLI `serve` supplies the same OAuth issuer/resource descriptor
  to the Web UI; OAuth remains unavailable without `--web-origin`.
- Added HTTP integration coverage for sign-in retries, mandatory TOTP, CSRF and
  origin checks on both mutations, device choice, invalid requests, denial,
  inactive consent, grant ownership, revocation and its audit chain. JSON,
  static-token MCP and OAuth MCP workflows now approve through the actual
  Web UI and rerun a real SSH command successfully.
- Browser acceptance found Chromium blocking the OAuth callback under the
  existing `form-action 'self'` policy. Consent responses now allow only the
  validated callback's origin too, escaping host characters with CSP meaning;
  all other pages retain their original policy. Added regression coverage.
- User authorized branch/PR delivery; branch `feat/oauth-web-consent`.

## Validation

Passed on the final code (Go 1.25.5, `GOFLAGS=-p=2`, writable build/lint caches
under `/tmp/agentssh-issue35`):

- `gofmt -l .`, `git diff --check`.
- `go vet ./...`, `go build ./cmd/...`.
- `go test -race -count=1 -timeout=20m ./...`: all 27 packages with tests pass,
  including signed gateway devices and local/managed mode coverage.
- `golangci-lint run --timeout=5m`: zero issues.
- `node scripts/verify_https_vectors.mjs`: independent request, bundle and SSH
  signatures verified.
- Regression: an isolated Go overlay removes the callback CSP allowance;
  `TestOAuthConsentCSPAllowsOnlyItsValidatedCallbackOrigin` fails for the
  missing origin, and passes on the final code. Before the fix, Chromium also
  blocked the actual form callback with a `form-action 'self'` violation.
- Actual Chromium at 1440×1000 and 390×844: password/TOTP sign-in returns to
  consent, Authorize reaches a different-origin loopback callback, Deny reaches
  the validated callback without a device selected, Devices shows and revokes
  grants with confirmation, and audit shows both events by `web:alice` with an
  intact chain. Consent and grants have no horizontal overflow on the phone;
  final browser console has zero errors/warnings.
- Official TypeScript `@modelcontextprotocol/sdk` 1.27.0 over a TLS ingress with
  `/agentssh` prefix, using no agent-side binary: discovery, dynamic
  registration, code + PKCE, browser consent, initialization and eight tools,
  hosts, new session, allowed `uptime`, denied `reboot`, pending `uname -s`,
  approval wait while the operator decides in the Web UI, then unchanged rerun
  producing `Linux`. After Web UI revocation, the SDK's next authenticated
  connection is refused with HTTP 401. Two clients completed the flow.

Screenshots, SDK results and validation logs are local artifacts under
`/tmp/agentssh-issue35/`; the browser fixture is an external Go overlay, not
part of the shipped source. Build succeeds with a nonfatal warning that the
sandbox cannot write the module's version metadata into its read-only module
cache. No required validation is blocked. Remote CI is verified separately on
the PR's final head after publishing.
