# Activate and deactivate devices in the Web UI (#38)

> Status: done · Issue: [#38](https://github.com/Praeviso/AgentSSH/issues/38) · Parent: [#36](https://github.com/Praeviso/AgentSSH/issues/36) · Epic: [#35](https://github.com/Praeviso/AgentSSH/issues/35)

## Goal and acceptance

Operators away from the gateway host open and close devices' activation
windows (#37) from the Web UI, for example from a phone when an agent needs
the gateway.

Done when:

- A signed-in operator who passed TOTP activates a device for a chosen
  duration with an optional note, and deactivates it; both need the CSRF token
  and a same-origin request, and are audited as `web:<operator>`.
- Without a duration, or with one the gateway refuses, nothing changes.
- Activating from the page makes the device's next request succeed;
  deactivating refuses it.
- The page is checked in a browser at desktop and phone widths.

Scope notes against the issue:

- "Kind (signed or token)": token devices arrive with #40, so every device is
  signed now and a column of one value would be noise; #40 adds the kind.
- "Last use": the gateway keeps no last-request time, so the page shows "last
  activity", the time of the device's latest own audit record (started,
  completed, failed, denied, approval requested).
- Durations: presets 30m, 1h, 4h, 8h and 24h, within the store's 1m–24h rule
  (#37 replaced `--max-activation` with that fixed rule).

## Approach

- `GET /devices`, `POST /devices/{id}/activate` (`for`, `note`),
  `POST /devices/{id}/deactivate`, all behind `withSession(StageActive)`; the
  nav gains Devices. Results come back as the page's notice or error banner, as
  decisions do.
- One card per device: active first, then inactive, then revoked; a state pill
  (Active · time left, Inactive, Revoked); ID, enrollment and last activity;
  for an active device the end, who activated it and the note. The form's
  duration select starts on a disabled "Choose…", so the browser requires a
  choice; the server refuses a missing or unaccepted one anyway. Deactivate asks
  for confirmation. Revoked devices offer nothing.
- The Web UI opens, closes and shows windows at the system clock
  (`activationNow`), which the device API checks them against, not at the
  Web UI's own clock, which tests move to step TOTP codes.
- `Remaining` moves from the CLI into the gateway package, shared by
  `device ls` and the page.
- Audit page: activation records show "until <end> · <note>" in the command
  column; the decision column no longer starts with a stray separator when a
  record has an operator but no scope.

## Progress

- [x] Handlers, template, styles, nav.
- [x] Tests: the end-to-end flow (inactive device refused → activate from the
  page → device runs → page shows the window and the operator's note →
  deactivate → refused; audit names `web:alice`; audit page shows the note);
  the guards (anonymous, password-stage session, no CSRF token, no duration,
  too long, too short, not a duration, note too long, unknown device, revoked
  device, and a revoked device's card offering no activation).
- [x] Browser check (playwright-cli, Chromium) on a live gateway with an
  active, an inactive and a revoked device: desktop 1280×800 and phone
  390×844, light and dark; activating with the browser refusing an empty
  duration; deactivating through the confirm dialog. Found and fixed: the
  intro text was two lines of explanation (now one sentence); the audit
  page's decision column showed "· web:alice" for activation records.
- [x] Docs: README, remote-control.md, gateway-mode.md.
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
Mutation checks, each failing its test: activation routed for any session
stage (a password-stage session activated a device); no bound on the note;
windows closed at the Web UI's clock instead of the system clock (the device
still ran after deactivation); the operator not recorded.
