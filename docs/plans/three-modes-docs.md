# Docs for the three modes (#21)

> Status: done · Issue: [#21](https://github.com/Praeviso/AgentSSH/issues/21) · Epic: [#11](https://github.com/Praeviso/AgentSSH/issues/11)

## Goal and acceptance

Readers choose between local, managed and gateway from the README, knowing what
each protects against and what it does not, and enroll in the one they chose.
The gateway's design as built, with each sub-task's trade-offs, is recorded in
one place.

Done when:

- The README compares the three modes, says what each protects against and
  what it does not, and shows how to set up and enroll in each. It says that a
  gateway must reach the target hosts and is the single point of execution,
  and that `remote enroll --mode` must match the control plane.
- `docs/architecture/gateway-mode.md` records the design as implemented and
  the trade-offs of #12, #14–#17, #19 and #20.
- `docs/architecture/remote-control.md` has a threat-model table with a column
  per mode.
- `skills/agentssh-usage/SKILL.md` is checked across the three modes.
- Every command example in the new docs runs against a test control plane.

## Findings before writing

- `remote-control.md` has no threat-model table to extend; the only one is in
  `overview.md` §11 (Chinese, local mode only). The new table goes in
  `remote-control.md`, and `overview.md` §11 points to it.
- Release archives contain `agentssh` and `agentssh-server` but not
  `agentssh-gateway` (#14 deferred it until gateway mode worked end to end,
  which it now does). The README's gateway install would not work, so the
  release build adds it.
- The skill does need a change. In gateway mode `policy test`,
  `session grants` and `audit show|verify` exit 2 with a hint naming the
  gateway's administrator, and the skill's status router tells the agent to
  stop on hints that name the control plane. An agent would abandon its task
  over an optional check. The fix stays mode-neutral: those inspection
  commands may be unavailable on a device, which does not block the task.

## Progress

- [x] README: "Choose a mode" (comparison table, what each mode protects
  against and what it does not, when to choose it, the `--mode` rule), then
  "Managed mode" and "Gateway mode" sections with setup, enrollment, operator
  decisions, the Web UI, audit and revocation.
- [x] `docs/architecture/gateway-mode.md`: why the mode exists, components,
  trust boundaries, design and trade-offs per sub-task, limits.
- [x] Threat-model table in `remote-control.md` (ten threats × three modes);
  `overview.md` §11 points to it.
- [x] Release build adds `agentssh-gateway`; it cross-compiles for the four
  release targets and takes the version from `-X main.version`.
- [x] Skill: the "stop when a hint names the control plane" row now covers
  `run`, `plan` and `status` only, and a note says `policy test`,
  `session grants` and `audit` may be refused with exit 2 on some devices,
  which is not a blocker.
- [x] Doc commands run as written against real binaries: `agentssh-server`
  and `agentssh-gateway` behind a TLS ingress that preserves the path, and a
  test SSH target trusting both control planes' identities (a throwaway
  harness outside the repository). Checked:
  - gateway: `init`, `identity create`, `serve` (with `--web-listen
    --web-origin`), `device token create`, enrollment refused without
    `--mode gateway` (token not spent) then accepted, `config push`, `hosts`,
    allowed run (0), deny (6), gray zone (7), `approval ls`,
    `approval grant --session`, `approval wait` (0), rerun (0), a local
    `policy.yaml` allowing everything changing nothing, `policy test` refused
    (2), `plan submit`, `plan show`, `plan grant --session`, `plan wait`,
    `plan run` (0), `approval deny`, `operator add|ls`, the Web UI login page,
    `device ls`, `audit verify`, `device revoke` (next run refused);
  - managed: `init`, `identity create`, `serve`, `device token create`,
    enrollment refused with `--mode gateway` (token not spent) then accepted
    by default, `config push`, `remote status`, allowed run (0), deny (6),
    `log`.
- [x] Found while writing: revoking a gateway device refuses its next request,
  but a run already started continues until it finishes or `--exec-timeout`.
  Documented in the threat model and in gateway-mode.md's limits.
- [x] Final validation.

## Validation

```
gofmt -l .
go vet ./...
golangci-lint run
go test -race ./...
scripts/e2e_tui_audit_run_summary.sh --no-tui
```

Plus the doc commands, run as written against the test control planes.
