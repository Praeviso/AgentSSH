---
name: agentssh-usage
description: Run remote diagnostics, maintenance, and deployment through AgentSSH on managed servers.
---

# Operate managed servers with AgentSSH

Complete the user's remote task through AgentSSH, which resolves hosts, enforces
authorization, filters output, and records execution. Local repository edits do
not require this remote workflow.

## Task scope and continuity

The user's request defines the work and any stopping point. Continue covered
actions under existing user authorization and AgentSSH permissions without
asking for another confirmation. A grant does not expand the requested work.
For execution tasks, carry the work through the relevant result or health check;
an approval or submitted plan alone is not completion.

Reuse the session already declared for this task. If none exists, mint one with
`agentssh session new`, then pass its returned ID as `--session` across calls.
Discover a target with `agentssh hosts --json` only when it is not already known.

Operator decisions remain in the human's TUI or authenticated operator CLI. Do
not self-approve, change AgentSSH policy or approval/execution stores to unblock
a run, or bypass AgentSSH with direct SSH or operator credentials. When blocked,
identify the operation, relevant ID, and actual missing permission; complete
independent work that remains within scope.

## Choose the execution path

- **One command or output-dependent investigation:** use `run --json`. `--argv`
  preserves literal argument boundaries; omit it for intentional shell syntax.
  `--cwd` sets an absolute remote working directory.
- **A known sequence on one host:** use `plan run`; read
  [plans.md](references/plans.md) for the file format and saved execution rules.
  Separate stages when later commands depend on inspecting earlier output.
- **Approval submission only:** use `plan submit`, which does not execute. See
  [plans.md](references/plans.md#approval-only-batching) for that workflow.

Use the actual target and task session in examples:

```bash
agentssh run web-1 --session s_TASK --argv --json -- systemctl status app --no-pager
```

Add `--wait-approval 30s` when waiting and continuing in the same call is useful.
It rechecks authorization before execution and emits one final JSON on stdout;
pending IDs go to stderr. A wait timeout remains pending, not approved.

## Read only the detail needed

- For **pending/denied results, permission reuse, or uncertain execution**, read
  [authorization.md](references/authorization.md). It covers task scope, status
  meanings, and continuation without replaying completed operations.
- For **plans, stdin uploads, or resuming an execution**, read
  [plans.md](references/plans.md). Preserve the approved command and payload
  identity across submission and execution.

Preflight is optional; use a batched `policy test` when its verdicts help decide
the next action. It includes grants but exits **0 even for deny**: inspect its
output instead of chaining `policy test && run`.

Use bounded remote output, such as `journalctl -n 100 --no-pager` or Compose
`logs --tail 100`. Keep JSON status and execution IDs needed for continuation;
use audit commands when execution evidence is missing or an audit is requested.
If a documented command is unavailable, inspect that installed subcommand's
`--help` and use the compatible path described in the references.
