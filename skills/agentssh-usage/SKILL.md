---
name: agentssh-usage
description: How to operate managed servers through AgentSSH — the trust boundary, session discipline, policy, output, and audit. Load this before running any `agentssh` command against a host.
---

# Operating Servers with AgentSSH

AgentSSH is the only way you touch managed hosts. You call `agentssh`; the CLI resolves the host, checks policy, filters output, and records every command to a tamper-evident audit log. This is the manual for using it well — it is **not** a runbook for any specific task. Apply these practices to whatever the operator asks.

## Trust boundary

- You only ever call `agentssh hosts` and `agentssh run`. You never see addresses, keys, or passwords — they stay in the operator's ssh-agent, `~/.ssh/`, and an encrypted local store.
- Do not try to SSH directly, read credential files, or reconstruct connection details. If `agentssh` can't reach a host, report that; don't route around it.

## Core loop

1. **Discover the target.** Never assume a hostname or group — confirm it:

   ```bash
   agentssh hosts
   ```

2. **Open one session for the task.** A `run` requires a declared session, and one task = one session keeps the audit trail reviewable as a unit. Mint one and reuse it for every command in this task:

   ```bash
   export AGENTSSH_SESSION=$(agentssh session new)   # e.g. s_1a2b3c4d
   ```

   Optionally label the task on its first run: `--session-label "fix 502 on web-1"`.

3. **Diagnose read-only first.** Inspect before you change anything — status, logs, metrics. Keep output bounded (`-n`, `head`, `--no-pager`); large dumps get truncated and waste context.

4. **Act only after summarizing.** Before a state-changing command (restart, reload, write, delete), state what you found, the risk, and the exact command. Rely on the harness/operator confirmation flow for the go-ahead.

5. **Review via audit.** Hand back the session id and key request ids so the operator can replay the task:

   ```bash
   agentssh audit ls --session "$AGENTSSH_SESSION"
   agentssh audit show <req_id>
   agentssh tui                       # audit grouped by session
   ```

## Practices that matter

- **Policy is the safety boundary, not a suggestion.** Exit `6` is final — do not retry the same command, reword it, or look for a syntax that slips past. It means a hard deny or disabled gray-area approval path blocked the command.
- **Never self-approve.** You may read `approval status` / `approval wait`, but you must never run `approval grant`, `approval deny`, edit policy, write approval files, or otherwise approve your own command. If a run returns exit `7`, surface the approval id and exact command to the operator, wait for the operator's decision, then rerun the same command only after approval.
- **One session per task.** Don't reuse a previous task's `AGENTSSH_SESSION`, and don't share one session across unrelated tasks — that merges them in the audit trail. Start a new task → mint a new id.
- **Bounded, relevant output.** Prefer targeted commands (`systemctl status`, `journalctl -n`, `ps --sort`) over broad recursive scans. Output filtering may redact secrets and truncate length before results reach you; treat `«REDACTED»` and truncation as expected.
- **No destructive exploration.** Never run recursive deletes, mass `kill`, or cleanup as part of diagnosis. If the task needs them, propose them explicitly and let policy + the operator gate it.
- **Read exit codes, don't fight them.** `0` ok · `1` remote command failed · `2` usage (e.g. no session declared, missing `--`) · `6` policy denied/final · `7` approval required or still pending · `9` connection failed. A `9` means fix connectivity/inventory, not retry blindly.

## Async approval flow

When optional approval is enabled, a gray-area command that hits `default-deny` returns immediately with exit `7` and a JSON body like:

```json
{
  "status": "approval_pending",
  "approval_id": "ap_0123456789abcdef01234567",
  "host": "web-1",
  "cmd": "systemctl status nginx"
}
```

Your flow is:

1. Tell the operator the `approval_id`, host, session id, and exact command.
2. Wait for a result:

   ```bash
   agentssh approval wait <approval_id> --timeout 10m
   ```

3. If approved, rerun the original `agentssh run ... -- <cmd...>` cleanly. Execution only happens on the rerun, after AgentSSH rechecks current policy.
4. If denied or exit `6`, stop. Do not rewrite the command to bypass policy.

`agentssh approval status <id>` and `agentssh approval wait <id>` are read-only and agent-safe. Their exit codes are: approved `0`, denied `6`, pending/timeout `7`, malformed or unknown id `2`.

## Command reference

```bash
agentssh hosts [--json]                              # list targets (names + tags only; no credentials)
agentssh session new                                 # mint a fresh session id for a task
agentssh session ls                                  # recent sessions (id / label / span / command count)
agentssh run <host|group> [--session <id>] [--session-label <text>] [--json] -- <cmd...>
agentssh status <req_id> [--json]                    # look up a past run's result (exit / denied)
agentssh approval status <approval_id>               # read approval result: 0 approved, 6 denied, 7 pending
agentssh approval wait <approval_id> [--timeout 10m]  # wait for approval result, never grants approval
agentssh audit ls [--session <id>] | show <req_id> | verify   # browse / inspect / verify the hash chain
agentssh policy test --host <host> '<cmd>'           # static policy check, without running it or consulting session grants
agentssh tui                                         # interactive audit + policy viewer
```

The command after `--` is sent verbatim as one remote command. Bind every run in a task to the same session (via `$AGENTSSH_SESSION` or `--session`) so audit groups them by task.
