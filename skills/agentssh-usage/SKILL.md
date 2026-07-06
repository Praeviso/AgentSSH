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

2. **Open one session for the task.** A `run` requires a declared session, and one task = one session keeps the audit trail reviewable as a unit. Mint one id at the start of the task:

   ```bash
   agentssh session new                              # prints an id, e.g. s_1a2b3c4d
   ```

   Remember the id and pass it explicitly on every run in the task:

   ```bash
   agentssh run web-1 --session s_1a2b3c4d --json -- <cmd...>
   ```

   Do **not** mint a new id per command — that fragments the task's audit trail. If your shell persists environment variables between commands, `export AGENTSSH_SESSION=$(agentssh session new)` also works; most agent harnesses run each command in a fresh shell, so the explicit `--session` flag is the reliable form.

   Optionally label the task on its first run: `--session-label "fix 502 on web-1"`.

3. **Pre-check commands with `policy test` before sending them.** It predicts the exact runtime verdict — `allow`, `deny`, or `needs-approval` — without executing anything or creating approval requests. Use it whenever you are not certain a command is already allowed, and pre-check a whole batch before starting a multi-step change so every approval need surfaces up front instead of one costly round-trip at a time:

   ```bash
   agentssh policy test --host web-1 'systemctl status nginx'
   agentssh policy test --host web-1 'docker compose -f /opt/app/compose.yml up -d'
   ```

   A `deny` verdict is final — don't send that command at all. A `needs-approval` verdict tells you to bundle it into a plan or flag it to the operator before you begin.

4. **Diagnose read-only first.** Inspect before you change anything — status, logs, metrics. Keep output bounded (`-n`, `head`, `--no-pager`); large dumps get truncated and waste context.

5. **Act only after summarizing.** Before a state-changing command (restart, reload, write, delete), state what you found, the risk, and the exact command. Rely on the harness/operator confirmation flow for the go-ahead.

6. **Review via audit.** Hand back the session id and key request ids so the operator can replay the task. A run's `req_id` appears in its `--json` response and in `audit ls`; the human-readable run output omits it.

   ```bash
   agentssh audit ls --session s_1a2b3c4d
   agentssh audit show <req_id>
   ```

   Group runs record one derived session per host (`s_1a2b3c4d@web-1`); filtering by the base id matches all of them. The operator can also browse the same data with `agentssh tui`.

## Practices that matter

- **Policy is the safety boundary, not a suggestion.** Exit `6` is final — do not retry the same command, reword it, or look for a syntax that slips past. It means a hard deny or disabled gray-area approval path blocked the command.
- **Never self-approve.** You may read `approval status` / `approval wait` and `plan status` / `plan wait`, but you must never run `approval grant`, `approval deny`, `plan grant`, `plan deny`, edit policy, write approval files, or otherwise approve your own command. If a run returns exit `7`, surface the approval id and exact command to the operator, wait for the operator's decision, then rerun the same command only after approval.
- **One session per task.** Don't reuse a previous task's session id, and don't share one session across unrelated tasks — that merges them in the audit trail. Start a new task → mint a new id.
- **Bounded, relevant output.** Prefer targeted commands (`systemctl status`, `journalctl -n`, `ps --sort`) over broad recursive scans. Output filtering may redact secrets and truncate length before results reach you; treat `«REDACTED»` and truncation as expected.
- **Prefer `--json` on `run`.** The structured response carries `req_id`, `approval_id`, `redactions`, and `output_truncated`, none of which appear in the human-readable output. Parse it instead of scraping text.
- **`policy test` before `run`, and read its verdict on stdout, not via exit code.** Pre-checking is free and saves whole approval round-trips; skipping it means discovering `needs-approval` one command at a time. It prints `allow`, `deny`, or `needs-approval` and exits `0` in all three cases — never chain it as `policy test ... && run ...`.
- **No destructive exploration.** Never run recursive deletes, mass `kill`, or cleanup as part of diagnosis. If the task needs them, propose them explicitly and let policy + the operator gate it.
- **Read exit codes, don't fight them.** `0` ok · `1` remote command failed · `2` usage (e.g. no session declared, missing `--`) · `6` policy denied/final · `7` approval required or still pending · `9` connection failed. A `9` means fix connectivity/inventory, not retry blindly.

## Async approval flow

When optional approval is enabled, a gray-area command that hits `default-deny` returns immediately with exit `7`. Without `--json`, the approval id and candidate matcher are printed on stderr; with `--json` (preferred) the body looks like:

```json
{
  "req_id": "a1b2c3",
  "session_id": "s_1a2b3c4d",
  "host": "web-1",
  "cmd": "systemctl status nginx",
  "status": "approval_pending",
  "exit_code": 7,
  "approval_id": "ap_0123456789abcdef01234567"
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

### Plan approvals — one review for a multi-step task

When a task needs several gray-zone commands, do not submit them one at a time — that costs one operator round-trip per command. Bundle them into a plan:

```bash
agentssh plan submit web-1 --session s_1a2b3c4d --json -- \
  'mkdir -p /opt/app/releases' \
  'docker compose -f /opt/app/compose.yml pull' \
  'docker compose -f /opt/app/compose.yml up -d'
```

Each quoted argument is one complete command (`--file cmds.txt` also works, one command per line). Already-allowed commands are reported as `allowed`; hard-denied ones as `denied` (final — drop them); the rest become one pending approval each under a single `plan_id`. The operator reviews the batch once (TUI `[p]` or `agentssh plan grant <plan_id> --once|--session`), which mints one exact-match grant per command. Then:

```bash
agentssh plan wait <plan_id> --timeout 10m    # 0 all approved · 6 any denied · 7 still pending · 2 records expired (re-submit)
agentssh run web-1 --session s_1a2b3c4d --json -- <cmd...>   # run each command as usual
```

(A plan queried long after resolution can report `expired` with exit `2` once its approval records are reaped — that is not a denial; re-submit the plan.)

Execution still happens per command through `run` with full per-command audit; a plan never bypasses explicit deny rules. Submit the plan with the same `--session` you will run under — the grants are bound to that session.

### Sending stdin — config files without quoting pain

`run --stdin-file <path>` streams a local file (up to 32 MiB) to the remote command's stdin, replacing fragile `printf`-quoting and oversized inline arguments:

```bash
agentssh run web-1 --session s_1a2b3c4d --json --stdin-file nginx.conf -- tee /etc/nginx/nginx.conf
```

The content never enters the approval store or audit log — both record only `stdin_sha256` + `stdin_bytes`. A stdin approval is pinned to the exact content hash: change the file and the same command needs a fresh approval, so re-run with byte-identical content after approval.

## Command reference

```bash
agentssh hosts [--json]                              # list targets (names + tags only; no credentials)
agentssh session new                                 # mint a fresh session id for a task
agentssh session ls                                  # recent sessions (id / label / span / command count)
agentssh run <host|group> [--session <id>] [--session-label <text>] [--stdin-file <path>] [--json] [--fields a,b,c] -- <cmd...>
agentssh status <req_id> [--json]                    # look up a past run's result (exit / denied)
agentssh approval status <approval_id>               # read approval result: 0 approved, 6 denied, 7 pending
agentssh approval wait <approval_id> [--timeout 10m]  # wait for approval result, never grants approval
agentssh plan submit <host> --session <id> [--json] -- '<cmd>' '<cmd>'...  # bundle gray commands into one review
agentssh plan status <plan_id> | wait <plan_id> [--timeout 10m]            # 0 approved, 6 denied, 7 pending, 2 expired
agentssh audit ls [--session <id>] | show <req_id> | verify   # browse / inspect / verify the hash chain
agentssh policy test --host <host> '<cmd>'           # static check; verdict on stdout (allow/deny/needs-approval), exits 0 either way
agentssh tui                                         # interactive audit + policy viewer (operator-facing)
```

Large-output note: `run --json` truncates the echoed `cmd` field at 2 KiB (`cmd_truncated: true`, full command stays in the audit log; correlate via `cmd_sha256`). Use `--fields req_id,status,exit_code,stdout` to keep responses small when you only need a few fields.

The command after `--` is sent verbatim as one remote command. Bind every run in a task to the same session (via `--session <id>`, or `$AGENTSSH_SESSION` in a persistent shell) so audit groups them by task.
