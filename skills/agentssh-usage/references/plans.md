# Plan submission, execution, and recovery

## Structured commands

A plan targets one host. Each entry has exactly one of `cmd` (shell text) or
`argv` (literal arguments), plus optional `cwd`, `id`, `name`, `phase`,
`on_failure`, and either `stdin_file` or `payload_ref`:

```yaml
version: 1
metadata:
  title: Reviewable deploy
  revision: abc123
commands:
  - id: upload-config
    name: Upload config
    phase: apply
    on_failure: stop
    cmd: tee /opt/app/app.conf
    stdin_file: ./app.conf
  - id: start-app
    argv: [docker, compose, -f, /opt/app/compose.yaml, up, -d, app]
    cwd: /opt/app
  - id: verify-app
    phase: verify
    on_failure: continue
    argv: [docker, compose, -f, /opt/app/compose.yaml, ps, app]
    cwd: /opt/app
```

`cwd` is an absolute remote path, not filesystem isolation. `stdin_file` names a
local regular file; relative paths use the CLI's working directory. Include it
in the initial plan so approval binds the command and stdin hash together.
Preserve its bytes for resume, or use the retention workflow in
[payloads.md](payloads.md).

`metadata.description`, step `name`, and other submitter descriptions help the
operator review intent. They are not parsed facts and do not authorize anything
by themselves; AgentSSH still authorizes the parsed command, cwd, stdin identity,
and task profile.

Steps default to `phase: apply` and `on_failure: stop`. Use `phase: verify` with
`on_failure: continue` only for independent checks: each failure is recorded,
later checks can run, and the overall execution still finishes failed. Keep
upload, apply, build, and start steps on `stop`.

## Execute and continue

Use actual returned IDs in place of these examples:

```bash
agentssh plan run web-1 --session s_TASK --file plan.yaml --wait-approval 30s --json
agentssh plan execution px_EXECUTION --json
agentssh plan wait pl_APPROVAL --timeout 30s --json
agentssh plan resume px_EXECUTION --wait-approval 30s --json
```

`plan run` batches required approvals before starting and reauthorizes each
sequential step. Pending returns exit 7 and a saved `execution_id` (`px_...`).
Use it for progress/resume; `approval_plan_id` (`pl_...`) tracks the batch
decision through `plan status/wait`, not execution.

While pending, follow the returned `next_action` to observe the existing batch.
Use `plan inspect pl_APPROVAL --json` for its immutable review. Once approved,
resume the same execution; authorization is checked again before each step.

Resume uses the saved snapshot and skips completed steps. Source YAML edits do
not change it. Repeating `plan run` creates a new execution and may repeat
effects. Failed or unknown steps cannot resume; interruption during execution
counts as unknown. Inspect results before creating a new plan for the remaining
work.

Use `plan run/resume --events` for filtered, bounded JSONL on stdout instead of
the final `--json` result. It remains in the foreground; there is no background
daemon. Observe without executing with `plan execution px_EXECUTION --follow
--timeout 30s`; add `--after-seq N` to continue from an event cursor. `--events`
and `--follow` each exclude `--json` on their respective commands.

## Approval-only batching

```bash
agentssh plan submit web-1 --session s_TASK --file plan.yaml --json
```

This never executes. Stop here when only submission was requested. If execution
is subsequently requested, use the same commands, payloads, and session with
`plan run` or individual `run` calls to reuse valid grants.

## Older CLIs

For older CLIs lacking `plan run/resume`, use supported `plan submit` and
individual `run` calls, tracking completed effects yourself. If `argv/cwd` is
also absent, use equivalent quoted `cmd` strings for both approval and execution.
