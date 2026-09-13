# Plans, stdin, and saved execution

## Structured commands

A plan targets one host. Each entry has exactly one of `cmd` (shell text) or
`argv` (literal arguments), plus optional `cwd` and `stdin_file`:

```yaml
version: 1
commands:
  - cmd: tee /opt/app/app.conf
    stdin_file: ./app.conf
  - argv: [docker, compose, -f, /opt/app/compose.yaml, up, -d, app]
    cwd: /opt/app
  - argv: [docker, compose, -f, /opt/app/compose.yaml, ps, app]
    cwd: /opt/app
```

`cwd` is an absolute remote path, not filesystem isolation. `stdin_file` is a
local regular file, at most 32 MiB; relative paths use the **CLI's working
directory**, not the YAML directory or remote `cwd`.

## Execute and continue

Use actual returned IDs in place of these examples:

```bash
agentssh plan run web-1 --session s_TASK --file deploy.yaml --wait-approval 30s --json
agentssh plan execution px_EXECUTION
agentssh plan resume px_EXECUTION --wait-approval 30s --json
```

`plan run` batches required approvals before starting and reauthorizes each
sequential step. Pending returns exit 7 and a saved `execution_id` (`px_…`).
Use it for progress/resume; `approval_plan_id` (`pl_…`) tracks the batch decision
through `plan status/wait`, not execution.

Resume uses the saved snapshot and skips completed steps. Source YAML edits do
not change it. Repeating `plan run` creates a new execution and may repeat effects.
Failed or unknown steps cannot resume; interruption during execution counts as
unknown. Inspect results before creating a new plan for the remaining work.

## Stdin identity

Include payloads in the initial plan to batch their approvals. Exact grants bind
command and stdin hash; empty stdin differs from no stdin. Changed bytes need a
new approval when relying on that grant. Records retain hash and size, but remote
commands such as `tee` can echo payload contents into output.

`run --wait-approval` keeps the original bytes in memory. Saved plans keep
absolute local paths and hashes, then reread and verify remaining payloads before
execution/resume. Preserve those files; submit changed content as a new request
rather than modifying execution records. Standalone runs use `--stdin-file`.

## Approval-only batching

```bash
agentssh plan submit web-1 --session s_TASK --file deploy.yaml --json
```

This never executes. Stop here when only submission was requested. If execution
is subsequently requested, use the same commands, payloads, and session with
`plan run` or individual `run` calls to reuse valid grants.

For older CLIs lacking `plan run/resume`, use supported `plan submit` and individual
`run` calls, tracking completed effects yourself. If `argv/cwd` is also absent,
use equivalent quoted `cmd` strings for both approval and execution.
