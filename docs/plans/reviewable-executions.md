# Reviewable executions and deployment templates

AgentSSH separates plan review from execution. A submitted or approved plan is
not proof that anything ran; execution state is tracked separately with `px_...`
IDs, per-step status, filtered output hashes, and foreground events.

## Generate a reviewable Compose plan

Use the template command when you have a local release archive and want an
ordinary inspectable plan file:

```bash
agentssh plan template compose \
  --cwd /opt/app \
  --service web \
  --compose-file compose.yaml \
  --compose-file compose.production.yaml \
  --revision REV \
  --archive ./release.tar \
  --output deploy.yaml
```

The command only creates local files. It does not submit, approve, execute, or
connect to a remote host. It creates `deploy.yaml` with `O_EXCL` semantics and
fails if that output already exists. It also creates a validated archive copy
beside the YAML and points the plan's upload step at that copy, so the plan is
bound to the archive bytes that were checked during template generation.

The archive must be a local regular tar or tar.gz file no larger than the normal
stdin payload limit. The template reads the bounded archive bytes, computes a
SHA-256, validates the tar headers without rewriting member names, rejects unsafe
paths, leading/trailing whitespace, control characters, unsupported tar types
such as symlinks and hard links, and the reserved `.agentssh-deploy/` subtree,
and caps member count and expanded regular-file bytes. Relative `--compose-file`
values are resolved against `--cwd` into clean absolute Compose file paths; their
order is preserved exactly.

The generated `version: 1` YAML uses named steps:

| Step | Purpose |
| --- | --- |
| `upload-archive` | Upload the validated sidecar archive through `stdin_file`. |
| `assert-upload-sha256` | Stop if the uploaded archive hash does not match the validated bytes. |
| `backup-current-files` | Reject existing symlinks on member paths or their parents, write existing/missing member lists, stop on unreadable or non-regular existing paths, create a tar backup from a NUL-delimited verbatim list of existing member files, and write the backup contents list. Empty backup means every member path was new. |
| `capture-compose-before` | Capture before-apply Compose image and status evidence. |
| `apply-archive` | Recheck that member paths and existing parents are not symlinks, then extract the archive into `--cwd`. |
| `build-service` | Build only the selected Compose service with the requested Compose files. |
| `up-service` | Start only the selected service with `up -d`; Compose may still start declared dependencies. |
| `collect-compose-ps` | Collect status evidence. |
| `assert-compose-running` | Assert every container selected by `docker compose ps -q <service>` is running and, when Docker reports a health status, healthy. Docker/inspect errors fail the step. |
| `collect-compose-logs` | Collect bounded logs with `--tail 100 --no-color`. |
| `verify-local-health-*` / `verify-public-health-*` | Optional fixed HTTP(S) GET probes. |

The template never embeds project-specific credentials, environment values, CMM
knowledge, arbitrary CLI substitution, or automatic rollback. If rollback or
cleanup is needed, inspect the generated evidence and write a separate plan with
explicit corrective commands. Treat the file backup as evidence, not a promise:
an empty backup is expected on first deploys where every archive path was
missing, and the missing-file list identifies newly introduced paths for manual
recovery decisions. The generated commands do not rewrite existing symlinks; a
symlink on an archive member path or existing parent stops the plan so the
operator can inspect the remote tree explicitly.

Optional health checks use fixed URLs and bounded curl arguments:

```text
curl -q --fail --silent --show-error --max-time <seconds> <url>
```

Health URLs must be HTTP(S), include a host, and omit credentials and fragments.
`--health-timeout` is capped at 30 seconds. Health checks are independent
`verify` steps with `on_failure: continue`, so AgentSSH can collect all health
evidence while still marking the whole execution failed if any continued verify
step fails.

## Execute, observe, and resume

Use the returned IDs from your own command output:

```bash
agentssh plan run web-1 --session s_TASK --file deploy.yaml --wait-approval 30s --json
agentssh plan execution px_EXECUTION --json
agentssh plan execution px_EXECUTION --follow --after-seq 12 --timeout 30s
agentssh plan resume px_EXECUTION --wait-approval 30s --json
```

`plan run` batches required approvals before starting and reauthorizes each step
at execution time. A pending approval returns exit 7 and a saved `execution_id`
(`px_...`). `approval_plan_id` (`pl_...`) tracks the review batch through
`plan status`, `plan wait`, and operator decisions; it is not an execution ID.

`--events` streams foreground JSONL events to stdout and saves the same filtered
events under the execution state. It is mutually exclusive with `--json`. The
run/resume command remains in the foreground while it owns execution; AgentSSH
does not leave a background daemon. Use `plan execution px_EXECUTION --follow
--after-seq N --timeout 30s` to observe saved events without taking ownership of
execution or replaying work.

## Status router

| Saved state | Correct response |
| --- | --- |
| Pending approval/request | Observe the existing `approval_id`, `approval_plan_id`, or `execution_id`; do not submit duplicates. |
| Authorized `not_started` step | Resume the same `px_...`; do not run a fresh copy. |
| Running execution | Observe with `plan execution px_... --follow --timeout 30s` or `--json`. |
| Failed execution | Inspect recorded effects, outputs, and evidence before deciding on a new plan. |
| Unknown execution | Never replay automatically; inspect remote state first. |
| Completed execution | Verify business/app checks outside AgentSSH when needed. |

Resume uses the saved execution snapshot and skips completed steps. Editing the
source YAML after `plan run` does not change the saved execution. Running the
same YAML again creates a new execution and can repeat effects.

Submitter descriptions, metadata, and step names help a human reviewer
understand intent. They are not parsed facts. AgentSSH authorizes the rendered
command, cwd, stdin identity, task profile, and approval scope.

## Payload retention and state directories

Payloads are sensitive local runtime state. By default, saved plans keep absolute
local paths and hashes and reread the payload before execution or resume. Use
`--save-payloads --payload-ttl 24h` only when resume must survive the original
local file disappearing. Saved payload bytes are content-addressed and retained
while active plan/execution references exist; cleanup is safe only after those
active refs are gone.

`AGENTSSH_HOME` still owns configuration, inventory, policy, secrets, and the
operator verifier. `AGENTSSH_STATE_DIR` moves runtime state: audit, pending
approvals, responses, session grants, plans, executions, events, and payloads.
Set the same `AGENTSSH_STATE_DIR` for operator TUI/CLI and agent commands. There
is no automatic migration, and changing state directories will not copy or reset
policies or grants.

`agentssh diagnostics --json` is read-only and does not create directories. It
reports local path existence and writability plus the likely impact of missing or
unwritable runtime directories. It cannot prove access through an outer sandbox,
container mount, or remote filesystem policy.
