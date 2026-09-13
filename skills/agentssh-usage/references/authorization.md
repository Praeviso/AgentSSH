# Authorization and result handling

## Reuse granted scope

When coverage is unclear, `agentssh session grants s_TASK` returns permissions
and expiry as JSON. `once` permits one exact execution; `session` repeats the exact
command until expiry/revocation. Both bind any stdin hash.

Task grants bind host, session, resources, `cwd`, sudo context, and Compose file
arguments. Default lifetime is two hours (`approval.task_ttl`); `session end`
revokes them.

| Resource | Diagnostic actions | Maintenance adds |
| --- | --- | --- |
| Specified services | status/show/is-active/is-enabled, bounded journal logs | restart/reload |
| Fixed Compose project | ps, bounded logs | build/pull/up/restart with supported options |

Diagnostic requests do not propose maintenance permission. Named service grants
cover named subsets; omitting selectors may broaden a Compose operation and need
another approval. Compose file paths are fixed, but remote contents are not
hash-pinned and normal dependencies may also start.

Task logs require an explicit bound of at most 1000 lines (`journalctl -n` or
Compose `logs --tail`). Scripts, pipelines, stdin, and unsupported options stay
exact; a mixed plan's task decision gives these members exact grants of the same
lifetime. Do not seek persistent host grants merely to avoid task approvals.

## Pending and terminal results

Read JSON state alongside the exit code:

| Result | Next action |
| --- | --- |
| Pending, exit 7 | Preserve the approval/execution ID and observe the existing request. |
| Denied, exit 6 | Stop that operation; do not reword it to evade the decision. |
| Failed, exit 1 | Inspect partial effects before retrying. |
| SSH error, exit 9, or unknown execution | Determine what ran before retrying; a connection failure does not prove nothing happened. |

For a pending single command, use `approval status <id>` or
`approval wait <id> --timeout 30s`. After approval, rerun the same command,
session, and stdin bytes. Report the pending ID if human action is still needed;
bounded waits avoid busy-polling and duplicate submissions.

For saved executions, use [plan resume](plans.md#execute-and-continue).
For group results with `next_action: retry_unstarted_targets`, wait for outstanding
approvals and continue **only unstarted hosts**, each with its returned
`session_id` (including the host suffix). Do not repeat the whole group.

## Preflight and evidence

`policy test --host web-1 --session s_TASK --file deploy.yaml --json` previews
grants and stdin identity without consuming once grants or creating requests.
Read verdicts as described in the skill entrypoint.

Retain status and continuation IDs when selecting `--fields`. Keep the original
command: JSON `cmd` may be truncated at 2 KiB. Use `req_id` with `audit show` to
correlate execution evidence; `audit verify` checks chain integrity, not app health.
