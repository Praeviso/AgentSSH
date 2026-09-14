# Stdin identity and retained payloads

Read this when sending file content through stdin, retaining it for recovery, or
inspecting and cleaning stored payloads. Use [plans.md](plans.md) for the plan
lifecycle.

## Supply exact bytes

Standalone `run` accepts `--stdin-file`; a structured plan entry accepts either
`stdin_file` or `payload_ref`. A stdin file must be a local regular file no larger
than 32 MiB. Relative paths use the CLI's working directory, not the YAML
directory or remote `cwd`.

Include stdin in the initial plan to batch its approval. Exact grants bind the
command and stdin hash; empty stdin differs from no stdin. Changed bytes need
new approval when relying on that grant. Submit changed content as a new request
rather than modifying execution records.

`run --wait-approval` keeps the original bytes in memory. Saved executions
normally keep absolute local paths, hashes, and sizes, then reread and verify
remaining payloads before execution/resume. Preserve those files until the work
finishes. Commands such as `tee` may echo payload contents into remote output.

## Retain content for recovery

When resume must survive deletion of the original file, opt in at submission:

```bash
agentssh plan run web-1 --session s_TASK --file plan.yaml --save-payloads --payload-ttl 24h --json
```

The same retention flags work with approval-only `plan submit`. Saved bytes are
content-addressed and revalidated on read. Use the returned
`sha256:<hash>:<bytes>` reference as `payload_ref` when preparing another plan;
do not combine it with `stdin_file` on the same entry.

Payloads are sensitive local state under the configured runtime state directory
(`AGENTSSH_STATE_DIR`, or the default AgentSSH home). Active plan/execution
references protect them from normal removal and expiry cleanup. Expiry is not a
guaranteed deletion time while work still references the content.

## Inspect and clean up

Use actual references returned by the CLI in place of `REF`, `OLD_REF`, and
`NEW_REF`:

```bash
agentssh plan payload list --json
agentssh plan payload show REF --json
agentssh plan payload diff OLD_REF NEW_REF --json
agentssh plan payload remove REF
agentssh plan payload gc --json
```

`show` provides a bounded text preview and supported archive inventories;
`diff` provides a bounded text comparison. Check truncation and binary flags
before treating either as a complete review. TUI preview is 4 KiB; CLI preview
is 64 KiB. In the plan review, `v` opens the preview and `n`/`p` switches payloads.

`gc` removes expired, unreferenced payloads. Normal `remove` refuses active
references. `remove --force` overrides that protection and can break recovery;
it is not a way to resolve a pending execution.
