# Reviewable Compose deployment plans

Read this when generating a deployment plan from a local release archive.
Generation creates local files; it does not submit, approve, or execute.

## Generate and review

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

The output YAML and a validated archive copy beside it are created without
overwriting existing files. The upload step references that copy. The template
validates tar/tar.gz members and rejects unsafe paths, leading/trailing
whitespace, control characters, unsupported types such as links, and the
reserved `.agentssh-deploy/` subtree.

Pass every required Compose file in overlay order. Relative paths resolve
against the remote `--cwd`. The plan builds and starts the named service;
Compose may also start declared dependencies.

Review the generated YAML and its payload, then follow [plans.md](plans.md) when
execution is requested. For recovery independent of the local archive copy,
use the retention options in [payloads.md](payloads.md).

## Generated steps and evidence

The plan uploads the archive, confirms its SHA-256, backs up affected existing
files, captures Compose image/status evidence, extracts the release, builds and
starts the service, and runs independent status/log/health checks.

The backup uses GNU tar with a NUL-delimited verbatim file list. It records
existing files, newly introduced paths, and the backup's contents. If all paths
are new, an empty backup is expected; use the missing-file list when planning
recovery. Unreadable or non-regular existing files stop the plan. Archive member
paths and existing parents are checked for symlinks before backup and again
before extraction.

The container assertion includes exited replicas: every selected service
container must be running, and any Docker healthcheck must report healthy.
Status and log collection alone do not establish application readiness.

There is no automatic rollback. Inspect the backup, file lists, and execution
evidence before writing an explicit corrective plan; an empty backup cannot
restore a previous release.

## Optional application checks

`--local-health-url` and `--public-health-url` add fixed HTTP(S) probes from the
remote host. They use `curl -q --fail --silent --show-error --max-time <seconds>`;
`--health-timeout` is capped at 30 seconds. URLs must omit credentials and
fragments.

These are independent `verify` steps with `on_failure: continue`. Other checks
can still collect evidence after a failure, while the overall execution remains
failed.
