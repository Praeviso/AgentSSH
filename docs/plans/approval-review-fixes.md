# Approval Review Fixes

Date: 2026-07-01

Requested branch: `fix/approval-review-findings`

Actual git state in this environment: branch creation and commits could not be
created because `.git` is read-only under the managed sandbox. The attempted
commands failed with:

- `git checkout -b fix/approval-review-findings`: `unable to create directory for .git/refs/heads/fix/approval-review-findings`
- `git commit ...`: `Unable to create .../.git/index.lock: Read-only file system`

All source fixes below are present in the working tree.

## Findings Addressed

- F1: removed `journalctl` safe-prefix host generalization so grants for a
  specific journalctl invocation stay exact.
- F2: hardened safe-prefix tails so git `--output` and git `-o` variants force
  exact matching.
- F3: hardened kubectl safe-prefix tails so identity-bearing options such as
  `--as`, `--as-group`, `--token`, `--kubeconfig`, and `--server` force exact
  matching.
- F4: reordered `ApplyDecision` so the response file `O_EXCL` resolve is the
  first mutating claim; only the winner applies grants and audit side effects.
- F5: made TUI approval decisions abort on inventory or policy load errors
  instead of saving an empty policy.
- F6: disabled approval TUI verdict keys, queue polling, and pending badges when
  approval runtime is disabled.
- F7: made `session end <base>` remove derived `base@host` approval session
  files.
- F8: when approval is disabled, authorization now evaluates the full policy,
  including persisted `__agentssh_approval` host rules.
- F9: included `Matcher.Promotable` in matcher SHA-256 integrity checks.
- F10: corrupt approval response files now return `ErrCorruptResolution` instead
  of wedging status or adjudication forever.
- F11: removed single-host session-file binding so one session file can safely
  contain host-filtered grants for multiple hosts.
- F12: pending creation reuses an unresolved request for the same
  `SessionID+Host+CmdSHA256`, and resolved pending/response files older than
  the TTL are reaped on create/list.
- F13: invalid optional approval runtime config now emits an English warning and
  treats approval as disabled for `run`, preserving explicitly allowed commands
  while default-denying gray commands.
- F14: `policy test` is now a static policy-engine check; it does not consult
  session grants and still includes persisted approval host rules.
- F15: approval-pending human output is now English.

## Mechanical Items

- Added an audit record for `not_run` preflight-blocked targets.
- Added `cmd` to `runResponse`, populated it in run JSON responses including
  approval-pending responses, and updated the agent usage skill wording for
  static `policy test`.
- Added `approval.ChannelExit` and used it for exit-channel approval audit
  records; audit tests assert the same exported constant.

## Judgment Calls

- F8 decision: persisted `__agentssh_approval` host rules remain effective when
  approval is disabled. The authorization path intentionally builds the engine
  from the full policy in disabled mode and does not strip generated approval
  rules.
- F1-F3 decision: implemented kubectl/git first-positional pinning where clean.
  For example, `kubectl get pods` generalizes to a prefix that includes `pods`,
  preventing it from freeing `kubectl get secret`. The same pattern applies to
  `git diff HEAD`.

## Validation

Latest full validation after code changes:

```bash
GOCACHE=/tmp/agentssh-gocache GOMODCACHE=/tmp/agentssh-gomodcache go build ./...
GOCACHE=/tmp/agentssh-gocache GOMODCACHE=/tmp/agentssh-gomodcache go test ./...
```

Result: both commands passed.

## Commit Plan

No actual commits were created because the sandbox exposed `.git` as read-only.
If committed outside this sandbox, use the following sequence, with every commit
message ending in the required co-author line:

1. `fix approval safe-prefix escalation hardening`
2. `fix approval decision atomicity`
3. `fix tui approval disabled and load-error guards`
4. `fix approval session host and derived-end cleanup`
5. `fix approval disabled host-rule authorization`
6. `fix approval integrity and corrupt response handling`
7. `fix approval pending dedupe and resolved reaping`
8. `fix approval runtime degrade and static policy test`
9. `fix approval UI text and mechanical audit/json/channel items`
10. `document approval review fix decisions`

Required commit trailer:

```text
Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>
```

Final commit body decision record:

```text
Decision record:
- When approval is disabled, persisted __agentssh_approval host rules remain
  effective by evaluating the full policy instead of stripping generated rules.
- Safe-prefix hardening includes git/kubectl first-positional pinning where
  clean, so kubectl get pods and git diff HEAD no longer widen across their
  first resource/revision positional.

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>
```

## Unfixed Findings

None. All F1-F15 and the three mechanical items are addressed in the working
tree. The only incomplete requested workflow item is git branch/commit creation,
which was blocked by the read-only `.git` filesystem in this environment.
