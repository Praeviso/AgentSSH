# CI selection and full verification

The PR and main-push workflow is [ci.yml](../.github/workflows/ci.yml). It first
classifies the complete change range without installing Go. Its package selector
and result checker live in [scripts/ci/ci.py](../scripts/ci/ci.py).

## What runs

| Change | Checks |
| --- | --- |
| README, LICENSE, docs, Markdown under skills | Classification and ci-result only; no Go setup |
| Go test files | Tests in the modified packages |
| Go production files | Modified packages and their transitive production consumers, plus test consumers |
| go.mod/go.sum, workspace or lint configuration | Full race tests, vet, lint and command builds |
| .github or scripts/ci | Full verification, selector regression tests, actionlint, shell syntax and the audit demo |
| Shell scripts | Shell syntax; the audit demo script also gets a real CLI smoke run |
| Deletions/renames, unclassified files, unavailable diff | Conservative full verification |

The diff uses the target base and the tested PR merge commit, or the push event's
before/after range. Thus earlier commits in a PR or multi-commit push are included.
Only the classifier fetches history. A missing/zero base selects full verification.

For Go changes, go list with race instrumentation provides Imports, TestImports
and XTestImports. A test-only change does not propagate to production consumers.
A test consumer of a changed library is selected without treating that consumer's
production code as modified. Unreadable or incomplete package graphs fall back to
one unsplit ./... invocation, including any newly added package roots.

Quality checks, internal package race tests and CLI race tests run independently.
The quality job retains whole-project gofmt, vet and lint, and builds both commands.
It is deliberately broader than test selection: static checks are relatively
cheap and catch broken callers even on a test-only change.

The ci-result job always runs and requires each selected job to succeed and each
unselected job to be skipped. Missing analysis outputs, failed/cancelled jobs and
unexpected test skips fail the result. Use the **ci-result** job from the **CI**
workflow as the required branch check if protection is enabled; workflows do not change
repository protection settings.

Each test job uploads JSONL results for seven days and writes its slowest package
and test timings to the job summary. PR and main-push CI retain normal Go test caching.
New PR commits cancel previous runs of the same PR; push, full and release
verification are not cancelled by this policy.

## Full and release verification

[ci-full.yml](../.github/workflows/ci-full.yml) calls the same CI with full=true:

- Daily at 19:17 UTC (03:17 Asia/Shanghai the following day).
- Manually through the Full CI workflow's Run workflow button.
- From the release workflow, on the exact ref being released.

Full verification uses go test -race -count=1 -json -timeout=20m, so successful
test-result caches cannot replace execution. It also exercises the selector,
workflow validation and non-interactive audit demo. Release builds run in parallel
with verification; publishing requires both to pass. Test artifacts are excluded
from the release artifact download.

## Caches and cryptographic fixtures

The shared setup-go composite action disables setup-go's combined cache. It
downloads the complete module set before any job can save the module cache,
whose key includes platform, Go version and module manifests.

Build caches have separate owners for quality, tooling, internal race, CLI race
and each release target. Their keys include platform, Go version, mode and Go
source/manifests, with a same-mode prefix fallback. Each owner saves its own
completed build outputs; lint cannot win a cache key intended for race builds.
PR caches remain scoped to the PR by GitHub Actions.

CLI workflow tests prepare real age-encrypted verifier and secrets fixtures with
a test-only scrypt work factor of 10. Production code and production parameters
are unchanged. Tests still exercise real decryption and wrong-password rejection.
TestOperatorVerifierProductionParameters invokes operator init, checks its
production work factor of 18 and verifies correct/incorrect passwords. The
secrets store round-trip, tampering and atomic-write tests retain production writes.

## Reproduce locally

From the repository root:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s scripts/ci -v
go run github.com/rhysd/actionlint/cmd/actionlint@v1.7.12
python3 scripts/ci/ci.py classify --base BASE_SHA --head HEAD --plan /tmp/ci-plan.json
python3 scripts/ci/ci.py select --plan /tmp/ci-plan.json
python3 scripts/ci/ci.py test --packages '["./cmd/agentssh"]' --full --report /tmp/cli-tests.jsonl
gofmt -l .
go vet ./...
go build ./cmd/...
go test -race -count=1 -timeout=20m ./...
golangci-lint run --timeout=5m
```

The Python checks use temporary Git histories and a real dependency graph. They
cover documentation, test-only and production changes, cross-package external
tests, cumulative push and PR merge diffs, server-only changes, fallbacks and
failure/cancellation handling. They require Git, Python 3 and the project's Go
version, with no third-party Python packages.
