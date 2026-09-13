# Task authorization and agent execution workflow

Status: implemented. Existing approval scopes remain compatible; task scope is
an explicit operator choice.

The existing session scope repeats one exact command. The new task scope grants
expiring permission for supported service and Compose operations while preserving
old once/session/host grants. An operator selects task scope explicitly after seeing
the permitted actions and resources. Default lifetime is two hours, configurable
through `approval.task_ttl`. Session end revokes these grants too.

Task matching uses literal shell words and explicit operation/option validators,
not a general command prefix. Initially support service diagnostics, service
maintenance, Compose diagnostics, and Compose maintenance with fixed configuration
files and execution context. A diagnostic request cannot propose maintenance
permission. Shell programs, command substitution, arbitrary pipelines, and stdin
payloads keep exact approval. A plan's task decision uses exact grants of the same
lifetime for unsupported members and says so in the operator interface.

Preflight and execution share authorization inputs, including session and stdin
identity. Preflight does not claim once grants or create pending requests. Real
execution still checks current policy; task grants participate only after the
base policy returns default-deny. Policy rule ordering remains compatible.

Explicit cwd and argv inputs preserve legacy raw shell input. These
are quoting/execution conveniences, not remote filesystem isolation.

Optional approval waiting retains the original command and payload bytes while
waiting, reports pending IDs on stderr, and emits one final JSON result. Approval
does not imply execution; denial, cancellation, timeout, or changed policy stop
the operation. Waiting is bounded and cancellation-aware. A group that partially
executed before another member lost authorization is returned for targeted
continuation; the wait loop never replays completed group members.

Plan execution stores a complete immutable command list and stdin identities,
with a separate execution checkpoint synced to disk before starting a remote
step. It executes sequentially, reauthorizes each
step, and stops on failure. Resume never repeats a completed step, a failed
remote operation, or a step whose outcome is unknown after interruption. A new
explicit plan is needed to retry those operations. File content is not persisted;
resume verifies original stdin identities before executing remaining steps.

The TUI groups pending plan members by default, offers an expanded command view,
shows task permissions and expiry, and distinguishes exact fallback members.
The agent skill treats preflight as optional and respects existing task approval
without asking again inside its scope.

Validation covers authorization widening and rejection, host/session/stdin
binding, expiry/revocation, deny precedence, actual payload delivery after wait,
preflight parity, batch stop/resume, and audit compatibility.

Validation completed with `go test -race ./...`, `go vet ./...`, and a CLI build.
The final argv executable-quoting, strict structured-plan parsing, partial-group
continuation, and disk-synced checkpoint changes also passed focused race tests.
Workflow tests simulate SSH execution and operator
decisions in isolated stores; no managed host or installed policy was changed.

Compose permissions pin requested service selectors, not an OS isolation boundary.
Compose up can start linked services, and build/up execute the configured project
and application code. Configuration-file paths are fixed, but their remote
contents are not content-addressed. Review task grants as maintenance access to
that configured project, including its normal dependencies. See the official
[Compose up contract](https://docs.docker.com/reference/cli/docker/compose/up/)
and [build options](https://docs.docker.com/reference/cli/docker/compose/build/).

Unknown options (including destructive volume/orphan operations, Docker daemon
selection, build argument/SSH forwarding, and interactive exec) fall back to
exact approval. Log task permissions require an explicit line bound of at most
1000 lines. Diagnostic grants do not cover maintenance actions.
