# AgentSSH

AgentSSH is a local, single-binary SSH gateway for AI agents. It keeps SSH credentials and policy enforcement on the human-controlled machine, exposes only a constrained CLI to agents, and records every operation in a tamper-evident audit log.

Two principals, one binary:

- **You (the operator)** drive everything from one full-screen console — `agentssh tui` — to onboard hosts, register credentials, test connectivity, tune policy, and review the audit trail.
- **The agent** uses `agentssh hosts`, `run`, `plan run/resume`, and read-only status commands. It never sees addresses, keys, or passwords — those stay in your ssh-agent, `~/.ssh/`, and an encrypted local store.

AgentSSH uses standard SSH from the local machine (its built-in Go SSH client by default) and needs no agent or daemon on remote hosts. Two optional control planes move credentials, and in gateway mode all enforcement, off the agent's machine; see [Choose a mode](#choose-a-mode).

## Quick Start

```bash
# 1. Install — static binary, no Go required (see "Install" for macOS / arm64).
curl -fsSL https://github.com/Praeviso/AgentSSH/releases/download/v0.15.0/agentssh_v0.15.0_linux_amd64.tar.gz \
  | sudo tar xz --strip-components=1 -C /usr/local/bin agentssh_v0.15.0_linux_amd64/agentssh

# 2. Open the console — this is your main entry point:
agentssh tui
#   On first run it creates ~/.agentssh/ with a starter inventory.yaml and a
#   policy.yaml scaffold. Out of the box every command is denied until you add
#   allow rules.
#   In the Hosts tab:
#     D  discover the SSH hosts you can already reach (from ~/.ssh/config + known_hosts),
#        select with space, p to probe, enter to import
#     a  add a host by hand (addr/user, optional identity_file, optional password)
#     t  test connectivity to the selected host
#     enter  open a host's detail screen — its Info pane edits fields inline (incl. key/password auth)
#   Switch entry tabs with 1/2 or tab: Hosts · Policy.

# 3. Add an explicit allow rule before running anything:
agentssh policy rule add readonly --cmd-regex '^(systemctl status|journalctl|uptime)\b' --action allow --priority 10
#    Optional: add higher-priority deny rules for commands that must never run.
agentssh policy rule add catastrophic --cmd-regex '\b(rm\s+-rf|mkfs|dd|shutdown|reboot|init\s+0|userdel)' --action deny --priority 100

# 4. The agent calls agentssh — every command is policy-checked and audited:
agentssh hosts                                 # discover targets (no credentials shown)
export AGENTSSH_SESSION=$(agentssh session new) # one session per task -> grouped in audit
agentssh run web-1 -- systemctl status nginx   # allowed -> executed over SSH
agentssh run web-1 -- rm -rf /                 # denied by policy -> exit 6, never runs

# 5. Review everything back in the console:
agentssh tui            # Hosts tab for inventory · Policy tab for global/group rules
```

That is the whole loop: you own hosts, policy, and the audit trail through `agentssh tui`; the agent only ever calls `agentssh`.

## Choose a mode

The Quick Start is **local** mode. Two control planes, each its own binary,
take over parts of it. A control plane runs in one mode only, and a device
enrolls for that mode.

| | Local | Managed | Gateway |
| --- | --- | --- | --- |
| Control plane | none | `agentssh-server` | `agentssh-gateway` |
| Inventory and policy | files on the device | signed bundle from the control plane; local deny rules still apply | on the gateway only; local files are ignored |
| SSH private keys | your ssh-agent, `~/.ssh`, `secrets.enc` | control plane, which signs each login | gateway, never sent anywhere |
| Connects to target hosts | the device | the device, with a login signature from the control plane | the gateway |
| Enforces policy, approvals and output filtering | the CLI on the device | the CLI on the device | the gateway |
| Approvals are decided | operator TUI or CLI on the device | operator TUI or CLI on the device | `agentssh-gateway` CLI or its Web UI |
| Audit | hash chain on the device | the device's chain, plus the control plane's signing log | the gateway's chain, covering every run and decision |

**What each mode protects against, and what it does not:**

- **Local.** The agent goes through the CLI: deny rules hold even with no one
  watching, credentials never appear in what the agent reads, and every
  request is audited. The CLI is the boundary only for an agent that uses it.
  A process running as the same OS user can read your keys, run `ssh`
  directly, and edit policy, approvals and the audit files.
- **Managed.** SSH private keys stay on the control plane, configuration is
  central, and revoking a device stops its next login. Policy, approvals and
  audit are still enforced by the client. A same-user process can read
  `device.key`, request login signatures directly, and run any command the
  identity's login user can, on any host it is assigned. Use it for machines
  you trust that run agents you supervise.
- **Gateway.** The device holds no SSH keys and no policy. It can only ask the
  gateway to run commands, and the gateway authorizes, runs and audits each
  one. A same-user process with the device key, or a modified client, can
  still run what that device's gateway policy allows, but only while an
  operator has activated the device, and only until it is revoked. It cannot
  get login signatures, reach target hosts with the
  gateway's identities, decide its own approvals, or alter the audit. The
  gateway must be able to reach every target host, and it is the single point
  of execution: if it is down, no commands run, and if it is compromised, every
  target host trusting its identities is exposed. Choose it for cloud-hosted
  or unattended agents, and for any agent machine you do not trust.

The agent's commands (`hosts`, `run`, `status`, `plan`, `approval wait`) and
their exit codes (0, 6 denied, 7 approval required, 9 SSH error) are the same
in every mode. Set up [managed](#managed-mode-agentssh-server) or
[gateway](#gateway-mode-agentssh-gateway) mode below; `agentssh remote enroll
--mode` must name the control plane's mode, and a mismatch is refused before
the token is spent.

## Task approvals and executable plans

AgentSSH can approve a bounded family of operations for one host and session,
with a default two-hour lifetime. An operator chooses `--task` (or **t** in the
Approvals tab) to review and approve service diagnostics/maintenance or a fixed
Compose project's operations. Existing `--once`, `--session`, and `--host` scopes
retain their meaning; unsupported scripts and stdin remain exact.

```yaml
approval:
  enabled: true
  task_ttl: 2h
```

The agent can run a complete saved plan and continue it after approval:

```bash
agentssh session new
agentssh plan run web-1 --session <session_id> --file deploy.yaml --wait-approval 30s --json
agentssh plan resume <execution_id> --wait-approval 30s --json
agentssh plan execution <execution_id>       # saved progress as JSON
agentssh plan execution <execution_id> --follow --after-seq <n> --timeout 30s
agentssh session grants <session_id>         # permissions and expiry as JSON
```

```yaml
version: 1
commands:
  - argv: [docker, compose, -f, /opt/app/compose.yaml, build, app]
    cwd: /opt/app
  - argv: [docker, compose, -f, /opt/app/compose.yaml, up, -d, app]
    cwd: /opt/app
```

The TUI groups plans by default: **e** expands their commands, **enter** reviews
one plan, and **t** previews task permissions and exact fallback members. Human
CLI equivalents are `approval grant <id> --task` and `plan grant <id> --task`;
operator authentication still applies. `session end <id>` revokes session and
task grants. Expiry/revocation prevents subsequent commands; it does not undo or
forcibly terminate commands already running.

`run --wait-approval 30s` can wait and execute an unchanged single request too.
`run --argv --cwd /opt/app -- <arguments...>` preserves argument boundaries and
sets the remote working directory. `policy test --host <host> --session <id>`
now checks current grants and stdin identities, using the same authorization
path as execution. Preflight is optional and never substitutes for runtime checks.

Saved plans stop on failure and resume only unstarted steps. Completed steps are
never replayed; a `running` execution should be observed with `plan execution
<px_...> --follow --timeout 30s`, and an `unknown` execution must be inspected
before creating a new plan. A failed step also requires effect inspection. `verify` steps may use
`on_failure: continue` for independent checks, but the overall execution still
finishes failed when any continued verification fails.

Reviewable deployment plans can be generated before submission:

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

The template command only writes ordinary `version: 1` plan YAML; it does not
submit, approve, or execute anything. It validates the local tar/tar.gz archive,
rejects unsafe tar member paths, leading/trailing whitespace, control characters,
unsupported tar types, and the reserved `.agentssh-deploy/` subtree, creates a
validated archive copy beside the YAML, preserves every `--compose-file` in order
by resolving it against `--cwd`, and fails if `--output` or the archive copy
already exists. The generated plan uploads that validated copy, asserts its
SHA-256 before extraction, writes existing and missing member lists, rejects
existing member paths and parents that are symlinks before backup and before
extraction, backs up only existing readable regular archive member files with a
NUL-delimited verbatim tar list, records the backup contents, captures current
Compose image/status evidence, extracts the archive, builds and starts only the
selected service, then runs bounded verification/evidence steps. The Compose
status assertion requires every selected service container to be running and, if
a Docker healthcheck exists, healthy. An empty backup can be valid for first
deploys but is not a rollback by itself. It never embeds project-specific
credentials or automatic rollback.

Input-file hashes remain pinned to the original snapshot. `plan run
--save-payloads` can retain stdin payload bytes for resume; retained payloads
are sensitive local state and remain removable only when no active execution or
plan pin references them. Without saved payloads, resume rereads the original
absolute local paths and refuses changed bytes. Arbitrary shell programs,
pipelines, changed Compose projects, destructive options, and changed stdin do
not inherit a task grant.

By default, configuration and runtime state both live under `AGENTSSH_HOME`
(`~/.agentssh`). Set `AGENTSSH_STATE_DIR` to move runtime state only: audit,
pending approvals, responses, session grants, plans, executions, events, and
payloads. Inventory, policy, secrets, and the operator verifier stay under
`AGENTSSH_HOME`. Use the same `AGENTSSH_STATE_DIR` for operator TUI/CLI and
agent commands; AgentSSH does not migrate old state automatically. `agentssh
diagnostics --json` reports path existence and local filesystem writability
without creating directories, but it cannot prove access through an outer
sandbox, container mount, or remote filesystem policy.

See [the operating skill](skills/agentssh-usage/SKILL.md) for the full workflow and
[the reviewable execution guide](docs/plans/reviewable-executions.md) for plan
states, payload retention, and deployment templates.

## The console (`agentssh tui`)

`agentssh tui` is the primary operator interface — one full-screen app with top-level Hosts and Policy tabs (switch with `1`/`2` or `tab`, quit with `q`):

| Tab | What you do |
| --- | --- |
| **Hosts** | onboard, inspect, edit, test, and remove hosts; manage credentials |
| **Policy** | manage the Global rule list and reusable rule groups as cards; open a card to add/edit/remove rules |

**Hosts grid keys** — `↑↓←→/hjkl move · / filter · a add · D discover · t test · enter/i open · r reload`. The grid is a pure navigator; per-host **edit** and **delete** live on the host's detail screen (open it with `enter`/`i`).

- **`D` Discover** — opens an overlay of hosts you can likely already reach, gathered from `~/.ssh/config` and `~/.ssh/known_hosts`, annotated with key/known-hosts/in-inventory status. `space` selects, `p` probes (a real connection test), `enter`/`i` imports the connectable, not-yet-known ones into your inventory. `esc`/`q` closes.
- **`a` Add** — a form for a *new* host: `name / addr / user / port / tags / ssh_config_alias / identity_file / password`. `identity_file` points at a private key for that host. `password` is optional and **masked**; it is stored encrypted, never in `inventory.yaml`. Setting a password in the TUI requires `AGENTSSH_MASTER_PASSWORD` to be set (bubbletea owns the terminal, so there is no separate master prompt) — otherwise use `agentssh secret set`.
- **`t` Test** — runs a real connectivity check against the selected host, updates its detected OS metadata, and shows `OK` or an actionable hint (missing credentials, unknown host key, unreachable, …).
- **Host detail (`enter`/`i`)** — a three-pane screen for the selected host: `1` Info · `2` Sessions · `3` Policy (switch with `tab` or `1`–`3`; `esc` returns to the grid).
- **Info pane** — the field list doubles as the editor: `j/k` move a field cursor, `enter` edits the focused field **in place** and saves on `enter` (`esc` cancels) — no separate form. Editable rows: `addr / user / port / alias / auth / tags`. The **`auth`** row is a two-mode edit — **key** (a private-key path; empty falls back to the default `~/.ssh` keys the client already scans) or **password** (masked, stored encrypted; needs `AGENTSSH_MASTER_PASSWORD`). `t` tests connectivity; `d`/`x` delete the host (with confirm).
- **Policy tab** — Global and each reusable rule group render as cards with rule counts. `enter` opens the selected card; `a/e/r` add, edit, and remove rules; `n` creates a group; `d` deletes a group. Rule groups are presets: stamping one onto a host copies its current rules and records the group name as provenance.
- **Host detail Policy pane** — press `enter`/`i` on a host, then `3` for Policy. The pane shows one unified, borderless rule list with host-tier rows first and global rows below as read-only context. `a` adds a manual host rule (`allow|deny [priority] <regex>`), `p` stamps a rule group, `j/k` selects rows, `r` removes editable host rows, `R` removes all rows stamped from the selected group, and `x` clears that host's rules.

The remote side is always your responsibility — AgentSSH never touches a server's `authorized_keys`; it only connects with the credentials you give it and tells you what to fix when a connection fails.

## Install

### Prebuilt binary (recommended — no Go needed)

Static binaries (`CGO_ENABLED=0`, no runtime deps). Pick your platform; each is one command that drops `agentssh` into `/usr/local/bin`:

```bash
# Linux x86_64
curl -fsSL https://github.com/Praeviso/AgentSSH/releases/download/v0.15.0/agentssh_v0.15.0_linux_amd64.tar.gz \
  | sudo tar xz --strip-components=1 -C /usr/local/bin agentssh_v0.15.0_linux_amd64/agentssh

# Linux arm64
curl -fsSL https://github.com/Praeviso/AgentSSH/releases/download/v0.15.0/agentssh_v0.15.0_linux_arm64.tar.gz \
  | sudo tar xz --strip-components=1 -C /usr/local/bin agentssh_v0.15.0_linux_arm64/agentssh

# macOS Apple Silicon (arm64)
curl -fsSL https://github.com/Praeviso/AgentSSH/releases/download/v0.15.0/agentssh_v0.15.0_darwin_arm64.tar.gz \
  | sudo tar xz --strip-components=1 -C /usr/local/bin agentssh_v0.15.0_darwin_arm64/agentssh

# macOS Intel (amd64)
curl -fsSL https://github.com/Praeviso/AgentSSH/releases/download/v0.15.0/agentssh_v0.15.0_darwin_amd64.tar.gz \
  | sudo tar xz --strip-components=1 -C /usr/local/bin agentssh_v0.15.0_darwin_amd64/agentssh
```

Verify: `agentssh --version`. (Bump `v0.15.0` for a different release; checksums are in `SHA256SUMS.txt` on the Releases page.)

Each archive also contains the optional control planes, `agentssh-server` (managed mode) and `agentssh-gateway` (gateway mode, since v0.15.0); see [Choose a mode](#choose-a-mode). To install one, replace the trailing `/agentssh` in the command with `/agentssh-server` or `/agentssh-gateway`.

### From source (needs Go matching the go.mod directive)

```bash
go install github.com/Praeviso/AgentSSH/cmd/agentssh@latest   # into $GOBIN
go build -o agentssh ./cmd/agentssh                           # single binary from a checkout
```

Put the binary on the local operator machine where SSH already works.

For contributor checks, affected-test selection and release verification, see [CI](docs/ci.md).

## Configure

AgentSSH reads `~/.agentssh/` by default. Set `AGENTSSH_HOME` to use another directory. The first run of `agentssh tui` creates the directory and seeds `inventory.yaml` + `policy.yaml` for you (existing files are never overwritten), so you can skip the manual setup below and just edit what it wrote.

```text
~/.agentssh/
  inventory.yaml   # hosts (seeded on first `tui`; managed via the TUI or `agentssh inventory`)
  policy.yaml      # allow/deny rules + output filtering (seeded on first `tui`)
  secrets.enc      # encrypted SSH passwords (created on first `secret set`)
  audit.log        # created automatically
  session          # created automatically
```

Example `inventory.yaml` (you normally never hand-edit this — the TUI does):

```yaml
version: 1
transport: native           # default: built-in Go SSH client; "ssh" shells out to system ssh
host_key_policy: strict      # or "accept-new" for trust-on-first-use
hosts:
  web-1:
    addr: 10.0.0.11
    user: deploy
    identity_file: ~/.ssh/web-1   # optional per-host private key
    tags: [web, prod]
groups:
  prod: { tags: [prod] }
```

Example `policy.yaml`:

```yaml
version: 1
rules:
  - name: readonly
    priority: 10
    match: { cmd_regex: '^(systemctl status|journalctl|uptime)\b' }
    action: allow
  - name: catastrophic
    priority: 100
    match: { cmd_regex: '\b(rm\s+-rf|mkfs|dd|shutdown|reboot|init\s+0|userdel)' }
    action: deny
host_overrides:
  host:web-1:
    rules:
      - priority: 20
        match: { cmd_regex: '^systemctl status\b' }
        action: allow
rule_groups:
  readonly:
    rules:
      - priority: 10
        match: { cmd_regex: '^(uptime|whoami)\b' }
        action: allow
output:
  max_bytes: 16384
  redact:
    - '(?i)(password|passwd|secret|token)\s*[=:]\s*\S+'
```

### Credentials

AgentSSH connects with **public-key auth by default** and never stores keys of its own — it reuses your ssh-agent, `~/.ssh/config`, and `~/.ssh/id_*`. Per host you can also:

- **`identity_file`** — point a host at a specific private key (a path, not a secret; lives in `inventory.yaml`).
- **Password** — stored **encrypted** in `~/.agentssh/secrets.enc` (age, scrypt passphrase), never in `inventory.yaml` and never in the audit log. Public key is always tried before a password.

The encrypted store is unlocked with a **master password** from `AGENTSSH_MASTER_PASSWORD`, or a no-echo TTY prompt for operator commands. For agent-driven `run`, the master is read from the env only (no prompt); if it is unset, password auth is simply skipped and key auth is used. Register passwords with:

```bash
agentssh secret set web-1     # prompts (no echo) and encrypts
agentssh secret ls            # lists host names only — never values
agentssh secret rm web-1
```

> Security note: with `AGENTSSH_MASTER_PASSWORD` in an unattended agent's environment, that process can decrypt every stored password. Prefer key auth for agent-driven hosts; reserve passwords for hosts that truly need them.

## Managed mode (`agentssh-server`)

A hosted control plane can manage AgentSSH devices, hold SSH identities and sign
each login on demand. Clients authenticate over HTTPS using Ed25519 device request
signatures and obtain inventory/policy as a signed configuration bundle. Revoking
a device blocks its next login. A config-center plugin can implement this protocol
inside the existing service; no additional AgentSSH service is required.

The repository also provides `agentssh-server` as a reference implementation. Run
its private HTTP origin behind an ordinary HTTPS ingress that preserves the path:

```bash
# On the reference control plane. The master password comes from
# AGENTSSH_SERVER_MASTER_PASSWORD or a prompt.
agentssh-server init
agentssh-server identity create web          # public key for target authorized_keys
agentssh-server serve --public-url https://cp.example/agentssh
# Default origin: 127.0.0.1:8080, reachable only by the trusted HTTPS ingress.

# Per device
agentssh-server device token create --name alice-laptop \
  --public-url https://cp.example/agentssh
agentssh remote enroll https://cp.example/agentssh --token '<token>'   # --mode managed is the default
agentssh-server config push --device <dev_id> --inventory inventory.yaml --policy policy.yaml

# Day to day
agentssh remote status
agentssh-server log
agentssh-server device revoke <dev_id>
```

The one-time token binds the public endpoint and bundle public-key fingerprint.
The device private key remains local; target SSH private keys remain in the control
plane. Request signatures cover the method, URL and body, with a short validity
window and durable replay protection.

In managed mode:

- **Inventory** comes only from the bundle. Each host needs `addr`, `user` and
  `identity`; local SSH aliases, identity files and password authentication are
  unavailable.
- **Policy** comes from the control plane, with local deny rules applied first.
  Local allow rules are ignored. Configuration edits and host discovery are
  refused; once and session approvals still work.
- **Connections fail closed** when no signature can be obtained. Each command
  establishes a new SSH connection. A cached bundle is usable only until expiry
  (10 minutes by default); running commands check device standing every 30 seconds.

`agentssh remote leave` is operator-gated and removes local device credentials.
See the [remote-control contract](docs/architecture/remote-control.md) for the
wire protocol, trust boundaries, key storage and configuration-version semantics.
Previously enrolled devices require a fresh enrollment, and the reference server
requires a fresh data directory; old state is not automatically migrated.

## Gateway mode (`agentssh-gateway`)

`agentssh-gateway` keeps each device's inventory, policy, approvals, SSH
identities and audit, and runs every command itself. The device only forwards:
`agentssh run` sends the command to the gateway and prints what comes back.
Like `agentssh-server`, it serves a private HTTP origin behind an HTTPS ingress
that preserves the path and streams responses. The gateway must reach every
target host on SSH.

```bash
# On the gateway host. The master password comes from
# AGENTSSH_GATEWAY_MASTER_PASSWORD or a prompt.
agentssh-gateway init
agentssh-gateway identity create web          # public key for target authorized_keys
agentssh-gateway serve --public-url https://gw.example/agentssh
# Default origin: 127.0.0.1:8080, reachable only by the trusted HTTPS ingress.

# Per device
agentssh-gateway device token create --name ci-runner \
  --public-url https://gw.example/agentssh
agentssh remote enroll https://gw.example/agentssh --token '<token>' --mode gateway
agentssh-gateway config push --device <dev_id> --inventory inventory.yaml --policy policy.yaml
agentssh-gateway device activate <dev_id> --for 4h --note 'nightly deploy'
```

A device is usable only while an operator has activated it. It starts
inactive, and `device activate` opens a window of the length you choose (at
most 24h); when the window ends the device is refused again until it is
activated again. `device deactivate <dev_id>` closes the window early. Unlike
`device revoke`, which is permanent, deactivation and the end of a window can
be undone by activating again. An inactive device can still enroll, cancel its
own runs and see its state in `agentssh remote status`; everything else is
refused with a hint to ask the gateway's operator.

Hosts in the pushed inventory need `addr`, `user` and `identity`, as in managed
mode; the gateway keeps host keys in its own `known_hosts`, following the
inventory's `host_key_policy`. On the device, `hosts`, `run`, `status`, `plan`
and `approval status|wait` work as in local mode, with the same output and exit
codes, and the local `inventory.yaml` and `policy.yaml` are ignored. Commands
for state the device no longer keeps (inventory, policy, secrets, approval
decisions, audit, the TUI) exit 2 and name the gateway.

A dropped connection does not stop a command: it keeps running on the gateway,
and the device reattaches and receives the rest of its output. Only Ctrl-C (an
explicit cancel) or the gateway's `--exec-timeout` (30 minutes by default)
stops it.

Approvals are decided on the gateway, never on the device:

```bash
agentssh-gateway approval ls
agentssh-gateway approval grant <approval-id> --once|--session|--task|--host
agentssh-gateway approval deny <approval-id>
agentssh-gateway plan show <plan-id>
agentssh-gateway plan grant <plan-id> --once|--session|--task
```

A host grant adds an allow rule to that device's policy and pushes it as a new
configuration version. Operators away from the gateway host can use its Web UI,
on a listener of its own, with a password and mandatory TOTP:

```bash
agentssh-gateway operator add alice    # password from the TTY, or AGENTSSH_GATEWAY_OPERATOR_PASSWORD
agentssh-gateway serve --public-url https://gw.example/agentssh \
  --web-listen 127.0.0.1:8443 --web-origin https://ops.example
# Without --web-cert/--web-key it speaks plain HTTP for a TLS-terminating proxy
# that browsers reach at --web-origin.
```

Every run and every decision is recorded in the gateway's audit chain, with
the device and the deciding operator:

```bash
agentssh-gateway audit verify
agentssh-gateway device ls                 # with each device's activation window
agentssh-gateway device deactivate <dev_id>
agentssh-gateway device revoke <dev_id>    # for good; the device's next request is refused
```

See [gateway mode](docs/architecture/gateway-mode.md) for the design and its
trade-offs, and the [remote-control contract](docs/architecture/remote-control.md#gateway-mode)
for the gateway's endpoints.

## What the agent calls

These are the only commands an agent needs. They go through inventory resolution, policy, output filtering, and audit:

```bash
agentssh hosts                                   # list targets (name + tags only; no credentials)
agentssh hosts --json
export AGENTSSH_SESSION=$(agentssh session new)  # declare one session per task (required by run)
agentssh run web-1 -- systemctl status nginx
agentssh run web-1 --json -- uptime
agentssh status <req_id>
```

`run` requires a declared session — `--session <id>` or `$AGENTSSH_SESSION` — so each task maps to one auditable session; without one it exits 2. Mint a fresh id per task with `agentssh session new`.

On a connection failure, `run` prints a credential-free hint and exits 9.

## CLI for humans

Everything the console does is also scriptable. Manage hosts and credentials:

```bash
agentssh inventory discover [--probe] [--json] [--import]   # find reachable hosts; --probe really connects
agentssh inventory add web-1 --addr 10.0.0.11 --user deploy --identity-file ~/.ssh/web-1 [--password]
agentssh inventory add                                       # interactive form (TUI)
agentssh inventory update web-1 --addr 10.0.0.12 --tags web,prod
agentssh inventory rm web-1                                  # writes a tamper-evident delete audit record
agentssh inventory ls
agentssh inventory test web-1                                # connectivity check + hint
agentssh secret set|ls|rm <host>
```

Inspect and review:

```bash
agentssh policy show
agentssh policy rule ls
agentssh policy rule add readonly --cmd-regex '^(systemctl status|journalctl|uptime)\b' --action allow --priority 10
agentssh policy rule add no-reboot --cmd-regex '^(sudo )?reboot\b' --action deny --priority 100
agentssh policy rule update no-reboot --cmd-regex '^(sudo )?(reboot|shutdown)\b' --priority 100
agentssh policy rule rm no-reboot
agentssh policy group ls
agentssh policy group add readonly
agentssh policy group rule add readonly --cmd-regex '^(uptime|whoami)\b' --action allow --priority 10
agentssh policy group rule ls readonly
agentssh policy group rule rm readonly 0
agentssh policy group rm readonly
agentssh policy host ls
agentssh policy host rule add web-1 --cmd-regex '^systemctl status\b' --action allow --priority 20
agentssh policy host rule add web-1 --from-group readonly
agentssh policy host rule ls web-1
agentssh policy host rule rm web-1 0
agentssh policy host group rm web-1 readonly
agentssh policy host rm web-1
agentssh policy test --host web-1 'rm -rf /'
agentssh policy test --host web-1 --json -- 'uptime' 'systemctl restart nginx'   # batch pre-check, one call
agentssh audit ls
agentssh audit show <req_id>
agentssh audit verify        # confirm the tamper-evident hash chain is intact
agentssh audit repair --truncate-broken  # remove a broken audit tail after backing it up
agentssh session ls
agentssh session new         # mint a fresh session id for a task
```

`inventory edit` / `policy edit` are still placeholders for opening the raw YAML. Use `inventory add/update/rm`, `policy rule ...`, and `policy host ...` for structured CRUD.

## Transport

By default AgentSSH uses its **built-in Go SSH client** (no system `ssh` binary required). It still reuses ssh-agent, key files, `~/.ssh/config` aliases, and `ProxyJump`, and verifies host keys against `~/.ssh/known_hosts` with **strict** checking — a never-seen host must already be in `known_hosts`, or set `host_key_policy: accept-new` for trust-on-first-use. Set `transport: ssh` (or `AGENTSSH_TRANSPORT=ssh`) to shell out to the system `ssh` client instead.

## Output filtering

Before stdout/stderr return to the agent, AgentSSH applies `policy.output.redact` regex replacements and `policy.output.max_bytes` truncation independently to stdout and stderr. Redacted text becomes `«REDACTED»`. Audit records store the SHA-256 of the filtered bytes that crossed the trust boundary, plus `redactions` and `output_truncated` metadata. Raw unfiltered output is not stored.

## Skills

An Anthropic Agent Skill-style operating manual lives under `skills/`:

- `skills/agentssh-usage/SKILL.md` — best practices and command reference for driving servers through AgentSSH: the trust boundary, one-session-per-task discipline, policy, bounded output, and audit review.

This is procedural knowledge for agents, not an RPC tool: it teaches the agent *how to use `agentssh` well* for whatever the operator asks, while the CLI enforces policy and audit. It is a soft control — it shapes what the agent attempts, but the CLI, not the manual, is the security boundary.

See the project documents for the product and implementation contract:

- `docs/prds/agentssh.md`
- `docs/architecture/overview.md`
- `docs/architecture/ssh-auth-onboarding.md`
- `docs/DESIGN.md`
- `docs/plans/mvp.md`
