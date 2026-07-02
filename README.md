# AgentSSH

AgentSSH is a local, single-binary SSH gateway for AI agents. It keeps SSH credentials and policy enforcement on the human-controlled machine, exposes only a constrained CLI to agents, and records every operation in a tamper-evident audit log.

Two principals, one binary:

- **You (the operator)** drive everything from one full-screen console — `agentssh tui` — to onboard hosts, register credentials, test connectivity, tune policy, and review the audit trail.
- **The agent** only ever calls `agentssh run` / `agentssh hosts`. It never sees addresses, keys, or passwords — those stay in your ssh-agent, `~/.ssh/`, and an encrypted local store.

AgentSSH uses standard SSH from the local machine (its built-in Go SSH client by default) and needs no agent or daemon on remote hosts.

## Quick Start

```bash
# 1. Install — static binary, no Go required (see "Install" for macOS / arm64).
curl -fsSL https://github.com/Praeviso/AgentSSH/releases/download/v0.8.0/agentssh_v0.8.0_linux_amd64.tar.gz \
  | sudo tar xz --strip-components=1 -C /usr/local/bin agentssh_v0.8.0_linux_amd64/agentssh

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
curl -fsSL https://github.com/Praeviso/AgentSSH/releases/download/v0.8.0/agentssh_v0.8.0_linux_amd64.tar.gz \
  | sudo tar xz --strip-components=1 -C /usr/local/bin agentssh_v0.8.0_linux_amd64/agentssh

# Linux arm64
curl -fsSL https://github.com/Praeviso/AgentSSH/releases/download/v0.8.0/agentssh_v0.8.0_linux_arm64.tar.gz \
  | sudo tar xz --strip-components=1 -C /usr/local/bin agentssh_v0.8.0_linux_arm64/agentssh

# macOS Apple Silicon (arm64)
curl -fsSL https://github.com/Praeviso/AgentSSH/releases/download/v0.8.0/agentssh_v0.8.0_darwin_arm64.tar.gz \
  | sudo tar xz --strip-components=1 -C /usr/local/bin agentssh_v0.8.0_darwin_arm64/agentssh

# macOS Intel (amd64)
curl -fsSL https://github.com/Praeviso/AgentSSH/releases/download/v0.8.0/agentssh_v0.8.0_darwin_amd64.tar.gz \
  | sudo tar xz --strip-components=1 -C /usr/local/bin agentssh_v0.8.0_darwin_amd64/agentssh
```

Verify: `agentssh --version`. (Bump `v0.8.0` for a different release; checksums are in `SHA256SUMS.txt` on the Releases page.)

### From source (needs Go matching the go.mod directive)

```bash
go install github.com/Praeviso/AgentSSH/cmd/agentssh@latest   # into $GOBIN
go build -o agentssh ./cmd/agentssh                           # single binary from a checkout
```

Put the binary on the local operator machine where SSH already works.

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
