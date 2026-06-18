# AgentSSH

AgentSSH is a local, single-binary SSH gateway for AI agents. It keeps SSH credentials and policy enforcement on the human-controlled machine, exposes only a constrained CLI to agents, and records operations in an append-only audit log.

AgentSSH uses standard SSH from the local machine and does not require any agent or daemon on remote hosts. AI agents call `agentssh`; credentials stay in ssh-agent, `~/.ssh/config`, and the local operator environment.

## Quick Start

```bash
# 1. Install — download the static binary for your platform (no Go required).
#    Linux x86_64 shown; see "Install" below for macOS and arm64.
curl -fsSL https://github.com/Praeviso/AgentSSH/releases/download/v0.3.0/agentssh_v0.3.0_linux_amd64.tar.gz \
  | sudo tar xz --strip-components=1 -C /usr/local/bin agentssh_v0.3.0_linux_amd64/agentssh

# 2. Add a host. Run with no flags to open an interactive form, or pass flags
#    to script it. Auth reuses your existing ssh-agent / ~/.ssh/config —
#    AgentSSH stores no keys of its own.
agentssh inventory add                                       # interactive TUI form
agentssh inventory add web-1 --addr 10.0.0.11 --user deploy --tags prod

# 3. Define a deny rule (hard, unoverridable boundary):
mkdir -p ~/.agentssh
cat > ~/.agentssh/policy.yaml <<'EOF'
version: 1
defaults: { policy: allow }
rules:
  - name: catastrophic
    match: { cmd_regex: '\b(rm\s+-rf|mkfs|dd|shutdown|reboot)' }
    action: deny
EOF

# 4. The agent calls agentssh — every command is policy-checked and audited:
agentssh hosts                                 # discover targets (no credentials shown)
agentssh run web-1 -- systemctl status nginx   # allowed -> executed over SSH
agentssh run web-1 -- rm -rf /                 # denied by policy -> exit 6, never runs

# 5. The human reviews everything:
agentssh tui            # unified console: Hosts, Audit, Policy, Sessions
agentssh audit verify   # confirm the tamper-evident hash chain is intact
```

That is the whole loop: the agent only ever calls `agentssh`, while the human owns the config and the audit trail. The sections below cover full configuration and the complete command set.

## Install

### Prebuilt binary (recommended — no Go needed)

The release ships a single static binary per platform (`CGO_ENABLED=0`, no
runtime dependencies). Pick yours — each is one command that drops `agentssh`
into `/usr/local/bin`:

```bash
# Linux x86_64
curl -fsSL https://github.com/Praeviso/AgentSSH/releases/download/v0.3.0/agentssh_v0.3.0_linux_amd64.tar.gz \
  | sudo tar xz --strip-components=1 -C /usr/local/bin agentssh_v0.3.0_linux_amd64/agentssh

# Linux arm64
curl -fsSL https://github.com/Praeviso/AgentSSH/releases/download/v0.3.0/agentssh_v0.3.0_linux_arm64.tar.gz \
  | sudo tar xz --strip-components=1 -C /usr/local/bin agentssh_v0.3.0_linux_arm64/agentssh

# macOS Apple Silicon (arm64)
curl -fsSL https://github.com/Praeviso/AgentSSH/releases/download/v0.3.0/agentssh_v0.3.0_darwin_arm64.tar.gz \
  | sudo tar xz --strip-components=1 -C /usr/local/bin agentssh_v0.3.0_darwin_arm64/agentssh

# macOS Intel (amd64)
curl -fsSL https://github.com/Praeviso/AgentSSH/releases/download/v0.3.0/agentssh_v0.3.0_darwin_amd64.tar.gz \
  | sudo tar xz --strip-components=1 -C /usr/local/bin agentssh_v0.3.0_darwin_amd64/agentssh
```

Verify it: `agentssh --version`. (Bump `v0.3.0` to install a different release;
checksums for every asset are in `SHA256SUMS.txt` on the Releases page.)

### From source (needs Go matching the go.mod directive)

```bash
go install github.com/Praeviso/AgentSSH/cmd/agentssh@latest   # into $GOBIN
go build -o agentssh ./cmd/agentssh                           # single binary from a checkout
```

Put the binary on the local operator machine where SSH already works.

## Configure

AgentSSH reads `~/.agentssh/` by default. Set `AGENTSSH_HOME` to use another directory.

Minimum files:

```text
~/.agentssh/
  inventory.yaml
  policy.yaml
  audit.log      # created automatically
  session        # created automatically
```

Example `inventory.yaml`:

```yaml
version: 1
hosts:
  web-1:
    addr: 10.0.0.11
    user: deploy
    tags: [web, prod]
groups:
  prod: { tags: [prod] }
```

### Transport

By default AgentSSH connects with its **built-in Go SSH client** (no system
`ssh` binary required). It still reuses your ssh-agent, key files, `~/.ssh/config`
aliases, and `ProxyJump`, and verifies host keys against `~/.ssh/known_hosts`
with **strict** checking — a host you have never connected to must already be in
`known_hosts`, or set `host_key_policy: accept-new` to trust on first use.

```yaml
version: 1
transport: native            # default; use "ssh" to shell out to the system ssh client
host_key_policy: strict      # or "accept-new" for trust-on-first-use
hosts:
  web-1: { addr: 10.0.0.11, user: deploy, tags: [prod] }
```

Override per-invocation with `AGENTSSH_TRANSPORT=ssh|native`.

Example `policy.yaml`:

```yaml
version: 1
defaults:
  policy: allow
rules:
  - name: catastrophic
    match: { cmd_regex: '\b(rm\s+-rf|mkfs|dd|shutdown|reboot|init\s+0|userdel)' }
    action: deny
output:
  max_bytes: 16384
  redact:
    - '(?i)(password|passwd|secret|token)\s*[=:]\s*\S+'
```

## Agent Commands

List available targets without exposing credentials:

```bash
agentssh hosts
agentssh hosts --json
```

Run a command through inventory resolution, policy, output filtering, and audit:

```bash
agentssh run web-1 --skill restart-service -- systemctl status nginx
agentssh run web-1 --json -- uptime
agentssh status <req_id>
```

`--skill <name>` links the run to a playbook in audit records and the TUI.

## Human Commands

Open the unified console (Hosts / Audit / Policy / Sessions in one full-screen app), or use the individual subcommands:

```bash
agentssh tui
agentssh audit ls
agentssh audit show <req_id>
agentssh audit verify
agentssh session ls
```

Inspect and test policy:

```bash
agentssh policy show
agentssh policy test --host web-1 'rm -rf /'
```

Manage inventory from the CLI (or do it visually in `agentssh tui`):

```bash
agentssh inventory add          # interactive form
agentssh inventory ls
```

`inventory edit` and `policy edit` are still placeholders — edit
`~/.agentssh/inventory.yaml` / `policy.yaml` directly for now.

## Output Filtering

Before stdout/stderr return to the agent, AgentSSH applies `policy.output.redact` regex replacements and `policy.output.max_bytes` truncation independently to stdout and stderr. Redacted text is replaced with `«REDACTED»`. Audit records store the SHA-256 of the filtered bytes that crossed the trust boundary, plus `redactions` and `output_truncated` metadata. Raw unfiltered output is not stored by AgentSSH.

## Skills

Example Anthropic Agent Skill-style playbooks live under `skills/`:

- `skills/restart-service/SKILL.md` guides safe systemd service diagnosis and restart.
- `skills/investigate-cpu/SKILL.md` guides mostly read-only high-CPU investigation.

These files are procedural knowledge for agents, not RPC tools. They instruct agents to call `agentssh run --skill <name> ...` while the CLI enforces policy and audit.

See the project documents for the product and implementation contract:

- `docs/prds/agentssh.md`
- `docs/architecture/overview.md`
- `docs/DESIGN.md`
- `docs/plans/mvp.md`
