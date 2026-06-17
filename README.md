# AgentSSH

AgentSSH is a local, single-binary SSH gateway for AI agents. It keeps SSH credentials and policy enforcement on the human-controlled machine, exposes only a constrained CLI to agents, and records operations in an append-only audit log.

AgentSSH uses standard SSH from the local machine and does not require any agent or daemon on remote hosts. AI agents call `agentssh`; credentials stay in ssh-agent, `~/.ssh/config`, and the local operator environment.

## Install

Build the single binary:

```bash
go build -o agentssh ./cmd/agentssh
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

Review and verify activity:

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

`inventory edit` and `policy edit` are command placeholders for the MVP.

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
