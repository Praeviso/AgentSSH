---
name: restart-service
description: Diagnose and safely restart a systemd service on an AgentSSH managed host.
---

# Restart A Systemd Service

Use this skill when a service appears unhealthy and the operator wants a careful, auditable restart through `agentssh`.

## Principles

- Start with read-only diagnosis. Do not restart first.
- Use `agentssh hosts` to confirm the target host or group name before running commands.
- Treat policy `deny` as final. Do not retry the same denied command or try to bypass policy.
- Before a state-changing command such as `restart` or `reload`, summarize the diagnosis and rely on the agent harness/operator confirmation flow.

## Flow

1. Identify the host and service name from the user request.
2. Check service state:

```bash
agentssh run <host> -- systemctl status <service>
```

3. Check recent logs, keeping output small:

```bash
agentssh run <host> -- journalctl -u <service> -n 80 --no-pager
```

4. If the service is clearly failed or wedged, explain what you found and restart:

```bash
agentssh run <host> -- sudo systemctl restart <service>
```

5. Verify recovery:

```bash
agentssh run <host> -- systemctl status <service>
```

6. If restart fails, collect focused follow-up evidence:

```bash
agentssh run <host> -- journalctl -u <service> -n 120 --no-pager
```

## Notes

- Prefer `status`, `journalctl`, `reload`, and `restart` over broad shell exploration.
- Avoid destructive cleanup commands. AgentSSH policy may deny dangerous commands, and that denial is the safety boundary.
- Include the returned request ids in the final summary when helpful so the operator can inspect `agentssh audit show <req_id>` or `agentssh tui`.
