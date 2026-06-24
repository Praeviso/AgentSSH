---
name: investigate-cpu
description: Investigate high CPU on an AgentSSH managed host using mostly read-only commands.
---

# Investigate High CPU

Use this skill when the user reports high CPU, load average, slow responses, or a suspected runaway process on a managed host.

## Principles

- Prefer read-only commands. Do not kill or restart processes until the operator explicitly confirms the plan.
- Keep output bounded. Ask for narrower checks instead of dumping huge logs.
- Treat policy `deny` as final. Do not try alternate syntax to bypass a denied command.

## Flow

1. Confirm the host or group:

```bash
agentssh hosts
```

2. Check load and CPU summary:

```bash
agentssh run <host> -- uptime
agentssh run <host> -- top -b -n 1 -o %CPU | head -40
```

3. Identify the hottest processes:

```bash
agentssh run <host> -- ps -eo pid,ppid,user,stat,pcpu,pmem,comm,args --sort=-pcpu | head -25
```

4. If a service is implicated, inspect its status and recent logs:

```bash
agentssh run <host> -- systemctl status <service>
agentssh run <host> -- journalctl -u <service> -n 80 --no-pager
```

5. If the cause is unclear, collect narrow system context:

```bash
agentssh run <host> -- vmstat 1 5
agentssh run <host> -- df -h
```

6. Before any state-changing action, summarize evidence, likely risk, and the exact command you intend to run.

## Notes

- Do not run broad recursive searches or destructive cleanup as part of initial CPU diagnosis.
- If output contains secrets, AgentSSH output filtering may redact it before it enters the model context.
- Final answers should include the suspected process/service, supporting command outputs, and any relevant request ids for audit review.
