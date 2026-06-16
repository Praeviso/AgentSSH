# AgentSSH

AgentSSH is a local, single-binary SSH gateway for AI agents. It keeps SSH credentials and policy enforcement on the human-controlled machine, exposes only a constrained CLI to agents, and records operations in an append-only audit log.

This repository is currently at the M0 scaffold stage: module layout, CLI command skeletons, configuration loading contracts, and core audit/policy types are in place. SSH execution, policy evaluation, audit persistence, output filtering, and the TUI are planned for later MVP milestones.

See the project documents for the product and implementation contract:

- `docs/prds/agentssh.md`
- `docs/architecture/overview.md`
- `docs/DESIGN.md`
- `docs/plans/mvp.md`
