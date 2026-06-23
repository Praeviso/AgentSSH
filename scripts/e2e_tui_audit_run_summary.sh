#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

usage() {
  cat <<'EOF'
Usage: scripts/e2e_tui_audit_run_summary.sh [--no-tui]

Creates an isolated AGENTSSH_HOME with a deterministic audit.log, then opens the
real AgentSSH TUI so you can inspect the Audit tab's session-first behavior.

Options:
  --no-tui   Generate data and print audit ls / verify output, but do not open TUI.

Environment:
  AGENTSSH_E2E_HOME   Use this directory instead of creating /tmp/agentssh-tui-e2e.*.
  AGENTSSH_BIN        Command used to run AgentSSH. Defaults to: go run ./cmd/agentssh

The generated audit data is synthetic. It includes a literal denied command such
as "rm -rf /" in audit.log, but the command is never executed.
EOF
}

open_tui=1
case "${1:-}" in
  "")
    ;;
  "--no-tui")
    open_tui=0
    ;;
  "-h"|"--help")
    usage
    exit 0
    ;;
  *)
    usage >&2
    exit 2
    ;;
esac

home="${AGENTSSH_E2E_HOME:-}"
if [[ -z "$home" ]]; then
  home="$(mktemp -d /tmp/agentssh-tui-e2e.XXXXXX)"
else
  mkdir -p "$home"
fi

agentssh_cmd="${AGENTSSH_BIN:-go run ./cmd/agentssh}"

cat > "$home/inventory.yaml" <<'YAML'
version: 1
host_key_policy: strict
hosts:
  web-prod-1:
    addr: 10.0.0.11
    user: deploy
    tags: [web, prod]
  web-staging-1:
    addr: 10.0.1.21
    user: deploy
    tags: [web, staging]
groups:
  web: { tags: [web] }
  prod: { tags: [prod] }
YAML

cat > "$home/policy.yaml" <<'YAML'
version: 1
defaults:
  policy: allow
rules:
  - name: catastrophic
    match: { cmd_regex: 'rm\s+-rf' }
    action: deny
output:
  max_bytes: 24
  redact:
    - 'password=\S+'
YAML

python3 - "$home/audit.log" <<'PY'
import hashlib
import json
import sys
from collections import OrderedDict

path = sys.argv[1]
zero = "0" * 64

def output_hash(stdout="", stderr=""):
    return hashlib.sha256((stdout + stderr).encode("utf-8")).hexdigest()

def canonical(record):
    fields = OrderedDict()
    fields["seq"] = record["seq"]
    fields["ts"] = record["ts"]
    fields["req_id"] = record["req_id"]
    fields["session_id"] = record["session_id"]
    fields["session_label"] = record["session_label"]
    fields["event"] = record["event"]
    fields["agent"] = record["agent"]
    fields["host"] = record["host"]
    fields["cmd"] = record["cmd"]
    fields["policy_action"] = record["policy_action"]
    fields["policy_rule"] = record["policy_rule"]
    if record.get("exit_code") is not None:
        fields["exit_code"] = record["exit_code"]
    fields["output_sha256"] = record["output_sha256"]
    fields["output_truncated"] = record["output_truncated"]
    fields["redactions"] = record["redactions"]
    fields["duration_ms"] = record["duration_ms"]
    fields["prev_hash"] = record["prev_hash"]
    return json.dumps(fields, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

def make_record(seq, ts, req, session, label, event, host, cmd, action, rule, *,
                exit_code=None, stdout="", stderr="", truncated=False,
                redactions=0, duration_ms=0, prev_hash=zero):
    record = OrderedDict()
    record["seq"] = seq
    record["ts"] = ts
    record["req_id"] = req
    record["session_id"] = session
    record["session_label"] = label
    record["event"] = event
    record["agent"] = "codex-e2e"
    record["host"] = host
    record["cmd"] = cmd
    record["policy_action"] = action
    record["policy_rule"] = rule
    if exit_code is not None:
        record["exit_code"] = exit_code
    record["output_sha256"] = output_hash(stdout, stderr) if (stdout or stderr) else ""
    record["output_truncated"] = truncated
    record["redactions"] = redactions
    record["duration_ms"] = duration_ms
    record["prev_hash"] = prev_hash
    digest = hashlib.sha256(prev_hash.encode("utf-8") + canonical(record)).hexdigest()
    record["hash"] = digest
    return record

records = []
prev = zero

fixtures = [
    dict(ts="2026-06-23T08:31:01Z", req="r_ok_01", session="s_incident",
         label="incident: nginx 502", event="started", host="web-prod-1",
         cmd="systemctl status nginx", action="allow", rule="default"),
    dict(ts="2026-06-23T08:31:03Z", req="r_ok_01", session="s_incident",
         label="incident: nginx 502", event="completed", host="web-prod-1",
         cmd="systemctl status nginx", action="allow", rule="default",
         exit_code=0, stdout="nginx active\n", duration_ms=1800),
    dict(ts="2026-06-23T08:32:10Z", req="r_redact_02", session="s_incident",
         label="incident: nginx 502", event="started", host="web-prod-1",
         cmd="journalctl -u nginx -n 80 --no-pager", action="allow", rule="default"),
    dict(ts="2026-06-23T08:32:15Z", req="r_redact_02", session="s_incident",
         label="incident: nginx 502", event="completed", host="web-prod-1",
         cmd="journalctl -u nginx -n 80 --no-pager", action="allow", rule="default",
         exit_code=0, stdout="password=REDACTED\ntruncated log\n", truncated=True,
         redactions=2, duration_ms=4200),
    dict(ts="2026-06-23T08:33:20Z", req="r_deny_03", session="s_incident",
         label="incident: nginx 502", event="denied", host="web-prod-1",
         cmd="rm -rf /", action="deny", rule="rules:catastrophic"),
    dict(ts="2026-06-23T09:04:01Z", req="r_fail_04", session="s_followup",
         label="restart follow-up", event="started", host="web-staging-1",
         cmd="sudo systemctl restart nginx", action="allow", rule="default"),
    dict(ts="2026-06-23T09:04:07Z", req="r_fail_04", session="s_followup",
         label="restart follow-up", event="failed", host="web-staging-1",
         cmd="sudo systemctl restart nginx", action="allow", rule="default",
         exit_code=1, stderr="Job failed\n", duration_ms=6100),
    dict(ts="2026-06-23T09:10:00Z", req="r_live_05", session="s_followup",
         label="restart follow-up", event="started", host="web-staging-1",
         cmd="tail -f /var/log/nginx/error.log", action="allow", rule="default"),
]

for i, item in enumerate(fixtures):
    rec = make_record(i, prev_hash=prev, **item)
    records.append(rec)
    prev = rec["hash"]

with open(path, "w", encoding="utf-8") as fh:
    for rec in records:
        fh.write(json.dumps(rec, separators=(",", ":"), ensure_ascii=False))
        fh.write("\n")
PY

echo "AgentSSH TUI audit-session-first E2E"
echo "  AGENTSSH_HOME=$home"
echo "  AgentSSH command: $agentssh_cmd"
echo
echo "Seeded audit records:"
AGENTSSH_HOME="$home" bash -lc "$agentssh_cmd audit ls"
echo
echo "Hash-chain verification:"
AGENTSSH_HOME="$home" bash -lc "$agentssh_cmd audit verify"
echo

cat <<EOF
Manual TUI checklist:
  1. TUI opens on Hosts. Press "2" to switch to Audit.
  2. Audit should show sessions only, sorted by latest update time.
  3. Session "s_incident" should show 3 commands, not 5 records.
  4. Press Enter on "s_incident"; the detail should list command results only.
  5. The denied command should show exit 6 / not executed semantics.
  6. Raw record evidence such as seq/hash/Event chain should not appear in TUI detail.
  7. Press "/" then type "status:started" and Enter. Only the live session should remain.
  8. Press Esc to clear the filter, then press "q" to exit.
EOF

if [[ "$open_tui" -eq 0 ]]; then
  exit 0
fi

echo
echo "Opening TUI..."
echo
AGENTSSH_HOME="$home" bash -lc "$agentssh_cmd tui"
