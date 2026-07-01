#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

usage() {
  cat <<'EOF'
Usage: scripts/e2e_tui_audit_run_summary.sh [--no-tui]

Creates an isolated AGENTSSH_HOME with a deterministic audit.log and a queue of
pending gray-zone approvals, then opens the real AgentSSH TUI so you can inspect
both the Approvals tab and the per-host Audit (Sessions) viewer.

Options:
  --no-tui   Generate data and print audit ls / verify plus the seeded pending
             approvals, but do not open the TUI.

Environment:
  AGENTSSH_E2E_HOME   Use this directory instead of creating /tmp/agentssh-tui-e2e.*.
  AGENTSSH_BIN        Command used to run AgentSSH. Defaults to: go run ./cmd/agentssh

The generated data is synthetic. audit.log includes a literal denied command
such as "rm -rf /", and the pending approvals are produced by `run` returning
exit 7 in the gray zone; no SSH connection is made and no command is executed.
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
approval:
  enabled: true
  host_grant_mode: safe-prefix
rules:
  - name: catastrophic
    priority: 100
    match: { cmd_regex: 'rm\s+-rf' }
    action: deny
  - name: demo-readonly
    priority: 0
    match: { cmd_regex: '^(echo|systemctl status|uptime)\b' }
    action: allow
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

# Seed the Approvals tab. With approval.enabled: true in policy.yaml, gray-zone
# (default-deny) commands from `run` return exit 7 and write a pending request
# file under approvals/pending/ — no SSH connection is attempted. The commands
# below are chosen to exercise every row marker and consequence the tab renders:
#   - prefix matcher (safe-prefix host-allow would generalize): ls / git / kubectl
#   - exact matcher (host-allow stays this-command-only): systemctl / journalctl
#   - privileged, non-promotable (host scope unavailable): sudo ...
# Each run also appends an approval-requested record to audit.log, so the chain
# stays intact and the events show up in the host Sessions view too.
seed_pending() {
  local sess="$1" host="$2"
  shift 2
  AGENTSSH_HOME="$home" AGENTSSH_SESSION="$sess" \
    bash -lc "$agentssh_cmd run $host -- $*" >/dev/null 2>&1 || true
}

# Start from a clean queue so re-running against a reused AGENTSSH_E2E_HOME keeps
# the seeded set at exactly six (fresh session ids each run would otherwise stack).
rm -rf "$home/approvals"

s_prod="$(AGENTSSH_HOME="$home" bash -lc "$agentssh_cmd session new")"
s_stg="$(AGENTSSH_HOME="$home" bash -lc "$agentssh_cmd session new")"

seed_pending "$s_prod" web-prod-1 systemctl restart nginx
seed_pending "$s_prod" web-prod-1 journalctl -u nginx -n 100
seed_pending "$s_prod" web-prod-1 sudo systemctl restart nginx
seed_pending "$s_stg" web-staging-1 ls -la /var/log/nginx
seed_pending "$s_stg" web-staging-1 git status
seed_pending "$s_stg" web-staging-1 kubectl get pods -n prod

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

echo "Seeded pending approvals (adjudicate these in the Approvals tab):"
# `approval ls` requires an operator TTY, so read the pending files directly here.
python3 - "$home/approvals/pending" <<'PY'
import glob
import json
import os
import sys

pending_dir = sys.argv[1]
rows = []
for path in sorted(glob.glob(os.path.join(pending_dir, "*.json"))):
    with open(path, encoding="utf-8") as fh:
        req = json.load(fh)
    cand = req["candidate_matcher"]
    if not cand.get("promotable", False):
        kind = "priv"       # host scope unavailable
    elif cand["kind"] == "prefix":
        kind = "prefix"     # host-allow generalizes to "<prefix> *"
    else:
        kind = "exact"      # host-allow stays this-command-only
    rows.append((req["host"], req["cmd"], kind))

if not rows:
    print("  (none)")
else:
    for host, cmd, kind in rows:
        print(f"  {host:<14} {kind:<6} {cmd}")
PY
echo

cat <<EOF
Manual TUI checklist:

Approvals tab (async gray-zone adjudication):
  1. TUI opens on Hosts. Press "3" to switch to Approvals.
  2. The queue should list 6 pending requests, one line each: id / host / command
     / a kind marker (prefix rows have no marker, "exact" or "priv" otherwise).
  3. Move with j/k. For the focused row, the consequence line below the list
     states exactly what an [h] host-allow would free:
       - "ls -la ..." (prefix)       -> host-allow frees "ls *"
       - "systemctl restart nginx"   -> host-allow stays this exact command
       - "sudo systemctl restart .."  -> [h] unavailable (privileged)
  4. Press "s" (session) on one row: it disappears and a toast confirms; a re-run
     of that exact command in the same session would now be allowed.
  5. Press "h" (host) on a prefix row (e.g. the git or kubectl one): a generated
     approval/... rule is written to policy.yaml. Press "2" (Policy) to see it.
  6. Press "h" on the "sudo ..." row: it is refused (privileged, non-promotable).
  7. Press "d" to deny a row; press "r" to refresh the queue.

Audit (per-host session viewer):
  8. Press "1" (Hosts), select a host, press Enter to open its detail.
  9. Open the Sessions pane: sessions are shown newest-first, one row per command
     (not per raw record). The denied "rm -rf /" shows exit 6 / not executed.
 10. Approval-requested events seeded above appear here too. Press "q" to exit.
EOF

if [[ "$open_tui" -eq 0 ]]; then
  exit 0
fi

echo
echo "Opening TUI..."
echo
AGENTSSH_HOME="$home" bash -lc "$agentssh_cmd tui"
