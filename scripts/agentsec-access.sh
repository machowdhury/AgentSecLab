#!/bin/sh
# Print how to open AgentSec. Does not change ports, firewalls, or secrets.
set -eu

ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
cd "$ROOT"

log() { printf '%s\n' "$*"; }

load_env_value() {
  key="$1"
  if [ ! -f "$ROOT/.env" ]; then
    return 0
  fi
  python3 - "$ROOT/.env" "$key" <<'PY'
from pathlib import Path
import sys
path, key = Path(sys.argv[1]), sys.argv[2]
for raw in path.read_text(encoding="utf-8").splitlines():
    line = raw.strip()
    if not line or line.startswith("#") or "=" not in line:
        continue
    name, value = line.split("=", 1)
    if name.strip() == key:
        print(value.strip().strip('"').strip("'"), end="")
        break
PY
}

if [ -z "${AGENTSEC_PUBLIC_HOST:-}" ]; then
  from_file="$(load_env_value AGENTSEC_PUBLIC_HOST || true)"
  if [ -n "${from_file:-}" ]; then
    AGENTSEC_PUBLIC_HOST="$from_file"
    export AGENTSEC_PUBLIC_HOST
  fi
fi

MODE="${AGENTSEC_DEPLOYMENT:-}"
if [ -z "$MODE" ]; then
  MODE="$(load_env_value AGENTSEC_DEPLOYMENT || true)"
fi
if [ "$MODE" != "remote" ]; then
  MODE="local"
fi

log "AGENTSEC ACCESS"
log "Deployment mode: $(printf '%s' "$MODE" | tr '[:lower:]' '[:upper:]')"

if [ "$MODE" = "local" ]; then
  log "Open on this computer:"
  log "Academy: http://127.0.0.1:8000/en-US/app/agentsec/ws_agentsec_home"
  log "Attack Service: http://127.0.0.1:5001"
  log "AcmeBank health stays on this computer: http://127.0.0.1:5000/health"
  exit 0
fi

HOST="$(python3 "$ROOT/scripts/agentsec_access.py" public-host --metadata || true)"
if [ -n "$HOST" ]; then
  log "AgentSec Academy:"
  log "http://${HOST}:8000/en-US/app/agentsec/ws_agentsec_home"
  log "Attack Service:"
  log "http://${HOST}:5001"
else
  log "AgentSec is using remote bindings, and no public host was configured or discovered."
  log "Open:"
  log "http://<your-server-public-ip>:8000/en-US/app/agentsec/ws_agentsec_home"
  log "Attack Service:"
  log "http://<your-server-public-ip>:5001"
  log "Set AGENTSEC_PUBLIC_HOST to your public IP or DNS name to print a concrete URL."
fi
log "Internal readiness URL on this server: http://127.0.0.1:8000/en-US/app/agentsec/ws_agentsec_home"
log "External browser reachability: NOT MEASURED"
log "Your host or cloud firewall must permit TCP 8000 and TCP 5001 only from trusted learner IPs."
log "Do not open 8000, 5001, 5000, 8088, or 11434 to 0.0.0.0/0."
log "Academy and Attack Service links use the host in the browser address bar. They do not assume the learner browser is on this server."
exit 0
