#!/bin/sh
# Verify the LOCAL Docker lab is actually usable. Exit 0 only when required
# pieces respond. Does not print secrets. Does not claim Splunk authorized a loan.
set -eu

ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
cd "$ROOT"

log() { printf '[lab-ready] %s\n' "$*"; }

fail() {
  log "NOT READY: $*"
  exit 1
}

load_env_value() {
  key="$1"
  if [ ! -f "$ROOT/.env" ]; then
    return 0
  fi
  # Read KEY=value from .env without sourcing the whole file into the shell history dump.
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

require_container() {
  name="$1"
  state="$(docker inspect -f '{{.State.Status}}' "$name" 2>/dev/null || true)"
  if [ "$state" != "running" ] && [ "$state" != "exited" ]; then
    fail "container ${name} is not present (state='${state}')"
  fi
  if [ "$name" != "agentsec_splunk_app_init" ] && [ "$name" != "agentsec_splunk_hec_init" ] && [ "$state" != "running" ]; then
    fail "container ${name} is not running (state='${state}')"
  fi
}

log "Checking required containers..."
require_container agentsec_splunk
require_container agentsec_otel_collector
require_container agentsec_acmebank
require_container agentsec_attack_service
require_container agentsec_ollama

init_state="$(docker inspect -f '{{.State.Status}} {{.State.ExitCode}}' agentsec_splunk_app_init 2>/dev/null || true)"
case "$init_state" in
  "exited 0") log "splunk_app_init completed successfully." ;;
  *) fail "splunk_app_init did not complete successfully (state='${init_state}')" ;;
esac

hec_state="$(docker inspect -f '{{.State.Status}} {{.State.ExitCode}}' agentsec_splunk_hec_init 2>/dev/null || true)"
case "$hec_state" in
  "exited 0") log "splunk_hec_init completed successfully." ;;
  *) fail "splunk_hec_init did not complete successfully (state='${hec_state}')" ;;
esac

health="$(docker inspect -f '{{.State.Health.Status}}' agentsec_splunk 2>/dev/null || true)"
if [ "$health" != "healthy" ]; then
  fail "Splunk health is '${health}', not healthy"
fi

log "Checking AgentSec app files inside Splunk..."
docker exec agentsec_splunk bash -lc 'test -f /opt/splunk/etc/apps/agentsec/default/app.conf'
docker exec agentsec_splunk bash -lc 'test -f /opt/splunk/etc/apps/agentsec/default/indexes.conf'
docker exec agentsec_splunk bash -lc 'test -f /opt/splunk/etc/apps/agentsec/default/data/ui/views/ws_lab_pi_001.xml'
docker exec agentsec_splunk bash -lc 'test -f /opt/splunk/etc/apps/agentsec/default/data/ui/views/ws_lab_mcp_001.xml'
docker exec agentsec_splunk bash -lc 'test -f /opt/splunk/etc/apps/agentsec/default/data/ui/views/ws_lab_mcp_003.xml'
docker exec agentsec_splunk bash -lc 'test -f /opt/splunk/etc/apps/agentsec/default/data/ui/views/ws_lab_mcp_004.xml'
docker exec agentsec_splunk bash -lc 'test -f /opt/splunk/etc/apps/agentsec/default/data/ui/nav/default.xml'
log "AgentSec app, ws_lab_pi_001.xml, ws_lab_mcp_001.xml, ws_lab_mcp_003.xml, and ws_lab_mcp_004.xml are present."

login_code="$(curl -sS -o /dev/null -w "%{http_code}" --max-time 15 http://127.0.0.1:8000/en-US/account/login || echo 000)"
if [ "$login_code" != "200" ]; then
  fail "Splunk login page HTTP ${login_code}"
fi
log "Splunk Web login page HTTP 200."

SPLUNK_PASSWORD="$(load_env_value SPLUNK_PASSWORD)"
HEC_TOKEN="$(load_env_value SPLUNK_HEC_TOKEN)"
if [ -z "${SPLUNK_PASSWORD}" ] || [ -z "${HEC_TOKEN}" ]; then
  fail "SPLUNK_PASSWORD and SPLUNK_HEC_TOKEN must be set in .env"
fi

log "Checking index agentsec_telemetry..."
idx_code="$(
  docker exec -u splunk -e SPLUNK_PASSWORD="$SPLUNK_PASSWORD" agentsec_splunk bash -lc \
    'curl -sk -u "admin:${SPLUNK_PASSWORD}" -o /dev/null -w "%{http_code}" https://127.0.0.1:8089/services/data/indexes/agentsec_telemetry'
)"
if [ "$idx_code" != "200" ]; then
  fail "index agentsec_telemetry HTTP ${idx_code}"
fi
log "Index agentsec_telemetry exists."

log "Checking HEC..."
hec_code="$(
  curl -sS -o /dev/null -w "%{http_code}" --max-time 15 \
    http://127.0.0.1:8088/services/collector/health/1.0 || echo 000
)"
if [ "$hec_code" != "200" ]; then
  fail "HEC health HTTP ${hec_code}"
fi
log "HEC health HTTP 200."

log "Checking OTel collector can reach HEC on the mesh..."
mesh_net="$(docker inspect -f '{{range $name, $_ := .NetworkSettings.Networks}}{{$name}}{{end}}' agentsec_otel_collector 2>/dev/null || true)"
if [ -z "$mesh_net" ]; then
  fail "could not resolve collector compose network"
fi
mesh_code="$(
  docker run --rm --network "$mesh_net" \
    curlimages/curl:8.5.0 \
    curl -sS -o /dev/null -w "%{http_code}" --max-time 15 \
      http://splunk:8088/services/collector/health/1.0 || echo 000
)"
if [ "$mesh_code" != "200" ]; then
  fail "collector-mesh HEC health HTTP ${mesh_code}"
fi
log "Mesh HEC health from a collector-network client HTTP 200."

log "Checking Dashboard Studio view is loaded..."
view_code="$(
  docker exec -u splunk -e SPLUNK_PASSWORD="$SPLUNK_PASSWORD" agentsec_splunk bash -lc \
    'curl -sk -u "admin:${SPLUNK_PASSWORD}" -o /tmp/ws_lab_pi_001_view.xml -w "%{http_code}" https://127.0.0.1:8089/servicesNS/nobody/agentsec/data/ui/views/ws_lab_pi_001'
)"
if [ "$view_code" != "200" ]; then
  fail "view ws_lab_pi_001 HTTP ${view_code}"
fi
if ! docker exec agentsec_splunk bash -lc 'grep -q "ws_lab_pi_001\|LAB-PI-001" /tmp/ws_lab_pi_001_view.xml'; then
  fail "view payload did not mention LAB-PI-001 / ws_lab_pi_001"
fi
log "Dashboard view ws_lab_pi_001 is available via Splunk REST."

mcp_view_code="$(
  docker exec -u splunk -e SPLUNK_PASSWORD="$SPLUNK_PASSWORD" agentsec_splunk bash -lc \
    'curl -sk -u "admin:${SPLUNK_PASSWORD}" -o /tmp/ws_lab_mcp_001_view.xml -w "%{http_code}" https://127.0.0.1:8089/servicesNS/nobody/agentsec/data/ui/views/ws_lab_mcp_001'
)"
if [ "$mcp_view_code" != "200" ]; then
  fail "view ws_lab_mcp_001 HTTP ${mcp_view_code}"
fi
if ! docker exec agentsec_splunk bash -lc 'grep -q "ws_lab_mcp_001\|LAB-MCP-001" /tmp/ws_lab_mcp_001_view.xml'; then
  fail "view payload did not mention LAB-MCP-001 / ws_lab_mcp_001"
fi
log "Dashboard view ws_lab_mcp_001 is available via Splunk REST."

mcp003_view_code="$(
  docker exec -u splunk -e SPLUNK_PASSWORD="$SPLUNK_PASSWORD" agentsec_splunk bash -lc \
    'curl -sk -u "admin:${SPLUNK_PASSWORD}" -o /tmp/ws_lab_mcp_003_view.xml -w "%{http_code}" https://127.0.0.1:8089/servicesNS/nobody/agentsec/data/ui/views/ws_lab_mcp_003'
)"
if [ "$mcp003_view_code" != "200" ]; then
  fail "view ws_lab_mcp_003 HTTP ${mcp003_view_code}"
fi
if ! docker exec agentsec_splunk bash -lc 'grep -q "ws_lab_mcp_003\|LAB-MCP-003" /tmp/ws_lab_mcp_003_view.xml'; then
  fail "view payload did not mention LAB-MCP-003 / ws_lab_mcp_003"
fi
log "Dashboard view ws_lab_mcp_003 is available via Splunk REST."

mcp004_view_code="$(
  docker exec -u splunk -e SPLUNK_PASSWORD="$SPLUNK_PASSWORD" agentsec_splunk bash -lc \
    'curl -sk -u "admin:${SPLUNK_PASSWORD}" -o /tmp/ws_lab_mcp_004_view.xml -w "%{http_code}" https://127.0.0.1:8089/servicesNS/nobody/agentsec/data/ui/views/ws_lab_mcp_004'
)"
if [ "$mcp004_view_code" != "200" ]; then
  fail "view ws_lab_mcp_004 HTTP ${mcp004_view_code}"
fi
if ! docker exec agentsec_splunk bash -lc 'grep -q "ws_lab_mcp_004\|LAB-MCP-004" /tmp/ws_lab_mcp_004_view.xml'; then
  fail "view payload did not mention LAB-MCP-004 / ws_lab_mcp_004"
fi
log "Dashboard view ws_lab_mcp_004 is available via Splunk REST."

acme_code="$(curl -sS -o /dev/null -w "%{http_code}" --max-time 10 http://127.0.0.1:5000/health || echo 000)"
atk_code="$(curl -sS -o /dev/null -w "%{http_code}" --max-time 10 http://127.0.0.1:5001/health || echo 000)"
if [ "$acme_code" != "200" ]; then
  fail "AcmeBank health HTTP ${acme_code}"
fi
if [ "$atk_code" != "200" ]; then
  fail "Attack UI health HTTP ${atk_code}"
fi
log "AcmeBank and Attack UI health HTTP 200."

log "READY — local Docker lab is provisioned (app, dashboard, index, HEC). No manual cp/chown."
unset SPLUNK_PASSWORD HEC_TOKEN
exit 0
