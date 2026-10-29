#!/bin/sh
# Verify the LOCAL Docker lab is actually usable. Exit 0 only when required
# pieces respond. Does not print secrets. Does not claim Splunk authorized a loan.
set -eu

ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
cd "$ROOT"
. "$ROOT/scripts/lab-compose.sh"

log() { printf '[lab-ready] %s\n' "$*"; }

fail() {
  log "NOT READY: $*"
  exit 1
}

# Gateway mode: when the opt-in gateway container exists, host ports 5000/5001 are not published, so the application checks run inside the
# network, and the readiness taxonomy comes from scripts/gateway-ready.sh (see docs/GATEWAY.md). Direct mode is unchanged.
GATEWAY_MODE=0
if [ -n "$(svc_id gateway)" ]; then GATEWAY_MODE=1; fi
http_code() {  # http_code <service> <port>
  if [ "$GATEWAY_MODE" = 1 ]; then docker exec "$(svc_id "$1")" curl -sS -o /dev/null -w "%{http_code}" --max-time 10 "http://127.0.0.1:$2/health" 2>/dev/null || echo 000
  else curl -sS -o /dev/null -w "%{http_code}" --max-time 10 "http://127.0.0.1:$2/health" || echo 000; fi
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

require_container() {  # require_container <compose service>
  name="$1"
  state="$(docker inspect -f '{{.State.Status}}' "$(svc_id "$name")" 2>/dev/null || true)"
  if [ "$state" != "running" ] && [ "$state" != "exited" ]; then
    fail "container ${name} is not present (state='${state}')"
  fi
  if [ "$name" != "splunk_app_init" ] && [ "$name" != "splunk_hec_init" ] && [ "$state" != "running" ]; then
    fail "container ${name} is not running (state='${state}')"
  fi
}

log "Checking required containers..."
lab_expects splunk || fail "this installation does not run the bundled Splunk; lab-ready.sh checks the bundled lab only. Use ./agentsec status (and scripts/gateway-ready.sh)"
require_container splunk
require_container otel_collector
require_container acmebank
require_container attack_service
if lab_expects ollama; then require_container ollama; fi

init_state="$(docker inspect -f '{{.State.Status}} {{.State.ExitCode}}' "$(svc_id splunk_app_init)" 2>/dev/null || true)"
case "$init_state" in
  "exited 0") log "splunk_app_init completed successfully." ;;
  *) fail "splunk_app_init did not complete successfully (state='${init_state}')" ;;
esac

hec_state="$(docker inspect -f '{{.State.Status}} {{.State.ExitCode}}' "$(svc_id splunk_hec_init)" 2>/dev/null || true)"
case "$hec_state" in
  "exited 0") log "splunk_hec_init completed successfully." ;;
  *)
    # Do not recreate Splunk or re-run init merely because a prior oneshot exited 1.
    # Index + HEC health below are the live proof. A failed oneshot with a healthy
    # HEC is a stale orchestration record, not a reason to rebuild volumes.
    log "WARN: splunk_hec_init state='${hec_state}'. Continuing if HEC health is 200."
    ;;
esac

health="$(docker inspect -f '{{.State.Health.Status}}' "$(svc_id splunk)" 2>/dev/null || true)"
if [ "$health" != "healthy" ]; then
  fail "Splunk health is '${health}', not healthy"
fi

log "Checking AgentSec app files inside Splunk..."
docker exec "$(svc_id splunk)" bash -lc 'test -f /opt/splunk/etc/apps/agentsec/default/app.conf'
docker exec "$(svc_id splunk)" bash -lc 'test -f /opt/splunk/etc/apps/agentsec/default/indexes.conf'
docker exec "$(svc_id splunk)" bash -lc 'test -f /opt/splunk/etc/apps/agentsec/default/data/ui/views/ws_agentsec_home.xml'
docker exec "$(svc_id splunk)" bash -lc 'test -f /opt/splunk/etc/apps/agentsec/default/data/ui/views/ws_lab_pi_001.xml'
docker exec "$(svc_id splunk)" bash -lc 'test -f /opt/splunk/etc/apps/agentsec/default/data/ui/views/ws_lab_mcp_001.xml'
docker exec "$(svc_id splunk)" bash -lc 'test -f /opt/splunk/etc/apps/agentsec/default/data/ui/views/ws_lab_mcp_003.xml'
docker exec "$(svc_id splunk)" bash -lc 'test -f /opt/splunk/etc/apps/agentsec/default/data/ui/views/ws_lab_mcp_004.xml'
docker exec "$(svc_id splunk)" bash -lc 'test -f /opt/splunk/etc/apps/agentsec/default/data/ui/views/ws_lab_mcp_005.xml'
docker exec "$(svc_id splunk)" bash -lc 'test -f /opt/splunk/etc/apps/agentsec/default/data/ui/views/ws_lab_mcp_006.xml'
docker exec "$(svc_id splunk)" bash -lc 'test -f /opt/splunk/etc/apps/agentsec/default/data/ui/views/ws_lab_mcp_catalog.xml'
docker exec "$(svc_id splunk)" bash -lc 'test -f /opt/splunk/etc/apps/agentsec/default/data/ui/views/ws_lab_scanner_runtime_evidence.xml'
docker exec "$(svc_id splunk)" bash -lc 'test -f /opt/splunk/etc/apps/agentsec/default/data/ui/views/ws_lab_external_evaluation_garak.xml'
  docker exec "$(svc_id splunk)" bash -lc 'test -f /opt/splunk/etc/apps/agentsec/default/data/ui/views/ws_lab_rag_context.xml'
  docker exec "$(svc_id splunk)" bash -lc 'test -f /opt/splunk/etc/apps/agentsec/default/data/ui/views/ws_lab_memory_security.xml'
  docker exec "$(svc_id splunk)" bash -lc 'test -f /opt/splunk/etc/apps/agentsec/default/data/ui/views/ws_lab_agent_goal_integrity.xml'
  docker exec "$(svc_id splunk)" bash -lc 'test -f /opt/splunk/etc/apps/agentsec/default/data/ui/views/ws_lab_agent_delegation.xml'
  docker exec "$(svc_id splunk)" bash -lc 'test -f /opt/splunk/etc/apps/agentsec/default/data/ui/views/ws_lab_agentsec_capstone.xml'
docker exec "$(svc_id splunk)" bash -lc 'test -f /opt/splunk/etc/apps/agentsec/default/data/ui/views/ws_agentsec_mastery.xml'
docker exec "$(svc_id splunk)" bash -lc 'test -f /opt/splunk/etc/apps/agentsec/default/data/ui/nav/default.xml'
log "AgentSec app files including Home, Capstone, and Mastery Check XML are present."

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
  docker exec -u splunk -e SPLUNK_PASSWORD="$SPLUNK_PASSWORD" "$(svc_id splunk)" bash -lc \
    'curl -sk -u "admin:${SPLUNK_PASSWORD}" -o /dev/null -w "%{http_code}" https://127.0.0.1:8089/services/data/indexes/agentsec_telemetry'
)"
if [ "$idx_code" != "200" ]; then
  fail "index agentsec_telemetry HTTP ${idx_code}"
fi
log "Index agentsec_telemetry exists."

log "Checking HEC..."
# HEC is HTTPS with the lab CA trusted explicitly and the host name verified.
HEC_CA="$(load_env_value AGENTSEC_HEC_CA_FILE)"
[ -n "$HEC_CA" ] || HEC_CA="$ROOT/.certs/hec-ca.crt"
case "$HEC_CA" in /*) ;; *) HEC_CA="$ROOT/$HEC_CA" ;; esac
[ -r "$HEC_CA" ] || fail "HEC CA file not readable: ${HEC_CA}. Run ./scripts/hec-certs.sh."
hec_code="$(
  curl -s --cacert "$HEC_CA" -o /dev/null -w "%{http_code}" --max-time 15 \
    https://localhost:8088/services/collector/health/1.0 || echo 000
)"
if [ "$hec_code" != "200" ]; then
  fail "HEC health HTTP ${hec_code} (HTTPS with CA ${HEC_CA}; verification is on)"
fi
log "HEC health HTTP 200."

log "Checking OTel collector can reach HEC on the mesh..."
mesh_net="$(docker inspect -f '{{range $name, $_ := .NetworkSettings.Networks}}{{$name}}{{end}}' "$(svc_id otel_collector)" 2>/dev/null || true)"
if [ -z "$mesh_net" ]; then
  fail "could not resolve collector compose network"
fi
mesh_code="$(
  docker run --rm --network "$mesh_net" -v "$HEC_CA:/certs/hec-ca.crt:ro" \
    curlimages/curl:8.5.0 \
    curl -s --cacert /certs/hec-ca.crt -o /dev/null -w "%{http_code}" --max-time 15 \
      https://agentsec_splunk:8088/services/collector/health/1.0 || echo 000
)"
if [ "$mesh_code" != "200" ]; then
  fail "collector-mesh HEC health HTTP ${mesh_code}"
fi
log "Mesh HEC health from a collector-network client HTTP 200."

log "Checking Dashboard Studio view is loaded..."
view_code="$(
  docker exec -u splunk -e SPLUNK_PASSWORD="$SPLUNK_PASSWORD" "$(svc_id splunk)" bash -lc \
    'curl -sk -u "admin:${SPLUNK_PASSWORD}" -o /tmp/ws_lab_pi_001_view.xml -w "%{http_code}" https://127.0.0.1:8089/servicesNS/nobody/agentsec/data/ui/views/ws_lab_pi_001'
)"
if [ "$view_code" != "200" ]; then
  fail "view ws_lab_pi_001 HTTP ${view_code}"
fi
if ! docker exec "$(svc_id splunk)" bash -lc 'grep -q "ws_lab_pi_001\|LAB-PI-001" /tmp/ws_lab_pi_001_view.xml'; then
  fail "view payload did not mention LAB-PI-001 / ws_lab_pi_001"
fi
log "Dashboard view ws_lab_pi_001 is available via Splunk REST."

mcp_view_code="$(
  docker exec -u splunk -e SPLUNK_PASSWORD="$SPLUNK_PASSWORD" "$(svc_id splunk)" bash -lc \
    'curl -sk -u "admin:${SPLUNK_PASSWORD}" -o /tmp/ws_lab_mcp_001_view.xml -w "%{http_code}" https://127.0.0.1:8089/servicesNS/nobody/agentsec/data/ui/views/ws_lab_mcp_001'
)"
if [ "$mcp_view_code" != "200" ]; then
  fail "view ws_lab_mcp_001 HTTP ${mcp_view_code}"
fi
if ! docker exec "$(svc_id splunk)" bash -lc 'grep -q "ws_lab_mcp_001\|LAB-MCP-001" /tmp/ws_lab_mcp_001_view.xml'; then
  fail "view payload did not mention LAB-MCP-001 / ws_lab_mcp_001"
fi
log "Dashboard view ws_lab_mcp_001 is available via Splunk REST."

mcp003_view_code="$(
  docker exec -u splunk -e SPLUNK_PASSWORD="$SPLUNK_PASSWORD" "$(svc_id splunk)" bash -lc \
    'curl -sk -u "admin:${SPLUNK_PASSWORD}" -o /tmp/ws_lab_mcp_003_view.xml -w "%{http_code}" https://127.0.0.1:8089/servicesNS/nobody/agentsec/data/ui/views/ws_lab_mcp_003'
)"
if [ "$mcp003_view_code" != "200" ]; then
  fail "view ws_lab_mcp_003 HTTP ${mcp003_view_code}"
fi
if ! docker exec "$(svc_id splunk)" bash -lc 'grep -q "ws_lab_mcp_003\|LAB-MCP-003" /tmp/ws_lab_mcp_003_view.xml'; then
  fail "view payload did not mention LAB-MCP-003 / ws_lab_mcp_003"
fi
log "Dashboard view ws_lab_mcp_003 is available via Splunk REST."

mcp004_view_code="$(
  docker exec -u splunk -e SPLUNK_PASSWORD="$SPLUNK_PASSWORD" "$(svc_id splunk)" bash -lc \
    'curl -sk -u "admin:${SPLUNK_PASSWORD}" -o /tmp/ws_lab_mcp_004_view.xml -w "%{http_code}" https://127.0.0.1:8089/servicesNS/nobody/agentsec/data/ui/views/ws_lab_mcp_004'
)"
if [ "$mcp004_view_code" != "200" ]; then
  fail "view ws_lab_mcp_004 HTTP ${mcp004_view_code}"
fi
if ! docker exec "$(svc_id splunk)" bash -lc 'grep -q "ws_lab_mcp_004\|LAB-MCP-004" /tmp/ws_lab_mcp_004_view.xml'; then
  fail "view payload did not mention LAB-MCP-004 / ws_lab_mcp_004"
fi
log "Dashboard view ws_lab_mcp_004 is available via Splunk REST."

mcp005_view_code="$(
  docker exec -u splunk -e SPLUNK_PASSWORD="$SPLUNK_PASSWORD" "$(svc_id splunk)" bash -lc \
    'curl -sk -u "admin:${SPLUNK_PASSWORD}" -o /tmp/ws_lab_mcp_005_view.xml -w "%{http_code}" https://127.0.0.1:8089/servicesNS/nobody/agentsec/data/ui/views/ws_lab_mcp_005'
)"
if [ "$mcp005_view_code" != "200" ]; then
  fail "view ws_lab_mcp_005 HTTP ${mcp005_view_code}"
fi
if ! docker exec "$(svc_id splunk)" bash -lc 'grep -q "ws_lab_mcp_005\|LAB-MCP-005" /tmp/ws_lab_mcp_005_view.xml'; then
  fail "view payload did not mention LAB-MCP-005 / ws_lab_mcp_005"
fi
log "Dashboard view ws_lab_mcp_005 is available via Splunk REST."

mcp006_view_code="$(
  docker exec -u splunk -e SPLUNK_PASSWORD="$SPLUNK_PASSWORD" "$(svc_id splunk)" bash -lc \
    'curl -sk -u "admin:${SPLUNK_PASSWORD}" -o /tmp/ws_lab_mcp_006_view.xml -w "%{http_code}" https://127.0.0.1:8089/servicesNS/nobody/agentsec/data/ui/views/ws_lab_mcp_006'
)"
if [ "$mcp006_view_code" != "200" ]; then
  fail "view ws_lab_mcp_006 HTTP ${mcp006_view_code}"
fi
if ! docker exec "$(svc_id splunk)" bash -lc 'grep -q "ws_lab_mcp_006\|LAB-MCP-006" /tmp/ws_lab_mcp_006_view.xml'; then
  fail "view payload did not mention LAB-MCP-006 / ws_lab_mcp_006"
fi
log "Dashboard view ws_lab_mcp_006 is available via Splunk REST."

mcp_catalog_view_code="$(
  docker exec -u splunk -e SPLUNK_PASSWORD="$SPLUNK_PASSWORD" "$(svc_id splunk)" bash -lc \
    'curl -sk -u "admin:${SPLUNK_PASSWORD}" -o /tmp/ws_lab_mcp_catalog_view.xml -w "%{http_code}" https://127.0.0.1:8089/servicesNS/nobody/agentsec/data/ui/views/ws_lab_mcp_catalog'
)"
if [ "$mcp_catalog_view_code" != "200" ]; then
  fail "view ws_lab_mcp_catalog HTTP ${mcp_catalog_view_code}"
fi
if ! docker exec "$(svc_id splunk)" bash -lc 'grep -q "ws_lab_mcp_catalog\|LAB-MCP-CATALOG" /tmp/ws_lab_mcp_catalog_view.xml'; then
  fail "view payload did not mention LAB-MCP-CATALOG / ws_lab_mcp_catalog"
fi
log "Dashboard view ws_lab_mcp_catalog is available via Splunk REST."

scanner_runtime_view_code="$(
  docker exec -u splunk -e SPLUNK_PASSWORD="$SPLUNK_PASSWORD" "$(svc_id splunk)" bash -lc \
    'curl -sk -u "admin:${SPLUNK_PASSWORD}" -o /tmp/ws_lab_scanner_runtime_evidence_view.xml -w "%{http_code}" https://127.0.0.1:8089/servicesNS/nobody/agentsec/data/ui/views/ws_lab_scanner_runtime_evidence'
)"
if [ "$scanner_runtime_view_code" != "200" ]; then
  fail "view ws_lab_scanner_runtime_evidence HTTP ${scanner_runtime_view_code}"
fi
if ! docker exec "$(svc_id splunk)" bash -lc 'grep -q "ws_lab_scanner_runtime_evidence\|LAB-SCANNER-RUNTIME" /tmp/ws_lab_scanner_runtime_evidence_view.xml'; then
  fail "view payload did not mention LAB-SCANNER-RUNTIME / ws_lab_scanner_runtime_evidence"
fi
log "Dashboard view ws_lab_scanner_runtime_evidence is available via Splunk REST."

external_toolbox_view_code="$(
  docker exec -u splunk -e SPLUNK_PASSWORD="$SPLUNK_PASSWORD" "$(svc_id splunk)" bash -lc \
    'curl -sk -u "admin:${SPLUNK_PASSWORD}" -o /tmp/ws_lab_external_evaluation_garak_view.xml -w "%{http_code}" https://127.0.0.1:8089/servicesNS/nobody/agentsec/data/ui/views/ws_lab_external_evaluation_garak'
)"
if [ "$external_toolbox_view_code" != "200" ]; then
  fail "view ws_lab_external_evaluation_garak HTTP ${external_toolbox_view_code}"
fi
if ! docker exec "$(svc_id splunk)" bash -lc 'grep -q "ws_lab_external_evaluation_garak\|LAB-EXTERNAL-EVALUATION-GARAK" /tmp/ws_lab_external_evaluation_garak_view.xml'; then
  fail "view payload did not mention LAB-EXTERNAL-EVALUATION-GARAK / ws_lab_external_evaluation_garak"
fi
log "Dashboard view ws_lab_external_evaluation_garak is available via Splunk REST."

rag_view_code="$(
  docker exec -u splunk -e SPLUNK_PASSWORD="$SPLUNK_PASSWORD" "$(svc_id splunk)" bash -lc \
    'curl -sk -u "admin:${SPLUNK_PASSWORD}" -o /tmp/ws_lab_rag_context_view.xml -w "%{http_code}" https://127.0.0.1:8089/servicesNS/nobody/agentsec/data/ui/views/ws_lab_rag_context'
)"
if [ "$rag_view_code" != "200" ]; then
  fail "view ws_lab_rag_context HTTP ${rag_view_code}"
fi
if ! docker exec "$(svc_id splunk)" bash -lc 'grep -q "ws_lab_rag_context\|LAB-RAG-CONTEXT" /tmp/ws_lab_rag_context_view.xml'; then
  fail "view payload did not mention LAB-RAG-CONTEXT / ws_lab_rag_context"
fi
log "Dashboard view ws_lab_rag_context is available via Splunk REST."

memory_view_code="$(
  docker exec -u splunk -e SPLUNK_PASSWORD="$SPLUNK_PASSWORD" "$(svc_id splunk)" bash -lc \
    'curl -sk -u "admin:${SPLUNK_PASSWORD}" -o /tmp/ws_lab_memory_security_view.xml -w "%{http_code}" https://127.0.0.1:8089/servicesNS/nobody/agentsec/data/ui/views/ws_lab_memory_security'
)"
if [ "$memory_view_code" != "200" ]; then
  fail "view ws_lab_memory_security HTTP ${memory_view_code}"
fi
if ! docker exec "$(svc_id splunk)" bash -lc 'grep -q "ws_lab_memory_security\|LAB-MEMORY-001" /tmp/ws_lab_memory_security_view.xml'; then
  fail "view payload did not mention LAB-MEMORY-001 / ws_lab_memory_security"
fi
log "Dashboard view ws_lab_memory_security is available via Splunk REST."

goal_view_code="$(
  docker exec -u splunk -e SPLUNK_PASSWORD="$SPLUNK_PASSWORD" "$(svc_id splunk)" bash -lc \
    'curl -sk -u "admin:${SPLUNK_PASSWORD}" -o /tmp/ws_lab_agent_goal_integrity_view.xml -w "%{http_code}" https://127.0.0.1:8089/servicesNS/nobody/agentsec/data/ui/views/ws_lab_agent_goal_integrity'
)"
if [ "$goal_view_code" != "200" ]; then
  fail "view ws_lab_agent_goal_integrity HTTP ${goal_view_code}"
fi
if ! docker exec "$(svc_id splunk)" bash -lc 'grep -q "ws_lab_agent_goal_integrity\|LAB-AGENT-GOAL-INTEGRITY-001" /tmp/ws_lab_agent_goal_integrity_view.xml'; then
  fail "view payload did not mention LAB-AGENT-GOAL-INTEGRITY-001 / ws_lab_agent_goal_integrity"
fi
log "Dashboard view ws_lab_agent_goal_integrity is available via Splunk REST."

identity_view_code="$(
  docker exec -u splunk -e SPLUNK_PASSWORD="$SPLUNK_PASSWORD" "$(svc_id splunk)" bash -lc \
    'curl -sk -u "admin:${SPLUNK_PASSWORD}" -o /tmp/ws_lab_agent_delegation_view.xml -w "%{http_code}" https://127.0.0.1:8089/servicesNS/nobody/agentsec/data/ui/views/ws_lab_agent_delegation'
)"
if [ "$identity_view_code" != "200" ]; then
  fail "view ws_lab_agent_delegation HTTP ${identity_view_code}"
fi
if ! docker exec "$(svc_id splunk)" bash -lc 'grep -q "ws_lab_agent_delegation\|LAB-AGENT-DELEGATION-001" /tmp/ws_lab_agent_delegation_view.xml'; then
  fail "view payload did not mention LAB-AGENT-DELEGATION-001 / ws_lab_agent_delegation"
fi
log "Dashboard view ws_lab_agent_delegation is available via Splunk REST."

capstone_view_code="$(
  docker exec -u splunk -e SPLUNK_PASSWORD="$SPLUNK_PASSWORD" "$(svc_id splunk)" bash -lc \
    'curl -sk -u "admin:${SPLUNK_PASSWORD}" -o /tmp/ws_lab_agentsec_capstone_view.xml -w "%{http_code}" https://127.0.0.1:8089/servicesNS/nobody/agentsec/data/ui/views/ws_lab_agentsec_capstone'
)"
if [ "$capstone_view_code" != "200" ]; then
  fail "view ws_lab_agentsec_capstone HTTP ${capstone_view_code}"
fi
if ! docker exec "$(svc_id splunk)" bash -lc 'grep -q "ws_lab_agentsec_capstone\\|LAB-AGENTSEC-CAPSTONE-001" /tmp/ws_lab_agentsec_capstone_view.xml'; then
  fail "view payload did not mention LAB-AGENTSEC-CAPSTONE-001 / ws_lab_agentsec_capstone"
fi
log "Dashboard view ws_lab_agentsec_capstone is available via Splunk REST."

home_view_code="$(
  docker exec -u splunk -e SPLUNK_PASSWORD="$SPLUNK_PASSWORD" "$(svc_id splunk)" bash -lc \
    'curl -sk -u "admin:${SPLUNK_PASSWORD}" -o /tmp/ws_agentsec_home_view.xml -w "%{http_code}" https://127.0.0.1:8089/servicesNS/nobody/agentsec/data/ui/views/ws_agentsec_home'
)"
if [ "$home_view_code" != "200" ]; then
  fail "view ws_agentsec_home HTTP ${home_view_code}"
fi
log "Dashboard view ws_agentsec_home is available via Splunk REST."

mastery_view_code="$(
  docker exec -u splunk -e SPLUNK_PASSWORD="$SPLUNK_PASSWORD" "$(svc_id splunk)" bash -lc \
    'curl -sk -u "admin:${SPLUNK_PASSWORD}" -o /tmp/ws_agentsec_mastery_view.xml -w "%{http_code}" https://127.0.0.1:8089/servicesNS/nobody/agentsec/data/ui/views/ws_agentsec_mastery'
)"
if [ "$mastery_view_code" != "200" ]; then
  fail "view ws_agentsec_mastery HTTP ${mastery_view_code}"
fi
log "Dashboard view ws_agentsec_mastery is available via Splunk REST."

acme_code="$(http_code acmebank 5000)"
atk_code="$(http_code attack_service 5001)"
if [ "$acme_code" != "200" ]; then
  fail "AcmeBank health HTTP ${acme_code}"
fi
if [ "$atk_code" != "200" ]; then
  fail "Attack UI health HTTP ${atk_code}"
fi
log "AcmeBank and Attack UI health HTTP 200."

log "SERVICE READY: containers, Splunk Web, HEC health, Academy views, AcmeBank HTTP, Attack Service HTTP."
log "NOT PROVEN: a given run.id is searchable. HEC HTTP 200 is not indexed evidence."

MODEL="$(load_env_value OLLAMA_MODEL || true)"
if [ -z "${MODEL:-}" ]; then
  MODEL="llama3.2:1b"
fi
if [ "$GATEWAY_MODE" = 1 ]; then acme_status="$(docker exec "$(svc_id acmebank)" curl -sf --max-time 10 http://127.0.0.1:5000/health || true)"
else acme_status="$(curl -sf --max-time 10 http://127.0.0.1:5000/health || true)"; fi
if [ -n "$acme_status" ]; then
  log "AcmeBank /health: ${acme_status}"
fi
# Ask Ollama the way AcmeBank does: from inside AcmeBank, at its configured OLLAMA_BASE_URL.
# That identifies the provider actually in use (container default, or documented host fallback).
ollama_base="$(docker inspect -f '{{range .Config.Env}}{{println .}}{{end}}' "$(svc_id acmebank)" 2>/dev/null | sed -n 's/^OLLAMA_BASE_URL=//p')"
[ -n "$ollama_base" ] || ollama_base="http://ollama:11434"
case "$ollama_base" in
  *host.docker.internal*|*127.0.0.1*|*localhost*) ollama_provider="HOST" ;;
  *) ollama_provider="CONTAINER" ;;
esac
log "OLLAMA PROVIDER: ${ollama_provider} (${ollama_base}) model ${MODEL}"
ollama_tags="$(docker exec "$(svc_id acmebank)" curl -sf --max-time 10 "${ollama_base}/api/tags" 2>/dev/null || true)"
if printf '%s' "$ollama_tags" | sh "$ROOT/scripts/model_present.sh" --json "$MODEL"; then
  log "MODEL PRESENT: ${MODEL} is listed by the ${ollama_provider} Ollama as seen from AcmeBank. A listed name is not a measured digest and is not proof of generation quality."
else
  log "MODEL ABSENT: ${MODEL} is required for LIVE generation and is not listed by the ${ollama_provider} Ollama (${ollama_base})."
  log "LIVE model-dependent generation is DEGRADED, not PASS."
  log "Academy REPLAY does not need this model."
  if [ "$ollama_provider" = "HOST" ]; then
    log "Host provider: run 'ollama serve' on the host and 'ollama pull ${MODEL}' there (see docs/LOCAL_DOCKER_LAB.md)."
  else
    log "Command normally used: docker compose exec ollama ollama pull ${MODEL}"
    log "Certificate or TLS errors must be resolved at the host trust layer. Do not disable certificate verification."
    log "Fallback if the container cannot pull: use the host Ollama option in docs/LOCAL_DOCKER_LAB.md."
  fi
fi
unset SPLUNK_PASSWORD HEC_TOKEN
if [ "$GATEWAY_MODE" = 1 ]; then
  log "Deployment mode: GATEWAY (single HTTPS entry point; see below)"
  sh "$ROOT/scripts/gateway-ready.sh" || fail "gateway readiness failed (details above)"
  exit 0
fi
if [ "${AGENTSEC_DEPLOYMENT:-local}" = "remote" ]; then
  log "Deployment mode: REMOTE"
  log "Internal readiness URL: http://127.0.0.1:8000/en-US/app/agentsec/ws_agentsec_home"
  set +e
  python3 "$ROOT/scripts/agentsec_access.py" classify --mode remote
  listen_rc=$?
  set -e
  if [ "$listen_rc" -ne 0 ]; then
    log "REMOTE LISTENERS: NOT ACCEPTED"
    log "Remote access is not ready while Academy stays on 127.0.0.1:8000 or a private port is public."
    log "External browser reachability: NOT MEASURED"
    exit 2
  fi
  log "REMOTE LISTENERS: Academy and Attack Service are public listeners. Private ports are not."
  "$ROOT/scripts/agentsec-access.sh"
  log "External browser reachability: NOT MEASURED"
  exit 0
fi
log "Deployment mode: LOCAL"
log "Academy: http://127.0.0.1:8000/en-US/app/agentsec/ws_agentsec_home"
log "Attack Service: http://127.0.0.1:5001"
log "Open these URLs on this computer. They are localhost bindings."
exit 0
