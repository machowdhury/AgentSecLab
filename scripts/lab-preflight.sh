#!/bin/sh
# Check local prerequisites. Does not install software. Does not start the lab.
# Prints PASS / WARN / FAIL. Exit 1 if any FAIL.
set -eu

ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
cd "$ROOT"

FAILS=0
WARNS=0

log() { printf '[lab-preflight] %s\n' "$*"; }

pass() { log "PASS  $*"; }
warn() { log "WARN  $*"; WARNS=$((WARNS + 1)); }
fail() { log "FAIL  $*"; FAILS=$((FAILS + 1)); }

log "Preflight (no installs, no host mutation)."

if command -v docker >/dev/null 2>&1; then
  pass "docker CLI is available ($(docker --version | tr -d '\n'))"
else
  fail "docker CLI is not on PATH. Install Docker Desktop or an equivalent engine, then retry."
fi

if docker info >/dev/null 2>&1; then
  pass "Docker daemon is reachable"
  DOCKER_OK=1
else
  fail "Docker daemon is not running. Start Docker Desktop (or dockerd), then retry."
  DOCKER_OK=0
fi

if docker compose version >/dev/null 2>&1; then
  pass "docker compose is available ($(docker compose version --short 2>/dev/null || echo present))"
else
  fail "docker compose is not available. Install Docker Compose v2."
fi

if command -v git >/dev/null 2>&1; then
  pass "git is available"
else
  warn "git is not on PATH. Clone/update will need another tool."
fi

if [ -f "$ROOT/docker-compose.yml" ] && [ -f "$ROOT/docker-compose.local.yml" ]; then
  pass "compose files exist"
else
  fail "docker-compose.yml or docker-compose.local.yml is missing. Run preflight from the repository root."
fi

if [ -f "$ROOT/.env.example" ]; then
  pass ".env.example exists"
else
  fail ".env.example is missing"
fi

if [ -f "$ROOT/.env" ]; then
  pass ".env exists (do not commit this file)"
else
  fail ".env is missing. Copy .env.example to .env, then edit lab credentials locally. Never commit .env."
fi

if [ -d "$ROOT/splunk_app/agentsec" ] && [ -f "$ROOT/src/agentsec/templates/attack.html" ]; then
  pass "Splunk app and Attack Service source are present"
else
  fail "expected application source is missing"
fi

check_port() {
  port="$1"
  name="$2"
  if [ "${DOCKER_OK:-0}" = "1" ]; then
    owner="$(docker ps --format '{{.Names}} {{.Ports}}' 2>/dev/null | grep -E "agentsec_.*:${port}->|127.0.0.1:${port}->" || true)"
    if [ -n "$owner" ]; then
      warn "port ${port} (${name}) is already published by an AgentSec container — lab may already be running"
      return 0
    fi
    if docker inspect "agentsec_splunk" >/dev/null 2>&1 && [ "$port" = "8000" ]; then
      warn "port ${port} (${name}): Splunk container exists; treating as already running"
      return 0
    fi
  fi
  if command -v lsof >/dev/null 2>&1; then
    if lsof -nP -iTCP:"${port}" -sTCP:LISTEN >/dev/null 2>&1; then
      fail "port ${port} (${name}) is in use by a non-AgentSec listener. Stop that process or change the bind before ./scripts/lab-up.sh"
      return 0
    fi
  fi
  pass "port ${port} (${name}) appears free on localhost"
}

check_port 5000 "AcmeBank"
check_port 5001 "Attack Service"
check_port 8000 "Splunk Web"
check_port 8088 "Splunk HEC"
check_port 4317 "OTel gRPC"
check_port 4318 "OTel HTTP"

if command -v df >/dev/null 2>&1; then
  avail="$(df -Pk "$ROOT" | awk 'NR==2 {print $4}')"
  if [ -n "$avail" ]; then
    log "INFO  observed free disk on this volume: ${avail} KiB (NOT BENCHMARKED; no minimum is claimed)"
  fi
fi

log "Hardware minimums: NOT BENCHMARKED. Observed development used Docker Desktop on macOS with Splunk 10.2 (amd64 image, emulated on Apple Silicon)."
log "Ollama model pull happens inside the stack on first boot and can take several minutes."

if [ "$FAILS" -gt 0 ]; then
  log "RESULT FAIL (${FAILS} fail, ${WARNS} warn). Remediate FAIL items before ./scripts/lab-up.sh"
  exit 1
fi
if [ "$WARNS" -gt 0 ]; then
  log "RESULT WARN (${WARNS} warn). You may proceed; read WARN lines."
  exit 0
fi
log "RESULT PASS"
exit 0
