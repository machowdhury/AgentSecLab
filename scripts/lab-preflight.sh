#!/bin/sh
# Check local prerequisites. Does not install software. Does not start the lab.
# Prints PASS / WARN / FAIL. Exit 1 if any FAIL.
set -eu

ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
cd "$ROOT"

FAILS=0
WARNS=0
REMOTE=0
for arg in "$@"; do
  case "$arg" in
    --remote) REMOTE=1 ;;
    -h|--help)
      cat <<'EOF'
Usage: ./scripts/lab-preflight.sh [--remote]

Checks host prerequisites. Does not install software and does not start the lab.

  (no flags)   local mode. Learner ports are expected on 127.0.0.1.
  --remote     plan a remote bind of 0.0.0.0 for ports 8000 and 5001 only.
EOF
      exit 0
      ;;
    *)
      printf '[lab-preflight] unknown argument: %s\n' "$arg" >&2
      exit 1
      ;;
  esac
done

log() { printf '[lab-preflight] %s\n' "$*"; }

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

pass() { log "PASS  $*"; }
warn() { log "WARN  $*"; WARNS=$((WARNS + 1)); }
fail() { log "FAIL  $*"; FAILS=$((FAILS + 1)); }

log "Preflight (no installs, no host mutation)."
if [ "$REMOTE" -eq 1 ]; then
  log "DEPLOYMENT MODE: REMOTE"
  log "LEARNER BIND ADDRESS: 0.0.0.0"
  log "ACADEMY PORT: 8000"
  log "ATTACK SERVICE PORT: 5001"
  log "INTERNAL SERVICES: PRIVATE"
  log "INFO  remote mode publishes 8000 and 5001 only. AcmeBank 5000, HEC 8088, OTel 4317/4318, and Ollama stay private."
  log "INFO  external firewall permission is NOT MEASURED."
else
  log "DEPLOYMENT MODE: LOCAL"
  log "LEARNER BIND ADDRESS: 127.0.0.1"
fi

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
    owner="$(docker ps --format '{{.Names}} {{.Ports}}' 2>/dev/null | grep 'agentsec_' | grep -E "(^|[^0-9])${port}([^0-9]|$)" || true)"
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
    avail_gb="$(awk -v k="$avail" 'BEGIN {printf "%.1f", k/1024/1024}')"
    log "INFO  CURRENTLY AVAILABLE disk on this volume: ${avail_gb} GB (${avail} KiB)"
    log "INFO  MINIMUM SUPPORTED disk: NOT BENCHMARKED"
    log "INFO  RECOMMENDED planning floor: 8 GB free before a first install. That floor is not a measured minimum."
    if [ "$avail" -lt 2097152 ]; then
      fail "Insufficient free disk for AgentSec. Available: ${avail_gb} GB. Recommended planning floor: 8 GB. Free disk space and rerun ./scripts/lab-preflight.sh. This check does not delete Docker data."
    elif [ "$avail" -lt 8388608 ]; then
      warn "free disk ${avail_gb} GB is below the 8 GB planning floor. Splunk images are large. This is not a measured minimum and this check does not delete Docker data."
    else
      pass "free disk ${avail_gb} GB is at or above the 8 GB planning floor (not a measured minimum)"
    fi
  fi
fi

if [ -r /proc/meminfo ]; then
  mem_kb="$(awk '/MemAvailable:/ {print $2}' /proc/meminfo)"
  if [ -n "$mem_kb" ]; then
    log "INFO  MemAvailable: ${mem_kb} kB. No memory minimum is benchmarked."
  fi
elif command -v sysctl >/dev/null 2>&1; then
  mem_bytes="$(sysctl -n hw.memsize 2>/dev/null || true)"
  if [ -n "$mem_bytes" ]; then
    log "INFO  host memory size: ${mem_bytes} bytes. Available memory was not measured. No memory minimum is benchmarked."
  fi
fi

if [ "${DOCKER_OK:-0}" = "1" ]; then
  if docker system df --format '{{.Type}} {{.Size}}' >/dev/null 2>&1; then
    docker system df --format '{{.Type}} {{.Size}}' | while IFS= read -r row; do
      log "INFO  Docker storage: ${row}"
    done
    log "INFO  Docker storage figures are observed. This check does not run docker system prune."
  else
    log "INFO  Docker storage: NOT MEASURED"
  fi
  volumes="$(docker volume ls --format '{{.Name}}' 2>/dev/null | grep -E 'splunk_app_agentsec|ollama_models|shared_telemetry' || true)"
  if [ -n "$volumes" ]; then
    log "INFO  existing AgentSec volumes:"
    printf '%s\n' "$volumes" | while IFS= read -r name; do
      log "INFO  volume ${name}"
    done
  else
    log "INFO  no AgentSec named volumes are present yet"
  fi
fi

log "Hardware minimums: NOT BENCHMARKED. Observed development used Docker Desktop on macOS with Splunk 10.2 (amd64 image, emulated on Apple Silicon)."

MODEL="llama3.2:1b"
if [ -f "$ROOT/.env" ]; then
  env_model="$(load_env_value OLLAMA_MODEL || true)"
  if [ -n "${env_model:-}" ]; then
    MODEL="$env_model"
  fi
fi
log "INFO  LIVE generation requires Ollama model ${MODEL}. Academy REPLAY does not."
log "INFO  The container entrypoint tries: ollama pull ${MODEL}"
log "INFO  Certificate or TLS errors must be resolved at the host trust layer. Do not disable certificate verification."
if [ "${DOCKER_OK:-0}" = "1" ] && docker inspect agentsec_ollama >/dev/null 2>&1; then
  ollama_state="$(docker inspect -f '{{.State.Status}}' agentsec_ollama 2>/dev/null || true)"
  if [ "$ollama_state" = "running" ]; then
    if docker exec agentsec_ollama ollama list 2>/dev/null | grep -q "$MODEL"; then
      pass "Ollama lists ${MODEL}. A listed name is not a measured digest."
    else
      warn "model ${MODEL} is required for LIVE generation and is currently absent"
      warn "command normally used: docker exec agentsec_ollama ollama pull ${MODEL}"
      warn "certificate or TLS errors must be resolved at the host trust layer. Do not disable certificate verification."
      warn "until that model is listed, AcmeBank /health stays degraded. LIVE generation is not READY."
    fi
  else
    warn "agentsec_ollama is not running, so model presence was not checked"
  fi
else
  log "INFO  model presence is checked when the agentsec_ollama container is running"
fi

if [ "$REMOTE" -eq 1 ]; then
  if command -v ufw >/dev/null 2>&1; then
    ufw_out="$(ufw status 2>&1 || true)"
    case "$ufw_out" in
      *inactive*) log "INFO  host firewall ufw: inactive" ;;
      *active*)
        warn "ufw is active. This check will not change it. Confirm TCP 8000 and TCP 5001 are allowed from the learner IP."
        ;;
      *) log "INFO  host firewall ufw: NOT MEASURED" ;;
    esac
  elif command -v firewall-cmd >/dev/null 2>&1; then
    fw_out="$(firewall-cmd --state 2>&1 || true)"
    case "$fw_out" in
      running)
        warn "firewalld is running. This check will not change it. Confirm TCP 8000 and TCP 5001 are allowed from the learner IP."
        ;;
      *) log "INFO  host firewall firewalld: NOT MEASURED" ;;
    esac
  else
    log "INFO  host firewall: NOT MEASURED"
  fi
fi

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
