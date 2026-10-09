#!/bin/sh
# Start or refresh the LOCAL Docker AgentSec lab.
# Splunk app staging is automatic (named volume). Do not docker cp the app.
set -eu

ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
cd "$ROOT"

REFRESH_APP=0
BUILD=0
WAIT_READY=1
REMOTE=0
for arg in "$@"; do
  case "$arg" in
    --refresh-app) REFRESH_APP=1 ;;
    --build) BUILD=1 ;;
    --no-wait) WAIT_READY=0 ;;
    --remote) REMOTE=1 ;;
    -h|--help)
      cat <<'EOF'
Usage: ./scripts/lab-up.sh [--build] [--refresh-app] [--no-wait] [--remote]

Starts the Docker lab (AcmeBank, Attack Service, Ollama, collector, Splunk).

Run from the repository root after copying .env.example to .env.

  (no flags)       localhost bindings, then wait until the lab is READY
  --remote         publish learner ports 8000 and 5001 on 0.0.0.0
  --build          rebuild AcmeBank / Attack Service images from this repository, then up
  --refresh-app    restage splunk_app/agentsec into the named volume and
                   restart Splunk so Dashboard Studio picks up XML changes
  --no-wait        start containers; do not run readiness checks

--remote does not publish HEC, OTel, AcmeBank, or Ollama.
Binding 0.0.0.0 does not open a cloud firewall. See docs/REMOTE_ACCESS.md.

First Splunk boot can take 10–20 minutes. Later starts are usually faster.
READY is service health (see ./scripts/lab-ready.sh). It is not proof that a
run.id is searchable. External browser reachability is not measured.

After local READY:
  Splunk Academy Home  http://127.0.0.1:8000/en-US/app/agentsec/ws_agentsec_home
  Attack Service       http://127.0.0.1:5001
  AcmeBank health      http://127.0.0.1:5000/health

Stop: ./scripts/lab-down.sh
Preflight: ./scripts/lab-preflight.sh
Access URLs again: ./scripts/agentsec-access.sh

This is the canonical start. Do not copy the Splunk app by hand.

External Splunk is not started by this script. See docs/LOCAL_DOCKER_LAB.md.
EOF
      exit 0
      ;;
    *)
      printf '[lab-up] unknown argument: %s\n' "$arg" >&2
      exit 1
      ;;
  esac
done

if [ ! -f "$ROOT/.env" ]; then
  printf '[lab-up] ERROR: %s/.env is missing. Copy .env.example to .env first.\n' "$ROOT" >&2
  exit 1
fi

COMPOSE="docker compose -f docker-compose.yml -f docker-compose.local.yml --profile local --env-file $ROOT/.env"

log() { printf '[lab-up] %s\n' "$*"; }
STARTED="$(date +%s)"

if [ "$REMOTE" -eq 1 ]; then
  export AGENTSEC_DEPLOYMENT=remote
  export AGENTSEC_BIND_ADDRESS=0.0.0.0
  log "AGENTSEC REMOTE LAB"
  log "[1/4] Checking prerequisites..."
  log "[2/4] Validating remote networking plan..."
  log "Learner bind address: 0.0.0.0"
  log "Academy port: 8000. Attack Service port: 5001."
  log "Private ports stay on 127.0.0.1: AcmeBank 5000, HEC 8088, OTel 4317 and 4318. Ollama is not published."
  log "External firewall: NOT MEASURED. Permit TCP 8000 and TCP 5001 only from trusted learner IPs."
else
  export AGENTSEC_DEPLOYMENT=local
  export AGENTSEC_BIND_ADDRESS=127.0.0.1
  log "[1/4] Checking prerequisites..."
  log "[2/4] Confirming localhost bindings for learner ports..."
fi

log "Source app remains in splunk_app/agentsec/. Deployment: ${AGENTSEC_DEPLOYMENT}."
log "Compose files: docker-compose.yml + docker-compose.local.yml (profile local)"

log "[3/4] Starting containers..."
if [ "$BUILD" -eq 1 ]; then
  log "Rebuilding application images..."
  $COMPOSE build
fi

if [ "$REFRESH_APP" -eq 1 ]; then
  log "Restaging Splunk app into named volume splunk_app_agentsec..."
  log "(repository files are copied; Splunk may chown the volume copy only)"
  $COMPOSE up -d --force-recreate --no-deps splunk_app_init
  i=1
  while [ "$i" -le 30 ]; do
    state="$(docker inspect -f '{{.State.Status}} {{.State.ExitCode}}' agentsec_splunk_app_init 2>/dev/null || true)"
    if [ "$state" = "exited 0" ]; then
      break
    fi
    if [ "$i" -eq 30 ]; then
      log "ERROR: splunk_app_init did not finish (state='${state}')"
      exit 1
    fi
    i=$((i + 1))
    sleep 1
  done
  log "Ensuring the stack is up, then restarting Splunk to reload default/ views..."
  $COMPOSE up -d
  $COMPOSE restart splunk
  log "Waiting for Splunk health after restart..."
  i=1
  while [ "$i" -le 40 ]; do
    health="$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' agentsec_splunk 2>/dev/null || true)"
    if [ "$health" = "healthy" ]; then
      break
    fi
    if [ "$i" -eq 40 ]; then
      log "ERROR: Splunk did not become healthy after restart (health='${health}')"
      exit 1
    fi
    i=$((i + 1))
    sleep 3
  done
  log "Re-running splunk_hec_init after restart (HTTP Event Collector does not survive restart)."
  $COMPOSE up -d --force-recreate --no-deps splunk_hec_init
  i=1
  while [ "$i" -le 90 ]; do
    state="$(docker inspect -f '{{.State.Status}} {{.State.ExitCode}}' agentsec_splunk_hec_init 2>/dev/null || true)"
    if [ "$state" = "exited 0" ]; then
      break
    fi
    if [ "$i" -eq 90 ]; then
      log "ERROR: splunk_hec_init did not finish after restart (state='${state}')"
      exit 1
    fi
    i=$((i + 1))
    sleep 5
  done
else
  splunk_health="$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' agentsec_splunk 2>/dev/null || true)"
  if [ "$splunk_health" = "healthy" ]; then
    log "Splunk is already healthy. Starting AgentSec app services without recreating Splunk or its volumes."
    $COMPOSE up -d --no-recreate ollama otel_collector acmebank attack_service
  else
    log "Starting stack (splunk_app_init copies the app before Splunk becomes ready)..."
    $COMPOSE up -d
  fi
fi

elapsed() {
  now="$(date +%s)"
  delta=$((now - STARTED))
  log "Elapsed time: $((delta / 60))m $((delta % 60))s"
}

if [ "$WAIT_READY" -eq 1 ]; then
  log "[4/4] Running readiness checks (first Splunk boot can take 10–20 minutes)..."
  i=1
  while [ "$i" -le 80 ]; do
    set +e
    AGENTSEC_DEPLOYMENT="$AGENTSEC_DEPLOYMENT" AGENTSEC_BIND_ADDRESS="$AGENTSEC_BIND_ADDRESS" "$ROOT/scripts/lab-ready.sh"
    ready_rc=$?
    set -e
    if [ "$ready_rc" -eq 0 ]; then
      log "Service health check exited 0."
      log "If lab-ready printed MODEL ABSENT, LIVE generation is DEGRADED. That is not a PASS."
      elapsed
      exit 0
    fi
    if [ "$ready_rc" -eq 2 ]; then
      log "ERROR: remote listener check failed. Waiting will not change the bind."
      elapsed
      exit 1
    fi
    log "Not ready yet (attempt ${i}/80). Sleeping 15s..."
    i=$((i + 1))
    sleep 15
  done
  log "ERROR: lab did not become ready. See docker compose logs splunk splunk_app_init splunk_hec_init"
  elapsed
  exit 1
fi

log "Started without readiness wait. Run ./scripts/lab-ready.sh later."
elapsed
