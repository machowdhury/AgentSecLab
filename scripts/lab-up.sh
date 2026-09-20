#!/bin/sh
# Start or refresh the LOCAL Docker AgentSec lab.
# Splunk app staging is automatic (named volume). Do not docker cp the app.
set -eu

ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
cd "$ROOT"

REFRESH_APP=0
BUILD=0
WAIT_READY=1
for arg in "$@"; do
  case "$arg" in
    --refresh-app) REFRESH_APP=1 ;;
    --build) BUILD=1 ;;
    --no-wait) WAIT_READY=0 ;;
    -h|--help)
      cat <<'EOF'
Usage: ./scripts/lab-up.sh [--build] [--refresh-app] [--no-wait]

Starts the LOCAL Docker lab (AcmeBank, Attack UI, Ollama, collector, Splunk).

  (no flags)       docker compose up -d, then wait until the lab is READY
  --build          rebuild AcmeBank / Attack UI images, then up
  --refresh-app    restage splunk_app/agentsec into the named volume and
                   restart Splunk so Dashboard Studio picks up XML changes
  --no-wait        start containers; do not run readiness checks

This is the normal local workflow. Do not copy the Splunk app by hand.

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

log "Local Docker lab. Source app remains in splunk_app/agentsec/"
log "Compose files: docker-compose.yml + docker-compose.local.yml (profile local)"

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
  log "Starting stack (splunk_app_init copies the app before Splunk becomes ready)..."
  $COMPOSE up -d
fi

if [ "$WAIT_READY" -eq 1 ]; then
  log "Waiting for readiness (first Splunk boot can take 10–20 minutes)..."
  i=1
  while [ "$i" -le 80 ]; do
    if "$ROOT/scripts/lab-ready.sh"; then
      log "Lab is READY."
      log "AcmeBank    http://127.0.0.1:5000"
      log "Attack UI   http://127.0.0.1:5001"
      log "Splunk      http://127.0.0.1:8000  (app: AgentSec / Home / Attack Labs / Context Security / Agent Authority / Supply Chain)"
      exit 0
    fi
    log "Not ready yet (attempt ${i}/80). Sleeping 15s..."
    i=$((i + 1))
    sleep 15
  done
  log "ERROR: lab did not become ready. See docker compose logs splunk splunk_app_init splunk_hec_init"
  exit 1
fi

log "Started without readiness wait. Run ./scripts/lab-ready.sh later."
