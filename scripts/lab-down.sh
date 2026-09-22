#!/bin/sh
# Soft stop: stop compose services. Does not delete volumes, Splunk indexes,
# Ollama models, or named volume splunk_app_agentsec.
set -eu

ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
cd "$ROOT"

if [ ! -f "$ROOT/.env" ]; then
  printf '[lab-down] ERROR: %s/.env is missing.\n' "$ROOT" >&2
  exit 1
fi

COMPOSE="docker compose -f docker-compose.yml -f docker-compose.local.yml --profile local --env-file $ROOT/.env"

printf '[lab-down] Stopping AgentSec containers (volumes preserved).\n'
$COMPOSE down
printf '[lab-down] Stopped. Indexed Splunk data and named volumes remain.\n'
printf '[lab-down] Next start: ./scripts/lab-up.sh\n'
printf '[lab-down] Destructive full reset (explicit): docker compose -f docker-compose.yml -f docker-compose.local.yml --profile local --env-file .env down -v\n'
