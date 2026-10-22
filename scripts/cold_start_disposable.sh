#!/bin/sh
# Disposable cold-start harness. Brings the lab up from a CLEAN CLONE of this branch under its own Compose project,
# names, ports, networks, volumes and artifacts, so it can never touch the running lab.
#
#   cold_start_disposable.sh preflight   prove isolation and print requirements (changes nothing)
#   cold_start_disposable.sh up          clone, build, start (needs a passing preflight)
#   cold_start_disposable.sh status      what exists in the disposable project
#   cold_start_disposable.sh down        remove ONLY resources labelled with the disposable project, then the clone
#
# Never uses `docker system prune`, `volume prune`, a wildcard, or any name not derived from COLD_PROJECT.
set -eu

COLD_PROJECT="agentseclab_cold"
COLD_PREFIX="agentsec_cold_"
SRC="$(cd "$(dirname "$0")/.." && pwd)"
COLD_ROOT="${COLD_ROOT:?set COLD_ROOT to an empty scratch directory outside every lab tree}"
REPO="$COLD_ROOT/repo"
OVERRIDE="$COLD_ROOT/cold.override.yml"
P_ACME=15000; P_ATTACK=15001; P_SPLUNK_WEB=18000; P_HEC=18088; P_OTLP_G=14317; P_OTLP_H=14318
BRANCH="${COLD_BRANCH:-feature/phase1-hardening}"

dc() { (cd "$REPO" && docker compose -p "$COLD_PROJECT" --env-file "$REPO/.env" -f docker-compose.yml -f docker-compose.local.yml -f "$OVERRIDE" --profile local "$@"); }
fail() { echo "[cold] ISOLATION FAILURE: $*" >&2; exit 1; }
ok() { echo "[cold] ok: $*"; }

write_override() {
  cat >"$OVERRIDE" <<EOF
name: $COLD_PROJECT
services:
  ollama:
    container_name: ${COLD_PREFIX}ollama
    profiles: [never]          # never started: its entrypoint would pull a model
  acmebank:
    container_name: ${COLD_PREFIX}acmebank
    ports: !override ["127.0.0.1:$P_ACME:5000"]
    depends_on: !override
      otel_collector: {condition: service_started}
  attack_service:
    container_name: ${COLD_PREFIX}attack_service
    ports: !override ["127.0.0.1:$P_ATTACK:5001"]
    environment:
      - AGENTSEC_BIND_HOST=0.0.0.0
      - ATTACK_SERVICE_PORT=5001
      - ACMEBANK_URL=http://acmebank:5000
      - AGENTSEC_ARTIFACTS_DIR=/app/artifacts
      - AGENTSEC_SPLUNK_WEB_URL=http://127.0.0.1:$P_SPLUNK_WEB
  otel_collector:
    container_name: ${COLD_PREFIX}otel_collector
    ports: !override ["127.0.0.1:$P_OTLP_G:4317", "127.0.0.1:$P_OTLP_H:4318"]
  splunk_app_init:
    container_name: ${COLD_PREFIX}splunk_app_init
  splunk_hec_init:
    container_name: ${COLD_PREFIX}splunk_hec_init
  splunk:
    container_name: ${COLD_PREFIX}splunk
    ports: !override ["127.0.0.1:$P_SPLUNK_WEB:8000", "127.0.0.1:$P_HEC:8088"]
    networks: !override
      agentsec_mesh:
        aliases: [agentsec_splunk, splunk]   # in-network names only; the real lab's container keeps its own network
EOF
}

port_free() { ! lsof -nP -iTCP:"$1" -sTCP:LISTEN >/dev/null 2>&1; }

preflight() {
  echo "[cold] preflight (changes nothing)"
  case "$COLD_ROOT" in "$SRC"*|"") fail "COLD_ROOT must be outside the source tree";; esac
  case "$COLD_ROOT" in /private/tmp/*|/tmp/*|"$HOME"/.cache/*|/var/folders/*) ok "COLD_ROOT=$COLD_ROOT is scratch space";; *) fail "COLD_ROOT is not under a scratch directory";; esac
  [ ! -e "$REPO" ] || fail "$REPO already exists; run 'down' first"
  command -v docker >/dev/null || fail "docker not found"
  docker compose version >/dev/null 2>&1 || fail "docker compose v2 not found"
  [ "$(docker compose version --short | cut -d. -f1)" -ge 2 ] || fail "Compose v2 required"
  for p in $P_ACME $P_ATTACK $P_SPLUNK_WEB $P_HEC $P_OTLP_G $P_OTLP_H; do port_free "$p" || fail "host port $p is in use"; done
  ok "host ports $P_ACME $P_ATTACK $P_SPLUNK_WEB $P_HEC $P_OTLP_G $P_OTLP_H are free"
  existing="$(docker ps -a --filter "label=com.docker.compose.project=$COLD_PROJECT" -q | wc -l | tr -d ' ')"
  [ "$existing" = "0" ] || fail "$existing containers already belong to project $COLD_PROJECT"
  for n in ollama acmebank attack_service otel_collector splunk_app_init splunk_hec_init splunk; do
    docker container inspect "${COLD_PREFIX}$n" >/dev/null 2>&1 && fail "container ${COLD_PREFIX}$n exists"
  done
  ok "no container named ${COLD_PREFIX}* exists; every disposable name is ${COLD_PREFIX}-prefixed"
  [ "$(docker volume ls -q --filter "label=com.docker.compose.project=$COLD_PROJECT" | wc -l | tr -d ' ')" = "0" ] || fail "volumes already belong to $COLD_PROJECT"
  docker network inspect "${COLD_PROJECT}_agentsec_mesh" >/dev/null 2>&1 && fail "network ${COLD_PROJECT}_agentsec_mesh exists"
  live="$(docker ps --format '{{.Names}}' | grep -v "^$COLD_PREFIX" | tr '\n' ' ')"
  ok "running lab left alone: $live"
  mem="$(docker info --format '{{.MemTotal}}')"; [ "$mem" -ge 8000000000 ] || fail "Docker VM has less than 8 GB"
  ok "Docker VM memory $((mem / 1000000000)) GB (a second Splunk needs about 4 GB; the running lab uses about 3 GB)"
  for img in splunk/splunk:10.2 otel/opentelemetry-collector-contrib:0.96.0 curlimages/curl:8.5.0 busybox:1.36; do
    docker image inspect "$img" >/dev/null 2>&1 || fail "image $img is not present locally (the harness never pulls)"
  done
  ok "all four third-party images are already local; nothing is pulled"
  echo "[cold] PREFLIGHT PASSED"
}

assert_config_isolated() {
  cfg="$(dc config 2>/dev/null)" || fail "compose config does not render"
  echo "$cfg" | grep -E "container_name:" | grep -vq "$COLD_PREFIX" && fail "a container_name is not disposable-prefixed"
  echo "$cfg" | grep -E "^\s+published:" | tr -d ' "' | sed 's/published://' | while read -r p; do
    case "$p" in $P_ACME|$P_ATTACK|$P_SPLUNK_WEB|$P_HEC|$P_OTLP_G|$P_OTLP_H) ;; *) fail "published port $p is not one of the disposable ports";; esac
  done
  echo "$cfg" | grep -E "source:" | grep -E "/Users/|/home/" | grep -v "$COLD_ROOT" | grep -q . && fail "a bind mount leaves the disposable clone"
  echo "$cfg" | grep -q "docker.sock" && fail "docker socket mounted"
  ok "rendered config: all names, ports and bind mounts are disposable"
}

up() {
  preflight
  mkdir -p "$COLD_ROOT"
  git clone -q --branch "$BRANCH" "$SRC" "$REPO"
  (cd "$REPO" && git log --oneline -1)
  write_override
  # Throwaway credentials, generated here, written only to the clone's .env, never printed.
  python3 - "$REPO/.env.example" "$REPO/.env" <<'PY'
import secrets, sys
src = open(sys.argv[1]).read().splitlines()
out = []
for line in src:
    if line.startswith("SPLUNK_PASSWORD="):
        line = "SPLUNK_PASSWORD=Cold!" + secrets.token_hex(8) + "Aa1"
    if line.startswith("SPLUNK_HEC_TOKEN="):
        line = "SPLUNK_HEC_TOKEN=" + secrets.token_hex(16)
    out.append(line)
open(sys.argv[2], "w").write("\n".join(out) + "\n")
PY
  grep -q "^SPLUNK_HEC_TOKEN=" "$REPO/.env" || { printf 'SPLUNK_HEC_TOKEN=%s\n' "$(python3 -c 'import secrets;print(secrets.token_hex(16))')" >>"$REPO/.env"; }
  chmod 600 "$REPO/.env"
  assert_config_isolated
  (cd "$REPO" && sh scripts/hec-certs.sh >/dev/null && mkdir -p artifacts/loan_desk/requests artifacts/loan_desk/receipts)
  ok "clean clone, own .env, own certificates, own artifacts directory"
  dc build acmebank attack_service
  dc up -d --no-deps splunk_app_init
  dc up -d --no-deps splunk
  echo "[cold] splunk starting; wait for health, then: up2"
}

up2() {
  dc up -d --no-deps splunk_hec_init
  dc up -d --no-deps otel_collector acmebank attack_service
}

status() { docker ps -a --filter "label=com.docker.compose.project=$COLD_PROJECT" --format '{{.Names}}\t{{.Status}}\t{{.Ports}}'; }

down() {
  [ "$COLD_PROJECT" = "agentseclab_cold" ] || fail "refusing: unexpected project name"
  ids="$(docker ps -a --filter "label=com.docker.compose.project=$COLD_PROJECT" -q)"
  [ -z "$ids" ] || docker rm -f $ids >/dev/null
  vols="$(docker volume ls -q --filter "label=com.docker.compose.project=$COLD_PROJECT")"
  [ -z "$vols" ] || docker volume rm $vols >/dev/null
  docker network inspect "${COLD_PROJECT}_agentsec_mesh" >/dev/null 2>&1 && docker network rm "${COLD_PROJECT}_agentsec_mesh" >/dev/null
  for img in $(docker image ls --format '{{.Repository}}:{{.Tag}}' | grep "^${COLD_PROJECT}-"); do docker image rm "$img" >/dev/null; done
  [ -n "$COLD_ROOT" ] && [ "$COLD_ROOT" != "/" ] && rm -rf "$REPO" "$OVERRIDE"
  echo "[cold] removed disposable containers, volumes, network, images and clone; nothing else touched"
}

case "${1:-}" in
  preflight) preflight ;;
  up) up ;;
  up2) up2 ;;
  status) status ;;
  config) write_override; assert_config_isolated ;;
  down) down ;;
  *) echo "usage: COLD_ROOT=<scratch dir> $0 preflight|up|up2|status|down" >&2; exit 2 ;;
esac
