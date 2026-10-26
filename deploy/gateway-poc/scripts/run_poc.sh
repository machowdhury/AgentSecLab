#!/bin/sh
# Disposable gateway POC controller. Every docker command names the POC project explicitly.
# up | down | cleanup --yes.  `down` keeps images and certs; `cleanup --yes` removes ONLY resources named/labelled agentsec-gw-poc.
set -eu
DIR="$(cd "$(dirname "$0")/.." && pwd)"; PROJECT=agentsec-gw-poc; RT="${POC_RUNTIME:-$DIR/.runtime}"; export POC_RUNTIME="$RT"
dc() { docker compose -p "$PROJECT" -f "$DIR/docker-compose.yml" "$@"; }
case "${1:-}" in
  up)
    mkdir -p "$RT"; chmod 700 "$RT"
    [ -d "$RT/certs/active" ] || sh "$DIR/scripts/make_certs.sh" "$RT/certs"
    if [ ! -f "$RT/creds.env" ]; then   # disposable credentials, random per checkout, never printed
      L=$(openssl rand -hex 12); O=$(openssl rand -hex 12); S=$(openssl rand -hex 12)
      printf 'POC_LEARNER_PASSWORD=%s\nPOC_OPERATOR_PASSWORD=%s\nSTUB_PASSWORD=%s\n' "$L" "$O" "$S" > "$RT/creds.env"; chmod 600 "$RT/creds.env"
      printf 'learner:%s\noperator:%s\n' "$(openssl passwd -apr1 "$L")" "$(openssl passwd -apr1 "$O")" > "$RT/htpasswd"; chmod 644 "$RT/htpasswd"
    fi
    . "$RT/creds.env"; export STUB_PASSWORD
    dc up -d --build
    sleep 2; docker exec agentsec-gw-poc-gateway nginx -s reload >/dev/null 2>&1 || true   # config files are bind-mounted: reload picks up edits
    ;;
  down) dc down ;;      # no -v, no --remove-orphans
  cleanup)
    [ "${2:-}" = "--yes" ] || { echo "refusing: cleanup removes the POC containers, images and .runtime; pass --yes"; exit 1; }
    dc down
    for c in $(docker ps -aq --filter label=agentsec.poc=tls-scenario); do docker rm -f "$c" >/dev/null; done
    for i in agentsec-gw-poc/attack:m1 agentsec-gw-poc/acmebank:m1; do docker image rm "$i" >/dev/null 2>&1 || true; done
    rm -rf "$RT"; echo "POC resources removed (project $PROJECT only)" ;;
  *) echo "usage: run_poc.sh up | down | cleanup --yes"; exit 2 ;;
esac
