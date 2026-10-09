#!/bin/sh
# Restart Attack Service only. Does not touch Splunk, volumes, certificates,
# or unrelated host applications. Used to qualify durable Academy notebook state.
set -eu

log() { printf '[academy-restart] %s\n' "$*"; }

if ! docker inspect agentsec_attack_service >/dev/null 2>&1; then
  log "ERROR: agentsec_attack_service is not present."
  exit 1
fi

log "Restarting agentsec_attack_service only."
docker restart agentsec_attack_service >/dev/null

i=1
while [ "$i" -le 30 ]; do
  health="$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' agentsec_attack_service 2>/dev/null || true)"
  if [ "$health" = "healthy" ]; then
    code="$(curl -sS -o /dev/null -w '%{http_code}' -m 5 http://127.0.0.1:5001/academy || true)"
    if [ "$code" = "200" ]; then
      log "Attack Service is healthy. Academy HTTP ${code}."
      exit 0
    fi
  fi
  i=$((i + 1))
  sleep 1
done

log "ERROR: Attack Service did not become healthy after restart (health='${health:-unknown}')."
exit 1
