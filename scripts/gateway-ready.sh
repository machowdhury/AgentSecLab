#!/bin/sh
# Readiness for gateway mode. READ-ONLY: starts nothing, changes nothing, prints no secrets.
# Reports six DIFFERENT facts and never lets one stand in for another:
#   GATEWAY, ACADEMY, ATTACK SERVICE, SPLUNK reachability  -> checked
#   TELEMETRY                                              -> NOT VERIFIED unless --run-id <id> finds indexed events for that run
#   LIVE WORKFLOW                                          -> always NOT VERIFIED here (a readiness check never launches an attack)
# Exit 0 when the gateway, the Academy and the Attack Service are ready; Splunk reachability and telemetry never change the exit code.
set -eu
ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"; cd "$ROOT"
GDIR="${AGENTSEC_GATEWAY_DIR:-$ROOT/.gateway}"
log() { printf '[gateway-ready] %s\n' "$*"; }
if [ -f "$GDIR/gateway.env" ]; then
  while IFS='=' read -r k v; do [ -n "$k" ] || continue; eval "[ -n \"\${$k+x}\" ]" || export "$k=$v"; done < "$GDIR/gateway.env"
fi
HOST="${AGENTSEC_PUBLIC_HOST:-localhost}"; PORT="${AGENTSEC_PUBLIC_PORT:-${AGENTSEC_HTTPS_PORT:-443}}"
RUN_ID=""; [ "${1:-}" = "--run-id" ] && RUN_ID="${2:-}"
status=0

# 1. Gateway: container running, nginx configuration valid, TLS verified with the configured CA, authentication required.
if docker ps --format '{{.Names}}' 2>/dev/null | grep -qx agentsec_gateway && docker exec agentsec_gateway nginx -t >/dev/null 2>&1; then
  CA="${AGENTSEC_TLS_CHAIN_FILE:-$GDIR/tls/ca.pem}"
  if [ -r "$CA" ]; then
    code="$(curl -sS -o /dev/null -w '%{http_code}' --max-time 10 --cacert "$CA" --resolve "$HOST:$PORT:127.0.0.1" "https://$HOST:$PORT/learn" 2>/dev/null || echo 000)"
    if [ "$code" = "401" ]; then log "GATEWAY READY: https://$HOST:$PORT answers with a certificate that verifies against the configured CA and requires authentication."
    else log "GATEWAY NOT READY: https://$HOST:$PORT/learn returned HTTP $code (expected 401 without credentials; 000 means the TLS handshake or connection failed)."; status=1; fi
  else
    log "GATEWAY RUNNING: container and nginx configuration are valid. TLS NOT VERIFIED: no CA file to verify against (set AGENTSEC_TLS_CHAIN_FILE)."
  fi
else
  log "GATEWAY NOT READY: container agentsec_gateway is not running or its nginx configuration is invalid."; status=1
fi

# 2. Academy and 3. Attack Service: checked inside the network (their host ports are not published in gateway mode).
a="$(docker exec agentsec_attack_service curl -sS -o /dev/null -w '%{http_code}' --max-time 10 http://127.0.0.1:5001/learn 2>/dev/null || echo 000)"
if [ "$a" = "200" ]; then log "ACADEMY READY: the React Academy page is served by the Attack Service app."; else log "ACADEMY NOT READY: /learn returned HTTP $a inside the network."; status=1; fi
h="$(docker exec agentsec_attack_service curl -sS -o /dev/null -w '%{http_code}' --max-time 10 http://127.0.0.1:5001/health 2>/dev/null || echo 000)"
if [ "$h" = "200" ]; then log "ATTACK SERVICE READY: /health answers. This is not proof that an attack runs."; else log "ATTACK SERVICE NOT READY: /health returned HTTP $h."; status=1; fi

# 4. Splunk: reachability of Splunk Web on a loopback port only (never claims telemetry).
sp=""
for p in "${AGENTSEC_SPLUNK_LOCAL_PORT:-18000}" 8000; do
  c="$(curl -sS -o /dev/null -w '%{http_code}' --max-time 5 "http://127.0.0.1:$p/en-US/account/login" 2>/dev/null || echo 000)"
  [ "$c" = "200" ] && { sp="$p"; break; }
done
if [ -n "$sp" ]; then log "SPLUNK REACHABLE: Splunk Web answers on 127.0.0.1:$sp (loopback only; it is not behind the gateway)."
else log "SPLUNK NOT REACHABLE on loopback (optional: it may not be started, or it may be an external Splunk)."; fi

# 5. Telemetry: only a run-specific search can verify ingestion.
if [ -n "$RUN_ID" ]; then
  case "$RUN_ID" in *[!A-Za-z0-9_-]*|"") log "TELEMETRY NOT VERIFIED: --run-id must be 1-64 characters from A-Z a-z 0-9 _ -"; RUN_ID="" ;; esac
fi
if [ -n "$RUN_ID" ]; then
  pw="$(grep -E '^SPLUNK_PASSWORD=' "$ROOT/.env" 2>/dev/null | head -1 | cut -d= -f2- || true)"
  n="$(docker exec -u splunk -e SPLUNK_PASSWORD="$pw" agentsec_splunk bash -lc "curl -sk -u \"admin:\${SPLUNK_PASSWORD}\" https://127.0.0.1:8089/services/search/jobs/export -d output_mode=csv -d earliest_time=0 --data-urlencode 'search=search index=agentsec_telemetry run_id=$RUN_ID | stats count' | tail -1" 2>/dev/null | tr -dc '0-9' || true)"
  if [ -n "$n" ] && [ "$n" -gt 0 ] 2>/dev/null; then log "TELEMETRY VERIFIED for run_id=$RUN_ID: $n indexed events. This says nothing about other runs."
  else log "TELEMETRY NOT VERIFIED for run_id=$RUN_ID: no indexed events found (not ingested yet, wrong id, or Splunk unreachable)."; fi
else
  log "TELEMETRY NOT VERIFIED: service readiness is not proof of ingestion. Run with --run-id <id> after a launch to search for that run."
fi
# 6. LIVE workflow
log "LIVE WORKFLOW NOT VERIFIED: a readiness check never launches an attack; launch one from the Academy and confirm its evidence."
exit "$status"
