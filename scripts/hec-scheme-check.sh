#!/bin/sh
# Fast (<10 s) HEC transport check. Detects scheme/trust mismatch without readiness retries.
# Exit 0 = HTTPS verified, 1 = mismatch/misconfig, 2 = HEC not reachable yet (not a failure).
# Prints no secrets.
set -u
ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
log() { printf '[hec-scheme] %s\n' "$*"; }
envv() { [ -f "$ROOT/.env" ] && sed -n "s/^$1=//p" "$ROOT/.env" | tail -n 1; }

endpoint="${SPLUNK_HEC_ENDPOINT:-$(envv SPLUNK_HEC_ENDPOINT)}"
ca="${AGENTSEC_HEC_CA_FILE:-$(envv AGENTSEC_HEC_CA_FILE)}"
[ -n "$ca" ] || ca="$ROOT/.certs/hec-ca.crt"
case "$ca" in /*) ;; *) ca="$ROOT/$ca" ;; esac

case "$endpoint" in
  https://*) ;;
  "") log "FAIL SPLUNK_HEC_ENDPOINT is not set in .env"; exit 1 ;;
  *) log "FAIL SPLUNK_HEC_ENDPOINT must be https:// (got a non-HTTPS scheme)"; exit 1 ;;
esac
[ -r "$ca" ] || { log "FAIL HEC CA file not readable: $ca (run scripts/hec-certs.sh)"; exit 1; }

# Only probe the bundled Splunk when it is published on this host.
https_code="$(curl -s --cacert "$ca" -o /dev/null -w '%{http_code}' --max-time 4 https://localhost:8088/services/collector/health/1.0 2>/dev/null || true)"
http_code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 4 http://localhost:8088/services/collector/health/1.0 2>/dev/null || true)"
case "$http_code" in 200) log "FAIL HEC serves plain HTTP but config expects HTTPS (check splunk_app/agentsec/local/inputs.conf)"; exit 1 ;; esac
case "$https_code" in
  200) log "PASS HEC answers HTTPS with the configured CA; plain HTTP rejected"; exit 0 ;;
  000|"") log "INFO HEC not reachable on localhost:8088 yet"; exit 2 ;;
  *) log "FAIL HEC HTTPS returned $https_code"; exit 1 ;;
esac
