#!/bin/sh
# Create index agentsec_telemetry and a HEC token. Lab-local only.
set -eu

SPLUNK_HOST="${SPLUNK_HOST:-splunk}"
SPLUNK_PASSWORD="${SPLUNK_PASSWORD:-}"
HEC_TOKEN="${SPLUNK_HEC_TOKEN:-}"
HEC_INDEX="${SPLUNK_HEC_INDEX:-agentsec_telemetry}"
HEC_SOURCETYPE="${SPLUNK_HEC_SOURCETYPE:-otel:agentic:json}"
HEC_INPUT_NAME="${SPLUNK_HEC_INPUT_NAME:-agentsec-otel}"
AUTH="admin:${SPLUNK_PASSWORD}"
MGMT_URL="https://${SPLUNK_HOST}:8089"
HEC_URL_HTTP="http://${SPLUNK_HOST}:8088/services/collector/event"

log() { printf '[hec-init] %s\n' "$*"; }

if [ -z "$SPLUNK_PASSWORD" ] || [ -z "$HEC_TOKEN" ]; then
  log "ERROR: SPLUNK_PASSWORD and SPLUNK_HEC_TOKEN must be set from the environment."
  exit 1
fi

mgmt_request() {
  method="$1"
  path="$2"
  shift 2
  curl -sk -u "$AUTH" -X "$method" "${MGMT_URL}${path}" "$@" 2>/dev/null || true
}

mgmt_code() {
  method="$1"
  path="$2"
  shift 2
  mgmt_request "$method" "$path" -o /dev/null -w "%{http_code}" "$@" | tail -c 3
}

wait_for_mgmt_api() {
  log "Waiting for Splunk management API..."
  i=1
  while [ "$i" -le 90 ]; do
    code="$(mgmt_code GET "/services/server/info")"
    if [ "$code" = "200" ]; then
      log "Splunk management API is up."
      return 0
    fi
    if [ "$code" = "401" ]; then
      log "ERROR: HTTP 401 — SPLUNK_PASSWORD does not match this Splunk volume."
      return 1
    fi
    i=$((i + 1))
    sleep 5
  done
  log "ERROR: Splunk management API not ready."
  return 1
}

ensure_index() {
  idx="$1"
  log "Ensuring index '${idx}' exists..."
  index_code="$(mgmt_code GET "/services/data/indexes/${idx}")"
  if [ "$index_code" = "200" ]; then
    log "Index '${idx}' already exists."
    return 0
  fi
  create_code="$(mgmt_code POST "/services/data/indexes" -d "name=${idx}" -d "datatype=event")"
  if [ "$create_code" = "200" ] || [ "$create_code" = "201" ]; then
    log "Index '${idx}' created."
    return 0
  fi
  log "ERROR: failed to create index '${idx}' (HTTP ${create_code})"
  return 1
}

test_hec_url() {
  curl -s -o /tmp/hec_init_body.txt -w "%{http_code}" \
    "$1" \
    -H "Authorization: Splunk ${HEC_TOKEN}" \
    -d "{\"event\":{\"hec_init\":true,\"sourcetype\":\"${HEC_SOURCETYPE}\"}}" 2>/dev/null || echo "000"
}

wait_for_mgmt_api || exit 1
sleep 10

log "Enabling HTTP Event Collector..."
hec_code="$(mgmt_code POST "/services/data/inputs/http/http/enable")"
log "HEC enable returned HTTP ${hec_code}"

log "Disabling HEC SSL for in-mesh HTTP..."
ssl_code="$(mgmt_code POST "/services/data/inputs/http/http" -d "enableSSL=0")"
if [ "$ssl_code" = "200" ] || [ "$ssl_code" = "201" ]; then
  mgmt_code POST "/services/admin/server/control/restart_splunkd" >/dev/null || true
  sleep 20
  wait_for_mgmt_api || exit 1
fi

ensure_index "${HEC_INDEX}" || exit 1

early_code="$(test_hec_url "${HEC_URL_HTTP}")"
if [ "$early_code" = "200" ]; then
  log "PASS — HEC already working."
  exit 0
fi

log "Configuring HEC token input '${HEC_INPUT_NAME}'..."
token_code="$(mgmt_code POST "/services/data/inputs/http" \
  -d "name=${HEC_INPUT_NAME}" \
  -d "token=${HEC_TOKEN}" \
  -d "index=${HEC_INDEX}" \
  -d "indexes=${HEC_INDEX}" \
  -d "sourcetype=${HEC_SOURCETYPE}" \
  -d "disabled=0")"
log "HEC token create returned HTTP ${token_code}"

attempt=1
while [ "$attempt" -le 20 ]; do
  test_code="$(test_hec_url "${HEC_URL_HTTP}")"
  if [ "$test_code" = "200" ]; then
    log "PASS — HEC HTTP 200 (attempt ${attempt})."
    exit 0
  fi
  log "HEC attempt ${attempt}/20 HTTP ${test_code}"
  attempt=$((attempt + 1))
  sleep 5
done

log "ERROR: HEC test failed."
exit 1
