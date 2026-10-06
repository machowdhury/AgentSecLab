#!/bin/sh
# Create index agentsec_telemetry and a HEC token. Lab-local only.
set -eu

SPLUNK_HOST="${SPLUNK_HOST:-splunk}"
SPLUNK_PASSWORD="${SPLUNK_PASSWORD:-}"
HEC_TOKEN="${SPLUNK_HEC_TOKEN:-}"
HEC_INDEX="${SPLUNK_HEC_INDEX:-agentsec_telemetry}"
HEC_SOURCETYPE="${SPLUNK_HEC_SOURCETYPE:-otel:agentic:json}"
HEC_INPUT_NAME="${SPLUNK_HEC_INPUT_NAME:-agentsec-otel}"
SPECIMEN_ROOT="${AGENTSEC_SPECIMEN_ROOT:-/specimens}"
AUTH="admin:${SPLUNK_PASSWORD}"
MGMT_URL="https://${SPLUNK_HOST}:8089"
HEC_URL_HTTP="http://${SPLUNK_HOST}:8088/services/collector/event"
# The raw endpoint re-indexes each committed line verbatim and lets props.conf
# take _time from the event's own "timestamp". The /event endpoint would wrap
# the body and stamp it at ingest, which would misdate historical evidence.
HEC_URL_RAW="http://${SPLUNK_HOST}:8088/services/collector/raw?index=${HEC_INDEX}&sourcetype=${HEC_SOURCETYPE}"

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

# --- canonical REPLAY specimen seeding ---------------------------------------
# A workshop that offers a run.id in an "Investigate specimen" dropdown promises
# the learner evidence. Committed packs under learning/level_1/<LAB>/specimens/
# are the definition of that promise; this is where it is kept. See
# src/agentsec/replay_specimens.py.

indexed_count() {
  # Rows currently searchable for one run.id. Empty output is treated as 0 by
  # the caller: an unparseable answer must never look like a successful seed.
  mgmt_request POST "/services/search/jobs/export" \
    --data-urlencode "search=search index=${HEC_INDEX} sourcetype=${HEC_SOURCETYPE} \"agentsec.run.id\"=\"$1\" | stats count" \
    --data-urlencode "earliest_time=0" \
    --data-urlencode "output_mode=csv" 2>/dev/null \
    | tr -d '"\r' | tail -n 1 | grep -E '^[0-9]+$' || true
}

seed_one_specimen() {
  pack="$1"
  run_id="$(basename "$pack" .jsonl)"
  expected="$(grep -c '[^[:space:]]' "$pack" || true)"
  [ -n "$expected" ] || expected=0
  if [ "$expected" -eq 0 ]; then
    log "SPECIMEN ${run_id}: committed pack is empty — refusing to seed."
    return 1
  fi

  current="$(indexed_count "$run_id")"
  [ -n "$current" ] || current=0

  if [ "$current" -eq "$expected" ]; then
    log "SPECIMEN ${run_id}: already indexed (${current}/${expected}). No action."
    return 0
  fi
  if [ "$current" -gt 0 ]; then
    # Re-posting would duplicate the events that are already there and inflate
    # every count the learner reads. Partial state is a human decision.
    log "SPECIMEN ${run_id}: PARTIAL (${current}/${expected} indexed). Not re-posting; duplicates would corrupt counts."
    return 1
  fi

  log "SPECIMEN ${run_id}: absent. Replaying ${expected} committed events..."
  post_code="$(curl -s -o /tmp/hec_seed_body.txt -w "%{http_code}" \
    "${HEC_URL_RAW}" \
    -H "Authorization: Splunk ${HEC_TOKEN}" \
    --data-binary "@${pack}" 2>/dev/null || echo "000")"
  if [ "$post_code" != "200" ]; then
    log "SPECIMEN ${run_id}: HEC POST returned HTTP ${post_code}."
    return 1
  fi

  # HEC ACCEPTANCE IS NOT EVIDENCE READINESS. A 200 means the payload was
  # queued, not that a learner can search it. Only the search below decides.
  attempt=1
  while [ "$attempt" -le 12 ]; do
    sleep 5
    current="$(indexed_count "$run_id")"
    [ -n "$current" ] || current=0
    if [ "$current" -eq "$expected" ]; then
      log "SPECIMEN ${run_id}: VERIFIED searchable (${current}/${expected})."
      return 0
    fi
    attempt=$((attempt + 1))
  done
  log "SPECIMEN ${run_id}: HEC accepted the payload but only ${current}/${expected} events are searchable."
  return 1
}

seed_replay_specimens() {
  if [ ! -d "$SPECIMEN_ROOT" ]; then
    log "No specimen root at ${SPECIMEN_ROOT}; skipping REPLAY seeding."
    return 0
  fi
  found=0
  failed=0
  for pack in "$SPECIMEN_ROOT"/*/specimens/*.jsonl; do
    [ -f "$pack" ] || continue
    found=$((found + 1))
    seed_one_specimen "$pack" || failed=$((failed + 1))
  done
  if [ "$found" -eq 0 ]; then
    log "No committed REPLAY packs found under ${SPECIMEN_ROOT}."
    return 0
  fi
  if [ "$failed" -gt 0 ]; then
    log "ERROR: ${failed} of ${found} REPLAY specimens are not searchable. Workshop specimen dropdowns will show empty panels."
    return 1
  fi
  log "PASS — all ${found} canonical REPLAY specimens are searchable."
  return 0
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
  seed_replay_specimens
  exit $?
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
    seed_replay_specimens
    exit $?
  fi
  log "HEC attempt ${attempt}/20 HTTP ${test_code}"
  attempt=$((attempt + 1))
  sleep 5
done

log "ERROR: HEC test failed."
exit 1
