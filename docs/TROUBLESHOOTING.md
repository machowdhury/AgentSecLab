# Troubleshooting

Learner-oriented symptoms also live in [AGENTSEC_TROUBLESHOOTING_FOR_LEARNERS.md](AGENTSEC_TROUBLESHOOTING_FOR_LEARNERS.md). This runbook is the operator + learner canonical list for v1.0.

Rule: **infrastructure failure is not a security conclusion.**

## Docker daemon unavailable

**Symptom:** `lab-up` / `docker` errors cannot connect.  
**Cause:** Docker Desktop/engine stopped.  
**Check:** `docker info`.  
**Remediation:** Start Docker, rerun `./scripts/lab-preflight.sh`.  
**Do not conclude:** anything about ALLOW/DENY.

## Port already in use

**Symptom:** bind errors or preflight FAIL on 5000/5001/8000/8088/4317/4318.  
**Cause:** another process, or a leftover container.  
**Check:** `./scripts/lab-preflight.sh`, `docker ps`.  
**Remediation:** stop the other listener, or `./scripts/lab-down.sh` if AgentSec leftovers exist.  
**Do not conclude:** the lab “blocked an attack.”

## Splunk Web unavailable

**Symptom:** :8000 not HTTP 200.  
**Cause:** still booting (10–20 min first time), crashed container, port conflict.  
**Check:** `docker inspect -f '{{.State.Health.Status}}' agentsec_splunk`.  
**Remediation:** wait; `./scripts/lab-up.sh`; logs for `splunk`.  
**Do not conclude:** experiments failed.

## Splunk login failure

**Symptom:** admin password rejected.  
**Cause:** `.env` `SPLUNK_PASSWORD` does not match the volume created on first boot.  
**Check:** you did not change password after first `lab-up` without recreating the Splunk volume.  
**Remediation:** use the password from the `.env` used at first boot, or FULL RESET (destructive) if you accept losing indexed data.  
**Do not conclude:** authorization succeeded.

## HEC unhealthy

**Symptom:** :8088 health not 200.  
**Cause:** Splunk not ready; `splunk_hec_init` not completed; HEC lost after Splunk restart without re-init.  
**Check:** `docker inspect agentsec_splunk_hec_init`; `./scripts/lab-ready.sh`.  
**Remediation:** `./scripts/lab-up.sh --refresh-app` (re-runs HEC init after restart).  
**Do not conclude:** a control DENY.

## Attack Service unavailable

**Symptom:** :5001 down.  
**Cause:** container stopped; image stale; AcmeBank unhealthy (depends_on).  
**Check:** `curl http://127.0.0.1:5001/health`.  
**Remediation:** `./scripts/lab-up.sh --build` if UI/source mismatch; else `lab-up`.  
**Do not conclude:** RETEST passed.

## AcmeBank unavailable

**Symptom:** :5000 health fail; launches error.  
**Cause:** Ollama still starting; crash.  
**Check:** `curl http://127.0.0.1:5000/health`; `docker logs agentsec_acmebank`.  
**Remediation:** wait for ollama healthy; restart acmebank.  
**Do not conclude:** DENY.

## Collector unhealthy

**Symptom:** no events in Splunk after a successful runtime.  
**Cause:** collector not running; HEC token mismatch.  
**Check:** `docker ps` `agentsec_otel_collector`; mesh HEC in `lab-ready`.  
**Remediation:** fix `.env` token to match HEC init; restart collector.  
**Do not conclude:** prevention.

## Events generated but not searchable

**Symptom:** Attack Service run.id exists; Search empty.  
**Cause:** indexing delay; wrong index/sourcetype; wrong id; HEC ok but pipeline lag.  
**Check:** wait; quoted run.id; `index=agentsec_telemetry sourcetype=otel:agentic:json`.  
**Remediation:** wait and retry; confirm WAITING_FOR_EVIDENCE vs READY.  
**Do not conclude:** blocked.

## WAITING_FOR_EVIDENCE

**Symptom:** launcher says waiting.  
**Cause:** honest default until export/searchability is known.  
**Check:** Search later; local artifacts if present.  
**Remediation:** wait; do not invent rows.  
**Do not conclude:** SAFE or DENY.

## Empty Studio table

**Symptom:** Path B / data-driven panel empty.  
**Cause:** REPLAY id not on this volume; token not your LIVE id; hunt zero-rows.  
**Check:** LIVE vs REPLAY; Search independently.  
**Remediation:** Path A with LIVE id; or another specimen.  
**Do not conclude:** DENY.

## LIVE run.id not found

**Symptom:** Search empty for a UUID you copied.  
**Cause:** typo; different Splunk; not indexed yet; copied specimen id.  
**Check:** Attack Service page for **this** launch.  
**Remediation:** recopy; wait; confirm index.  
**Do not conclude:** blocked.

## REPLAY run.id absent

**Symptom:** canonical UUID empty.  
**Cause:** this volume never ingested that specimen.  
**Check:** documented as expected on a fresh Splunk.  
**Remediation:** use LIVE labs for evidence; treat Path B as expected shape only.  
**Do not conclude:** the historical experiment was DENY.

## Schema mismatch

**Symptom:** fields missing.  
**Cause:** expecting a schema bump that did not happen. v1.0 schema is **1.9.0**.  
**Check:** `agentsec.schema.version`.  
**Remediation:** hunt with documented 1.9.0 fields.  
**Do not conclude:** product version equals schema.

## Stale container image

**Symptom:** Attack UI missing copy that exists in git (e.g. ATLAS qualifier).  
**Cause:** Python is baked into the image; no source bind for `src/`.  
**Check:** `./scripts/lab-up.sh --build`.  
**Remediation:** rebuild.  
**Do not conclude:** the repository lacks the fix.

## Studio XML not restaged

**Symptom:** dashboards show old copy.  
**Cause:** named volume copy is stale.  
**Check:** `./scripts/lab-up.sh --refresh-app`.  
**Remediation:** refresh-app. Browser hard reload if needed.

## HTTP 400 from launch

**Symptom:** launch JSON rejected.  
**Cause:** unknown_fields, unknown_lab, unknown_mode, malformed JSON.  
**Check:** only four fields; mode BASELINE|ATTACK|RETEST; execution live.  
**Remediation:** use the UI buttons; do not add profile/grants.  
**Do not conclude:** coded_policy DENY.

## unknown_fields

Authority-like keys are rejected as **ERROR**, not DENY.

## Profile / experiment mismatch

**Cause:** expecting browser-selected profile.  
**Remediation:** read ExperimentContext; ATTACK vs RETEST specimens.

## Ollama unavailable

**Symptom:** PI/LIVE model path fails; AcmeBank waits.  
**Cause:** model pull; ollama unhealthy.  
**Check:** `docker logs agentsec_ollama`.  
**Remediation:** wait through start_period; do not use host :11434 unless you changed compose.

## Browser cache

**Symptom:** old Attack UI.  
**Remediation:** hard reload; confirm rebuild.

## HTTP 400 workshop page

**Symptom:** Studio view fails to parse.  
**Cause:** bad XML restage.  
**Remediation:** `--refresh-app`; do not hand-edit volume files.
