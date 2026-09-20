# AgentSec LIVE launch evidence contract (Phase 14B)

**Status:** IMPLEMENTED as Attack Service states + optional probe.  
**Schema packs:** still default `splunk.verified=false` in `export.json`. Attack Service does **not** rewrite that file.  
**Do not start Phase 14C from this file.**

---

## Fresh run.id

Every successful `/api/launch` must return a **new** UUID from AcmeBank. Canonical workshop dropdown ids are REPLAY and must not be used as 14B proof.

---

## Layers (independent)

| Layer | Proves | Does not prove |
|-------|--------|----------------|
| Runtime HTTP 200 + hops | Local control decision / LLM placement | Splunk has a copy |
| `events.jsonl` | Local OBSERVED bundle | Indexing |
| `export.json` `otlp.ok` | SDK flush | Collector, HEC, Search |
| HEC 200 | Transport acceptance | Searchable events |
| Splunk `dc(_raw)` for that `run.id` | Searchable copy | Prevention, detection, incident |

---

## Probe

`GET /api/launches/<run_id>/evidence?timeout_seconds=0..120`

Query (reuse, not a new hunt file):

```
index=agentsec_telemetry sourcetype=otel:agentic:json earliest=-1h "agentsec.run.id"="<run.id>"
| stats dc(_raw) as n
```

Relative `earliest=-1h` is for LIVE freshness, not a production `earliest=0` claim. Existing Q-* files still use `earliest=0` for REPLAY canonical ids.

| `n` | State |
|-----|--------|
| >= 1 | `EVIDENCE_READY`, `splunk_verified=true` |
| 0 or probe unavailable | `WAITING_FOR_EVIDENCE`, `splunk_verified=false` |
| budget exhausted | `evidence_timeout=true`, still WAITING — **not** FAILED ATTACK / BLOCKED / SAFE |

If docker CLI is absent (Attack Service container without a probe), `splunk_attempted=false`. That is a gap, not a control outcome. Host-side live validation uses `docker exec agentsec_splunk` with password inside the Splunk container.

---

## Completeness

`completeness_ok` is `splunk_count == local_event_count` when both are known. EVIDENCE_READY only requires `n >= 1`. Do not call a timeout DENY.
