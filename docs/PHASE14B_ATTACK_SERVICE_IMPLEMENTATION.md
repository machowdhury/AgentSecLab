# Phase 14B — Attack Service + first LIVE learner launch

**Status:** IMPLEMENTED + OFFLINE TESTED (2026-09-19). LIVE Splunk reported separately in this file after the live probe.  
**Reference lab:** **LAB-PI-001 / Direct Prompt Injection** (Phase 14A choice; not substituted).  
**Schema:** **1.9.0 UNCHANGED**  
**Runtime authorization / CTRL-INPUT-001:** **UNCHANGED**  
**Detectors:** none created. DET-MCP-001 **UNCHANGED**.  
**Studio:** no new views. No custom JavaScript token binding. **Do not start Phase 14C from this file.**

---

## WHAT IS IT?

The smallest closed Attack Service launch path that lets a learner:

PREDICT → LAUNCH allowlisted BASELINE or ATTACK → receive a **fresh** `run.id` → copy it → hunt in Splunk Search.

It is the **execution plane**. It is not Guided Investigation Path A/B (that is 14C/14D).

---

## WHY DOES IT EXIST?

Phase 14A designed the contract. Learners still needed an honest LIVE path that does not turn Studio into a POST launcher or Splunk into enforcement.

---

## HOW IT WORKS

```text
Attack Service Flask  (127.0.0.1:5001, unauthenticated)
        |
        | POST /api/launch  {lab_id, specimen_id, profile, mode, execution}
        | allowlist + AcmeBank /health match
        v
AcmeBank POST /process     (existing PI pipeline, CTRL-INPUT-001)
        |
        | OTEL (if enabled)
        v
Collector → HEC → Splunk
        |
        v
Learner copies run.id → Search starter query (Q-RUN-EVENTS reuse)
```

Legacy `POST /api/attacks/ATK-002` is kept. It is not the typed contract.

---

## Reference lab verification

Phase 14A selected LAB-PI-001. OBSERVED: Attack Service already fired ATK-002; `POST /process` already ran ATK-001. No blocker required a lab substitution. MCP-001 remains the designated second lab (not implemented here).

---

## RETEST

**Classification: BLOCKED BY PROCESS-ENV ARCHITECTURE**

`testbed.mode=RETEST` is `AGENTSEC_TESTBED_MODE` on the AcmeBank process (`settings.testbed_mode_override`). 14B does **not** mutate that environment per request. `mode=RETEST` returns HTTP 400 `error=retest_not_live` (`error_class=ERROR`), not DENY.

If AcmeBank is already started with a mode override, LIVE BASELINE/ATTACK launches fail closed (`testbed_override_blocks_mode`) so a global RETEST label cannot silently relabel ATK-001/ATK-002.

---

## Evidence states actually measured

| State | Measured how |
|-------|----------------|
| REQUESTED | Allowlist + health checks passed |
| RUNNING | Runtime POST in flight |
| TELEMETRY_SENT | Runtime returned a `run.id`; local `events.jsonl` may exist |
| WAITING_FOR_EVIDENCE | Default after success. `splunk_verified=false` |
| EVIDENCE_READY | Separate probe: Splunk `dc(_raw) >= 1` for that `run.id` |
| ERROR | Allowlist/health/runtime failure. Not a control decision |

`otlp.ok` and HEC 200 are recorded when present in `export.json`. They never set EVIDENCE_READY.

---

## LIVE validation (separate from pytest)

Pytest is OFFLINE. It does not prove Splunk.

Targeted live probe (when compose + Splunk are up):

`uv run --extra test python scripts/validate_phase14b_live_launch.py`

That script must use a **fresh** `run.id`, not a canonical REPLAY id.

Record results below only after the script runs.

| Check | Class | Result |
|-------|-------|--------|
| OFFLINE pytest | MEASURED | 734 passed, 2 deselected |
| LOCAL RUNTIME launch | OBSERVED | Host Attack Service `127.0.0.1:5022` (compose `:5001` still ran a pre-14B image during this probe) |
| BASELINE LIVE | OBSERVED / MEASURED | `3e5d7ca0-5df9-449c-8a12-825926f486ab` — 22 local events, `testbed.mode=BASELINE`, `splunk_verified=false` at launch |
| ATTACK LIVE | OBSERVED / MEASURED | `130a7e1e-89a5-4960-af69-8a2840dac27c` — 6 local events, DENY, `llm_call_count=0`, `testbed.mode=ATTACK` |
| RETEST LIVE | OBSERVED | HTTP 400 `retest_not_live` / `error_class=ERROR` |
| TRANSPORT | OBSERVED | `export.json` `otlp.ok=true`; runtime `hec.ok=false` (runtime never fills HEC) |
| LIVE SPLUNK `dc(_raw)` | MEASURED | BASELINE 22=22; ATTACK 6=6; `EVIDENCE_READY` after probe, not from HEC |
| Existing hunt | MEASURED | `Q-CONTROL-DECISION` on ATTACK id: 1 row DENY / `CTRL-INPUT-001` / `prevented` |
| Live container schema | OBSERVED | Running AcmeBank image emitted `agentsec.schema.version=1.7.0`. Repository schema remains **1.9.0**; 14B did not bump it and did not rebuild AcmeBank. |
| UI | OBSERVED | Attack Service Flask on 5022 served predict + launch copy; no Studio redesign |

---

## Localhost limitation

LOCAL EDUCATIONAL SERVICE. **NOT PRODUCTION AUTHENTICATION.** NOT MULTI-TENANT. NOT INTERNET-FACING.

## Security boundaries

- Splunk ≠ enforcement
- Attack Simulator ≠ authorization engine
- Learning metadata ≠ security policy
- REPLAY ≠ LIVE
- Missing Splunk row ≠ prevention
- HEC 200 ≠ searchable evidence

---

## What 14B did not do

- Phase 14C guided investigation notebook
- New Q-* or DET-*
- Schema bump (repository remains 1.9.0)
- Rebuild of the running AcmeBank image (live packs from that container were 1.7.0)
- Per-request RETEST
- Authentication / tenancy / rate limits
- Custom JS Studio token write
- Global UI redesign
- Compose `:5001` image refresh (live probe used host `:5022`)
