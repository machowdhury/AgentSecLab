# AgentSec Attack Simulator architecture

**Status:** Phase 14A DESIGN ONLY. **Not implemented.**  
**Existing code:** `src/agentsec/attack_app.py` (ATK-002 only), `src/agentsec/bank_app.py` (`POST /process`, `POST /mcp/invoke`, RAG/memory routes)  
**Do not start Phase 14B from this file.**

---

## WHAT IS IT?

A **closed educational execution plane**: an allowlisted HTTP service that launches a named lab specimen against the AgentSec runtime and returns a `run.id`. It is not a general exploit framework, a shell, or an authorization engine.

Today the Attack Service fires one catalog attack (`ATK-002`) into AcmeBank. Phase 14A designs how that service becomes the learner-facing launcher **without** moving authorization into Splunk or Studio.

---

## WHY DOES IT EXIST?

Learners need to **perform** BASELINE / ATTACK / RETEST, not only inspect canonical REPLAY ids. The runtime already exists. The missing product piece is a safe, explainable launch path plus honest evidence-readiness.

---

## HOW IT WORKS (target architecture)

```text
Dashboard Studio (orientation + investigation)
        |
        | link / documented URL  (NOT a Studio POST, NOT Splunk SPL-to-exec)
        v
AgentSec Attack Service   allowlisted lab / specimen / profile / mode
        |
        | validated request only
        v
AgentSec Runtime          CTRL-* before dangerous operations
        |
        | OpenTelemetry
        v
Collector → HEC → Splunk index agentsec_telemetry
        |
        v
Workshop investigation    Q-* hunts / Search  (copy, not enforcement)
```

HEC HTTP 200 is **transport**, not “evidence ready.”

---

## Trust boundary

| Surface | Trust | Notes |
|---------|-------|-------|
| Learner browser | Untrusted | May click launch; cannot supply grants |
| Attack Service | Untrusted relative to AcmeBank | Lab peer, not admin backdoor (`docs/ATTACK_CONTROL_MODEL.md`) |
| AcmeBank / runtime | Trusted for lab policy | Coded controls; `vulnerable` is labeled fail-open |
| Splunk | Observe-only | Does not ALLOW/DENY |
| Studio | Observe-only | Does not launch by executing SPL |

An attacker who can reach Attack Service on localhost can fire allowlisted specimens. That is the existing Phase 1A bind model. Authentication, tenancy, rate limits, and isolation are **FUTURE PRODUCTION REQUIREMENTS**, not claimed here.

---

## What the simulator MUST NOT accept

- arbitrary shell
- arbitrary Python
- arbitrary SPL translated into execution
- arbitrary tool names
- arbitrary profiles
- arbitrary payloads / extra JSON fields
- user-supplied authorization grants
- global coded-policy mutation
- arbitrary external targets
- production credentials

Malformed requests **fail closed** (ERROR / HTTP 4xx). Unknown fields are rejected (same spirit as `ALLOWED_MCP_INVOKE_FIELDS` on `POST /mcp/invoke`).

---

## Allowlist model

Launch refers to a **catalog row**, not a free-form attack:

| Field | Meaning |
|-------|---------|
| `lab_id` | Published lab (`LAB-PI-001`, `LAB-MCP-001`, …) |
| `specimen_id` | Catalog specimen (`ATK-002`, `MCP-001-ATTACK`, …) |
| `profile` | `defended` \| `vulnerable` |
| `mode` | `BASELINE` \| `ATTACK` \| `RETEST` |
| `execution` | `live` only for this service |

Payload bytes live in the catalog (`src/agentsec/attacks.py` and lab fixtures). The client does not send the injection string.

Exact HTTP shape: `docs/AGENTSEC_ATTACK_LAUNCH_CONTRACT.md`.

---

## Current vs designed

| Capability | OBSERVED today | Designed later |
|------------|----------------|----------------|
| Fire ATK-002 | `POST /api/attacks/ATK-002` | Keep |
| Return `run.id` | AcmeBank JSON includes `run_id` | Required on all launches |
| List attacks | ATK-002 only | Allowlisted catalog |
| BASELINE launch | AcmeBank UI / `POST /process` benign | Named specimen on Attack Service |
| RETEST launch | Process env `AGENTSEC_TESTBED_MODE=RETEST` | Per-request mode **only if runtime supports it**; otherwise document operator procedure |
| MCP / RAG / memory launch | Direct runtime HTTP | Attack Service allowlist rows — **not implemented** |
| Studio embedded POST | Absent | **Do not build** |
| Authn on Attack Service | None (localhost) | FUTURE PRODUCTION |

---

## Auditable launch event

Every accepted launch should emit a runtime security event on the resulting `run.id` (already true for `/process` and `/mcp/invoke`). Optionally the Attack Service access log records `lab_id`, `specimen_id`, `profile`, `mode`, timestamp. Do not invent a second authorization decision in that log.

Label **INTENTIONALLY VULNERABLE LAB PROFILE** whenever `profile=vulnerable`.

---

## Bounded execution

Reuse existing runtime timeouts (Attack Service already uses a long HTTP timeout to AcmeBank). Do not add a second LLM client. Do not skip controls in `defended`.

---

## Related

Launch contract: `docs/AGENTSEC_ATTACK_LAUNCH_CONTRACT.md`  
Modes: `docs/AGENTSEC_LAB_EXECUTION_MODES.md`  
Learning: `docs/AGENTSEC_LEARNING_EXPERIENCE_ARCHITECTURE.md`
