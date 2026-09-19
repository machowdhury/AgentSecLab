# Delegation / identity detection model

**Status:** Phase 12A **DESIGN / ANALYSIS**. **DETECTION ANALYZED — NO DETECTOR JUSTIFIED IN 12A.**  
**DET-MCP-001 unchanged.** **No DET-DELEGATION. No DET-A2A. No SPL.**  
**Evidence class:** **DOCUMENTED**.

Parents: `docs/DELEGATION_EVENT_MODEL_REVIEW.md`, `docs/MCP006_DETECTION_MODEL.md`, `docs/PHASE11D_MEMORY_DETECTION_ANALYSIS.md`.

---

## Question a detector would have to answer

Did Agent B **execute** `lookup_customer_tier` because a **caller/A2A claim** was treated as a grant, even though **coded policy** did not include that tool for A or B?

That is **not** DET-MCP-001 (DENY then `mcp.started`).

## DET-MCP-001 — do not broaden

| Specimen | Expected DET-MCP-001 |
|----------|----------------------|
| BASELINE | 0 (no DENY) |
| ATTACK | 0 (vulnerable **ALLOW** path — no DENY to pair) |
| RETEST | 0 (DENY respected — no later start) |

0 rows is **CORRECT**. 0 rows ≠ SAFE. Do not widen the detector to “identity mismatch” or “any A2A.”

## Candidate classification

| Candidate | Class | Why |
|-----------|-------|-----|
| Caller agent != expected caller | **HUNT** / **CONTEXT** | Needs first-class caller field; allow-list of pairs is lab-specific |
| Privilege amplification (requested tool ∉ coded grants of A and B) | **HUNT** | Needs grant snapshot **or** honest coded-policy join. Snapshot **absent** → **TELEMETRY GAP** for a detector |
| Requested scope exceeds claimed delegated scope | **HUNT** | Claimed vs requested; not a production notable by itself |
| Cross-agent sensitive-tool request | **CONTEXT / HUNT** | Sensitive is a lab label |
| Unexpected delegation depth | **BEHAVIORAL / ML CANDIDATE** | First lab is depth 1 |
| Rare agent→agent→tool sequence | **BEHAVIORAL / ML CANDIDATE** | ANOMALY ≠ INCIDENT |
| Delegation followed by sensitive execution | **HUNT** | Insufficient without grant context |
| Execution after identity/delegation DENY | **DETECTION CANDIDATE (future)** | Only if a **DENY** control exists then start. First lab DENYs at **CTRL-MCP-001**, which DET-MCP-001 already covers **if** start happens after that DENY |
| Cross-principal activity | **TELEMETRY GAP / FUTURE** | Tenant/principal ownership incomplete |
| Confused deputy behavior | **Already MCP-006 hunt space** | Do not create a second deputy detector here |
| Overlay reason `caller_identity_derived_authority` as notable | **REJECT** | Lab-only fail-open string. Same class as memory/RAG overlay reasons |
| Agent Card skill name regex | **REJECT** | Advertisement, not grant |
| Prompt DID / `Delegation-Chain:` | **REJECT** | AgentWatch theater |
| JWT `role=admin` in _raw | **REJECT** | Must not index JWTs |

## Verdict

**NO DETECTOR JUSTIFIED** in Phase 12A (and not assumed for 12B). Future hunt after field discovery: reconstruct caller + callee + requested tool + CTRL-MCP-001. Promote to detection only with grant snapshot or DENY-then-start (already DET-MCP-001).

## Behavioral / ML future path (not implemented)

Possible later: rare A→B edges, new delegation paths, unusual depth, sensitive tools after claims, scope amplification, principal→agent drift, fan-out bursts.

Mechanisms: statistical SPL, MLTK, CDTSM, **graph** (see below).

```text
ANOMALY != INCIDENT
RARE != MALICIOUS
ML MAY PRIORITIZE INVESTIGATION
ML MUST NOT GRANT AUTHORITY
ML MUST NOT DENY AUTHORITY BY ITSELF
```

## Graph security model (DESIGN ONLY)

```text
Principal --delegates_to--> Agent A --calls--> Agent B
                              |                  |
                           requests           requests
                              v                  v
                            Tool --authorized_for / executed--> Resource
```

Nodes: principals, agents, tools, resources.  
Edges: `delegates_to`, `calls`, `requests`, `authorized_for`, `executed`, `accesses`.

Later Splunk use: join-free **hunt assist** (who talked to whom before a sensitive tool). Not a PDP. Not implemented. No graph database in 12A.

## Stop

No DET-DELEGATION. No saved search. No notable. No SPL in this phase.
