# AgentSec cross-workshop readiness matrix

**Status:** Phase 14A inventory. Classifications are DESIGN honesty, not a claim that 14B implemented launch.  
**Evidence class:** OBSERVED (Pass-2 UI, Attack Service code, runtime routes) + DOCUMENTED (workshops, hunts).  
**Do not start Phase 14B from this file.**

A workshop may have several flags. **LIVE READY** requires an actual learner launch path for BASELINE, ATTACK, and RETEST without pretending env-only RETEST is a click.

Legend:

| Flag | Meaning |
|------|---------|
| LIVE READY | Learner can generate fresh A/B/C through a documented launcher |
| LIVE PARTIAL | Some specimens launch; others need operator/runtime work |
| REPLAY READY | Canonical ids + Studio dropdown + hunts exist |
| GUIDED READY | Path A/B investigation cells exist (none do yet) |
| REQUIRES RUNTIME WORK | Per-request mode/profile/fixture not exposed without authz change |
| REQUIRES ATTACK-SERVICE WORK | No allowlisted launcher row |
| REQUIRES SPLUNK WORK | Hunt/token/Search-link work (bind-only; no new DET) |
| REQUIRES WORKSHOP-COPY WORK | ATTACK-before-launch / CONNECT / Path A copy |

---

## Published workshops

| Workshop | View | LIVE | REPLAY | GUIDED | Notes |
|----------|------|------|--------|--------|-------|
| Direct Prompt Injection | `ws_lab_pi_001` | LIVE PARTIAL | REPLAY READY | REQUIRES WORKSHOP-COPY WORK; REQUIRES SPLUNK WORK for Path A links | **14B:** Attack Service `POST /api/launch` fires LIVE BASELINE (ATK-001) and LIVE ATTACK (ATK-002) when AcmeBank profile matches. RETEST remains **BLOCKED BY PROCESS-ENV ARCHITECTURE**. Q-RUN-EVENTS family VALIDATED. |
| Tool Authorization | `ws_lab_mcp_001` | REQUIRES ATTACK-SERVICE WORK | REPLAY READY | REQUIRES WORKSHOP-COPY WORK | `POST /mcp/invoke` exists; not allowlisted on Attack Service. Handler counts authoritative. Best **second** reference after PI. |
| Scope Escalation | `ws_lab_mcp_003` | REQUIRES ATTACK-SERVICE WORK | REPLAY READY | REQUIRES WORKSHOP-COPY WORK | Reuses Q-MCP-*. Same invoke path. |
| Parameter / Resource Authorization | `ws_lab_mcp_004` | REQUIRES ATTACK-SERVICE WORK | REPLAY READY | REQUIRES WORKSHOP-COPY WORK | Closed invoke body; extra fields ERROR. |
| Tool Result Trust | `ws_lab_mcp_005` | REQUIRES ATTACK-SERVICE WORK | REPLAY READY | REQUIRES WORKSHOP-COPY WORK | Two-hop; do not clone PI evidence. |
| Confused Deputy | `ws_lab_mcp_006` | REQUIRES ATTACK-SERVICE WORK | REPLAY READY | REQUIRES WORKSHOP-COPY WORK | Caller vs deputy; no Identity Studio. |
| Tool Catalog | `ws_lab_mcp_catalog` | REQUIRES ATTACK-SERVICE WORK | REPLAY READY | REQUIRES WORKSHOP-COPY WORK | Metadata ≠ grant. |
| Scanner + Runtime Evidence | `ws_lab_scanner_runtime_evidence` | PRE-GENERATED / REQUIRES RUNTIME WORK | REPLAY READY | REQUIRES WORKSHOP-COPY WORK | mcp-scanner not launched from Attack Service. Scanner finding ≠ authz. |
| RAG / Retrieved Context | `ws_lab_rag_context` | REQUIRES ATTACK-SERVICE WORK | REPLAY READY | REQUIRES WORKSHOP-COPY WORK | `POST /rag/retrieve` exists; not a learner launcher. |
| Persistent Memory | `ws_lab_memory_security` | REQUIRES ATTACK-SERVICE WORK | REPLAY READY | REQUIRES WORKSHOP-COPY WORK | Write ≠ recall; two run.ids. |
| Goal / Instruction Integrity | `ws_lab_agent_goal_integrity` | REQUIRES ATTACK-SERVICE WORK | REPLAY READY | REQUIRES WORKSHOP-COPY WORK | Strongest COMPARE teaching; 13C LIVE packs. No DET-GOAL. |
| Home | `ws_agentsec_home` | NOT APPLICABLE | NOT APPLICABLE | NOT APPLICABLE | Orientation only. |
| Identity / Delegation | *(no Studio view)* | NOT APPLICABLE | NOT APPLICABLE | NOT APPLICABLE | Do not invent a published workshop. |

No published workshop is **LIVE READY** or **GUIDED READY** today.

---

## Attack Service

| Item | Status |
|------|--------|
| `GET /` Flask UI | IMPLEMENTED (LAB-PI-001 predict + LIVE BASELINE/ATTACK; RETEST refused) |
| `POST /api/attacks/ATK-002` | IMPLEMENTED (legacy) |
| Allowlisted `POST /api/launch` | IMPLEMENTED (LAB-PI-001 BASELINE + ATTACK only) |
| Evidence-state machine | IMPLEMENTED (in-memory; EVIDENCE_READY only after Splunk probe) |
| Authn | NOT IMPLEMENTED (localhost) — FUTURE PRODUCTION |

---

## Splunk investigation quality (REPLAY)

All eleven workshops have LEARN→PROVE Studio shells and validated Q-* binds. That is **REPLAY READY**, not guided Path A.

PI indexed copy may be missing on a given volume (Pass-2 OBSERVED empty HUNT tables). Empty ≠ DENY. Completeness remains local pack vs `dc(_raw)`.
