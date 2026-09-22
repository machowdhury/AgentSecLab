# AgentSec live / replay lab matrix (Phase 16C)

**Status:** AUDIT inventory 2026-09-20. Canonical current surface.  
**Does not replace** the dated 15A snapshot in `docs/AGENTSEC_EXISTING_LAB_INVENTORY.md`.  
**Do not infer LIVE from runtime code.** LIVE here means Attack Service `known_lab_ids()` plus a documented MEASURED Splunk ATTACK/RETEST pair.

Schema **1.9.0**. No new detector. Learning metadata ≠ policy.

Legend: **LIVE** = Attack Service closed launch + MEASURED official pair. **REPLAY** = Studio + historical packs / canonical Investigate tokens. **DESIGN** = specified, not built.

---

## Summary

| lab_id | Human title | Mode | Attack Service | Path A/B | Studio | Detector |
|--------|-------------|------|----------------|----------|--------|----------|
| LAB-PI-001 | Direct Prompt Injection | LIVE | YES | YES | `ws_lab_pi_001` | NONE JUSTIFIED |
| LAB-MCP-001 | Tool Authorization | LIVE | YES | YES | `ws_lab_mcp_001` | DET-MCP-001 (disabled) |
| LAB-RAG-CONTEXT | RAG / Retrieved Context | LIVE | YES | YES | `ws_lab_rag_context` | NONE JUSTIFIED |
| LAB-MEMORY-001 | Persistent Memory | LIVE | YES | YES | `ws_lab_memory_security` | NONE JUSTIFIED |
| LAB-AGENT-GOAL-INTEGRITY-001 | Goal / Instruction Integrity | LIVE | YES | YES | `ws_lab_agent_goal_integrity` | NONE JUSTIFIED |
| LAB-AGENT-DELEGATION-001 | Agent Identity / Delegation | LIVE | YES | YES | `ws_lab_agent_delegation` | NONE JUSTIFIED |
| LAB-AGENTSEC-CAPSTONE-001 | Lending Assistant Investigation | LIVE | YES | YES | `ws_lab_agentsec_capstone` | NONE JUSTIFIED (DET-MCP-001 0 rows expected) |
| LAB-MCP-003 | Scope Escalation | REPLAY | NO | NO (`investigations.json` absent) | `ws_lab_mcp_003` | DET-MCP-001 reuse |
| LAB-MCP-004 | Parameter / Resource Authorization | REPLAY | NO | NO | `ws_lab_mcp_004` | DET-MCP-001 reuse |
| LAB-MCP-005 | Tool Result Trust | REPLAY | NO | NO | `ws_lab_mcp_005` | NONE JUSTIFIED |
| LAB-MCP-006 | Confused Deputy | REPLAY | NO | NO | `ws_lab_mcp_006` | NONE JUSTIFIED |
| LAB-MCP-CATALOG | Tool Catalog | REPLAY | NO | NO | `ws_lab_mcp_catalog` | Candidate later; no DET-MCP-CATALOG |
| LAB-SCANNER-RUNTIME-EVIDENCE | Scanner + Runtime Evidence | REPLAY / OBSERVED_SCANNER | NOT APPLICABLE | NO | `ws_lab_scanner_runtime_evidence` | NONE JUSTIFIED |
| Home | Home | ORIENTATION (stale copy) | n/a | n/a | `ws_agentsec_home` | n/a |
| Attack Service | closed launcher | LIVE for seven labs | YES | n/a | Flask `/` and `/labs/<id>` | n/a |
| Search | learner notebook | n/a | n/a | Path A lives here | `search` view | n/a |

---

## LIVE labs (detail)

### LAB-PI-001 — Direct Prompt Injection

| Field | Value | Class |
|-------|-------|-------|
| Attack ids | ATK-001 BASELINE; ATK-002 ATTACK/RETEST | OBSERVED |
| Domain / difficulty | Direct input injection / BEGINNER | OBSERVED |
| Prerequisites | Level 0 orientation (currently DESIGN, missing in product) | DESIGNED |
| Invariant / boundary | INV-008; untrusted HTTP loan input → CTRL-INPUT-001 → LLM | OBSERVED |
| Control / PDP | CTRL-INPUT-001 is the PDP | OBSERVED |
| Attack | Catalog ATK-002 string treated as instruction | OBSERVED |
| LIVE ATTACK / RETEST | YES; 14D pair DOCUMENTED MEASURED | DOCUMENTED |
| Guided investigations | PI-I1–I7 | OBSERVED |
| COMPARE / PROVE | Studio tabs | OBSERVED |
| Framework | LLM01-class RELATED; ATLAS AML.T0054 historically coded, REQUIRES REVALIDATION | DOCUMENTED |
| Limitations | Regex control; paraphrases may ALLOW; HEC ≠ evidence | OBSERVED |

### LAB-MCP-001 — Tool Authorization

| Field | Value | Class |
|-------|-------|-------|
| Attack ids | MCP-001 BASELINE; MCP-002 ATTACK/RETEST | OBSERVED |
| Domain | Tool allow-list | OBSERVED |
| Invariant / PDP | INV-001; CTRL-MCP-001 sole tool PDP | OBSERVED |
| Attack | Ungranted `lookup_customer_tier` / `customer:read` / `cust-001` | OBSERVED |
| LIVE | 14E pair DOCUMENTED MEASURED | DOCUMENTED |
| Investigations | MCP-I1–I6 | OBSERVED |
| Detector | DET-MCP-001 DENY-then-start only; ATTACK ALLOW is silent ≠ SAFE | DOCUMENTED |

### LAB-RAG-CONTEXT

| Field | Value | Class |
|-------|-------|-------|
| Attack id | RAG-001 | OBSERVED |
| Invariant | INV-002 | OBSERVED |
| Classifier / PDP | CTRL-RAG-CONTEXT-001 OBSERVE; CTRL-MCP-001 PDP | OBSERVED |
| Attack | Malicious retrieved document → follow-on privileged request | OBSERVED |
| LIVE | 15B official pair MEASURED in 15B docs | DOCUMENTED |
| Investigations | RAG-I1–I7 | OBSERVED |

### LAB-MEMORY-001

| Field | Value | Class |
|-------|-------|-------|
| Attack id | MEMORY-001 | OBSERVED |
| Invariant | INV-003 (+ INV-002 on follow-on) | OBSERVED |
| Classifier / PDP | CTRL-MEMORY-CONTEXT-001 OBSERVE; CTRL-MCP-001 PDP | OBSERVED |
| Attack | Write malicious memory, later recall, privileged follow-on | OBSERVED |
| LIVE | 15C two-run pair MEASURED | DOCUMENTED |
| Investigations | MEMORY-I1–I9 | OBSERVED |

### LAB-AGENT-GOAL-INTEGRITY-001

| Field | Value | Class |
|-------|-------|-------|
| Attack id | GOAL-001 | OBSERVED |
| Invariant | INV-002, INV-006 | OBSERVED |
| Control / PDP | CTRL-GOAL-INTEGRITY-001 on task; CTRL-MCP-001 still ALLOWs `lookup_policy` | OBSERVED |
| Attack | Untrusted instruction proposes `extract_full_policy` | OBSERVED |
| LIVE | 15D pair MEASURED; RETEST is GOAL DENY + MCP ALLOW | DOCUMENTED |
| Investigations | GOAL-I1–I9 | OBSERVED |

### LAB-AGENT-DELEGATION-001

| Field | Value | Class |
|-------|-------|-------|
| Attack id | A2A-001 | OBSERVED |
| Invariant | INV-001, INV-002, INV-005 | OBSERVED |
| Classifier / PDP | CTRL-IDENTITY-001 OBSERVE; CTRL-MCP-001 PDP | OBSERVED |
| Attack | Delegation claim treated as grant via labeled overlay | OBSERVED |
| LIVE | 15E pair MEASURED | DOCUMENTED |
| Investigations | IDENTITY-I1–I10 | OBSERVED |
| Not this lab | Real A2A, OAuth, SPIFFE | NOT IMPLEMENTED |

### LAB-AGENTSEC-CAPSTONE-001 — Lending Assistant Investigation

| Field | Value | Class |
|-------|-------|-------|
| Specimen | CAPSTONE-001 ATTACK/RETEST; CAPSTONE-BASELINE | OBSERVED |
| Telemetry attack.id | RAG-001 (schema enum; no CAPSTONE-001) | MEASURED (16B) |
| Domain | Integrated retrieve → persist → recall → MCP | OBSERVED |
| Invariant | INV-001, INV-002, INV-003, INV-007, INV-008 | OBSERVED |
| Classifier / PDP | RAG OBSERVE, Memory OBSERVE, CTRL-MCP-001 PDP | OBSERVED |
| Attack | Malicious lending-policy bytes persist and later request `lookup_customer_tier` | OBSERVED |
| LIVE | 16B official triples MEASURED | DOCUMENTED |
| Investigations | CAP-I1–I16 | OBSERVED |
| Goal / Identity | NOT PRESENT as active failures | OBSERVED |
| Detector | No DET-CAPSTONE; DET-MCP-001 0 rows expected | DOCUMENTED |

---

## REPLAY workshops (detail)

Runtime exists for MCP-003/004/005/006/catalog. Historical Splunk packs are DOCUMENTED MEASURED in their phase reports. They are **not** Attack Service LIVE. Do not relabel them LIVE.

| lab_id | Trust boundary | Control | Why still valuable |
|--------|----------------|---------|-------------------|
| LAB-MCP-003 | requested_scope vs grant | CTRL-MCP-001 | Grant is tool+scope |
| LAB-MCP-004 | resource / parameter | CTRL-MCP-001 | Grant is tool+scope+resource |
| LAB-MCP-005 | tool **result** as data | CTRL-MCP-RESULT-001 OBSERVE + MCP PDP | INV-002 after a legitimate call |
| LAB-MCP-006 | deputy ambient vs caller | CTRL-DELEGATION-001 then MCP | Distinct from identity-claims lab |
| LAB-MCP-CATALOG | tool description as data | CTRL-MCP-METADATA-001 OBSERVE + MCP | Metadata ≠ grant |
| LAB-SCANNER-RUNTIME-EVIDENCE | scanner plane vs runtime | none (scanner ≠ PDP) | SCANNER FINDING ≠ AUTHORIZATION |

---

## Honesty rules

- Historical LIVE packs for REPLAY labs remain MEASURED in those phase docs. They are operator/runtime evidence, not learner-launched Attack Service.
- Canonical Investigate dropdown ids are REPLAY (or official 16B tokens for capstone). Fresh LIVE ids come from Attack Service Search. Studio does not auto-bind.
- BASELINE is not SAFE. RETEST is not universal security.
