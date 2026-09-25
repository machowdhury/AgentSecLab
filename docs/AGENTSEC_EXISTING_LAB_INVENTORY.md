# AgentSec existing lab inventory (Phase 15A)

**Status:** DESIGN inventory from repository artifacts (2026-09-19). **Historical 15A snapshot.**  
**Evidence class:** OBSERVED (source tree, views, hunts, launch catalog) + DOCUMENTED (phase validation reports).  
**Do not start Phase 15B from this file.**

**Phase 16B:** `LAB-AGENTSEC-CAPSTONE-001` (Lending Assistant Investigation) is implemented as the integrated LIVE capstone. Studio `ws_lab_agentsec_capstone`. Attack Service YES. This 15A file remains a dated inventory snapshot; current coverage is the 16B implementation docs. No new capstone detector.

Classifications are not inferred from roadmap prose alone. Cross-check: `learning/level_1/`, `src/agentsec/`, `splunk_app/…/views/`, `src/agentsec/experiment_context.py`, `src/agentsec/launch_catalog.py`, `learning/**/searches/*.spl`, `docs/IMPLEMENTATION_STATUS.md` proof columns.

Legend: **IMPLEMENTED** / **DESIGNED** / **LIVE VALIDATED** / **REPLAY** / **SIMULATED** / **PARTIAL** / **NOT IMPLEMENTED** / **NOT APPLICABLE**.

Attack Service LIVE means `known_lab_ids()` in `launch_catalog.py`. That set is `{LAB-PI-001, LAB-MCP-001}` only.

---

## Summary

| Lab ID | Title | Studio | Attack Service | LIVE ATTACK/RETEST | Path A/B | Detector |
|--------|-------|--------|----------------|--------------------|----------|----------|
| LAB-PI-001 | Direct Prompt Injection | `ws_lab_pi_001` | YES | LIVE VALIDATED | YES | NONE JUSTIFIED |
| LAB-MCP-001 | Tool Authorization | `ws_lab_mcp_001` | YES | LIVE VALIDATED | YES | DET-MCP-001 (disabled) |
| LAB-MCP-003 | Scope Escalation | `ws_lab_mcp_003` | NOT IMPLEMENTED | historical LIVE packs; no launcher | NOT IMPLEMENTED | DET-MCP-001 reuse |
| LAB-MCP-004 | Parameter / Resource | `ws_lab_mcp_004` | NOT IMPLEMENTED | historical LIVE packs | NOT IMPLEMENTED | DET-MCP-001 reuse |
| LAB-MCP-005 | Tool Result Trust | `ws_lab_mcp_005` | NOT IMPLEMENTED | historical LIVE packs | NOT IMPLEMENTED | NONE JUSTIFIED (DET-MCP-001 reuse only) |
| LAB-MCP-006 | Confused Deputy | `ws_lab_mcp_006` | NOT IMPLEMENTED | historical LIVE packs | NOT IMPLEMENTED | NONE JUSTIFIED |
| LAB-MCP-CATALOG | Tool Catalog | `ws_lab_mcp_catalog` | NOT IMPLEMENTED | historical LIVE packs | NOT IMPLEMENTED | NONE JUSTIFIED (candidate later) |
| LAB-SCANNER-RUNTIME-EVIDENCE | Scanner + Runtime | `ws_lab_scanner_runtime_evidence` | NOT APPLICABLE | scanner CLI packs; not a launcher | NOT IMPLEMENTED | NONE JUSTIFIED |
| LAB-EXTERNAL-EVALUATION-GARAK | Adversarial Model Evaluation | no Studio view (bounded Tool Lab) | NOT APPLICABLE | local garak CLI evaluation | NOT IMPLEMENTED | NONE JUSTIFIED |
| LAB-RAG-CONTEXT (LAB-RAG-001) | RAG / Retrieved Context | `ws_lab_rag_context` | NOT IMPLEMENTED | historical LIVE packs | NOT IMPLEMENTED | NONE JUSTIFIED |
| LAB-MEMORY-001 | Persistent Memory | `ws_lab_memory_security` | NOT IMPLEMENTED | historical LIVE packs (write+recall) | NOT IMPLEMENTED | NONE JUSTIFIED |
| LAB-AGENT-DELEGATION-001 | Identity / Delegation | **no view** | NOT IMPLEMENTED | historical LIVE packs | NOT IMPLEMENTED | NONE JUSTIFIED |
| LAB-AGENT-GOAL-INTEGRITY-001 | Goal / Instruction Integrity | `ws_lab_agent_goal_integrity` | NOT IMPLEMENTED | historical LIVE packs | NOT IMPLEMENTED | NONE JUSTIFIED |
| Home | AgentSec Home | `ws_agentsec_home` | NOT APPLICABLE | NOT APPLICABLE | NOT APPLICABLE | NOT APPLICABLE |

`lab-manifest.json` and `investigations.json` exist only under LAB-PI-001 and LAB-MCP-001.

---

## LAB-PI-001 — Direct Prompt Injection

| Field | Value |
|-------|-------|
| Human title | Direct Prompt Injection |
| Security domain | Direct prompt / input injection |
| Attack ID | ATK-001 (BASELINE), ATK-002 (ATTACK/RETEST) |
| Invariant(s) | INV-008 (fail-safe), INV-007 (evidence) |
| Control(s) | CTRL-INPUT-001 |
| Schema dependency | Emitters 1.9.0; loan fields from 1.0.0 lineage |
| Runtime | IMPLEMENTED (`POST /process`) |
| Local validation | IMPLEMENTED |
| Splunk validation | LIVE VALIDATED (14D pair MEASURED) |
| Hunt | Q-RUN-EVENTS, Q-CONTROL-DECISION, Q-LLM-EXECUTED, Q-LLM-AFTER-DENY |
| Detector | NOT APPLICABLE / NONE JUSTIFIED |
| Studio | IMPLEMENTED (`ws_lab_pi_001`) |
| Attack Service | IMPLEMENTED |
| LIVE ATTACK | LIVE VALIDATED |
| LIVE RETEST | LIVE VALIDATED (equivalent ATK-002 bytes) |
| REPLAY | YES (canonical specimen dropdown) |
| SIMULATED | Q-LLM-AFTER-DENY positive-control labeled SIMULATED |
| Limitations | LLM nondeterminism on vulnerable ALLOW; HEC ≠ EVIDENCE READY |
| Prerequisites | Level 0 orientation |
| Learner value | HIGH — first 14E reference lab |

## LAB-MCP-001 — Tool Authorization

| Field | Value |
|-------|-------|
| Human title | Tool Authorization |
| Security domain | MCP tool authorization |
| Attack ID | MCP-001 (granted BASELINE), MCP-002 (ungranted ATTACK/RETEST) |
| Invariant(s) | INV-001, INV-007, INV-008 |
| Control(s) | CTRL-MCP-001 (tool PDP) |
| Schema dependency | MCP fields from 1.1.0; emitters 1.9.0 |
| Runtime | IMPLEMENTED (`POST /mcp/invoke`) |
| Local / Splunk | LIVE VALIDATED (14E pair MEASURED) |
| Hunt | Q-MCP-WHO, Q-MCP-AUTHZ, Q-MCP-TOOL, Q-MCP-EXECUTED, Q-MCP-AFTER-DENY (+ SCOPE/PARAMS/RESULT family) |
| Detector | DET-MCP-001 disabled saved search (DENY-then-start only) |
| Studio | IMPLEMENTED (`ws_lab_mcp_001`) |
| Attack Service | IMPLEMENTED |
| LIVE ATTACK / RETEST | LIVE VALIDATED (same lookup_customer_tier request) |
| REPLAY | YES |
| SIMULATED | DET-MCP-001 positive-control fixtures labeled SIMULATED |
| Limitations | In-process JSON-RPC, not a remote MCP product; control-event `executed` ≠ handler start |
| Prerequisites | PI-001 recommended; not a hard runtime dependency |
| Learner value | HIGH — second 14E reference lab |

## LAB-MCP-003 — Scope Escalation

| Field | Value |
|-------|-------|
| Domain | MCP tool / scope authority |
| Attack ID | MCP-003 |
| Invariant / control | INV-001 / CTRL-MCP-001 (no CTRL-MCP-003) |
| Schema | Lab specified 1.1.0; current emitters 1.9.0 |
| Runtime / Splunk / Studio | IMPLEMENTED + LIVE VALIDATED historically (`docs/PHASE4C_MCP003_SPLUNK_VALIDATION.md`, `ws_lab_mcp_003`) |
| Attack Service / Path A/B | NOT IMPLEMENTED |
| LIVE launcher | NOT IMPLEMENTED (operator/runtime scripts exist) |
| Hunt reuse | Existing Q-MCP-* |
| Detector | DET-MCP-001 reuse; no DET-MCP-003 |
| Learner value | HIGH — grant is not “the tool,” it is tool+scope |
| Prerequisites | LAB-MCP-001 |

## LAB-MCP-004 — Parameter / Resource Authorization

| Field | Value |
|-------|-------|
| Attack ID | MCP-004 |
| Control | CTRL-MCP-001 (no CTRL-MCP-004) |
| Schema | Lab specified 1.2.0 |
| Runtime / Splunk / Studio | IMPLEMENTED + LIVE VALIDATED historically + `ws_lab_mcp_004` |
| Hunt | Q-MCP-* + Q-MCP-RESOURCE-AUTHZ |
| Attack Service / Path A/B | NOT IMPLEMENTED |
| Learner value | HIGH — resource after scope |
| Prerequisites | LAB-MCP-001; LAB-MCP-003 strongly recommended |

## LAB-MCP-005 — Tool Result Trust

| Field | Value |
|-------|-------|
| Attack ID | MCP-005 |
| Invariant | INV-002 |
| Control | CTRL-MCP-RESULT-001 OBSERVE + CTRL-MCP-001 follow-on |
| Schema | 1.3.0 lineage |
| Runtime / Splunk / Studio | IMPLEMENTED + LIVE VALIDATED historically + `ws_lab_mcp_005` |
| Hunt | Q-MCP-* + Q-MCP-RESULT-AUTHORITY |
| Detector | DETECTION ANALYZED — NO NEW DETECTOR |
| Attack Service | NOT IMPLEMENTED (two-hop) |
| Learner value | HIGH — data ≠ authority after a legitimate call |
| Prerequisites | LAB-MCP-001; 003/004 recommended |

## LAB-MCP-006 — Confused Deputy

| Field | Value |
|-------|-------|
| Attack ID | MCP-006 |
| Invariant | INV-001 |
| Control | CTRL-DELEGATION-001 then CTRL-MCP-001 |
| Schema | 1.4.0 lineage |
| Runtime / Splunk / Studio | IMPLEMENTED + LIVE VALIDATED historically + `ws_lab_mcp_006` |
| Hunt | Q-MCP-* + Q-MCP-DELEGATION |
| Attack Service | NOT IMPLEMENTED (two-agent pipeline) |
| Distinct from | LAB-AGENT-DELEGATION-001 (identity claims; no Studio) |
| Learner value | HIGH — deputy ambient ≠ caller delegation |
| Prerequisites | LAB-MCP-001 |

## LAB-MCP-CATALOG — Tool Catalog / Metadata

| Field | Value |
|-------|-------|
| Attack ID | MCP-CATALOG-001 |
| Invariant | INV-002 |
| Control | CTRL-MCP-METADATA-001 OBSERVE then CTRL-MCP-001 |
| Schema | 1.5.0 lineage |
| Runtime / Splunk / Studio | IMPLEMENTED + LIVE VALIDATED historically + `ws_lab_mcp_catalog` |
| Hunt | Q-MCP-* + Q-MCP-CATALOG-AUTHORITY |
| Detector | Candidate justified for later design; **no DET-MCP-CATALOG** |
| Attack Service | NOT IMPLEMENTED |
| Learner value | HIGH — metadata ≠ grant |
| Prerequisites | LAB-MCP-001 |

## LAB-SCANNER-RUNTIME-EVIDENCE — Scanner + Runtime

| Field | Value |
|-------|-------|
| Domain | Supply chain / imported scanner evidence |
| Attack ID | NOT APPLICABLE as a launcher specimen (catalog fixtures scanned) |
| Control | None; scanners do not authorize. CTRL-MCP-001 remains runtime PDP |
| Runtime | IMPLEMENTED (Cisco mcp-scanner static adapter, pin 4.8.4) |
| Splunk | LIVE VALIDATED ingest `sourcetype=agentsec:scanner:finding` |
| Studio | `ws_lab_scanner_runtime_evidence` |
| Hunt | Q-SCANNER-WHO / ARTIFACT / FINDINGS / RUNTIME-CORRELATION + Q-MCP |
| Attack Service | NOT APPLICABLE |
| LIVE ATTACK | NOT APPLICABLE as Attack Service LIVE; scanner CLI is OBSERVED_SCANNER |
| Learner value | MEDIUM–HIGH — SCANNER FINDING ≠ AUTHORIZATION |
| Prerequisites | LAB-MCP-CATALOG |

## LAB-EXTERNAL-EVALUATION-GARAK — Adversarial Model Evaluation

| Field | Value |
|-------|-------|
| Domain | Adversarial AI evaluation / external evidence |
| Attack ID | NOT APPLICABLE; native garak evaluation id retained |
| Control | None; garak is not a PDP. CTRL-MCP-001 remains runtime PDP |
| Runtime | Local garak 0.17.0 → Ollama `llama3.2:1b`; not AgentSec runtime |
| Splunk | `sourcetype=agentsec:external:evaluation`, live validated in P1A |
| Studio | No view; bounded Tool Lab and SPL searches |
| Hunt | Q-GARAK-EVALUATION + Q-EXTERNAL-EVIDENCE-PLANES |
| Attack Service | NOT APPLICABLE |
| Learner value | HIGH — evaluation result ≠ authorization or universal safety |
| Prerequisites | External evidence concepts; scanner lab recommended |

## LAB-RAG-CONTEXT / LAB-RAG-001

| Field | Value |
|-------|-------|
| Folder | `learning/level_1/LAB-RAG-CONTEXT`; runtime package `src/agentsec/rag/` (LAB-RAG-001) |
| Attack ID | RAG-001 |
| Invariant | INV-002 |
| Control | CTRL-RAG-CONTEXT-001 OBSERVE + CTRL-MCP-001 |
| Schema | 1.6.0 lineage |
| Runtime | IMPLEMENTED (`POST /rag/retrieve`) |
| Splunk / Studio | LIVE VALIDATED historically + `ws_lab_rag_context` |
| Hunt | Q-RAG-CONTEXT-AUTHORITY + Q-MCP-* |
| Attack Service / Path A/B | NOT IMPLEMENTED |
| Learner value | HIGH — retrieved content is data |
| Prerequisites | LAB-MCP-001; INV-002 labs (005 or catalog) recommended |

## LAB-MEMORY-001 — Persistent Memory

| Field | Value |
|-------|-------|
| Attack ID | MEMORY-001 |
| Invariant | INV-003 (+ INV-002 on follow-on) |
| Control | CTRL-MEMORY-CONTEXT-001 OBSERVE + CTRL-MCP-001 |
| Schema | 1.7.0 lineage |
| Runtime | IMPLEMENTED (`/memory/write`, `/memory/recall`) |
| Splunk / Studio | LIVE VALIDATED historically + `ws_lab_memory_security` |
| Hunt | Q-MEMORY-CONTEXT-AUTHORITY + Q-MCP-* |
| Attack Service | NOT IMPLEMENTED (two run.ids: write then recall) |
| Learner value | HIGH — persistence ≠ trust |
| Prerequisites | LAB-RAG-CONTEXT |

## LAB-AGENT-DELEGATION-001 — Identity / Delegation

| Field | Value |
|-------|-------|
| Attack ID | A2A-001 (not MCP-006) |
| Invariant | INV-001, INV-005 (identity integrity) |
| Control | CTRL-IDENTITY-001 OBSERVE; CTRL-MCP-001 sole tool PDP |
| Schema | 1.8.0 lineage |
| Runtime | IMPLEMENTED (`POST /identity/delegate`) in-process; **A2A transport NOT IMPLEMENTED** |
| Splunk | LIVE VALIDATED historically (`docs/PHASE12C_AGENT_DELEGATION_SPLUNK_VALIDATION.md`) |
| Studio | NOT IMPLEMENTED (no `ws_lab_*` view; absent from nav) |
| Hunt | Q-AGENT-DELEGATION-AUTHORITY + Q-MCP-* |
| Attack Service / Path A/B | NOT IMPLEMENTED |
| Learner value | HIGH conceptually; MEDIUM as published learner path until Studio exists |
| Prerequisites | LAB-MCP-001; LAB-MCP-006 recommended so learners do not conflate deputy ambient with identity claims |

## LAB-AGENT-GOAL-INTEGRITY-001 — Goal / Instruction Integrity

| Field | Value |
|-------|-------|
| Attack ID | GOAL-001 |
| Invariant | INV-002, INV-006 |
| Control | CTRL-GOAL-INTEGRITY-001 + CTRL-MCP-001 sole tool PDP |
| Schema | 1.9.0 |
| Runtime | IMPLEMENTED (`POST /goal/evaluate`) |
| Splunk / Studio | LIVE VALIDATED historically + `ws_lab_agent_goal_integrity` |
| Hunt | Q-GOAL-INTEGRITY-AUTHORITY + Q-MCP-* |
| Attack Service / Path A/B | NOT IMPLEMENTED |
| Learner value | HIGH — authorized tool ≠ authorized goal |
| Prerequisites | LAB-MCP-001 |

---

## Future curriculum gaps (not labs)

Do not inventory these as implemented labs:

- Live A2A / OAuth / SPIFFE transport
- Catalog rug-pull / `tools/list_changed`
- Snyk Agent Scan
- MLTK / CDTSM behavioral analytics
- Splunk ES notables
- Multi-domain capstone runtime
- Identity Studio workshop
- Production authentication on Attack Service

---

## 14A matrix note

`docs/AGENTSEC_CROSS_WORKSHOP_READINESS_MATRIX.md` is a **Phase 14A historical snapshot**. It predates 14D/14E LIVE RETEST and MCP-001 Attack Service. This inventory supersedes it for 15A planning.
