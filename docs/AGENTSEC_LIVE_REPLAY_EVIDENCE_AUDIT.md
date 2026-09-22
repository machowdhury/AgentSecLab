# AgentSec LIVE / REPLAY evidence audit

**Status:** Phase 17C. Schema **1.9.0**.  
**Do not start Phase 17D from this file.**

Curriculum (`learning/academy/curriculum.json`) labels each workshop **LIVE** or **REPLAY**. LIVE means Attack Service `known_lab_ids()` plus a documented MEASURED official pair. Every LIVE workshop except capstone also binds **canonical REPLAY Investigate dropdowns**. Capstone Investigate binds the official 16B LIVE UUIDs; those ids are still **historical copies**, not a launch the learner just minted.

`docs/AGENTSEC_EXISTING_LAB_INVENTORY.md` is a **dated 15A snapshot**. Current surface is this file plus `docs/AGENTSEC_LIVE_LAB_MATRIX.md`.

## Published workshops

| lab.id | Title | Curriculum mode | Investigate tokens | Official LIVE ATTACK/RETEST (historical MEASURED) | Attack Service |
|--------|-------|-----------------|--------------------|---------------------------------------------------|----------------|
| LAB-PI-001 | Direct Prompt Injection | LIVE | REPLAY B/A/R | 14D `7eb9176a-…` / `397f10ac-…` | YES |
| LAB-MCP-001 | Tool Authorization | LIVE | REPLAY B/A/R | 14E `bf5109de-…` / `0cd82b2a-…` | YES |
| LAB-RAG-CONTEXT | RAG / Retrieved Context | LIVE | REPLAY B/A/R | 15B `41b1dbf5-…` / `403319da-…` | YES |
| LAB-MEMORY-001 | Persistent Memory | LIVE | REPLAY write/recall pairs | 15C write/recall A `ad850327-…`/`e686da75-…` · R `a3ae94ba-…`/`87bd07c5-…` | YES (two-run) |
| LAB-AGENT-GOAL-INTEGRITY-001 | Goal / Instruction Integrity | LIVE | REPLAY B/A/R (13C) | 15D `dc1f549f-…` / `624b4223-…` | YES |
| LAB-AGENT-DELEGATION-001 | Agent Identity / Delegation | LIVE | REPLAY B/A/R (12C) | 15E `110dd7a6-…` / `7e4f74a8-…` | YES |
| LAB-AGENTSEC-CAPSTONE-001 | Lending Assistant Investigation | LIVE | **Official 16B UUIDs** | 16B retrieve/write/recall triples | YES (three-run) |
| LAB-MCP-003 | Scope Escalation | REPLAY | canonical historical | none | NO |
| LAB-MCP-004 | Parameter / Resource | REPLAY | canonical historical | none | NO |
| LAB-MCP-005 | Tool Result Trust | REPLAY | canonical historical | none | NO |
| LAB-MCP-006 | Confused Deputy | REPLAY | canonical historical | none | NO |
| LAB-MCP-CATALOG | Tool Catalog | REPLAY | canonical historical | none | NO |
| LAB-SCANNER-RUNTIME-EVIDENCE | Scanner + Runtime | REPLAY / OBSERVED_SCANNER | scan ids + catalog runtime ids | N/A | NOT APPLICABLE |

Home `ws_agentsec_home` and Mastery `ws_agentsec_mastery` are not labs.

## Rules

- No REPLAY specimen may be described as freshly executed.
- No LIVE run may be described as the canonical historical Investigate id (except capstone, which **reuses** the official 16B ids and must still be labeled historical if the learner did not just launch).
- Canonical REPLAY ≠ official LIVE pair for PI, MCP-001, RAG, Memory, Goal, Identity.
- Fresh Attack Service UUIDs are LIVE. Dropdown ids are REPLAY (or official historical for capstone).
- Memory WRITE ≠ RECALL. Capstone retrieve ≠ write ≠ recall.

## 17C correction

Memory BASELINE/RETEST cards previously stamped **LIVE** on canonical REPLAY write/recall UUIDs. Relabeled **REPLAY SPECIMEN**. PI LEARN banner no longer says **LIVE EVIDENCE** alone; it says **LIVE EXPERIMENT vs REPLAY SPECIMEN**.
