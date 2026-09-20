# AgentSec UI Information Architecture

**Status:** Pre-Phase-14 UI/UX remediation (2026-09-18)  
**Schema:** 1.9.0 unchanged  
**Splunk does not enforce authorization.**

This document is the product information architecture for AgentSec learner-facing Splunk UI. It does not describe runtime controls.

---

## Current inventory (after remediation)

| View | Class | Audience | Status |
|------|-------|----------|--------|
| `ws_agentsec_home` | HOME | LEARNER-FACING | CURRENT |
| `ws_lab_pi_001` | WORKSHOP / LAB | LEARNER-FACING | CURRENT |
| `ws_lab_mcp_001` | WORKSHOP / LAB | LEARNER-FACING | CURRENT |
| `ws_lab_mcp_003` | WORKSHOP / LAB | LEARNER-FACING | CURRENT |
| `ws_lab_mcp_004` | WORKSHOP / LAB | LEARNER-FACING | CURRENT |
| `ws_lab_mcp_005` | WORKSHOP / LAB | LEARNER-FACING | CURRENT |
| `ws_lab_mcp_006` | WORKSHOP / LAB | LEARNER-FACING | CURRENT |
| `ws_lab_mcp_catalog` | WORKSHOP / LAB | LEARNER-FACING | CURRENT |
| `ws_lab_rag_context` | WORKSHOP / LAB | LEARNER-FACING | CURRENT |
| `ws_lab_memory_security` | WORKSHOP / LAB | LEARNER-FACING | CURRENT |
| `ws_lab_agent_goal_integrity` | WORKSHOP / LAB | LEARNER-FACING | CURRENT |
| `ws_lab_scanner_runtime_evidence` | WORKSHOP / LAB | LEARNER-FACING | CURRENT |
| Splunk `search` | UTILITY / INVESTIGATION | SOC-FACING + LEARNER | CURRENT (platform) |

No classic Simple XML views besides Dashboard Studio wrappers. No Identity Studio workshop (do not invent one). No dedicated SOC, REFERENCE, or LEARN pages besides Home markdown and workshop tabs.

Internal / developer surfaces: build scripts under `scripts/build_*_dashboard.py`, capture scripts, pytest.

---

## Top-level navigation

Splunk `<nav>` collections, one level only:

- **Home** (`ws_agentsec_home`, default)
- **Attack Labs** — Prompt Injection, Tool Authorization, Scope Escalation, Parameter / Resource Authorization, Tool Result Trust, Confused Deputy, Tool Catalog
- **Context Security** — RAG / Retrieved Context, Persistent Memory
- **Agent Authority** — Goal / Instruction Integrity
- **Supply Chain** — Scanner + Runtime Evidence
- **Search**

Do not add a top-level `LAB-*` item. Lab IDs belong in workshop metadata and XML descriptions.

This grouping still works at 30 / 50 / 100 labs: add items to collections, not to the horizontal bar.

---

## Lab taxonomy

| Collection | Semantic group | Existing workshops |
|------------|----------------|--------------------|
| Attack Labs | Prompt injection | Direct Prompt Injection |
| Attack Labs | MCP security | Tool Authorization, Scope Escalation, Parameter / Resource Authorization, Tool Result Trust, Confused Deputy, Tool Catalog |
| Context Security | Retrieved / stored context | RAG / Retrieved Context, Persistent Memory |
| Agent Authority | Task vs tool authority | Goal / Instruction Integrity |
| Supply Chain | Scanner + runtime | Scanner + Runtime Evidence |

Identity / delegation remains a runtime + hunt domain without a Studio workshop. Do not publish a fake page.

---

## Two navigation layers

**Global navigation** = where am I in AgentSec?  
**Workshop tabs** = where am I in LEARN → PROVE?

Do not mix those layers. Workshop progression stays:

LEARN · BASELINE · ATTACK · OBSERVE · HUNT · DETECT · DEFEND · RETEST · COMPARE · PROVE

---

## Token / specimen chain (do not guess)

Canonical LIVE specimens are constants in each build script, taken from the lab `searches/catalog.json` (or equivalent validated pack).

```
CANONICAL SPECIMEN (catalog / Phase evidence)
      ↓
BUILD SCRIPT CONSTANT
      ↓
BASELINE / ATTACK / RETEST pages: literal quoted run.id in SPL (not a learner field)
HUNT dropdown: token `run_id` (or write/recall/scan equivalents)
      ↓
VALIDATED .spl with __RUN_ID__ replaced bind-only
      ↓
PANEL
```

Goal Integrity Phase 13C LIVE IDs (verified against `learning/level_1/LAB-AGENT-GOAL-INTEGRITY-001/searches/catalog.json`):

| Specimen | run.id |
|----------|--------|
| BASELINE | `0aced342-1295-4820-b807-9a8718d9e847` |
| ATTACK | `fd994587-7e1c-4a70-8013-54cb2c85254d` |
| RETEST | `605ba7c1-449b-4338-92df-7da3b704b08e` |

Hunt token `run_id` defaults to BASELINE. Changing the dropdown rebinds hunt/observe searches. Canonical specimen pages do not use that token.

**Studio limitation:** a dropdown and a free-text field cannot safely share one empty custom token without wiping the canonical default. Custom run.id is an advanced **Search** workflow. Documented, not faked.

---

## Governance

Future labs must not:

- add another `LAB-*` top-level nav item
- add four raw UUID text fields
- invent another status vocabulary
- create a different workshop progression
- expose implementation tokens as learner controls

Deviation requires a documented semantic reason in the workshop design doc.
