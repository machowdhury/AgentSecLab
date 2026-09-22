# AgentSec v1.0.0-rc1 — product inventory

Measured from repository files on the RC1 candidate tree. Schema **1.9.0**.

## A. Academy

Home `ws_agentsec_home` (nav default), ORIENT/START in Home, `learning/academy/curriculum.json`, Mastery `ws_agentsec_mastery`, Capstone `ws_lab_agentsec_capstone`, competency in curriculum levels, Path A Search / Path B review keys in Studio labs.

## B. Published workshops (nav labels)

Direct Prompt Injection, Tool Authorization, Scope Escalation, Parameter / Resource Authorization, RAG / Retrieved Context, Persistent Memory, Tool Result Trust, Tool Catalog, Scanner + Runtime Evidence, Goal / Instruction Integrity, Agent Identity / Delegation, Confused Deputy, Lending Assistant Investigation, Mastery Check, Search.

Learner-facing nav does not use `LAB-*` titles. View **ids** remain `ws_lab_*` (platform).

## C. LIVE labs (Attack Service + curriculum LIVE)

LAB-PI-001, LAB-MCP-001, LAB-RAG-CONTEXT, LAB-MEMORY-001, LAB-AGENT-GOAL-INTEGRITY-001, LAB-AGENT-DELEGATION-001, LAB-AGENTSEC-CAPSTONE-001.

Verified in `experiment_context.py` `EXPERIMENT_DEFINITIONS`.

## D. REPLAY-only workshops

LAB-MCP-003, LAB-MCP-004, LAB-MCP-005, LAB-MCP-CATALOG, LAB-SCANNER-RUNTIME-EVIDENCE, LAB-MCP-006.

No MIXED lab type in curriculum.json.

## E. Controls

See `docs/AGENTSEC_CONTROL_OWNERSHIP_MATRIX.md`. Tool PDP remains CTRL-MCP-001. RAG/memory/identity OBSERVE-only. Goal DENY is task expansion, not tool PDP.

## F. Hunts

Studio-embedded + `learning/**/searches/Q-*.spl`. Savedsearches.conf: `Q-RUN`, `Q-DENY` (placeholders, disabled), DET-MCP-001 disabled. Academy reuses Q-MCP-* families plus domain hunts (RAG/MEMORY/GOAL/DELEGATION). No new hunt for RC1.

## G. Detectors

Only **DET-MCP-001** (saved search “AgentSec - MCP Execution After Authorization Deny”, disabled). Invariant: DENY then later `mcp.started` same run/tool. No DET-RAG/MEMORY/GOAL/A2A/CAPSTONE/ASSESSMENT in `savedsearches.conf`.

## H–K. Runtime / Splunk / Attack Service / Docker

AcmeBank, Attack Service, Ollama, OTel collector, Splunk, splunk_app_init, splunk_hec_init. Attack Service closed JSON: lab_id, specimen_id, mode, execution.

## L–N. Evidence / schema / docs

`artifacts/<run-id>/` gitignored. Schema `schemas/security_event.schema.json` const 1.9.0. Learner entry: README → QUICKSTART / GETTING_STARTED.

## Contradictions flagged

- Historical `docs/PHASE*.md` still mention 0.3.0 / older schema slices: **HISTORICAL ONLY**.
- Running AcmeBank `/health` may still show `version: 0.3.0` until images rebuild after `__version__` bump: packaging, not schema.
- Savedsearches `Q-RUN`/`Q-DENY` still say Phase 2 placeholder: **DOC DEFECT / LOW** — learners use Studio Path B + Search, not those placeholders.
