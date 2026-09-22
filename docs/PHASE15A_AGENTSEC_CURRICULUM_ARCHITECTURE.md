# Phase 15A — AgentSec curriculum architecture

**Date:** 2026-09-19  
**Mode:** DESIGN / RESEARCH / CURRICULUM ARCHITECTURE ONLY  
**Schema:** **1.9.0** unchanged. Runtime authorization **UNCHANGED**.  
**Do not start Phase 15B from this file.** Do not migrate labs, dashboards, Attack Service launchers, detectors, or schema.

Predecessor: `docs/PHASE14E_LEARNING_LOOP_GENERALIZATION.md` (PASS). Locked platform roles:

| Role | Function |
|------|----------|
| Dashboard Studio | Syllabus / lesson / guided notebook |
| Splunk Search | Learner investigation workbench |
| Attack Service | Closed experiment launcher |
| AgentSec runtime | Enforcement |
| Splunk | Evidence, **not** enforcement |
| Learning metadata | Teaching metadata, **not** policy |

## Primary question

How should existing AgentSec security domains become a coherent journey from beginner to someone who can reason about, attack, investigate, defend, and explain agentic security systems?

Not: which dashboard to build next.  
Yes: what a graduate must **know**, **do**, and **prove**.

## Answer (design)

AgentSec is already a security range with eleven published workshops and one Splunk-validated identity lab without Studio. Only **two** labs (LAB-PI-001, LAB-MCP-001) currently support the full 14E loop with LIVE ATTACK/RETEST via Attack Service.

The curriculum therefore:

1. Teaches one reasoning chain (source → trust boundary → influence/request → authorization → execution → telemetry → Splunk → hunt/detection classification → defense → retest → proof).
2. Places each existing lab at the trust boundary it actually owns.
3. Migrates remaining labs onto the 14E loop **in dependency order**, without faking LIVE.
4. Treats completion as demonstrated reasoning, not dashboard tourism.

Companion documents:

| Document | Question it answers |
|----------|---------------------|
| `docs/AGENTSEC_EXISTING_LAB_INVENTORY.md` | What exists in the repository, honestly classified |
| `docs/AGENTSEC_SECURITY_REASONING_MODEL.md` | Shared mental model + inequalities |
| `docs/AGENTSEC_CURRICULUM_LEVELS.md` | Progressive levels, KNOW/DO/… outcomes |
| `docs/AGENTSEC_COMPETENCY_MODEL.md` | Observable abilities, not certificates |
| `docs/AGENTSEC_LAB_MIGRATION_MATRIX.md` | Per-lab readiness and order |
| `docs/AGENTSEC_ATTACK_SERVICE_MIGRATION_STRATEGY.md` | Which labs can use the closed launcher |
| `docs/AGENTSEC_SPLUNK_SKILL_PROGRESSION.md` | How Search difficulty should grow |
| `docs/AGENTSEC_CAPSTONE_DESIGN.md` | Multi-domain investigation (not implemented) |
| `docs/AGENTSEC_CURRICULUM_INFORMATION_ARCHITECTURE.md` | Home / nav as academy (not implemented) |
| `docs/learning-notes/how-to-learn-agentic-security-with-agentsec.md` | Learner-facing explanation |

## What 15A does not do

No new runtime routes. No new ExperimentDefinition rows. No Studio XML. No detectors. No schema bump. No PI-001 / MCP-001 semantic change. No capstone runtime. No A2A transport. No MLTK.

## Phase 15B (recommendation only)

**Exactly one next implementation wave:** LAB-MCP-003 then LAB-MCP-004.

| | |
|--|--|
| **Why they are next** | Completes REQUEST≠GRANT on the same CTRL-MCP-001 and `POST /mcp/invoke` that 14E already launched. Scope and resource are grant anatomy, not INV-002. Catalog/result wait. |
| **What will be implemented (in 15B, not here)** | ExperimentDefinition rows, Attack Service pages, lab-manifest + investigations.json, 14E GRID/Path A/B on existing `ws_lab_mcp_003` / `ws_lab_mcp_004` |
| **What remains unchanged** | Schema 1.9.0; CTRL-MCP-001 semantics; DET-MCP-001; PI-001 and MCP-001 launchers; no new detector |
| **LIVE / REPLAY** | Target LIVE ATTACK+RETEST with equivalent-input fingerprints; keep REPLAY dropdown |
| **Major risks** | Collapsing 003/004 into “another MCP-001”; treating ERROR unknown-scope as DENY; implying Splunk enforces scope |
| **Acceptance outline** | Fresh `run.id`; Path A hunts reuse Q-MCP-* / Q-MCP-RESOURCE-AUTHZ; RETEST same bytes; pytest + Splunk MEASURED; UI review; no schema/authz change |

**Do not start Phase 15B from this file.** **Do not implement Wave 1 from this document.**
