# AgentSec Splunk query validation (Phase 17C)

**Status:** Phase 17C. No new Q-*. No field invention. Schema **1.9.0**.  
**Do not start Phase 17D from this file.**

Default contract: `index=agentsec_telemetry` `sourcetype=otel:agentic:json` quoted `agentsec.run.id` (memory: two tokens; scanner: `agentsec:scanner:finding` + `__SCAN_ID__`). Empty = no indexed event matched this question. Empty is not DENY.

## Classes used here

| Class | Meaning |
|-------|---------|
| STATIC SPL REVIEW | Source hunt + Studio binding + tests inspected |
| REPLAY VERIFIED | Hunt designed against canonical specimen fields |
| LIVE SPLUNK MEASURED | Official pair measured in a prior phase report |
| 17C SESSION | Re-run this session against current volume, or NOT REVALIDATED |

## Learner-facing hunts

| ID | Index / ST | Token | Fields used (material) | Empty semantics | ATTACK/RETEST | LIVE/REPLAY | Overclaim risk | Static | Historical live |
|----|------------|-------|------------------------|-----------------|---------------|-------------|----------------|--------|-----------------|
| Q-RUN-EVENTS | agentsec_telemetry / otel:agentic:json | `__RUN_ID__` | event.name, run.id, sequence, schema.version, profile, mode | Not SAFE / not DENY | same SPL | same SPL | rows ≠ authorized | REVIEW | 14D+ |
| Q-CONTROL-DECISION | same | `__RUN_ID__` | control.id/decision/reason, attempted/executed/outcome | Not DENY | same | same | DENY ≠ LLM never ran | REVIEW | 14D |
| Q-LLM-EXECUTED | same | `__RUN_ID__` | llm.started/completed/failed | Corroboration iff complete | same | same | completed ≠ loan approval | REVIEW | 14D |
| Q-LLM-AFTER-DENY | same | `__RUN_ID__` | DENY then llm.* | Expected 0; not SAFE | same | same | Not a detector | REVIEW | 14D 0 |
| Q-MCP-WHO | same | `__RUN_ID__` | principal, agent, tool | Not DENY | same | same | Tool name is REQUEST | REVIEW | 14E+ |
| Q-MCP-AUTHZ | same | `__RUN_ID__` | control.id, decision, reason, scopes | Not DENY | same | same | control `executed` ≠ handler | REVIEW | 14E+ |
| Q-MCP-TOOL | same | `__RUN_ID__` | mcp.started | Not DENY | same | same | started = began, not success | REVIEW | 14E+ |
| Q-MCP-EXECUTED | same | `__RUN_ID__` | control + mcp.* execution_state | See hunt | same | same | Extra rows when two controls share a tool | REVIEW | 14E+ |
| Q-MCP-AFTER-DENY | same | `__RUN_ID__` | DENY then mcp.* | Expected 0; not SAFE | same | same | Hunt form of DET-MCP-001 | REVIEW | 0/0/0 |
| Q-MCP-SCOPE | same | `__RUN_ID__` | requested vs allowed_scope | Not a subset test | MCP-003 | REPLAY | ERROR ≠ known_but_ungranted | REVIEW | historical |
| Q-MCP-RESOURCE-AUTHZ | same | `__RUN_ID__` | resource vs allowed_resource.ids | Equality, not subset | MCP-004 | REPLAY | Not confused-deputy predicate | REVIEW | historical |
| Q-MCP-RESULT-AUTHORITY | same | `__RUN_ID__` | CTRL-MCP-RESULT-001 | Empty ≠ derived authority refused | MCP-005 | REPLAY | OBSERVE ≠ grant | REVIEW | historical |
| Q-MCP-DELEGATION | same | `__RUN_ID__` | CTRL-DELEGATION-001 | Empty ≠ refused | MCP-006 | REPLAY | Not IDENTITY hunt | REVIEW | historical |
| Q-MCP-CATALOG-AUTHORITY | same | `__RUN_ID__` | CTRL-MCP-METADATA-001 | Empty ≠ SAFE | catalog | REPLAY | No full catalog list indexed | REVIEW | historical |
| Q-RAG-CONTEXT-AUTHORITY | same | `__RUN_ID__` | CTRL-RAG-CONTEXT-001, follow-on MCP | Empty ≠ trusted | RAG/capstone retrieve | both | OBSERVE ≠ ALLOW; no vector DB | REVIEW | 15B |
| Q-MEMORY-CONTEXT-AUTHORITY | same | `__WRITE_RUN_ID__` + `__RECALL_RUN_ID__` | written+recalled, hashes, source_run_id | Drops row if either UUID missing | Memory/capstone | both | Write trust empty | REVIEW | 15C |
| Q-GOAL-INTEGRITY-AUTHORITY | same | `__RUN_ID__` | CTRL-GOAL-INTEGRITY-001 | Capstone expected 0 | Goal | both | Goal DENY ≠ MCP DENY; hashes PARTIAL in Splunk | REVIEW | 15D |
| Q-AGENT-DELEGATION-AUTHORITY | same | `__RUN_ID__` | CTRL-IDENTITY-001 | Capstone expected 0 | Identity | both | OBSERVE ≠ authn; no OAuth | REVIEW | 15E |
| Q-SCANNER-WHO/ARTIFACT/FINDINGS | agentsec_telemetry / agentsec:scanner:finding | `__SCAN_ID__` | scanner fields | Scan executed ≠ verdict | n/a | REPLAY | HIGH finding ≠ DENY | REVIEW | 9C |
| Q-SCANNER-RUNTIME-CORRELATION | both sourcetypes | `__DESCRIPTION_SHA256__` | description_sha256 vs content.hash | Wrong hash → 0 | n/a | REPLAY | artifact.sha256 ≠ content.hash | REVIEW | 9C |

Path A starters are unnamed: quoted run.id only. Mastery Path B binds existing Q-* (`academy.path_b_spl`). `Q-RUN` / `Q-DENY` placeholders in savedsearches.conf are **disabled, NOT VALIDATED**, not learner hunts.

## Fields that do not exist (do not teach)

`agentsec.mcp.allowed_tools`, `gen_ai.tool.call.id`, `session.id`, `trusted_document`, `authenticated`, write-run `agentsec.memory.trust`, retrieve-to-write join field.

## 17C session revalidation

Official pairs are **LIVE SPLUNK MEASURED** in 14D–16B reports.

**This session (2026-09-21):** completeness `dc(_raw)` + `agentsec.schema.version` + `agentsec.testbed.mode` for all 14 official ATTACK/RETEST (memory/capstone recall) ids. All present. Schema **1.9.0**. Counts match the phase reports (PI 22/6, MCP 7/6, RAG 10/9, Memory recall 11/10, Goal 10/10, Identity 10/9, Capstone recall 11/10). Class: **17C SESSION LIVE SPLUNK MEASURED** (completeness).

Representative Q-* hunt **bodies** were **STATIC SPL REVIEW** this session. Historical hunt outputs remain **LIVE SPLUNK MEASURED** in the phase reports. Hunt re-execution was not completed in this session after completeness succeeded.
