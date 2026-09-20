# Splunk KO review — Phase 14E LAB-MCP-001 guided investigation

**Date:** 2026-09-19  
**Object type:** DASHBOARD + existing INVESTIGATION SEARCH reuse  
**Scope:** `ws_lab_mcp_001` Path A/B; no new Q-*; no new saved search; DET-MCP-001 unchanged.

## Verdict

**PASS — reuse only.** No new persistent hunt. No new detector. Schema 1.9.0 unchanged.

## Classify

| Object | Type | Persistence justified? |
|--------|------|------------------------|
| Q-MCP-WHO / AUTHZ / TOOL / EXECUTED / AFTER-DENY | INVESTIGATION SEARCH | Existing; reused as Path B |
| Q-MCP-SCOPE / PARAMS / RESULT / RESULT-TRUST | INVESTIGATION SEARCH | Existing; Path B tables |
| DET-MCP-001 | DETECTION (disabled) | Existing; taught as ATTACK ≠ ALERT |
| ws_lab_mcp_001 | DASHBOARD | Syllabus; binds existing SPL |

## Field-contract gate

No new production SPL. Display searches already used `event.name`, `agentsec.run.id`, `mvindex(mvdedup(...),0)`. No `agentsec.event.name`, no `gen_ai.tool.call.arguments`.

## What 14E did not do

- Did not create DET-MCP-NEW
- Did not enable DET-MCP-001
- Did not add `__RUN_ID__` hunts
- Did not proxy learner SPL
- Did not claim pytest as Splunk validation

## Consumer

Studio HUNT stacked notebook Path A/B. Search remains the workbench for fresh LIVE run.id.

## LIVE reuse (2026-09-19 host Splunk CLI)

ATTACK `bf5109de-bcc0-4ca0-9916-cf4b63e77ef4` and RETEST `0cd82b2a-cefe-4fe5-86f3-4751929c3d1f` executed existing Q-MCP-WHO / AUTHZ / TOOL / EXECUTED / AFTER-DENY without new SPL. Completeness 7=7 and 6=6. Schema 1.9.0.

## Limitations

Canonical REPLAY ids may still be schema 1.1.0 on this volume. Fresh LIVE after restage is 1.9.0. Empty tables are not DENY.
