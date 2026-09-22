# UI review — ws_lab_agent_goal_integrity + Attack Service Goal (2026-09-20)

**Lab:** LAB-AGENT-GOAL-INTEGRITY-001  
**Surfaces:** Dashboard Studio `ws_lab_agent_goal_integrity`; Attack Service `/labs/LAB-AGENT-GOAL-INTEGRITY-001`  
**Pass:** Playwright `scripts/capture_lab_agent_goal_integrity_screenshots.py --label pass15d` after `./scripts/lab-up.sh --refresh-app` (lab READY, HEC HTTP 200).  
**Viewports:** 1440 / 1280 / 1024  
**HTTP:** Studio view loaded (10/10 tabs). Attack Service 200 at 1440, 1280, 1024.

Screenshots: `docs/screenshots/lab-agent-goal-integrity/pass15d_*.png`, `docs/screenshots/attack-service-goal/pass15d_*.png`. Report: `docs/screenshots/lab-agent-goal-integrity/pass15d_validation.json`.

## Tabs checked (1440)

LEARN, BASELINE, ATTACK, OBSERVE, HUNT, DETECT, DEFEND, RETEST, COMPARE, PROVE. Required set also captured at 1280 and 1024.

Tokens: Investigate specimen = `Baseline — defended / normal`. Human label, not a raw UUID form.

Attack Service Playwright launch minted ATTACK `a8fc304b-b142-453e-b9dd-18595b4f9043` and RETEST `c7e258c3-4d6e-4e5d-8629-26ae1004a08c` (UX pair). Official Splunk pair remains `docs/PHASE15D_SPLUNK_LIVE_VALIDATION.md`.

## SPLUNK ARCHITECT

No HTTP 400. No malformed XML. Datasources bind existing Q-GOAL-INTEGRITY-AUTHORITY and Q-MCP hunts. No DET-GOAL. DETECT heading is **DETECTION ANALYZED — NO NEW GOAL DETECTOR**. No `_raw` by default. OBSERVE keeps TASK / INSTRUCTION / GOAL DECISION / TOOL AUTHORIZATION / EXECUTION as separate planes. HUNT is stacked Path A / Hint / Path B.

## SOC ANALYST

Path A starter is index + sourcetype + quoted `agentsec.run.id`. Path B names Q-GOAL-INTEGRITY-AUTHORITY / Q-MCP-*. LIVE EXPERIMENT vs REPLAY SPECIMEN labeled. Attack Service exposes copy run.id and Open ATTACK / RETEST / ATTACK vs RETEST in Search.

## UX / INSTRUCTOR

COMPARE primary statement is in words: SAME TASK. SAME MALICIOUS INSTRUCTION. SAME PROPOSED GOAL. SAME AUTHORIZED TOOL. DIFFERENT GOAL-INTEGRITY DECISION. DIFFERENT EFFECTIVE ACTION. Readable at 1024. DEFEND teaches the task boundary, not “block lookup_policy.” RETEST says do not claim MCP blocked the attack. LEARN shows SERVER-OWNED TASK → UNTRUSTED INSTRUCTION → PROPOSED GOAL → GOAL INTEGRITY → TOOL AUTHORIZATION → EXECUTION. PROVE classifies SUPPORTED / CORROBORATED / NOT PROVEN / INCORRECT.

## Findings

| ID | Severity | Finding | Status |
|----|----------|---------|--------|
| U1 | LOW | Studio table column headers truncate (`goal_task_hash`, MCP preview). Full hashes live in markdown and Compare cards. Same Studio chrome as PI/RAG/Memory. | Accepted |
| U2 | LOW | Attack Service Goal page is long (teach card + predict + results). Buttons, copy run.id, and Search handoff remain present at 1440/1280/1024. | Accepted |
| U3 | LOW | Description banner truncates after “Splunk does not ALLOW or DENY” in Splunk chrome. Tab teaching statements remain readable. | Accepted |
| U4 | LOW | DETECT DET-MCP-001 tables show Studio “No search results returned.” Markdown above states 0 rows is CORRECT and is not SAFE. | Accepted |

No overlapping cards. No GFM pipe tables. No fake LIVE labels on REPLAY Investigate tokens. No UUID text-input regression. No unresolved BLOCKER/HIGH.

## Verdict

**PASS** for Phase 15D UI gate. No unresolved BLOCKER/HIGH.
