# UI review — ws_lab_agent_delegation + Attack Service Identity (2026-09-20)

**Lab:** LAB-AGENT-DELEGATION-001  
**Surfaces:** Dashboard Studio `ws_lab_agent_delegation`; Attack Service `/labs/LAB-AGENT-DELEGATION-001`  
**Pass:** Playwright `scripts/capture_lab_agent_delegation_screenshots.py --label pass15e` after named-volume restage. Lab READY. HEC HTTP 200. View `ws_lab_agent_delegation` present. Attack Service 200 at 1440/1280/1024.  
**Viewports:** 1440 / 1280 / 1024  
**HTTP:** Studio 10/10 tabs on first capture. Recapture of LEARN / OBSERVE / DETECT after layout and DETECT copy fix.

Screenshots: `docs/screenshots/lab-agent-delegation/pass15e_*.png`, `docs/screenshots/attack-service-identity/pass15e_*.png`. Report: `docs/screenshots/lab-agent-delegation/pass15e_validation.json`.

## Tabs checked (1440)

LEARN, BASELINE, ATTACK, OBSERVE, HUNT, DETECT, DEFEND, RETEST, COMPARE, PROVE. Required set also captured at 1280 and 1024.

Tokens: Investigate specimen = `Baseline — defended / normal`. Human label, not a raw UUID form.

Attack Service Playwright launch minted ATTACK `d8ff6007-2bdb-475e-8734-a2c73a16989e` and RETEST `b03aef31-9797-4acc-b8bf-a342bfac9f25` (UX pair). Official Splunk pair remains `docs/PHASE15E_SPLUNK_LIVE_VALIDATION.md`.

## SPLUNK ARCHITECT

No HTTP 400. No malformed XML. Datasources bind existing Q-AGENT-DELEGATION-AUTHORITY and Q-MCP hunts. No DET-A2A. DETECT heading is **DETECTION ANALYZED — NO NEW IDENTITY DETECTOR**. No `_raw` by default. OBSERVE keeps PRINCIPAL / CALLER-CALLEE / DELEGATION CLAIM / IDENTITY CLAIM TRUST / TOOL REQUEST / TOOL AUTHORIZATION / EXECUTION as separate planes. HUNT is stacked Path A / Hint / Path B.

## SOC ANALYST

Path A starter is index + sourcetype + quoted `agentsec.run.id`. Path B names Q-AGENT-DELEGATION-AUTHORITY / Q-MCP-*. LIVE EXPERIMENT vs REPLAY SPECIMEN labeled. Attack Service exposes copy run.id and Open ATTACK / RETEST / ATTACK vs RETEST in Search. WHO AUTHENTICATED = NOT PROVEN / NOT MODELED is on the launcher.

## UX / INSTRUCTOR

COMPARE primary statement is in words: SAME IDENTITY CLAIM. SAME DELEGATION CLAIM. SAME PRIVILEGED REQUEST. DIFFERENT AUTHORIZATION. DIFFERENT EXECUTION. Readable at 1024. DEFEND teaches claim ≠ grant and CTRL-MCP-001 as the tool PDP, not “block all delegation.” LEARN shows PRINCIPAL → CALLER → CALLEE → CLAIM → IDENTITY OBSERVE → REQUEST → MCP → EXECUTION. PROVE classifies SUPPORTED / CORROBORATED / NOT PROVEN / INCORRECT.

Pass-1 LEARN markdown overflowed onto the three teaching cards (HIGH). Pass-2 shortened LEARN and raised the card row. DETECT classification originally reused RAG “untrusted retrieval” language (HIGH). Pass-2 rewrote it for identity/delegation. Recaptured LEARN / OBSERVE / DETECT.

## Findings

| ID | Severity | Finding | Status |
|----|----------|---------|--------|
| U1 | HIGH | LEARN markdown overflowed onto Delegation path / PLANES cards. | Fixed pass-2 |
| U2 | HIGH | DETECT classification copied RAG retrieval language. | Fixed pass-2 |
| U3 | LOW | Studio table column headers truncate (`identity_reason`, MCP preview). Full values live in markdown and Compare cards. Same Studio chrome as PI/RAG/Memory/Goal. | Accepted |
| U4 | LOW | Attack Service Identity page is long (teach card + predict + results). Buttons, copy run.id, WHO AUTHENTICATED, and Search handoff remain present at 1440/1280/1024. | Accepted |
| U5 | LOW | Description banner truncates after “Splunk does not ALLOW or DENY a tool” in Splunk chrome. Tab teaching statements remain readable. | Accepted |
| U6 | LOW | DETECT DET-MCP-001 tables show Studio “No search results returned.” Markdown above states 0 rows is CORRECT and is not SAFE. SIMULATED positive-control table is labeled SIMULATED. | Accepted |

No overlapping cards after pass-2. No GFM pipe tables. No fake LIVE labels on REPLAY Investigate tokens. No UUID text-input regression. No unresolved BLOCKER/HIGH.

## Verdict

**PASS** for Phase 15E UI gate. No unresolved BLOCKER/HIGH.
