# UI review — ws_lab_memory_security + Attack Service Memory (2026-09-19)

**Lab:** LAB-MEMORY-001  
**Surfaces:** Dashboard Studio `ws_lab_memory_security`; Attack Service `/labs/LAB-MEMORY-001`  
**Pass:** Playwright `scripts/capture_lab_memory_security_screenshots.py --label pass3` after Splunk restart (Studio XML reloaded) and Attack Service healthy.  
**Viewports:** 1440 / 1280 / 1024  
**HTTP:** Studio view loaded (10/10 tabs). Attack Service 200 at 1440, 1280, 1024.

Screenshots: `docs/screenshots/lab-memory-security/pass3_*.png`, `docs/screenshots/attack-service-memory/pass3_*.png`. Report: `docs/screenshots/lab-memory-security/pass3_validation.json`.

## Tabs checked (1440)

LEARN, BASELINE, ATTACK, OBSERVE, HUNT, DETECT, DEFEND, RETEST, COMPARE, PROVE. Required set also captured at 1280 and 1024.

Tokens: Investigate write specimen = `Baseline write — defended / normal`. Investigate recall specimen = `Baseline recall — defended / normal`. Human labels, not raw UUID forms.

Attack Service Playwright launch minted WRITE+RECALL ids for ATTACK and RETEST (UX pair; official Splunk pair is in `docs/PHASE15C_SPLUNK_LIVE_VALIDATION.md`).

## SPLUNK ARCHITECT

No HTTP 400. No malformed XML. Datasources bind existing Q-MEMORY-CONTEXT-AUTHORITY and Q-MCP hunts. No DET-MEMORY. DETECT heading is **DETECTION ANALYZED — NO NEW MEMORY DETECTOR**. No `_raw` by default. OBSERVE keeps WRITE and RECALL on separate planes. HUNT is stacked Path A / Hint / Path B.

## SOC ANALYST

Path A starter is index + sourcetype + quoted `agentsec.run.id`. Path B names Q-MEMORY-CONTEXT-AUTHORITY / Q-MCP-*. LIVE EXPERIMENT vs REPLAY SPECIMEN labeled. Attack Service exposes copy WRITE/RECALL run.id and Open write/recall in Search.

## UX / INSTRUCTOR

COMPARE primary statement is in words: SAME MEMORY. SAME REQUEST. DIFFERENT AUTHORIZATION. DIFFERENT EXECUTION. Readable at 1024. DEFEND teaches server-owned authorization, not “sanitize all memory.” RETEST says do not label SAFE and do not claim universal resistance. LEARN shows WRITE → STORE → RECALL → REQUEST → CTRL-MCP-001 → HANDLER.

## Findings

| ID | Severity | Finding | Status |
|----|----------|---------|--------|
| U1 | LOW | Studio table column headers truncate (`write_run_id`, hash). Full hashes live in markdown and Compare cards. Same Studio chrome as PI/RAG. | Accepted |
| U2 | LOW | Attack Service Memory page is long (teach card + predict + two-run results). Buttons, WRITE/RECALL copy, and Search handoff remain present at 1440/1280/1024. | Accepted |
| U3 | LOW | HUNT numbered Path A list can skip a visual “2.” when step 2 is the Open Splunk Search link. The link is still visible in the Path A intro. | Accepted |
| U4 | LOW | Description banner truncates after “Saved search” in Splunk chrome. Tab teaching statements remain readable. | Accepted |

No overlapping cards. No GFM pipe tables. No fake LIVE labels on REPLAY Investigate tokens. No UUID text-input regression. No unresolved BLOCKER/HIGH.

## Verdict

**PASS** for Phase 15C UI gate. No unresolved BLOCKER/HIGH.
