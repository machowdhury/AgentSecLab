# UI review — `ws_lab_rag_context` + Attack Service RAG page (Phase 15B)

**Date:** 2026-09-19  
**Surface:** `ws_lab_rag_context` and `http://127.0.0.1:5001/labs/LAB-RAG-CONTEXT`  
**Pass:** Playwright after `./scripts/lab-up.sh --build --refresh-app`. Lab READY. View `ws_lab_rag_context` HTTP 200. Attack Service RAG page HTTP 200.

Screenshots: `docs/screenshots/lab-rag-context/pass15b_*.png`, `docs/screenshots/attack-ui/pass15b_rag_{1440,1280,1024}.png`.

## Tabs checked (1440)

LEARN, ATTACK, OBSERVE, HUNT, DEFEND, RETEST, COMPARE, PROVE. BASELINE/DETECT remain in the 10-tab workshop. Token: Investigate specimen = `Baseline — defended / normal` (human label, canonical REPLAY).

## SPLUNK ARCHITECT

No HTTP 400. No broken XML. Datasources bind existing Q-RAG / Q-MCP hunts. No DET-RAG. No `_raw` by default. HUNT `fit-to-width` stacked Path A/B.

## SOC ANALYST

Path A starter is index + sourcetype + quoted `run.id`. Path B names Q-RAG-CONTEXT-AUTHORITY / Q-MCP-*. LIVE vs REPLAY labeled. Attack Service Search handoff present.

## UX / INSTRUCTOR

SAME CONTENT / SAME REQUEST / DIFFERENT AUTHORIZATION / DIFFERENT EXECUTION is in words on COMPARE, not color alone. DEFEND teaches server-owned authorization, not sanitizing the document. REPLAY specimen cards are labeled REPLAY.

## Findings

| ID | Severity | Finding | Status |
|----|----------|---------|--------|
| U1 | LOW | Studio table column headers truncate (`run_id`, hash). Full hashes live in markdown. Same Studio chrome as PI/MCP. | Accepted |
| U2 | LOW | 1024 COMPARE REPLAY UUID on the BASELINE card is slightly clipped at the card footer. Teaching statement and full hash in the COMPARE intro remain readable. Known Studio chrome at 1024. | Accepted |
| U3 | LOW | Studio 1280 not captured as a separate workshop PNG. Attack Service was captured at 1280 and is readable. 1440 and 1024 workshop tabs were reviewed. | Accepted |
| U4 | LOW | Attack Service prediction copy is dense. Buttons, closed-field list, and Search handoff remain visible at 1440/1280/1024. | Accepted |

No overlapping cards. No GFM pipe tables. No fake LIVE labels on REPLAY cards. No UUID text-input clutter (dropdown). No BLOCKER/HIGH.

## Verdict

**PASS** for Phase 15B UI gate. No unresolved BLOCKER/HIGH.
