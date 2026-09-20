# UI review — `ws_lab_agent_goal_integrity` Phase 13E

**Date:** 2026-09-18  
**Surface:** Splunk Dashboard Studio `ws_lab_agent_goal_integrity`  
**Method:** Playwright 1440 / 1024 / 768. Screenshots under `docs/screenshots/lab-agent-goal-integrity/`.  
**Tokens checked:** Hunt run_id, BASELINE, ATTACK, RETEST (4/4 LIVE 13C IDs).  
**Tabs checked:** LEARN → PROVE (10/10).

Pass 1 written **before** COMPARE card reorder.

## Pass 1

JSON + Playwright PNG. GRID 1440, navy/white, large markdown. Nav lists LAB-AGENT-GOAL-INTEGRITY-001. Empty DETECT tables show Splunk’s own “No search results returned” graphic (documented Studio limitation; markdown already says 0 rows is CORRECT, not SAFE).

### Findings

| ID | Sev | Finding |
|----|-----|---------|
| P1-1 | MEDIUM (demoted) | LEARN first canvas at 1440 already shows AUTHORIZED TOOL != AUTHORIZED GOAL, AUTHORIZED TOOL != AUTHORIZED USE OF TOOL, the control ladder, and full LIVE UUIDs. At 768 the UUID values sit below the fold; the statements and ladder remain visible. Not HIGH. |
| P1-2 | **HIGH** | At 768, COMPARE cards led with profile/task and clipped MCP ALLOW + handler counts. 1440 cards were complete, including “Do not say MCP blocked the attack.” |
| P1-3 | MEDIUM | Four token boxes ellipsize UUIDs. Full IDs remain on LEARN / COMPARE / PROVE. |
| P1-4 | MEDIUM | Q-GOAL table column headers truncate (wide hunt). Horizontal scroll required. Live BASELINE rows still reconstruct OBSERVE + untrusted_instruction + summarize. |
| P1-5 | MEDIUM | DETECT FUTURE / TELEMETRY GAPS and PROVE answers require scroll. DETECT title + 0/0/0 classification are in the first viewport. |
| P1-6 | LOW | Dashboard description in the title bar is clipped by Studio chrome. |
| P1-7 | LOW | Studio empty-state graphic overrides `noDataMessage` on DETECT 0-row tables. |

No BLOCKER. No red token errors. No SAFE empty-state copy in our `noDataMessage`. Task SHA-256 is readable (wrapped) on LEARN, ATTACK, RETEST, COMPARE.

## Pass 1 remediation (applied after this review)

- COMPARE: Goal-integrity, effective action, MCP ALLOW, and handler counts are the first bullets on each card. Intro height 300. Card height 880.

## Pass 2

Playwright after rebuild + restage. Evidence: `docs/screenshots/lab-agent-goal-integrity/pass2_*.png` and `pass2_validation.json`.

**Observed:** 10/10 tabs. 4/4 token values match Phase 13C LIVE IDs. Hunt run_id defaults to BASELINE.

| ID | Pass-2 status |
|----|----------------|
| P1-1 | Remains MEDIUM at 768 only. LEARN 1440 first canvas has both required sentences, the ladder, and full UUIDs. |
| P1-2 | **FIXED at 1440.** COMPARE cards lead with Goal-integrity + MCP + handlers (OBSERVE/ALLOW/1/0 vs OBSERVE overlay/ALLOW/0/1 vs DENY/ALLOW/1/0). Header still states SAME TASK / DIFFERENT GOAL-INTEGRITY DECISION. **768:** discriminator fields stay at the top of each card; run.id / footer lines may still require scroll (MEDIUM, not HIGH). |
| P1-3 | Remains MEDIUM. Token inputs still ellipsize. Full UUIDs remain in LEARN / COMPARE / PROVE markdown. |
| P1-4 | Remains MEDIUM. Hunt/OBSERVE Q-GOAL headers still truncate; tables remain usable with horizontal scroll. Live BASELINE hunt row OBSERVED. |
| P1-5 | Remains MEDIUM. DETECT 0-row tables + classification are in the first viewport. |
| P1-6 | Remains LOW. Studio chrome clips the dashboard description. |
| P1-7 | Remains LOW. DETECT 0-row tables show Studio’s “No search results returned” graphic. Markdown still teaches 0 rows is CORRECT, not SAFE. |

**Pass-2 acceptance:** 0 BLOCKER, 0 HIGH. MEDIUM/LOW remain as documented.

### Accessibility (observed)

- Status is in TEXT (OBSERVE, ALLOW, DENY, handler 0/1, LIVE, SIMULATED, CONTEXT, HUNT), not color alone.
- Large Studio markdown. Design-system navy/white.
- Empty tables remain visible (Studio graphic is a UI limitation, not a SAFE verdict).
- 768: LEARN statements + ladder still present; COMPARE teaching lines remain at the top of cards; token row stacks.
- No WCAG certification claim.

### Instructor / SOC checks (observed)

- Intentionally vulnerable ATTACK profile is labeled.
- Overlay reason labeled LAB-ONLY, not a production IOC.
- RETEST states MCP ALLOW, goal DENY, wrong-goal handler 0, in-task 1. Copy: “Do not say MCP blocked the attack.”
- BASELINE is not labeled SAFE.
- DETECT title: DETECTION ANALYZED — NO NEW GOAL DETECTOR. 0 rows is CORRECT. 0 rows != SAFE.
- SIMULATED DET-MCP-001 positive-control table is labeled SIMULATED.
- Instruction hash labeled PARTIALLY SUPPORTED in Splunk.
- OBSERVE five planes are labeled TASK / INSTRUCTION / GOAL DECISION / TOOL AUTHORIZATION / EXECUTION. No `_raw` by default.
- HUNT states Q-MCP does not independently prove task/goal authorization.

### Security-semantics review (observed — no false authority claims)

The UI does **not** claim: untrusted_instruction = malicious; instruction = authorization; proposed goal = authorized goal; goal OBSERVE = goal ALLOW; goal DENY = MCP DENY; authorized tool = authorized task; MCP ALLOW = goal authorization; MCP ALLOW = execution; mcp.started = successful completion; missing Splunk row = blocked; BASELINE = safe; DET-MCP-001 silence = safe; anomaly = incident; Splunk = enforcement; LLM = authorization authority; SIMULATED = LIVE; MCP blocked RETEST.
