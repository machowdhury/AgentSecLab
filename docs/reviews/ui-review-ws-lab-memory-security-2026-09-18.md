# UI review — `ws_lab_memory_security` Phase 11E

**Date:** 2026-09-18  
**Surface:** Splunk Dashboard Studio `ws_lab_memory_security`  
**Method:** Playwright 1440 / 1024 / 768. Screenshots under `docs/screenshots/lab-memory-security/`.  
**Tokens checked:** Hunt write, Hunt recall, BASELINE WRITE/RECALL, ATTACK WRITE/RECALL, RETEST WRITE/RECALL (8/8 LIVE 11C IDs).  
**Tabs checked:** LEARN → PROVE (10/10).

Pass 1 written **before** layout fixes.

## Pass 1

JSON-only plus Playwright PNG. GRID 1440, navy/white/teal, large markdown. Nav lists LAB-MEMORY-001. Empty DETECT tables show Splunk’s own “No search results returned” graphic (documented Studio limitation; markdown already says 0 rows is CORRECT, not SAFE).

### Findings

| ID | Sev | Finding |
|----|-----|---------|
| P1-1 | **HIGH** | LEARN first viewport is title + IDs/hashes. The required WRITE RUN → … → HANDLER diagram (`viz_learn_flow`) sits below the fold at y=720. Two-run nature is not obvious without scroll. |
| P1-2 | **HIGH** | COMPARE three cards clip the last teaching lines (Execution / handler 0 or 1). Authorization is visible; execution on the cards is not. Header still states handler 1 vs 0. |
| P1-3 | MEDIUM | Eight token boxes wrap; input fields ellipsize UUIDs. Full IDs remain on LEARN / COMPARE / PROVE. |
| P1-4 | MEDIUM | Q-MEMORY table column headers truncate (wide hunt). Horizontal scroll required. |
| P1-5 | MEDIUM | DETECT FUTURE / TELEMETRY GAPS and PROVE questions 21–30 are below the fold. |
| P1-6 | LOW | Dashboard description in the title bar is clipped by Studio chrome. |
| P1-7 | LOW | Studio empty-state graphic overrides `noDataMessage` on DETECT 0-row tables. |

No BLOCKER. No red token errors. No SAFE empty-state copy in our `noDataMessage`. Malicious SHA-256 is readable (wrapped) on LEARN, ATTACK, RETEST, COMPARE.

## Pass 1 remediation (applied after this review)

- LEARN: `viz_learn_flow` (WRITE RUN → MEMORY STORE → LATER RECALL RUN → CTRL-MEMORY-CONTEXT-001 → REQUEST → CTRL-MCP-001 → HANDLER) is the first row, full width, height 380. IDs/hashes follow. Planes + RAG vs MEMORY sit on the second content row.
- COMPARE: Authz and Execution are the first bullets on each card. Intro height 300. Card height 780. Wrap-safe SHA-256 remains on the COMPARE header and inside each card.

## Pass 2

Playwright after rebuild + restage. Evidence: `docs/screenshots/lab-memory-security/pass2_*.png` and `pass2_validation.json`.

**Observed:** 10/10 tabs. 8/8 token values match Phase 11C LIVE IDs. Hunt write/recall default to the BASELINE pair.

| ID | Pass-2 status |
|----|----------------|
| P1-1 | **FIXED.** LEARN first viewport is “Memory path (two runs)” with the required chain and trust-boundary sentence. |
| P1-2 | **FIXED at 1440.** COMPARE cards lead with Authz + Execution (handler 0 / ALLOW+handler 1 / DENY+handler 0). Full malicious SHA-256 is on the header and wrapped inside ATTACK/RETEST cards. Statement “SAME MEMORY. SAME REQUEST. DIFFERENT AUTHORIZATION. DIFFERENT EXECUTION.” is above the cards. |
| P1-3 | Remains MEDIUM. Token inputs still ellipsize; RETEST RECALL wraps to a second row. Full UUIDs remain in LEARN / COMPARE / PROVE markdown. |
| P1-4 | Remains MEDIUM. Hunt/ATTACK/RETEST Q-MEMORY headers still truncate; tables remain usable with horizontal scroll. |
| P1-5 | Remains MEDIUM. DETECT classification + 0-row tables are in the first viewport; FUTURE / TELEMETRY GAPS still require scroll. PROVE questions 21–30 still require scroll. |
| P1-6 | Remains LOW. Studio chrome clips the dashboard description. |
| P1-7 | Remains LOW. DETECT 0-row tables show Studio’s “No search results returned” graphic. Markdown still teaches 0 rows is CORRECT, not SAFE. |

768 COMPARE: Authz and Execution stay readable at the top of each card. WRITE/RECALL UUIDs wrap; fingerprints may require scroll. Header hash remains complete. Documented as remaining MEDIUM (P1-3), not HIGH.

**Pass-2 acceptance:** 0 BLOCKER, 0 HIGH. MEDIUM/LOW remain as documented.

### Accessibility (observed)

- Status is in TEXT (OBSERVE, ALLOW, DENY, handler 0/1, LIVE, SIMULATED), not color alone.
- Large Studio markdown. Design-system navy/white/teal.
- Empty tables remain visible (Studio graphic is a UI limitation, not a SAFE verdict).
- 768: PATH diagram still present; COMPARE teaching lines remain at the top of cards; token row stacks.

### Instructor / SOC checks (observed)

- Intentionally vulnerable ATTACK profile is labeled.
- Overlay reason labeled LAB-ONLY, not a production IOC.
- RETEST states handler count is authoritative; missing `mcp.started` is corroboration.
- DETECT title: DETECTION ANALYZED — NO NEW MEMORY DETECTOR.
- SIMULATED DET-MCP-001 positive-control table is labeled SIMULATED.
