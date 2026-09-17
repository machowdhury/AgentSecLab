# UI review — `ws_lab_mcp_005` (LAB-MCP-005)

**Date:** 2026-09-14  
**Surface:** Dashboard Studio `ws_lab_mcp_005` (learner-facing). Splunk login/chrome not restyled.  
**Pass:** 1 written first; HIGH fixes then pass-2.  
**Screenshots:** `docs/screenshots/lab-mcp-005/pass1_*.png` (pass-1)  
**Validation:** `docs/screenshots/lab-mcp-005/pass1_validation.json`  
**Tokens checked:** `run_id`, `baseline_run_id`, `attack_run_id`, `retest_run_id` (all four MEASURED in DOM)  
**Tabs checked:** LEARN, BASELINE, ATTACK, OBSERVE, HUNT, DETECT, DEFEND, RETEST, COMPARE, PROVE (10/10 clicked)  
**Evidence class:** screenshot findings are **OBSERVED**. JSON/XML contracts remain **DOCUMENTED**. Indexed table rows on BASELINE / ATTACK / OBSERVE / HUNT / RETEST / COMPARE are **OBSERVED** for Phase 6C specimen tokens. DETECT live hunt is empty (0 DENY-then-start). DETECT right table is **SIMULATED**. This review does not re-MEASURE `dc(_raw)`.

Canonical tokens: `docs/AGENTSEC_DESIGN_SYSTEM.md`. Reference implementation: LAB-MCP-004.

Playwright viewport is 1440×1100. Studio content scrolls inside the view, so `full_page` still captures the first canvas, not the GRID below the fold.

Lab-ready HEC was empty-reply during capture (Splunk restart). Splunk Web HTTP 200. Indexed Phase 6C copies remained searchable.

---

## Roles

### Splunk architect

GRID tabs load. Four tokens exist and Submit-on-load ran. Hunt defaults to BASELINE (no empty-token red `!`). Q-MCP and `Q-MCP-RESULT-AUTHORITY` returned indexed rows for BASELINE / ATTACK / RETEST. DETECT left table is empty (0 violations) with Studio’s default empty graphic. DETECT right table rendered one **SIMULATED** `makeresults` row labeled SIMULATED. Table `description` is populated-caption. Q-MCP bind-only; no DET-MCP-005; rejected `Q-MCP-RESULT-FOLLOWON` is named only as not published. Schema copy says 1.3.0.

### SOC analyst

Can hunt: Hunt token is prefilled; specimen tabs bind Phase 6C ids. Cannot read a full 36-character UUID from the global inputs (ellipsis). LEARN heading “Phase 6C LIVE ids” is on the first screen but the UUID bullets themselves are clipped. HUNT primary `Q-MCP-RESULT-AUTHORITY` is on canvas; many columns wrap. COMPARE third-width AUTHORITY tables clip follow-on columns. OBSERVE shows control sequence 3 before `mcp.started` sequence 4 (BASELINE).

### UX designer

Reading order of tabs is clear. White panels, navy headers, no neon, no extra charts, no MLTK purple. Markdown `fontSize: large`. LEARN three-column SERVER-OWNED / RESULT-DERIVED / Trust boundary is the right teaching layout and lands on the first canvas (good). Trust-boundary ASCII is clipped before “FOLLOW-ON OPERATION = REQUIRES AUTHORIZATION”. DEFEND first panel is overlapped by the second markdown at the LIMITED heading. PROVE numbered evidence list collapsed into one paragraph.

### Technical instructor

LEARN states AUTHORIZED TOOL ≠ AUTHORITATIVE RESULT and the core question with defended NO. ATTACK states the initial invoke was not the failure and labels overlay vs server-owned. RETEST states same malicious hash, DENY `tool_not_granted`, runtime handler 0, Splunk corroboration wording. DETECT labels NO NEW DETECTOR, LIVE 0/0/0, SIMULATED / NOT INDEXED. COMPARE three cards make ATTACK vs RETEST readable. What Happened is the hunt table, not generated prose.

### Accessibility

Body markdown is Studio `large`. Severity is labeled in text (ALLOW / DENY / OBSERVE / SIMULATED / BASELINE / ATTACK / RETEST / present / absent), not color alone. Token fields clip 36-character UUIDs visually; Playwright still reads the full value. Keyboard tab bar is Splunk chrome (clicked in Playwright; not a WCAG certification). DEFEND overlapped text fails readable contrast for that strip.

---

## Findings

### HIGH — LEARN first canvas clips LIVE run IDs

**Where:** LEARN (`pass1_learn.png`)

Heading “Phase 6C LIVE ids (copy the full UUID)” is visible. The UUID bullets are not. Global token inputs ellipsis the same ids. Learners cannot copy a full run.id from the first canvas.

### HIGH — LEARN trust-boundary card clips the follow-on authorization label

**Where:** LEARN (`pass1_learn.png`)

Required visual ends at “FOLLOW-ON INTENT”. “FOLLOW-ON OPERATION = REQUIRES AUTHORIZATION” and “TOOL RESULT = DATA” pairing is incomplete on the first canvas.

### HIGH — DEFEND “SERVER AUTHORITY EVIDENCE — LIMITED” is overlapped / unreadable

**Where:** DEFEND (`pass1_defend.png`)

The LIMITED paragraph is smashed under the next panel title “Data cannot create permission”. A required Phase 6C limitation is not readable on this tab.

### HIGH — PROVE evidence hierarchy collapsed into one paragraph

**Where:** PROVE (`pass1_prove.png`)

RUNTIME / LOCAL / EXPORT / SPLUNK / SEARCH / DETECTION must be a list. Inserted corroboration sentence glued steps 1–6 together. Hierarchy teaching is lost on the first canvas.

### MEDIUM — DETECT empty left table uses Studio’s orange warning chrome

**Where:** DETECT (`pass1_detect.png`)

Indexed `Q-MCP-AFTER-DENY` is correctly empty (0 DENY-then-start). Caption teaching is right. Studio still shows a warning triangle and an unlabeled empty grid. Same Studio limit as LAB-MCP-004.

### MEDIUM — What Happened / COMPARE tables wrap `lookup_customer_tier` as `lookup_cu` / `stomer_tie`

Column wrap can be mistaken for the 200-character preview truncation (`lookup_customer_tie`). Markdown and COMPARE cards already spell `lookup_customer_tier`. Do not rewrite Q-MCP SPL.

### MEDIUM — COMPARE hashes wrap in third-width cards

Full sha256 strings wrap mid-hex. Cards still distinguish NORMAL vs same MALICIOUS. LEARN should carry the full strings after the ID fix.

### MEDIUM — BASELINE / ATTACK / RETEST supporting hunts sit below What Happened

AUTHZ / TOOL / EXECUTED require scroll. Captions already teach extra RESULT-001 rows and ALLOW ≠ execution.

### MEDIUM — HUNT intro is a dense wall of limitation text

Primary hunt table is visible. Extra-row and rejected-SPL teaching is correct but crowded.

### LOW — Submit button is Splunk default green

Out of scope to restyle. Not an AgentSec token.

### LOW — Token inputs ellipsis 36-character UUIDs

Playwright reads complete values. LEARN must show full ids after the HIGH fix.

### LOW — Dashboard description truncates in Splunk chrome

Title area clips after DET-MCP-001 packaging. Teaching markdown repeats the claim.

---

## Pass-1 summary

| Severity | Count |
|----------|------:|
| BLOCKER | 0 |
| HIGH | 4 |
| MEDIUM | 5 |
| LOW | 3 |

No BLOCKER. Security semantics on ATTACK / RETEST / DETECT are correct where readable. Fix all HIGH before pass-2.

---

## Fixes applied (after pass-1)

- LEARN intro shortened; full LIVE UUIDs placed above the three cards.
- Trust-boundary ASCII compacted so `TOOL RESULT = DATA` and `FOLLOW-ON OPERATION = REQUIRES AUTHORIZATION` fit the first canvas.
- DEFEND first panel height increased; LIMITED copy shortened so it is not overlapped.
- PROVE evidence steps restored as a numbered list.
- COMPARE cards use hash last-8 for wrap; full hashes remain on BASELINE / ATTACK / RETEST markdown.

---

## Pass-2

**Screenshots:** `docs/screenshots/lab-mcp-005/pass2_*.png`  
**Validation:** `docs/screenshots/lab-mcp-005/pass2_validation.json` — 10/10 tabs, four tokens MEASURED to Phase 6C LIVE ids.

**App reload:** `./scripts/lab-up.sh --refresh-app --no-wait` restaged `ws_lab_mcp_005.xml`. Splunk Web HTTP 200 after restart. HEC health stayed empty-reply (lab-ready NOT READY). Indexed Phase 6C copies remained searchable.

### HIGH — LEARN first canvas clips LIVE run IDs — FIXED

`pass2_learn.png` shows BASELINE / ATTACK / RETEST full UUIDs above the three cards.

### HIGH — LEARN trust-boundary card clips follow-on label — FIXED

Card shows `TOOL RESULT = DATA` and `FOLLOW-ON OPERATION = REQUIRES AUTHORIZATION`.

### HIGH — DEFEND LIMITED overlapped — FIXED

`pass2_defend.png` shows a readable LIMITED paragraph, then a separate “Data cannot create permission” panel.

### HIGH — PROVE hierarchy collapsed — FIXED

`pass2_prove.png` shows numbered RUNTIME through DETECTION.

### Pass-2 remaining

| Severity | Count | Notes |
|----------|------:|-------|
| BLOCKER | 0 | |
| HIGH | 0 | |
| MEDIUM | 5 | DETECT orange empty chrome; table wrap of `lookup_customer_tier`; COMPARE supporting tables below fold; specimen hunts below What Happened; HUNT intro density |
| LOW | 3 | Submit green; token ellipsis; chrome description clip |

Pass-2 = **0 BLOCKER / 0 HIGH**. Residual MEDIUM/LOW accepted. Not a WCAG certification.

