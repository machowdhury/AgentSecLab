# UI review — `ws_lab_scanner_runtime_evidence` (LAB-SCANNER-RUNTIME)

**Date:** 2026-09-16  
**Surface:** Dashboard Studio `ws_lab_scanner_runtime_evidence` (learner-facing). Splunk login/chrome not restyled.  
**Pass:** 1 written first; HIGH fixes then pass-2.  
**Screenshots:** `docs/screenshots/lab-scanner-runtime-evidence/pass1_*.png` (pass-1)  
**Validation:** `docs/screenshots/lab-scanner-runtime-evidence/pass1_validation.json`  
**Tokens checked:** Hunt, Hunt scan, BASELINE RUN, ATTACK RUN, RETEST RUN, NORMAL SCAN, MALICIOUS SCAN (7/7 MEASURED in DOM)  
**Tabs checked:** LEARN, BASELINE, ATTACK, OBSERVE, HUNT, DETECT, DEFEND, RETEST, COMPARE, PROVE (10/10 clicked)  
**Viewports OBSERVED:** 1440 (all tabs), 1024 (LEARN/COMPARE/DETECT), 768 (LEARN/COMPARE/DETECT)  
**Evidence class:** screenshot findings are **OBSERVED**. JSON/XML contracts remain **DOCUMENTED**. Indexed scanner/runtime tables on BASELINE/ATTACK/RETEST are **OBSERVED** for Phase 8D/9C specimen tokens. DETECT live hunts are empty (0 DENY-then-start). DETECT SIMULATED fixture is below the fold on pass-1. This review does not re-MEASURE `dc(_raw)`. Do not claim WCAG certification.

Canonical tokens: `docs/AGENTSEC_DESIGN_SYSTEM.md`.

`--refresh-app` restaged `ws_lab_scanner_runtime_evidence.xml`. Splunk REST view HTTP 200. HEC was empty after Splunk restart until `splunk_hec_init` was recreated (existing lab HTTP HEC contract, not a runtime change).

---

## Roles

### Splunk architect

GRID tabs load. Seven tokens exist and Submit-on-load ran. Hunt defaults to BASELINE; Hunt scan defaults to NORMAL. Q-SCANNER and Q-MCP binds returned indexed rows for NORMAL/MALICIOUS scans and BASELINE/ATTACK/RETEST runs. DETECT ATTACK/RETEST AFTER-DENY tables are empty (expected 0). No DET-SCANNER. No DET-MCP-CATALOG. Schema copy says 1.5.0. Scanner sourcetype stays on scanner tables.

### SOC analyst

Can hunt: tokens prefilled. Cannot read a full UUID from the global inputs (ellipsis). LEARN prints complete run ids, scan ids, and both description hashes on the first canvas. ATTACK/RETEST/COMPARE print the full MALICIOUS hash. Pivot teaching is on HUNT. DETECT 0/0 is explained in markdown.

### UX designer

White cards, navy headers, `#F6F8FB`, markdown large. No neon, no extra charts, no MLTK purple. Seven inputs wrap Submit onto a second row. COMPARE three cards are the most readable reconstruction. LEARN inequality sentence clips at the fold. DETECT uses Studio’s default empty graphic.

### Technical instructor

LEARN states scanner evidence does not feed CTRL-MCP-001. BASELINE: ZERO FINDINGS, do not display PASS, not SAFE. ATTACK: INTENTIONALLY VULNERABLE, native HIGH, do not treat native HIGH as the cause of execution. DETECT: DETECTION ANALYZED — NO NEW DETECTOR; ATTACK=0; RETEST=0; CONTEXT/HUNT/REJECT. DEFEND: scanner does not block; handler count 0. RETEST: same hash, DENY, handler 0, Splunk corroboration. COMPARE: scanner evidence same, authorization different.

### Accessibility

Status words OBSERVE, ALLOW, DENY, HIGH, ZERO FINDINGS, CONTEXT, HUNT, SIMULATED, LIVE appear as text. Full hashes are in LEARN/ATTACK/RETEST/COMPARE markdown. Color is not the only status channel. DETECT empty graphic is Studio default text “No search results returned” rather than the custom no-data sentence.

---

## Pass-1 findings

### HIGH — LEARN clips the central inequality line

**Where:** LEARN (`pass1_learn.png`, `pass1_w768_learn.png`)  
The SCANNER FINDING != … paragraph is a single wrapping line that is cut at `ALLOW !=` on 1440 and more severely at 768. The three-plane cards also sit on that fold.

**Fix:** Put each inequality on its own short line above the diagram so every sentence completes on the first canvas.

### MEDIUM — Seven global inputs ellipsize UUIDs and wrap Submit

**Where:** every tab  
Full ids are on LEARN (acceptance). Input ellipsis is the same class as LAB-MCP-CATALOG.

### MEDIUM — DETECT empty tables use Studio default graphic

**Where:** DETECT (`pass1_detect.png`)  
`hideWhenNoData` is false and `noDataMessage` is set, but Studio still shows “No search results returned.” Teaching that 0 is expected is in the markdown above the tables. Not interpreted as SAFE in copy.

### MEDIUM — ATTACK/RETEST finding tables wrap native HIGH off-canvas

**Where:** ATTACK, RETEST tables  
Markdown already states native HIGH / PROMPT INJECTION in words.

### LOW — 768 nav title clips “Runtime Evidence”

Splunk chrome. Not restyled.

### LOW — ASCII diagram uses mixed spacing

Readable enough for the three-plane model.

No BLOCKER. No false claim that scanner HIGH caused execution. No PASS label on ZERO FINDINGS.

---

## Pass-2

**Screenshots:** `docs/screenshots/lab-scanner-runtime-evidence/pass2_*.png`  
**Validation:** `docs/screenshots/lab-scanner-runtime-evidence/pass2_validation.json`  
**Tabs:** 10/10 clicked. **Tokens:** 7/7 MEASURED.

HIGH LEARN clipping is **fixed**. Each inequality is a complete bullet on the first LEARN canvas at 1440 and 768. Full BASELINE/ATTACK/RETEST/NORMAL/MALICIOUS ids and both description hashes remain readable. DETECT markdown now states the two AFTER-DENY tables are **expected empty** and that Studio’s default empty graphic is 0 rows, not SAFE.

Remaining MEDIUM/LOW (not blocking): seven input ellipsis, Studio default empty graphic, wrapped finding-table columns, 768 nav title clip, ASCII diagram ALLOW/DENY still near the LEARN fold.

No new BLOCKER/HIGH. No WCAG certification.
