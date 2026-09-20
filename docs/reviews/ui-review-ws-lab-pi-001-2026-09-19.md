# UI review — LAB-PI-001 + Attack Service (Phase 14D)

**Date:** 2026-09-19  
**Surfaces:** `ws_lab_pi_001`, Attack Service `http://127.0.0.1:5001/`  
**Screenshots:** `docs/screenshots/lab-pi-001/pass1_*.png`, `docs/screenshots/attack-service-pi/pass1_home_{1440,1280,1024}.png`  
**Tokens checked:** `run_id` (MEASURED: “Baseline — defended / normal”)  
**Tabs checked:** LEARN, BASELINE, ATTACK, OBSERVE, HUNT, DETECT, DEFEND, RETEST, COMPARE, PROVE at 1440; DEFEND/RETEST/COMPARE also at 1280 and 1024; ATTACK/HUNT/PROVE at 1280 and 1024.

Method: Playwright against restaged Splunk Web and rebuilt Attack Service. Pass-1 screenshots are OBSERVED.

---

## Verdict

**PASS with MEDIUM residual.** No BLOCKER. No remaining HIGH on the captured surfaces after DEFEND/RETEST/COMPARE copy and live RETEST launcher.

---

## Findings

### MEDIUM — Studio empty-table chrome

**Where:** RETEST, COMPARE (`pass1_retest.png`, `pass1_compare.png`)

Canonical REPLAY tables show Splunk’s “No search results returned” glyph rather than the workshop `noDataMessage`. Copy above the tables already says empty is not DENY. Same class as Phase 14C.

### MEDIUM — Investigate specimen token ellipsis

**Where:** all tabs, dropdown “Baseline — defende…”

Studio truncates the label. The value is still the canonical BASELINE id. Not a fake control.

### MEDIUM — PROVE canvas may clip limitation bullets

**Where:** `pass1_prove.png` ends at “Limitations that still apply”

The ten proof items and knowledge check are visible. Limitation bullets may sit below the live named-volume canvas (repo height was increased after this capture; Splunk XML restage was blocked after that edit). Not a missing teaching beat for the 14D close-loop questions.

### LOW — Attack Service compare Search is below the fold

**Where:** `pass1_home_1440.png`

Launch buttons, dual run.id copy, and single-run Search handoff are above. Dual compare Search is after the pair block. Acceptable; not a fake button.

---

## What is working

- ATTACK tab predicts before launch and states LIVE ATTACK is the vulnerable experiment.
- DEFEND names the trust boundary, CTRL-INPUT-001, AcmeBank as enforcement, Splunk as evidence not blocker, regex lab limitation.
- RETEST asks five prediction questions including falsifiability, then Launch RETEST (LIVE).
- COMPARE labels SAME vs DIFFERENT in words; “What changed?” is explicit.
- PROVE lists authoritative vs corroborative classes and that RETEST is not automatically SAFE.
- Attack Service does not POST `profile`. Launch RETEST (LIVE) is enabled. LIVE RUN PAIR copy buttons exist.
- No custom JavaScript in Studio JSON. No new detector. No pipe-table markdown.

---

## Accessibility

Flask pages keep skip link, landmarks, and teal focus. SAME/DIFFERENT use text prefixes, not color alone. 1024 stacks Attack Service facts to one column.
