# UI review — `ws_lab_rag_context` (LAB-RAG-CONTEXT)

**Date:** 2026-09-16  
**Surface:** Dashboard Studio `ws_lab_rag_context` (learner-facing). Splunk login/chrome not restyled.  
**Pass:** 1 written from first capture; HIGH fixes then pass-2.  
**Screenshots:** `docs/screenshots/lab-rag-context/pass1_*.png` (pass-1), `docs/screenshots/lab-rag-context/pass2_*.png` (pass-2)  
**Validation:** `docs/screenshots/lab-rag-context/pass1_validation.json`, `docs/screenshots/lab-rag-context/pass2_validation.json`  
**Tokens checked:** Hunt, BASELINE, ATTACK, RETEST (4/4 MEASURED in DOM)  
**Tabs checked:** LEARN, BASELINE, ATTACK, OBSERVE, HUNT, DETECT, DEFEND, RETEST, COMPARE, PROVE (10/10 clicked)  
**Viewports OBSERVED:** 1440 (all tabs), 1024 (LEARN/COMPARE/DETECT), 768 (LEARN/COMPARE/DETECT)  
**Evidence class:** screenshot findings are **OBSERVED**. JSON/XML contracts remain **DOCUMENTED**. Indexed tables on BASELINE/ATTACK/RETEST/HUNT are **OBSERVED** for Phase 10C specimen tokens. DETECT live AFTER-DENY tables are empty (0 DENY-then-start). DETECT SIMULATED fixture is labeled SIMULATED. This review does not re-MEASURE `dc(_raw)`. Do not claim WCAG certification.

Canonical tokens: `docs/AGENTSEC_DESIGN_SYSTEM.md`.

App XML restaged via `splunk_app_init` + Splunk restart. Splunk Web login HTTP 200. Playwright captured 10/10 tabs. Pytest does not prove Splunk rendering.

Default tokens MEASURED:

- Hunt / BASELINE `51f70fb9-994e-4dd4-9b36-cac6fb1e8232`
- ATTACK `3a43d24f-9281-42f6-8375-1fb2efaa80ac`
- RETEST `bea97bae-491b-4b36-b52f-1417d2bad01b`

MALICIOUS fingerprint `sha256:c565f364c7c5fba3cf25d235bb8e2bee7d9433daa9f07d5e097ab6d2a82a97ef`  
NORMAL fingerprint `sha256:0fc83ee727c6f33ad87e6ffec8698889de366311a281e4f831fe8c8d30e27f8e`

---

## Roles

### Splunk architect

GRID tabs load. Four tokens exist and Submit-on-load ran. Hunt defaults to BASELINE. Q-RAG-CONTEXT-AUTHORITY and Q-MCP binds returned indexed rows for LIVE A/B/C. DETECT AFTER-DENY tables are empty (expected 0/0/0). No DET-RAG. DET-MCP-001 is not enabled by this view. Schema copy says 1.6.0. OBSERVE sequence is a Studio view of indexed fields, not a new hunt file.

### SOC analyst

Can hunt: tokens prefilled. Token boxes ellipsize UUIDs. LEARN, ATTACK, RETEST, COMPARE, and PROVE print complete run ids. LEARN, COMPARE intro, COMPARE cards, ATTACK, RETEST, and PROVE print the full NORMAL and/or MALICIOUS hashes without relying on token truncation. HUNT reconstructs document → request → authorization → execution. DETECT 0/0/0 is explained in markdown.

### UX designer

White cards, navy headers, `#F6F8FB`, markdown large. No neon, no extra charts, no MLTK purple. COMPARE three cards are the primary reconstruction. DETECT uses Studio’s default empty graphic. 768 three-column Studio auto-scale clips some card bodies; 1440 is the design target.

### Technical instructor

LEARN states RETRIEVED CONTENT IS DATA and the six inequalities. Four evidence planes are named. AgentSec is not only MCP/RAG. BASELINE: do not label SAFE / TRUSTED / APPROVED / BENIGN; zero follow-on is an observation. ATTACK: INTENTIONALLY VULNERABLE; retrieved text did not grant the tool. DETECT: DETECTION ANALYZED — NO NEW RAG DETECTOR; 0 rows is CORRECT; 0 rows != SAFE. DEFEND: server-owned CTRL-MCP-001 DENY; Splunk is not the grant. RETEST: same hash, DENY, handler 0, missing start is corroboration. COMPARE: SAME RETRIEVED CONTENT. SAME REQUEST. DIFFERENT AUTHORIZATION OUTCOME.

### Accessibility

Status words OBSERVE, ALLOW, DENY, LIVE, SIMULATED, CONTEXT, HUNT, DETECTION, FUTURE appear as text. Full hashes are in LEARN/ATTACK/RETEST/COMPARE/PROVE markdown. Color is not the only status channel. DETECT empty graphic is Studio default text “No search results returned” rather than the custom no-data sentence; teaching that 0 is expected is in the markdown above the tables.

---

## Pass-1 findings

### HIGH — COMPARE card hashes truncated

**Where:** COMPARE (`pass1_compare.png`)  
ATTACK and RETEST cards showed a single backtick hash that clipped inside the 4-column card (`…9f07` / similar). The COMPARE intro already had the complete shared MALICIOUS hash.

**Fix:** Split fingerprints onto wrap-safe lines (`sha256:` + 32 + 32 hex). Taller COMPARE cards.

### HIGH — LEARN progression card clipped inequalities

**Where:** LEARN (`pass1_learn.png`)  
The right card cut `authorization != execution` at the fold. Header inequalities were complete.

**Fix:** Move the four inequalities to the top of the progression card. Raise LEARN header so the MALICIOUS wrap-hash is on the first canvas.

### MEDIUM — Four global inputs ellipsize UUIDs

**Where:** every tab  
Full ids are on LEARN / COMPARE / PROVE (acceptance). Same class as prior workshops.

### MEDIUM — DETECT empty tables use Studio default graphic

**Where:** DETECT (`pass1_detect.png`)  
`hideWhenNoData` is false and `noDataMessage` is set, but Studio still shows “No search results returned.” Teaching that 0 is expected is in the markdown. Not interpreted as SAFE in copy.

### MEDIUM — 768 three-column cards clip

**Where:** `pass1_w768_learn.png`, `pass1_w768_compare.png`  
Studio GRID auto-scale. 1440 is the design target. Do not claim arbitrary responsive behavior.

### LOW — Nav title clips at 768

Splunk chrome. Not restyled.

No BLOCKER. No claim that retrieved text authorized the tool. No SAFE label on BASELINE. No DET-RAG.

---

## Pass-2

**Screenshots:** `docs/screenshots/lab-rag-context/pass2_*.png`  
**Validation:** `docs/screenshots/lab-rag-context/pass2_validation.json`  
**Tabs:** 10/10 clicked. **Tokens:** 4/4 MEASURED, matching Phase 10C LIVE ids.

HIGH COMPARE fingerprint clipping is **fixed**. ATTACK and RETEST cards display the same complete MALICIOUS digest:

`c565f364c7c5fba3cf25d235bb8e2bee` / `7d9433daa9f07d5e097ab6d2a82a97ef`

COMPARE intro still shows the contiguous `sha256:c565f364c7c5fba3cf25d235bb8e2bee7d9433daa9f07d5e097ab6d2a82a97ef`.

HIGH LEARN clipping is **fixed**. Header lists all six inequalities, both full fingerprints, and three full UUIDs at 1440 and 768. The progression card shows `retrieval provenance != content trust` through `authorization != execution` at 1440.

Required teaching statements OBSERVED on pass-2:

- LEARN: RETRIEVED CONTENT IS DATA; REQUEST != GRANT; four planes; provenance is not trust
- BASELINE: do not label SAFE; zero follow-on is not proof of safety; handler 0
- ATTACK: INTENTIONALLY VULNERABLE; retrieved text did not authorize; handler 1
- OBSERVE: four planes; no `_raw`; hash + bounded preview
- HUNT: Q-RAG-CONTEXT-AUTHORITY primary; no AGENT NOTE regex hunt
- DETECT: DETECTION ANALYZED — NO NEW RAG DETECTOR; 0/0/0 CORRECT not SAFE; FUTURE — NOT IMPLEMENTED
- DEFEND: REQUEST then CTRL-MCP-001 DENY then handler does not start
- RETEST: SAME hash; handler count authoritative; missing start corroboration
- COMPARE: SAME RETRIEVED CONTENT. SAME REQUEST. DIFFERENT AUTHORIZATION OUTCOME.
- PROVE: 20 knowledge-check questions; schema 1.6.0; no DET-RAG

Remaining MEDIUM/LOW (not blocking): token ellipsis, Studio default empty graphic, 768 three-column clip of lower card bodies, 768 nav title clip.

No new BLOCKER/HIGH. No WCAG certification.
