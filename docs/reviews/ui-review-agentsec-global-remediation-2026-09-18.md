# UI review — AgentSec global pre-Phase-14 remediation

**Date:** 2026-09-18 (Pass 1) / 2026-09-19 (Pass 2 closure)  
**Surfaces:** Splunk app `agentsec` (Home + 11 learner workshops + grouped nav)  
**Schema:** 1.9.0 unchanged  
**Method:** Repository XML/JSON review, `lab-up --refresh-app`, Playwright Pass-1 then Pass-2 on restaged Splunk Web, offline pytest  
**Phase 14:** NOT STARTED

Pass-2 is OBSERVED (Playwright pass2 PNGs) + MEASURED (Web/HEC/pytest) + DOCUMENTED (repository XML). After the second restage, live volume XML matches the repository for Home, Goal Integrity COMPARE, PI ATTACK/RETEST copy, and grouped nav.

---

## Pass 1 (live Splunk, 2026-09-18 / 2026-09-19)

Captured:

- Home 1440 / 1280 / 1024 / 768 + four nav dropdowns (`docs/screenshots/agentsec-home/`)
- Goal Integrity 10 tabs + 1024/768 LEARN/COMPARE/DETECT (`docs/screenshots/lab-agent-goal-integrity/`)
- Direct Prompt Injection 10 tabs (`docs/screenshots/lab-pi-001/`)
- Tool Authorization 10 tabs (`docs/screenshots/lab-mcp-001/`)
- Scope Escalation overview only — **400 Bad Request** (`docs/screenshots/lab-mcp-003/`)

### Findings

| ID | Sev | Finding | Status in repository |
|----|-----|---------|----------------------|
| P1-B1 | **BLOCKER** | Eight workshop XML files had an unclosed `<description>` (`PLACEHOLDER` leftover). Live MCP-003 rendered Splunk 400 “Opening and ending tag mismatch: description”. | **FIXED** — closed short `<description>` + `test_view_xml_is_well_formed` |
| P1-B2 | **BLOCKER** | Attack Labs dropdown showed `ws_lab_mcp_003` … `ws_lab_mcp_catalog` instead of human labels. PI and Tool Authorization labels worked; Agent Authority showed Goal / Instruction Integrity. | **FIXED** — nav inner text labels in `default.xml` |
| P1-H1 | **HIGH** | Goal Integrity COMPARE / BASELINE / ATTACK / RETEST used GFM `\| tables \|`. Studio markdown rendered them as pipe soup, hiding aligned evidence rows. | **FIXED** — labeled lists; design system forbids GFM tables in `splunk.markdown` |
| P1-H2 | **HIGH** | Raw UUID text fields removed in repo, but live volume still had the first restage of broken XML for 8 workshops. Hunt dropdown on Goal Integrity / PI / MCP-001 **did** show `Baseline — defended / normal` (OBSERVED). | Repo correct; live volume needs restage |
| P1-M1 | MEDIUM | Investigate specimen combobox ellipsizes the label (`Baseline — defende…`). Full run.id remains on evidence cards. | Documented Studio chrome |
| P1-M2 | MEDIUM | Studio page `description` clips in the title bar. | Shortened on Goal Integrity + the 8 repaired views |
| P1-M3 | MEDIUM | Home 1024 clipped the Identity / delegation note in the context card. | Card height increased to 420 |
| P1-M4 | MEDIUM | HUNT markdown is still dense (security question is first). Wide hunt tables truncate column headers. | Acceptable for investigation tables |
| P1-M5 | MEDIUM | Studio empty-state graphic still appears on 0-row DETECT tables. Nearby copy says 0 rows is CORRECT, not SAFE. | Documented limitation |
| P1-L1 | LOW | Native Studio tab chrome is not a custom stepper. Active tab is a boxed control, but labels LEARN→PROVE are readable. | Splunk platform limit |
| P1-L2 | LOW | Home description previously leaked internal “LAB IDs belong…” copy into chrome. | Shortened |

No evidence that security semantics, SPL, detectors, or schema changed in Pass-1.

---

## Pass-1 BLOCKER/HIGH fixes (repository)

1. Close every workshop `<description>`; add well-formed XML pytest.
2. Put human labels inside `<view name="...">Label</view>` nav collections.
3. Replace GFM markdown tables with labeled lists on Goal Integrity specimen + COMPARE cards.
4. Capture scripts accept dropdown labels, not `input_value()` on comboboxes.
5. Home hero description shortened; context card taller.

These fixes are in git working tree. They were **not** restaged into the live named volume after Pass-1 because `lab-up --refresh-app` waited on HEC (`curl: (52) Empty reply from server`) and a second restage was not completed.

---

## Pass 2 (live Splunk, 2026-09-19) — CLOSURE

Method: `./scripts/lab-up.sh --refresh-app` (exit 0, lab-ready READY) → Playwright `--label pass2` against restaged Web → observed-defect fixes → second `--refresh-app` → recapture Home + Goal Integrity + Direct Prompt Injection. Screenshots under `docs/screenshots/agentsec-home/` and `docs/screenshots/lab-*/pass2_*.png`. Do not reuse Pass-1 PNGs as live proof.

Pytest does **not** prove Splunk rendering. This Pass-2 review is OBSERVED (Playwright) + MEASURED (HTTP/HEC/pytest) + DOCUMENTED (repository XML).

### RESTAGE RESULT

**PASS.** Named-volume restage via `splunk_app_init`. Splunk restarted. `splunk_hec_init` re-run after restart (`exited 0`). Volume fingerprints after the second restage: Goal Integrity COMPARE trailing `|` gone; Home identity sentence shortened; PI ATTACK no longer says “Paste … Hunt run.id”; nav inner text `Scope Escalation`.

### SPLUNK WEB RESULT

**HEALTHY.** Login page HTTP 200. AgentSec Home and all 11 published workshops rendered without HTTP 400. `lab-ready.sh` REST 200 for every `ws_lab_*` view plus Home file present.

### AGENTSEC APP RESULT

**HEALTHY.** App files present in `/opt/splunk/etc/apps/agentsec`. Default view is Home. Grouped nav loaded.

### HEC RESULT

**HEALTHY** (independent of Web). Host `http://127.0.0.1:8088/services/collector/health/1.0` HTTP 200. Mesh HEC from a collector-network client HTTP 200 (`lab-ready`). Web 200 is not treated as transport proof.

### XML VALIDATION RESULT

**PASS.** All 12 `ws_*.xml` files well-formed (`test_view_xml_is_well_formed`). No `PLACEHOLDER`. No unclosed `<description>`.

| VIEW | HTTP STATUS | XML VALID | NAV TARGET VALID | RESULT |
|------|-------------|-----------|------------------|--------|
| ws_agentsec_home | 200 | PASS | Home default | PASS |
| ws_lab_pi_001 | 200 | PASS | Attack Labs / Direct Prompt Injection | PASS |
| ws_lab_mcp_001 | 200 | PASS | Attack Labs / Tool Authorization | PASS |
| ws_lab_mcp_003 | 200 | PASS | Attack Labs / Scope Escalation | PASS |
| ws_lab_mcp_004 | 200 | PASS | Attack Labs / Parameter / Resource Authorization | PASS |
| ws_lab_mcp_005 | 200 | PASS | Attack Labs / Tool Result Trust | PASS |
| ws_lab_mcp_006 | 200 | PASS | Attack Labs / Confused Deputy | PASS |
| ws_lab_mcp_catalog | 200 | PASS | Attack Labs / Tool Catalog | PASS |
| ws_lab_rag_context | 200 | PASS | Context Security / RAG / Retrieved Context | PASS |
| ws_lab_memory_security | 200 | PASS | Context Security / Persistent Memory | PASS |
| ws_lab_agent_goal_integrity | 200 | PASS | Agent Authority / Goal / Instruction Integrity | PASS |
| ws_lab_scanner_runtime_evidence | 200 | PASS | Supply Chain / Scanner + Runtime Evidence | PASS |

Zero published workshop HTTP 400 pages. Identity / delegation is **not** a published Studio view.

### GLOBAL NAVIGATION RESULT

**PASS.** Live menus at 1440 / 1280 / 1024: Home · Attack Labs · Context Security · Agent Authority · Supply Chain · Search. Human labels OBSERVED (`pass2_nav_*.png`). Zero `ws_lab_*` or `LAB-*` learner-facing menu labels.

### HOME RESULT

**PASS** at the primary 1440 target. First canvas answers what AgentSec is, what to learn, where to start (Learning path including BASELINE), how labs are grouped, and LEARN→PROVE. Not a directory of LAB ids.

### WORKSHOP SHELL RESULT

**PASS.** Human titles, LEARN→PROVE tabs, Investigate specimen dropdown, `submitButton: false`. Evidence content remains lab-specific (not cloned from Goal Integrity).

### SPECIMEN SELECTOR RESULT

**PASS.** Default token display `Baseline — defended / normal` (MEASURED in every capture `token_values`). Values remain canonical LIVE run.ids. No four UUID text boxes. Custom run.id remains Search (Studio limitation unchanged).

### GOAL-INTEGRITY 10-TAB RESULT

**PASS.** All 10 tabs present. Canonical LIVE ids OBSERVED on COMPARE / BASELINE / ATTACK / RETEST cards:

- BASELINE `0aced342-1295-4820-b807-9a8718d9e847`
- ATTACK `fd994587-7e1c-4a70-8013-54cb2c85254d`
- RETEST `605ba7c1-449b-4338-92df-7da3b704b08e`

Dropdown default binds BASELINE. Hunt tables on OBSERVE/HUNT show the BASELINE copy.

### COMPARE RESULT

**PASS.** GFM pipe soup is gone. Structured labeled lists. Central proof visible: SAME task / instruction / proposed goal / authorized tool; DIFFERENT goal-integrity decision and effective action. ATTACK: CTRL-MCP-001 ALLOW + wrong-goal handler 1. RETEST: CTRL-MCP-001 ALLOW + wrong-goal 0 + legitimate handler 1. Copy says do **not** claim MCP blocked RETEST.

Pass-2 observed leftover `|` + duplicate RETEST footer — **FIXED** and recaptured.

### CROSS-WORKSHOP RESULT

**PASS.** All 11 published workshops load, use human titles, grouped nav, specimen dropdowns, and no GFM pipe soup. PI HUNT/COMPARE tables on this volume were empty (indexed copy missing); nearby copy already says empty ≠ DENY. MCP/Goal Integrity/Catalog/RAG/Memory/Scanner COMPARE cards had indexed or markdown evidence as designed.

Pass-2 observed PI ATTACK/RETEST “Paste … Hunt run.id” — **FIXED** (field no longer exists). Recaptured.

### RESPONSIVE RESULT

**PASS** for the supported desktop contract (primary 1440). 1280 usable. 1024 usable for Home nav and Goal Integrity LEARN/COMPARE. 768 diagnostic only.

### ACCESSIBILITY RESULT

Unchanged from Pass 1: status words in text; navy/white contrast; Studio combobox ellipsis; hunt tables need horizontal scroll; no independent WCAG certification.

### SECURITY SEMANTICS RESULT

**PASS.** Schema **1.9.0** unchanged. No DET-GOAL. DET-MCP-001 unchanged. OBSERVE ≠ ALLOW, ALLOW ≠ execution, untrusted ≠ malicious, empty ≠ SAFE, Splunk ≠ enforcement, handler counts authoritative, LIVE ≠ SIMULATED, authorized tool ≠ authorized goal. No workshop claims MCP prevented RETEST.

### ATTACK-SIMULATOR READINESS RESULT

Classification only. **No Attack Simulator was built in this closure pass.** Studio does not launch scenarios.

| Workshop | Classification | Notes |
|----------|----------------|-------|
| Direct Prompt Injection | PARTIALLY SUPPORTED | Attack Service (`:5001`) and `POST /process` exist. ATTACK tab tells the learner to fire there, then choose Investigate specimen. Studio does not launch. |
| Tool Authorization | PARTIALLY SUPPORTED | Runtime `POST /mcp/invoke` exists. Workshop binds pre-generated LIVE ids. |
| Scope Escalation | PARTIALLY SUPPORTED | Same MCP invoke path; pre-generated evidence. |
| Parameter / Resource Authorization | PARTIALLY SUPPORTED | Same. |
| Tool Result Trust | PARTIALLY SUPPORTED | Same. |
| Confused Deputy | PARTIALLY SUPPORTED | Same. |
| Tool Catalog | PARTIALLY SUPPORTED | Catalog fixture runtime exists; Studio does not run it. |
| Scanner + Runtime Evidence | PRE-GENERATED EVIDENCE ONLY | Scanner packs + runtime correlation. Workshop does not run mcp-scanner. |
| Retrieved Context | PRE-GENERATED EVIDENCE ONLY | Fixture retriever. No learner launch control. |
| Persistent Memory | PRE-GENERATED EVIDENCE ONLY | Write/recall packs. Dual dropdowns. No launch. |
| Goal / Instruction Integrity | PRE-GENERATED EVIDENCE ONLY | 13C LIVE A/B/C bound. No launch. |
| Home | NOT APPLICABLE | Orientation only. |

Workshops generally explain WHY the lab exists and what SAME vs DIFFERENT means on COMPARE. They do **not** provide a guided red-team execution wizard inside Splunk. That is the next UX increment, not this gate.

### PLAYWRIGHT PASS-2 RESULT

**PASS.** Fresh `--label pass2` captures after restage. Home 1440/1280/1024 + four nav opens. Goal Integrity 10/10 at 1440 + 1024 LEARN/COMPARE/DETECT. Remaining workshops: representative LEARN + COMPARE (and full 10-tab sets where the existing capture script already does). Recapture after COMPARE/PI/Home copy fixes: Home, Goal Integrity, PI.

### OFFLINE TEST RESULT

**PASS.** `.venv/bin/python -m pytest tests -q --tb=line -m "not live_ollama and not live_splunk"` → **710 passed, 2 deselected**. UI/XML tests cover well-formed XML, nav human labels, Home, no flat LAB navigation, canonical dropdowns, no GFM table regression, no paste-into-Hunt-run.id, schema 1.9.0.

Pytest does **not** prove Splunk rendering.

### Pass-2 findings

| ID | Sev | Finding | Status |
|----|-----|---------|--------|
| P2-H1 | HIGH | Goal Integrity COMPARE RETEST still had a leftover GFM `\|` and a duplicated footer. | **FIXED** + recaptured |
| P2-H2 | HIGH | PI ATTACK/RETEST still said “Paste … Hunt run.id” after the UUID fields were removed. | **FIXED** + recaptured |
| P2-M1 | MEDIUM | Home identity note still clips at 1024/1280 (full sentence visible at 1440). Studio markdown card overflow. | Documented |
| P2-M2 | MEDIUM | Investigate specimen combobox ellipsizes (`Baseline — defende…`). Full run.id on evidence cards. | Studio chrome |
| P2-M3 | MEDIUM | Studio page `description` clips in the title bar on denser workshops. | Studio chrome |
| P2-M4 | MEDIUM | PI canonical HUNT/COMPARE tables empty on this volume. Copy already: empty ≠ DENY. Not a UI rewrite. | Indexed-copy / transport |
| P2-M5 | MEDIUM | Some MCP OBSERVE copy still says “Hunt run.id” for the bound token. Control title is Investigate specimen. | Documented stale naming |
| P2-M6 | MEDIUM | MCP-004 LEARN evidence-identity card can clip RETEST/UNKNOWN below the three GRANT cards. Full ids remain on RETEST/COMPARE. | Documented |
| P2-L1 | LOW | Native Studio tabs are not a custom stepper. | Platform |
| P2-L2 | LOW | DETECT empty-state graphic still appears; nearby copy says 0 rows is CORRECT, not SAFE. | Platform |

Zero unresolved BLOCKER. Zero unresolved HIGH.

---


## Verdict of this review

**PASS — AGENTSEC UI/UX REMEDIATION COMPLETE**

0 published HTTP 400 pages. 0 `ws_lab_*` learner-facing menu labels. 0 unresolved BLOCKER. 0 unresolved HIGH. Goal Integrity COMPARE no longer renders GFM pipe text. Home works. Grouped nav works. Canonical dropdown works. Goal Integrity 10/10 tabs render. Canonical LIVE specimen binding works. Security semantics unchanged. Offline tests 710 passed, 2 deselected. Repository XML matches restaged live behavior for the Pass-2 fixes.

Phase 14 is **not** started. Attack Simulator is **not** implemented. Schema remains **1.9.0**.
