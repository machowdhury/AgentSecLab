# Gate A: curriculum preservation report

**Baseline:** commit `d415c93` (exported with `git archive`, never checked out in any repository, never run against Docker).
**Compared against:** `feature/phase1-hardening` at the time of this report. Date 2026-10-22.

## Result

| PRESERVED | ENHANCED | REGRESSED | UNVERIFIED | Total |
|---|---|---|---|---|
| **22** | **1** | **0** | **8** | **31** |

**No material regression was found; no stop condition was met.** One baseline defect (not a regression) was found and is described in section 4.

Definitions. PRESERVED: every dimension I could exercise is identical to the baseline. ENHANCED: identical plus a measured improvement
(LAB-MCP-001: its Academy workshop page lost the axe `region` violation). REGRESSED: a measured difference that makes a learner's
experience worse (none). UNVERIFIED: a dimension that could have regressed could not be exercised on this machine (the eight REPLAY labs whose
dashboards offer specimen run ids that are not in this Splunk index; the same ids are absent for the baseline, so nothing regressed, but the
evidence experience of those labs was not seen working).
These counts are not a claim that the lessons teach well; instructional quality was not re-assessed.

## 1. Method (what was compared, and how it differs from "IDs match and unit tests pass")

1. **Byte-level:** SHA-256 of every file under `learning/level_1/<lab>/` (lesson, workshop, knowledge checks, searches, dashboards, specimens), every Splunk view, Splunk static assets, `.conf` files, Academy templates and static files. 31 of 31 labs: **0 changed, 0 removed**. Splunk views: 35 of 36 identical; the one changed (`ws_agentsec_home.xml`) differs by the new mission's entry plus build-identity numbers. The live Splunk app volume equals the current tree, and differs from the baseline only in the same four additive files (learner-path script, `app.conf` build number, nav, home view).
2. **Behavioural, same code path, both trees:** each tree's own Flask apps ran in process with the repository's labelled `StubLLM`. All **21 LIVE launches** (7 labs x BASELINE/ATTACK/RETEST) compared on HTTP result, normalised response, and the ordered event sequence with control id, decision, tool and executed flag: **21 of 21 identical**. The legacy `POST /api/attacks/ATK-002` response is identical. Every GET route and a crawl of the Academy, Attack UI and Banking UI (61 Attack-service URLs in the baseline crawl, 63 now; 5 Banking URLs): statuses, titles, headings and control counts identical except the five Academy pages described below; **no route removed from either app; every baseline route still answers with the same status.**
3. **Browser, both trees, real Chromium:** 14 pages visited (axe, console errors, failed requests), and every launch control of the 7 LIVE labs clicked as a learner would (Attack UI pages, the LAB-MCP-001 stepper, the Academy MCP workshop with its prediction step): **38 steps, 0 differences** beyond the added nav item and brand text. 0 console errors and 0 failed requests in either tree.
4. **Splunk Web, live:** all 32 views (31 original + the new Loan Desk view) opened in the running Splunk Web: 0 missing views, 0 error banners or page errors, between 4 and 30 visualizations and 4 to 11 tabs each. Screenshots: `docs/reviews/batch7/splunk_views/`.
5. **Standing guard:** `tests/test_batch7_preservation.py` pins the original hashes, registry fields, checkpoints, curriculum prefix and views from `preservation_baseline.json`.

Not done: no learner read the lessons (instructional quality unmeasured); search *results* were not compared against a baseline Splunk because none exists, only the byte-identical search text and the identical index; Windows/Linux hosts.

## 2. Differences found between baseline and now (all of them)

| Where | Difference | Verdict |
|---|---|---|
| Academy pages (`/academy`, foundations, path, status, MCP workshop) | masthead mark and "AgentSec" removed (the requested duplicate-header fix); "Loan Desk Mission" nav item added; version note became a landmark (`aside`); home page gains the mission card; path page gains the mission row | intended, additive |
| Accessibility of those pages | baseline had one moderate axe violation (`region`) on each; now none | ENHANCED |
| `curriculum.json`, `lab_registry_data.json`, `apply_guided_learning.py`, learner-path JS, Splunk nav, home view/dashboard | one new entry each (Loan Desk); the rest unchanged; checkpoints identical | additive |
| `timeline.py`, `schema.py`, `bank_app.py`, `attack_app.py`, `academy_web.py`, `workshop_flows.py` | all changes add behaviour (model-proposed marker, closed Loan Desk schema, new routes); the 21 launches are identical, so existing labs are unaffected | additive |
| `Dockerfile.attack` | extra mkdir/COPY for the new manifest, and (this batch) `framework_refs.json` | additive; see section 4 |

## 3. Assets outside `curriculum.json`

| Asset | Evidence | Result |
|---|---|---|
| Attack UI (`/`, `/labs/<id>` for 7 labs, `/acmebank`) | in-process: identical page facts; browser: identical launch results | preserved |
| Banking UI (AcmeBank `/`, `/health`) | identical statuses and facts; one new page `/loan-desk` added | preserved |
| Academy MCP workshop (`/academy/labs/LAB-MCP-001`) | 13 browser steps identical apart from nav | preserved, a11y improved |
| Workshop files (`workshop.md`/`workshop.json`, README, knowledge checks, evidence docs, investigations) | byte-identical | preserved |
| Splunk learning materials (31 original views, searches, dashboards, flows, learner-path) | byte-identical except the home view and learner-path script (additive); all render in live Splunk | preserved |
| REPLAY specimen packs (`LAB-MCP-001` 3 packs) | byte-identical; 3 of 3 run ids present in the index | preserved |

## 4. Findings

1. **Baseline defect, present in every image built from the baseline Dockerfile (not a regression).** `docker/Dockerfile.attack` never copied `learning/academy/framework_refs.json`, so inside Docker `/` and the seven `/labs/<id>` Attack UI pages return **HTTP 500** (`FileNotFoundError ... framework_refs.json`). Proven on a freshly built baseline image (500 on all) and on the pre-Batch-4 rollback image's file list; in-process both trees return 200, which is why no test caught it. The launch API, the Academy MCP workshop and the Splunk views are unaffected. The one-line fix (a COPY) is in this branch and was verified on an isolated container: all ten URLs 200. It will ship with the Gate B image.
2. **Specimen evidence missing (baseline condition, UNVERIFIED for 8 labs).** The dashboards of 15 labs offer 56 specimen run ids; only LAB-MCP-001's 3 exist in this index. The eight REPLAY labs affected (BLUE-TEAM, MCP-003/004/005/006, MCP-CATALOG, MULTI-STAGE, SCANNER-RUNTIME-EVIDENCE) therefore cannot show their evidence on this machine; the LIVE labs create fresh runs and are unaffected. This is Batch 5's coverage gap, unchanged.
3. **Pre-existing accessibility debt, unchanged:** four Attack UI lab pages (RAG, MEMORY, GOAL, DELEGATION) have one *serious* `color-contrast` axe violation in the baseline and now.
4. **Pre-existing:** registry marks LAB-PRIVACY-DATA-GOVERNANCE-001 CONTENT-ONLY although a runnable pipeline exists (Batch 5).

## 5. Per-entry result

| Entry | Mode | Learning files | Launch behaviour | Browser flow | Splunk view | Accessibility | Result | Note |
|---|---|---|---|---|---|---|---|---|
| LAB-A2A-AUTH-DELEGATION | CONTENT-ONLY | 3 files identical | n/a (no launch) | n/a | view XML identical; renders (6 viz, 11 tabs, no error) | same axe result | **PRESERVED** |  |
| LAB-ADVANCED-CAPSTONE-MASTERY-001 | REPLAY | 13 files identical | n/a (no launch) | n/a | view XML identical; renders (8 viz, 11 tabs, no error) | same axe result | **PRESERVED** |  |
| LAB-AGENT-DELEGATION-001 | LIVE | 8 files identical | 3 launches identical (decisions and event order) | 2 UI steps run; identical results (only the added nav item and brand text differ) | view XML identical; renders (22 viz, 4 tabs, no error) | same axe result | **PRESERVED** | Docker image 500s on this Attack UI page in baseline too (fixed in Gate B image) |
| LAB-AGENT-GOAL-INTEGRITY-001 | LIVE | 11 files identical | 3 launches identical (decisions and event order) | 2 UI steps run; identical results (only the added nav item and brand text differ) | view XML identical; renders (22 viz, 4 tabs, no error) | same axe result | **PRESERVED** | Docker image 500s on this Attack UI page in baseline too (fixed in Gate B image) |
| LAB-AGENT-IDENTITY-NHI | REPLAY | 4 files identical | n/a (no launch) | n/a | view XML identical; renders (6 viz, 9 tabs, no error) | same axe result | **PRESERVED** |  |
| LAB-AGENTSEC-CAPSTONE-001 | LIVE | 8 files identical | 3 launches identical (decisions and event order) | 2 UI steps run; identical results (only the added nav item and brand text differ) | view XML identical; renders (28 viz, 4 tabs, no error) | same axe result | **PRESERVED** | Docker image 500s on this Attack UI page in baseline too (fixed in Gate B image) |
| LAB-ASSET-INVENTORY | CONTENT-ONLY | 2 files identical | n/a (no launch) | n/a | view XML identical; renders (6 viz, 4 tabs, no error) | same axe result | **PRESERVED** |  |
| LAB-BLUE-TEAM-INCIDENT-001 | REPLAY | 10 files identical | n/a (no launch) | n/a | view XML identical; renders (8 viz, 4 tabs, no error) | same axe result | **UNVERIFIED** | dropdown specimen run ids absent from this Splunk (same in baseline); evidence experience not exercisable |
| LAB-CHANGE-BOUNDS | CONTENT-ONLY | 2 files identical | n/a (no launch) | n/a | view XML identical; renders (6 viz, 4 tabs, no error) | same axe result | **PRESERVED** |  |
| LAB-CODE-AGENT-BOUNDS | CONTENT-ONLY | 2 files identical | n/a (no launch) | n/a | view XML identical; renders (6 viz, 4 tabs, no error) | same axe result | **PRESERVED** |  |
| LAB-COMPONENT-PROVENANCE | CONTENT-ONLY | 2 files identical | n/a (no launch) | n/a | view XML identical; renders (6 viz, 4 tabs, no error) | same axe result | **PRESERVED** |  |
| LAB-CREDENTIAL-LIFETIME | CONTENT-ONLY | 3 files identical | n/a (no launch) | n/a | view XML identical; renders (6 viz, 7 tabs, no error) | same axe result | **PRESERVED** |  |
| LAB-DETECTION-ENGINEERING | REPLAY | 4 files identical | n/a (no launch) | n/a | view XML identical; renders (6 viz, 6 tabs, no error) | same axe result | **PRESERVED** |  |
| LAB-EXTERNAL-EVALUATION-GARAK | REPLAY | 7 files identical | n/a (no launch) | n/a | view XML identical; renders (10 viz, 4 tabs, no error) | same axe result | **PRESERVED** |  |
| LAB-HITL-APPROVAL | CONTENT-ONLY | 3 files identical | n/a (no launch) | n/a | view XML identical; renders (4 viz, 7 tabs, no error) | same axe result | **PRESERVED** |  |
| LAB-MCP-001 | LIVE | 40 files identical | 3 launches identical (decisions and event order) | 13 UI steps run; identical results (only the added nav item and brand text differ) | view XML identical; renders (6 viz, 4 tabs, no error) | ENHANCED: Academy workshop page lost its axe 'region' violation | **ENHANCED** |  |
| LAB-MCP-003 | REPLAY | 6 files identical | n/a (no launch) | n/a | view XML identical; renders (28 viz, 10 tabs, no error) | same axe result | **UNVERIFIED** | dropdown specimen run ids absent from this Splunk (same in baseline); evidence experience not exercisable |
| LAB-MCP-004 | REPLAY | 11 files identical | n/a (no launch) | n/a | view XML identical; renders (30 viz, 10 tabs, no error) | same axe result | **UNVERIFIED** | dropdown specimen run ids absent from this Splunk (same in baseline); evidence experience not exercisable |
| LAB-MCP-005 | REPLAY | 9 files identical | n/a (no launch) | n/a | view XML identical; renders (28 viz, 10 tabs, no error) | same axe result | **UNVERIFIED** | dropdown specimen run ids absent from this Splunk (same in baseline); evidence experience not exercisable |
| LAB-MCP-006 | REPLAY | 9 files identical | n/a (no launch) | n/a | view XML identical; renders (28 viz, 10 tabs, no error) | same axe result | **UNVERIFIED** | dropdown specimen run ids absent from this Splunk (same in baseline); evidence experience not exercisable |
| LAB-MCP-CATALOG | REPLAY | 18 files identical | n/a (no launch) | n/a | view XML identical; renders (28 viz, 10 tabs, no error) | same axe result | **UNVERIFIED** | dropdown specimen run ids absent from this Splunk (same in baseline); evidence experience not exercisable |
| LAB-MEMORY-001 | LIVE | 11 files identical | 3 launches identical (decisions and event order) | 2 UI steps run; identical results (only the added nav item and brand text differ) | view XML identical; renders (22 viz, 4 tabs, no error) | same axe result | **PRESERVED** | Docker image 500s on this Attack UI page in baseline too (fixed in Gate B image) |
| LAB-MULTI-STAGE-INCIDENT-001 | REPLAY | 15 files identical | n/a (no launch) | n/a | view XML identical; renders (10 viz, 10 tabs, no error) | same axe result | **UNVERIFIED** | dropdown specimen run ids absent from this Splunk (same in baseline); evidence experience not exercisable |
| LAB-PI-001 | LIVE | 20 files identical | 3 launches identical (decisions and event order) | 6 UI steps run; identical results (only the added nav item and brand text differ) | view XML identical; renders (22 viz, 10 tabs, no error) | same axe result | **PRESERVED** | Docker image 500s on this Attack UI page in baseline too (fixed in Gate B image) |
| LAB-PRIVACY-DATA-GOVERNANCE-001 | REPLAY | 12 files identical | n/a (no launch) | n/a | view XML identical; renders (8 viz, 8 tabs, no error) | same axe result | **PRESERVED** |  |
| LAB-RAG-CONTEXT | LIVE | 11 files identical | 3 launches identical (decisions and event order) | 2 UI steps run; identical results (only the added nav item and brand text differ) | view XML identical; renders (22 viz, 4 tabs, no error) | same axe result | **PRESERVED** | Docker image 500s on this Attack UI page in baseline too (fixed in Gate B image) |
| LAB-RAG-PURPOSE | CONTENT-ONLY | 3 files identical | n/a (no launch) | n/a | view XML identical; renders (6 viz, 6 tabs, no error) | same axe result | **PRESERVED** |  |
| LAB-RECALL-ISOLATION | CONTENT-ONLY | 3 files identical | n/a (no launch) | n/a | view XML identical; renders (6 viz, 6 tabs, no error) | same axe result | **PRESERVED** |  |
| LAB-SCANNER-RUNTIME-EVIDENCE | REPLAY | 5 files identical | n/a (no launch) | n/a | view XML identical; renders (28 viz, 10 tabs, no error) | same axe result | **UNVERIFIED** | dropdown specimen run ids absent from this Splunk (same in baseline); evidence experience not exercisable |
| LAB-SPLUNK-DEFENDER-BRIDGE | REPLAY | 11 files identical | n/a (no launch) | n/a | view XML identical; renders (8 viz, 5 tabs, no error) | same axe result | **PRESERVED** |  |
| LAB-THREAT-MODELING-001 | REPLAY | 8 files identical | n/a (no launch) | n/a | view XML identical; renders (10 viz, 5 tabs, no error) | same axe result | **PRESERVED** |  |

Raw evidence: `preservation_baseline.json`, `preservation_head.json`, `preservation_compare.json`, `browser_baseline.json`, `browser_head.json`, `splunk_views_live.json`, `splunk_views/*.png`.
Scripts: `scripts/curriculum_preservation.py`, `preservation_servers.py`, `preservation_browser.py`, `curriculum_preservation_report.py`.
