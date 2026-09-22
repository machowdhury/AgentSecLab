# UI review — AgentSec Academy Phase 17C (2026-09-21)

**Surface:** Home ORIENT, LAB-PI-001 LEARN, LAB-MEMORY-001 BASELINE, Mastery Check PURPLE TEAM, Attack Service PI. Viewports **1440 / 1280 / 1024**.  
**Method:** Playwright `scripts/capture_phase17c.py` after `splunk_app_init` restage and Splunk restart. Does not launch attacks. Does not print credentials.  
**Evidence class:** OBSERVED (screenshots) + MEASURED (pytest of templates).

## Result

Studio corrections **PASS**. No unresolved BLOCKER/HIGH on restaged Dashboard Studio views.

| Check | Result |
|-------|--------|
| Home ORIENT fingerprint no longer “proves equivalent input” | PASS after Splunk restart |
| PI LEARN “LIVE EXPERIMENT vs REPLAY SPECIMEN” | PASS after Splunk restart |
| Memory BASELINE “REPLAY SPECIMEN” on canonical write/recall ids | PASS after Splunk restart |
| Mastery PURPLE TEAM Path B is not the 15-point readout | PASS after Splunk restart |
| Attack Service `AML.T0054` REQUIRES REVALIDATION | **Repo template PASS** (`tests/unit/test_phase17c_correctness.py` Flask). Running docker image was **not rebuilt** this session; Playwright against `:5001` still showed the pre-17C page. |

First Playwright pass (before Splunk restart) reported false HIGH defects from cached Studio XML. Container files already contained the 17C strings. After restart, those Studio HIGHs cleared.

Screenshots: `docs/screenshots/agentsec-academy-17c/pass17c_*.png`  
Validation JSON: `docs/screenshots/agentsec-academy-17c/pass17c_validation.json` (final Studio pass; leftover Attack Service docker HIGH is image-stale, not a source defect).

## Layout

No 17C visual redesign. Copy-only. 1440/1280/1024 screenshots captured; no overflow BLOCKER observed on the corrected tabs.

## Not proven

- Docker Attack Service image contents after 17C (image not rebuilt).  
- Learner comprehension.  
- Splunk Dashboard Studio token binding of fresh LIVE ids (still NOT SUPPORTED).
