# AgentSec P1 — Learner Experience Implementation Report

Date: 2026-10-07. Scope: LAB-MCP-001 golden path only. No Phase 2, no PyRIT, no tag, no release, no merge to `main`.

Evidence classes follow `.cursor/rules/50-research-integrity.mdc`. MEASURED = taken from the deployed app or Splunk in this session. SIMULATED = local run against stubbed APIs (UI layout only, never evidence).

## 1. Starting state, commits, deployed SHA

| Item | Value |
|---|---|
| Expected app implementation | `b616af9` (found as expected) |
| Expected P0 report | `223e484` (found as expected) |
| `origin/main` (start and end) | `0178c70e20cfe0152648e2aafb8e607280625c40` (unchanged) |
| Design commit (first action) | `79f7ab3` — P1 design + mockup frames only |
| Implementation commits | `584ca46` feat P1; `371fc5e` valid SPL in CHECK queries + measured Studio heights; `343deae` academy column no longer capped at 760px + CHECK heights; `49de0f8` REFERENCE prose panel heights |
| Deployed SHA (EC2 `agentlabs`, `/home/ubuntu/AgentSecLab`) | `49de0f82785707625a1db5c3f336dc21c2568c48` |
| `.tmp-path-pre/` | not touched, not committed |

Deploy path: AWS SSM, instance `i-03e570d023ce16d6f`, us-east-2, `./scripts/lab-up.sh --build --refresh-app --remote`. Volumes preserved; no Docker prune; no Splunk/Mongo/kernel change; AcmeBank :5000 not publicly exposed. Disk before and after: 96G total, 9.0–9.1G free, 91% used. No cleanup performed.

## 2. Slice results

| Slice | Result |
|---|---|
| A — Academy shell, Start, inline baseline | Implemented in the Flask wizard (`attack_mcp.html`, `agentsec-academy.css`). Eight instructional steps (START, UNDERSTAND, TEST ×2, INVESTIGATE, IMPROVE ×2, PROVE ×2). Baseline is inline and REPLAY ONLY (pinned to the specimen pack by test). Primary CTA "Explore baseline →". |
| B — Predict, short Attack, Attack complete | Two independent predictions (decision; execution), CTA "Lock prediction & continue →". Attack screen short; detail behind disclosures. Attack complete does not show the decision/executed/mcp.* outcome; CTA "Investigate evidence →" uses the LIVE deep link. MEASURED live: the only ALLOW text on that screen is the learner's own prediction chip. |
| C — Studio START / INVESTIGATE / REFERENCE | Old learner navigation replaced (one journey). Notebook order QUESTION → WHY → EVIDENCE RESULT → INTERPRETATION → SUPPORTS → DOES NOT PROVE → NEXT. SPL moved to REFERENCE; displayed SPL equals executed SPL (verifier script). Cell 2 does not use `agentsec.control.decision`. HUNT/DETECT/raw SPL/Search/technical evidence preserved under REFERENCE / ADVANCED. CURRENT EVIDENCE labelled LIVE or REPLAY. |
| D — Defend, Retest | Explanatory DEFEND, no fake toggle, CTA "Retest the same attack →". No SAFE/SECURE/FIXED wording. |
| E — Compare, Explain | Evidence-backed ATTACK vs RETEST table; EXPLAIN answers five questions with limits stated. |

## 3. Studio spikes (D-2) and fallbacks

All OBSERVED on the deployed Splunk 10.2. No JavaScript, no unsupported CSS, no Splunk patching, no fake control.

| Capability | Result |
|---|---|
| `input.radio` | NOT SUPPORTED |
| In-canvas `input.dropdown` | SUPPORTED (used for "your answer" selectors; selecting UNSURE renders the CHECK table on live evidence) |
| Token-gated tables | SUPPORTED (closed state uses sentinel `none`, because an empty token never runs a search; verifier asserts closed=0 rows, open≥1) |
| Image `altText` | NOT SUPPORTED |
| Click-through image | SUPPORTED WITH CONSTRAINTS (keyboard activation unproven) |
| Deep link `?tab=layout_investigate&form.live_run_id=<id>` | SUPPORTED WITH CONSTRAINTS (Studio appends `form.run_id=<baseline>` and `form.nb_a1..3=none`) |

Fallback used: dropdown clearly associated with each question (fallback 1). The START call to action is a bold heading link, not a button (PLATFORM CONSTRAINT).

## 4. P0 tests deliberately changed

Every change carries "CONTRACT CHANGE: P1 learner-experience redesign" with OLD CONTRACT / NEW CONTRACT / WHY. No security or evidence assertion was deleted or loosened.

`test_web_ui`, `test_visual_learning`, `test_phase14e_learning_loop`, `test_phase16d_academy`, `test_learner_ux_p0`, `test_p0_1_learner_evidence`, `test_generator_owns_mcp_workshop_surface`, `test_guided_learning`, `test_agentsec_ui_shell`, `test_investigation_notebook` (the P0 `viz_nb4_r: 543` pin replaced by measured minimums), `test_lab_mcp_001_dashboard`, `test_phase1_golden_path_invariants`.

New: `tests/unit/test_p1_web_experience.py`, `tests/splunk/test_p1_studio_experience.py` (incl. every SPL `case()` has condition/value pairs, added after live Splunk rejected an odd-arity `case()` that offline tests had missed), and measured-height pins in `tests/splunk/test_investigation_notebook.py` (INVESTIGATE, CHECK and REFERENCE panels).

## 5. Contrast (D-4) — MEASURED

| Pair | Before | After |
|---|---|---|
| DENY text `#B7791F` on `#F6EBD8` | 3.08:1 (fail) | `#7A4F0B` on `#F6EBD8` = **6.03:1** |
| ALLOW | — | 4.86:1 |
| ERROR | — | 4.67:1 |
| OBSERVE | — | 8.56:1 |

The rendered DENY cell on the deployed Studio page was read from the DOM: fg `122,79,11`, bg `246,235,216`, ratio 6.03. Web CTA contrast measured 6.2:1 / 6.35:1. Meaning is carried by text, not colour alone. The fix is central (`workshop_flows.py` `DENY_TEXT`); 13 other labs' generated definitions changed only in that colour.

## 6. Tests

- Full suite on the final tree (`49de0f8` content): **1499 passed, 3 skipped, exit 0** (baseline was 1392). Skips: two opt-in live-Splunk tests and one Ollama test.
- Regeneration is byte-identical (pinned by test).
- Live SPL check: `scripts/verify_investigation_notebook_spl.py` ran on the host against an earlier run pair at an earlier SHA: all cells returned rows, 0 problems. It was **not** re-run against the final pair (see debt).

## 7. Fresh ATTACK / RETEST pair — MEASURED, reconciled independently in Splunk

Created through the real learner workflow on deployed `343deae`. The app (`src/`) did not change between `343deae` and `49de0f8` (0 files); only the Studio definition heights and tests did. Re-reconciled on the final deployment:

| | ATTACK `be62d44a-cdb0-4dbd-afe4-192fc9c16156` | RETEST `e86fa4ae-aaaf-4af4-865e-7c2d16f8fb09` |
|---|---|---|
| Profile | vulnerable | defended |
| Event count | 7 | 6 |
| Control decision / reason | ALLOW / `vulnerable_profile_fail_open` | DENY / `tool_not_granted` |
| `mcp.started` | 1 | 0 |
| `mcp.completed` | 1 | 0 |
| `pipeline.stopped` | 0 | 1 |
| LLM events | 0 | 0 |
| Tool | `lookup_customer_tier` | `lookup_customer_tier` |

Positive control (an all-zero run id) returns 0. Method: `docker exec` Splunk CLI on the host, `index=agentsec_telemetry sourcetype=otel:agentic:json earliest=0`. Compare screen in the app showed ATTACK ALLOW handler count 1 versus RETEST DENY handler count 0. Older runs were not used as proof. Runtime schema 1.9.0 and ExternalEvidence 1.0.0 were not touched; no new telemetry; CTRL-MCP-001 semantics unchanged.

## 8. Browser walkthrough (MEASURED; Chrome for Testing via Playwright)

Genuine zoom used the `chrome.tabs.setZoom` extension (devicePixelRatio 2 at 200% confirmed; 400% likewise). Preferences-file zoom does not apply and was not used.

| Surface | 1920 | 1024 | 200% | 400% |
|---|---|---|---|---|
| Web app (all nine wizard views) | no horizontal overflow | no horizontal overflow | no horizontal overflow | no horizontal overflow (reflows) |
| Studio INVESTIGATE | 0 of 24 panels overflow | 0 of 24 | 0 of 24 | markdown clips (PLATFORM CONSTRAINT) |
| Studio REFERENCE prose panels | not re-measured after the final change (heights only grew) | all fit | all fit | not measured |

Keyboard order and visible focus checked on the web app. Studio: dropdown operable; click-through image keyboard activation unproven.

Owner-style check, per primary screen (where am I / what do I do / what do I click / why / what next): the web screens each lead with one dominant action; no beginner step requires `run.id`, SPL, HEC or token knowledge (the LIVE deep link carries the run).

## 9. Findings

AGENTSEC DEFECTS (observed, not fixed):
1. Start CTA sits below the fold at 1024×768 (~280px scroll).
2. Predict CTA ~31px below the fold at 1920×1080.
3. REFERENCE raw-explorer tables (pre-existing P0 panels) overflow at 1024; they scroll internally.

SPLUNK PLATFORM CONSTRAINTS:
1. Dashboard Studio grid is fixed-height and absolute; text does not reflow. At 400% (≈248px viewport) markdown panels clip.
2. Dashboard description is truncated under the Studio toolbar at 1920 (kept: a test pins "does not enable").
3. START CTA is a heading link, not a button.
4. Launcher console 404/503 noise.
5. Studio appends `form.*` tokens to the deep link.

## 10. Remaining debt

- `verify_investigation_notebook_spl.py` not re-run on the final pair/SHA.
- REFERENCE not re-measured at 1920 or 400% after `49de0f8`.
- D-2 keyboard click-through unproven.
- Items 1–3 under defects.
- Local Playwright walk with stubbed APIs was SIMULATED and UI-only; it is not evidence.
- ALLOW is a fail-open demonstration in a vulnerable lab profile; this proves nothing about production safety. DENY here shows one control decision for one tool; it does not prove the system is secure.

## 11. State at stop

- Branch `develop` = `origin/develop` = `49de0f8`; `origin/main` = `0178c70`.
- Untracked: `.tmp-path-pre/` and `docs/design/mockups/` render artefacts (left alone).
- This report is the only file added after `49de0f8`.

## 12. Recommendation and verdict

Every hard-stop condition held: no schema change, no new telemetry, no CTRL-MCP-001 change, no fabricated evidence, no unsupported Splunk JS/CSS, no public :5000. The golden path works end to end through the real workflow, and the live pair reconciles in Splunk. Open items are layout debt, not evidence or security regressions. Hand to the owner for experience review, with the three AgentSec defects as the first things to look at.

**P1 IMPLEMENTED — READY FOR OWNER EXPERIENCE REVIEW**
