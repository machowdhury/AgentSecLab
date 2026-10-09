# AGENTSEC P1.6 — 15 October 2026 release-candidate qualification

**Verdict: CONDITIONAL GO — READY WITH DISCLOSED LIMITATIONS**

Scope: the 15–20 minute LAB-MCP-001 demonstration on the local AgentSec Docker stack. This is not a production-readiness qualification.

Evidence classes: OBSERVED, MEASURED, DOCUMENTED, INFERRED, REPLAYED, UNTESTED. REPLAY packs are recordings of past runs and are never reported as new measurements.

---

## 1. Executive summary

The Academy demonstration works end to end on the deployed build, in both REPLAY and LIVE mode. This was MEASURED on 2026-10-09 in real Chromium against `http://127.0.0.1:5001`, with no mocks.

Rehearsal on the previously deployed build found one demo blocker. Once any durable LIVE pair existed on the server, every new tab adopted it and both LIVE launch buttons stayed disabled, so the scripted LIVE path could not run. It was reproduced, fixed with regression tests, redeployed and re-rehearsed. A fresh LIVE pair (`82423ce2-…` ALLOW/handler started, `2c4e5738-…` DENY/handler not started) was recorded and reconciled one-to-one with Splunk.

Remaining limitations, all disclosed in the demo docs:

- VoiceOver is UNTESTED.
- The lab model is unavailable on this host, so model-dependent LIVE labs are DEGRADED. LAB-MCP-001 does not use the model.
- A clean empty-stack rebuild was not attempted on the working host.
- `scripts/academy-restart.sh` was not re-executed this phase.
- DET-MCP-001 stays disabled.
- Only LAB-MCP-001 has the Academy workshop.

None of these blocks the demonstration. Together they prevent an unconditional GO.

## 2. Starting and final SHAs

| Item | Value |
|------|-------|
| Branch | `develop` |
| Starting HEAD = `origin/develop` | `f227708c78ccc48edc7bf047dd49032984e3ac86` (P1.5 close-out) |
| Divergence before commit | 0 / 0 (MEASURED after `git fetch`) |
| Final SHA | The commit that adds this report (`git log -1 -- docs/reviews/AGENTSEC_P1_6_OCT15_RELEASE_CANDIDATE_QUALIFICATION.md`); push and 0/0 divergence are reported in the session close-out |

Earlier P1.6 work by the previous writer (the REPLAY switch, the `[hidden]` CSS rule, docs and matrices) was uncommitted at the start. It was preserved and continued, not restarted.

## 3. Deployed build identity

| Item | Value | Class |
|------|-------|-------|
| Container | `agentsec_attack_service`, `127.0.0.1:5001`, healthy | OBSERVED |
| Image | `sha256:e5dc7f88bc9afbf77db483369f27fdfada25965ea69408fcb797fb026cc11107` | OBSERVED |
| Started | 2026-10-09T22:15:30Z | OBSERVED |
| Rollback tag | `agentseclab-attack_service:p16-rollback-d5b11d39` (the pre-P1.6 image) | OBSERVED |
| Served `academy.js` SHA-256 | `6468b1542e048fa9…` = committed file | MEASURED |
| Served `academy.css` SHA-256 | `fa6ae9fbfe1dae2a…` = committed file | MEASURED |
| `workshop_mcp.html` inside container | `8dd6480397c95574…` = committed file | MEASURED |
| Python sources | Unchanged from `f227708` in P1.6 | OBSERVED (`git diff`) |

Build path: `docker compose build attack_service`, then `docker compose up -d --no-deps attack_service`. Splunk, AcmeBank, the collector and all volumes were not recreated. Image history this phase: `d5b11d39…` (built before the CSS fix, so `[hidden]` buttons were visible in deployment) → `e193f8b3…` → `e5dc7f88…`.

## 4. Completed deliverables

| Gate | Deliverable | State |
|------|-------------|-------|
| A | LAB-MCP-001 nine-step workshop, REPLAY primary, LIVE extension | Complete. Fresh-LIVE reset and RETEST pairing guard added (see §8). |
| B | `docs/demo/AGENTSEC_OCT15_DEMO_SCRIPT.md`, `…FACILITATOR_GUIDE.md`, `…TROUBLESHOOTING.md`, `…TECHNICAL_QA.md` | Complete; updated with the clear-tab LIVE step and the final rehearsal IDs |
| C | `AGENTSEC_P1_6_PRODUCT_DELIVERABLES_MATRIX.md` | Complete, 20 sections, each with paths and evidence |
| D | `AGENTSEC_P1_6_CURRICULUM_COVERAGE.md`, `AGENTSEC_P1_6_ENTERPRISE_TELEMETRY_MATRIX.md` | Complete, with the Gate D labels and a prioritised Phase 2 list |
| E | Accessibility | Automated checks and genuine zoom MEASURED; VoiceOver UNTESTED (§10) |
| F | LIVE reconciliation | 7 of 7 run.ids reconciled (§9) |
| G | Operations and security | `lab-ready` exit 0, recreate persistence, security probes (§11, §12) |
| H | Regression | Full suite 1648 passed / 3 skipped, exit 0 (§13) |
| — | Learning note | `docs/learning-notes/p1-6-oct15-demo-readiness.md` updated |
| — | Reusable scripts | `scripts/p1_6_reconcile_live_evidence.py`, `scripts/p1_6_axe_audit.py` |

## 5. Remaining deliverables

| Item | Status | Why |
|------|--------|-----|
| VoiceOver test | UNTESTED | Needs a macOS accessibility setting change and a human listener; this session cannot produce a verifiable transcript |
| Clean empty-stack rebuild | NOT VERIFIED | Destructive on the working host; forbidden by the brief |
| `scripts/academy-restart.sh` re-run | NOT EXECUTED in P1.6 | Auto-review classifier errors on three attempts. The equivalent `--no-deps` recreate was measured twice instead. |
| Lab model (`llama3.2:1b`) | ABSENT | Model-dependent LIVE labs are DEGRADED. Not needed for LAB-MCP-001. |
| Academy workshops for other labs | NOT IMPLEMENTED | Out of P1.6 scope; Phase 2 candidate |
| DET-MCP-001 | Packaged disabled | Owner decision; would not fire on fail-open ALLOW anyway |
| Cosmetic "LIVE LIVE —" provenance line | Open | Harmless; documented in troubleshooting |
| `lab-ready.sh` "Academy" line points at the Splunk view | Open | Documented in troubleshooting |

## 6. Curriculum coverage

See `AGENTSEC_P1_6_CURRICULUM_COVERAGE.md`. In summary:

- 18 labs in `levels[]`, plus 12 checkpoints.
- **LAB-MCP-001** is the only Academy-integrated lab, and the only lab whose LIVE path was re-measured in P1.6.
- Seven labs are LIVE-capable (on the closed launch allowlist) and documented, not re-run.
- The remaining labs are REPLAY-only Studio labs or reference material.
- Checkpoints are SIMULATED, REPLAYED or DOCUMENTED and must not be shown as live experiments.

## 7. Enterprise coverage

See `AGENTSEC_P1_6_ENTERPRISE_TELEMETRY_MATRIX.md`.

- **LIVE INTEGRATION:** AI agent runtime / MCP and lab application telemetry, through OTel → collector → HEC → Splunk.
- **VALIDATED SAMPLE:** vulnerability exposure (scanner finding packs).
- **DOCUMENTED REFERENCE:** IAM, DLP and infrastructure.
- **NOT SUPPORTED:** EDR, NDR, firewall/SWG, cloud audit, Kubernetes, threat intel, email, SaaS audit, HR, and non-Splunk SIEMs.

Phase 2 priorities are listed there; they are an INFERRED recommendation.

## 8. Rehearsal

MEASURED on the deployed image `e5dc7f88…`, starting about 2026-10-09T22:17Z, in real Chromium with no route interception. Evidence: `p1.6-oct15-evidence/rc_rehearsal.json` and the screenshots `rc_shot_*.png`.

**Defect found first (OBSERVED on `e193f8b3…`):** with durable LIVE slots present, `Launch LIVE ATTACK` was disabled before and after the REPLAY switch.

The cause: the client adopts server slots as "this tab's runs", and one run per mode per tab is enforced. The server also picks ATTACK and RETEST slots independently, so a newer ATTACK could be shown beside an older RETEST.

**Fix:**

- **Clear this tab and launch a fresh LIVE pair.** This empties tab state only and stops this tab re-adopting server slots. Server references and artifacts are untouched.
- **RETEST pairing guard.** A recovered RETEST is adopted only when the matching ATTACK is adopted and the RETEST is not older than it.
- **Regression tests:** `test_recovered_live_pair_does_not_block_a_fresh_live_launch_mocked`, `test_older_recovered_retest_is_not_paired_with_a_newer_attack_mocked` and `test_workshop_offers_a_session_only_fresh_live_reset`.

**REPLAY path (REPLAYED evidence, live UI):**

- Baseline `163d11e2-…`: ALLOW, 7 events.
- ATTACK `5e8f55f3-…`: ALLOW `vulnerable_profile_fail_open`, handler OBSERVED.
- Notebook answers: q1 ALLOW, q2 Yes, q3 `agentsec.mcp.started`, q4 No, q5 0.
- RETEST `7a1d37b5-…`: DENY.
- Compare: decision DIFFERENT, `mcp.started` OBSERVED → NOT OBSERVED, `pipeline.stopped` NOT OBSERVED → OBSERVED, LLM 0/0, events 7/6. The page shows 5 OBSERVED and 2 INFERRED claims.
- Completion OK, 0 console errors.
- The REPLAY switch note states that it is not a live launch.

**LIVE path (MEASURED):**

- Launch was disabled before the clear and enabled after it.
- ATTACK `82423ce2-fae2-4adf-a9eb-39dd10f6c97f`, launched 22:17:25Z (~0.3 s): ALLOW, handler started, 7 events.
- RETEST `2c4e5738-d845-46f8-98d3-3193956c9876`, launched 22:17:26Z: DENY, 6 events.
- Compare matches the REPLAY pattern.
- The Splunk link uses exact run epochs.
- A newly opened tab adopts the new pair.

## 9. LIVE reconciliation

MEASURED with `scripts/p1_6_reconcile_live_evidence.py` (evidence `rc_gate_f_reconcile.json`). The script compares the local artifact (`artifacts/<id>/events.jsonl`, or the committed REPLAY pack) with an independent Splunk search on `index=agentsec_telemetry sourcetype=otel:agentic:json`.

A run reconciles only if both sides agree on:

- event count;
- a single distinct decision (multivalue fields deduplicated);
- `agentsec.mcp.started` count;
- `agentsec.pipeline.stopped` count;

and Splunk holds exactly one decision event.

| run.id | Kind | Local / Splunk events | Decision (reason) | started / stopped | Schema | Reconciled |
|--------|------|-----------------------|-------------------|-------------------|--------|------------|
| `82423ce2-fae2-4adf-a9eb-39dd10f6c97f` | LIVE ATTACK | 7 / 7 | ALLOW (`vulnerable_profile_fail_open`) | 1 / 0 | 1.9.0 | yes |
| `2c4e5738-d845-46f8-98d3-3193956c9876` | LIVE RETEST | 6 / 6 | DENY (`tool_not_granted`) | 0 / 1 | 1.9.0 | yes |
| `de60a91c-8aa0-411f-8731-2d79d760d427` | LIVE ATTACK (earlier P1.6) | 7 / 7 | ALLOW | 1 / 0 | 1.9.0 | yes |
| `b8c432ff-6e2e-4cec-a259-78761b50b969` | LIVE RETEST (earlier P1.6) | 6 / 6 | DENY | 0 / 1 | 1.9.0 | yes |
| `163d11e2-e751-4282-9406-19b490542ed4` | REPLAY BASELINE | 7 / 7 | ALLOW (`tool_granted`) | 1 / 0 | 1.1.0 | yes |
| `5e8f55f3-eb46-47ee-b979-b72d9c9b1f49` | REPLAY ATTACK | 7 / 7 | ALLOW (`vulnerable_profile_fail_open`) | 1 / 0 | 1.1.0 | yes |
| `7a1d37b5-d589-4dfd-8322-25ebd0152dbc` | REPLAY RETEST | 6 / 6 | DENY (`tool_not_granted`) | 0 / 1 | 1.1.0 | yes |

Notes:

- LLM events are 0 locally and in Splunk for every row; this lab path calls no model. No LLM events were fabricated.
- REPLAY first timestamps are 2026-09-12T03:05Z (indexed copies of past runs).
- Historical P1.4 runs were not backfilled.
- MCP-005 stays unpublished; `ws_lab_mcp_001` is unchanged.
- Decision before execution: in RETEST the DENY is recorded with `mcp.started` = 0 and `pipeline.stopped` = 1. The check ran before the handler, and the handler did not run.

## 10. Accessibility

| Check | Result | Class |
|-------|--------|-------|
| Genuine Chrome zoom 100/200/400% at 1920×1080 (dpr 1/2/4, inner width 1920/960/480) and 1024×768, deployed build | 0 horizontal overflow, clipping or off-screen controls on 5 pages and 9 workshop steps; skip link → `main`; keyboard reaches the REPLAY switch with a 3 px outline; narrow menu at 400% opens and returns focus; 0 console errors | MEASURED (`rc_zoom_deployed.json`) |
| axe-core 4.14.0 (`wcag2a`, `wcag2aa`, `wcag21a`, `wcag21aa`, `wcag22aa`), deployed build | 0 violations, 0 incomplete on 5 pages and 9 steps (19–34 passes per page) | MEASURED (`rc_axe_deployed.json`) |
| VoiceOver | Not run | **UNTESTED** (`gate_b_voiceover.json`) |

Automated checks are not presented as screen-reader testing, and no speculative accessibility fixes were made. axe was injected with CSP bypass in the test browser context only; the deployed CSP was not changed.

## 11. Operational reliability

| Check | Result | Class |
|-------|--------|-------|
| `./scripts/lab-ready.sh` | Exit 0. SERVICE READY; HEC health 200 directly and through the collector; 17 Studio views present | MEASURED (`rc_lab_ready.txt`) |
| `splunk_hec_init` | Exited 1 (historical); HEC healthy regardless | OBSERVED |
| AcmeBank status | `degraded`: `ollama_reachable:false`, model absent | OBSERVED |
| Attack Service `/health` | 200 | MEASURED |
| Run-reference persistence | Durable index survived two `--no-deps` recreates (4 → 6 references); slots point at the fresh pair | MEASURED |
| Evidence persistence | After recreate, the evidence API returns ALLOW/OBSERVED/7 and DENY/NOT OBSERVED/6 for the fresh pair | MEASURED |
| Splunk search | Independent CLI searches return the counts in §9 | MEASURED |
| Restart procedure | `docker compose up -d --no-deps attack_service` measured; `scripts/academy-restart.sh` not re-executed | Partially MEASURED |
| Recovery | Rollback image `agentseclab-attack_service:p16-rollback-d5b11d39` present (not exercised). Error-path recovery in `gate_f_recovery.json` (earlier P1.6): unknown run → 404 `UNAVAILABLE`, malformed id → 400, never SAFE | OBSERVED |
| Clean empty stack | Not attempted on the working host | NOT VERIFIED |

Only AgentSecLab containers were touched. No volumes were deleted, nothing was pruned, no certificates were rotated, TLS settings were not changed, and no shared-host settings were modified.

## 12. Security

| Check | Result | Class |
|-------|--------|-------|
| Response headers | CSP `default-src 'self'; script-src 'self'; … frame-ancestors 'none'`, `nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: same-origin`, `Cache-Control: no-store` | MEASURED |
| Academy is read-only | POST `/api/academy/live-runs` → 405; DELETE on evidence → 405 | MEASURED |
| Path traversal | `..%2f..` → 400; unknown UUID → 404 (missing, not SAFE) | MEASURED |
| Launch allowlist | Extra `profile` field → `unknown_fields` ERROR; `MCP-999` → `unknown_specimen` | MEASURED |
| Clear-tab control | Client state only; no server delete endpoint exists or was added | OBSERVED (code + 405 probe) |
| Secret scan | Regex scan (passwords/tokens, AWS, GitHub, JWT, private keys, Splunk HEC, `admin:` credentials) over the 19 changed or new text files and the evidence: 0 matches. No dedicated scanner such as gitleaks is installed. | MEASURED |
| Splunk credentials | Read from the container environment at runtime by `scripts/splunk_cli_csv.py`; never printed or committed | OBSERVED |
| Accepted dashboard | `ws_lab_mcp_001.xml` SHA-256 `154783d5…` unchanged; `splunk_app/` unchanged | MEASURED |
| Detections | 3 packaged saved searches, all `disabled = 1` | MEASURED |
| Policy authority | CTRL-MCP-001 in AcmeBank; Splunk and Academy make no authorization decisions | OBSERVED |

The posture is an educational localhost service without authentication. There is no production IAM, multi-tenant or internet-exposure claim.

## 13. Regression

Environment: macOS, Python 3.14 `.venv`, Playwright Chromium, run outside the sandbox.

| Command | Result | Exit |
|---------|--------|------|
| `.venv/bin/python -m pytest -q -p no:cacheprovider -p no:logging -rs` (final tree) | **1648 passed, 3 skipped** in 48 s | 0 |
| `pytest tests/integration/test_p1_4_academy_browser.py`, 5 consecutive runs | 15 passed each | 0 |
| Same full command before the fresh-LIVE change | 1645 passed, 3 skipped | 0 |
| First full run after the change | 1 failed, 1647 passed, 3 skipped | 1 |

**Skips:**

- `tests/integration/test_ollama_live.py`: model not reachable.
- `tests/splunk/test_external_evidence_live.py` and `test_live_transport.py`: opt-in live Splunk tests. Live Splunk was instead exercised directly in §9.

**Failure and fix:** `test_live_launch_double_click_sends_one_request_mocked` failed once. String `wait_for_function` predicates need in-page `eval`, which the Academy CSP forbids whenever polling is required, so these tests were timing-dependent. The four string waits were replaced with Playwright `expect(...).to_contain_text`. No assertion was changed.

**History:** P1.5's 1,642 passed / 3 deselected is historical and was measured on a different tree and selection. The difference is not a regression.

**Not run:** Ruff is not installed in this environment, so lint was not run. The new scripts pass `py_compile`.

## 14. Evidence manifest (SHA-256)

Committed under `docs/reviews/p1.6-oct15-evidence/` unless another path is shown.

| File | SHA-256 | Class |
|------|---------|-------|
| `rc_rehearsal.json` | `d617dd9f4853a93a06c29e65a334b46d38dc47d356582608867879730e66fb7f` | MEASURED |
| `rc_gate_f_reconcile.json` | `da6700e260a1568a41d4129fdaebe8b735f9813ff62d912fe67b474435645fa7` | MEASURED |
| `rc_axe_deployed.json` | `f2bd7187d90335cb5220c9f73e59b3085ecd6ccbda31825d1b86e80b8cc7ee93` | MEASURED |
| `rc_zoom_deployed.json` | `b18ef9adcc5f765545f20b62d3382b5f5588ec11092dde108691b979680791e3` | MEASURED |
| `rc_lab_ready.txt` | `0590328ee2ab2ea96f584816a77b69657a80716281732f7a8cd7c071c4d7189b` | MEASURED |
| `rc_pytest_full_final.txt` | `61067d3ac617705dcc648f472b92f963261893b21332e882e0fc1122ab90d178` | MEASURED |
| `rc_shot_attack_live.png` | `d6e5e2bf98f038d47e931166b58f5f8a9568c6f68331406f731f3685842969b9` | OBSERVED |
| `rc_shot_compare_live.png` | `cd21868493bd848e7bae6d1e5f601f6cf407bbcc8bb787e978525ddb11dc0f45` | OBSERVED |
| `rc_shot_compare_replay.png` | `aa11eb5165cae1e3892b12426ee33a5195239ae6aed7ea0dc8e416f362ce7cf9` | OBSERVED (REPLAYED data) |
| `gate_b_voiceover.json` | `7507d3020496d3de3f7b8837bcc234d5f2880610719c14dadc2f85a461aba13c` | UNTESTED record |
| `gate_f_recovery.json` | `c182270a6d98dd29b350db9a72661f23f28cb3c1e72f8d2441dde8725e7fd26b` | earlier P1.6 (error paths) |
| `gate_f_rehearsal.json` | `f1766e2dfe0f4000af13c9d7749f9ece4049d264d44eaf0411beeeec15197bf4` | earlier P1.6 |
| `gate_f_splunk.json` | `8648667002cb6cc2bc1cbfab3df6723fbeb41da9e66232ebcda7a520f2706921` | earlier P1.6 |
| `shot_home.png` | `2307ff52bf9e0a6e91879dea14f14327def3f4fcd10f0fdc3e5dd2ef4d0a819c` | earlier P1.6 |
| `shot_foundations.png` | `66f28da786028f9f6ed21082aaf695c0a6cad13187e6448b8099c818e6143068` | earlier P1.6 |
| `shot_path.png` | `22a4e914b11b2f7c07e25666449055cf5327047a8ac44146f49a03c844eea837` | earlier P1.6 |
| `shot_status.png` | `d0cc28b8845a6a4f947ad92d67337a677df2a89100ada86b99d585952fac110f` | earlier P1.6 |
| `shot_workshop.png` | `860210a8a518dcbd8ab7edeb41437db7dc9867172f033de5e047872589c16d30` | earlier P1.6 |
| `shot_workshop_attack.png` | `402aff2d9732fa03b269d02660d7cf8a0ab004b9b493ac5aec4f051ee5f0fb0b` | earlier P1.6 |
| `shot_workshop_baseline.png` | `52e578c21fb1850b4d1a26f0bb5520845fdb73707459310e32094a3887b7ec75` | earlier P1.6 |
| `shot_workshop_baseline_loaded.png` | `d5bc6729b1757d5e106e36da180d181548703360f76077e36a3a6b00afcae312` | earlier P1.6 |
| `scripts/p1_6_reconcile_live_evidence.py` | `6600c803f4d6eac317abaf89462ac8902db7dc1a89cd03d8fefc08f12b112544` | tool |
| `scripts/p1_6_axe_audit.py` | `57c9ef93666a6c536c4b9ddeb935e8b63d7744708d369e6c5286adb7dc957efd` | tool |
| `src/agentsec/static/academy.js` | `6468b1542e048fa9846baa2b88755c2b3a46fb3ae35e98117d1c2face1ace89f` | = deployed |
| `src/agentsec/static/academy.css` | `fa6ae9fbfe1dae2a5c89ccde4e747de60f9b714e5aeccd2b40a11bc919914155` | = deployed |
| `src/agentsec/templates/academy/workshop_mcp.html` | `8dd6480397c95574768f1dc82ee07623cd79eee98a2ee072c8005a0796770954` | = deployed |
| `splunk_app/agentsec/default/data/ui/views/ws_lab_mcp_001.xml` | `154783d5520473391b36266c86dee3883616605026c1b30c7c7e571976aba91c` | unchanged |
| axe-core 4.14.0 `axe.min.js` (local tool, not committed) | `20c09fe157a8a34a30e241aaa1fcdade657734f08ab379ecfbeb7d45cc46e878` | tool |

Uncommitted originals and the full screenshot sets are under `artifacts/p1.6-oct15-rc/`, which is git-ignored. LIVE run artifacts are under `artifacts/<run_id>/`.

## 15. Limitations

1. VoiceOver is UNTESTED, so no WCAG conformance claim is made.
2. The lab model is unavailable on this host, so model-dependent LIVE labs are DEGRADED. Only LAB-MCP-001 LIVE was re-measured.
3. The clean empty-stack rebuild is NOT VERIFIED, and `academy-restart.sh` was not re-run this phase.
4. CTRL-MCP-001 is a lab allow-list on in-process JSON-RPC MCP. It is not a remote MCP gateway or production policy engine.
5. DET-MCP-001 is disabled, and no ES notables exist.
6. Progress is per browser tab only.
7. Provenance is run-level and unsigned.
8. Enterprise coverage beyond Splunk and AgentSec runtime telemetry is sample, reference or unsupported.
9. Academy "Splunk indexing" status is intentionally NOT CHECKED. Splunk corroboration requires the search in §9.
10. REPLAY packs use schema 1.1.0 and new LIVE runs use 1.9.0. Presenters must say both.
11. Cosmetic: the provenance line reads "LIVE LIVE —", and the `lab-ready` "Academy" line names the Splunk view.
12. Qualified host is the **local Mac Docker stack** only. The EC2 deployment used in P1.0–P1.3 was not inspected or updated in P1.6, and its state is unknown.
13. The Splunk Studio view `ws_lab_mcp_001` keeps its P1.2/P1.3 limitation: mouse operation at 400% does not work in normal view. The Oct 15 beginner surface is the Flask Academy, which passes genuine 400% zoom.

## 16. 15 October GO / NO-GO

**CONDITIONAL GO — READY WITH DISCLOSED LIMITATIONS**

Why not NO-GO:

- The only critical blocker found (the LIVE launch lock) was fixed, tested and redeployed.
- REPLAY and LIVE were both rehearsed on the deployed build.
- Every LIVE claim in the script is backed by a reconciled Splunk record.

Why not GO: VoiceOver is untested, the model is degraded, clean-stack recovery is unverified, and restart-script re-execution is missing. The presenter must disclose these, and an unconditional qualification would overstate the evidence.

Presenter conditions:

- Use REPLAY as the primary path.
- Announce the mode.
- Use **Clear this tab and launch a fresh LIVE pair** before any new LIVE launch.
- Search Splunk by run.id before claiming indexing.
- Do not run `docker compose down -v`.

This verdict does not authorise a `main` merge, a tag, a release, Phase 2 or PyRIT.
