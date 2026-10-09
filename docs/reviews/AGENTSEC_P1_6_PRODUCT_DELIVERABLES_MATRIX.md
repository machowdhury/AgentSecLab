# AGENTSEC P1.6 — Product deliverables matrix

**Evidence class:** OBSERVED and MEASURED on 2026-10-09 against `develop` HEAD `f227708c78ccc48edc7bf047dd49032984e3ac86` and a later P1.6 implementation SHA recorded in the release-candidate report. Historical P1.4/P1.5 results are DOCUMENTED, not re-claimed as new measurements unless re-run.

**Classification vocabulary (exactly one per row):**

- IMPLEMENTED AND VERIFIED
- IMPLEMENTED BUT NOT FULLY VERIFIED
- PARTIAL
- REFERENCE ONLY
- NOT IMPLEMENTED
- BLOCKED

October 15 demonstration eligibility means: can this capability be shown in the supported 15–20 minute LAB-MCP-001 path without fabricating evidence?

Do not read a sample event, parser, or mapping as a vendor product integration.

---

## Summary

| Area | Classification | Oct 15 demo eligibility |
|------|----------------|-------------------------|
| Figma Academy | IMPLEMENTED AND VERIFIED | Yes — primary learner surface for LAB-MCP-001 |
| Learning paths | PARTIAL | Yes — path page; only LAB-MCP-001 has the nine-step Academy workshop |
| MCP security workshops | PARTIAL | Yes — LAB-MCP-001 live/replay; other MCP labs via Attack Service or Splunk Studio |
| Attack Workbench | IMPLEMENTED AND VERIFIED | Yes — Academy ATTACK step + closed `/api/launch` |
| Evidence Notebook | IMPLEMENTED AND VERIFIED | Yes — Academy INVESTIGATE + durable LIVE index |
| ATTACK/RETEST comparison | IMPLEMENTED AND VERIFIED | Yes — Compare step, REPLAY and LIVE rehearsed (§17) |
| Progress tracking | PARTIAL | Yes — per-tab stepper and completion; not durable (§18) |
| Splunk ingestion and investigation | IMPLEMENTED AND VERIFIED | Yes — 7/7 runs reconciled local vs Splunk (§6) |
| Security controls / runtime policy enforcement | IMPLEMENTED AND VERIFIED | Yes — CTRL-MCP-001 in AcmeBank before the handler (§7, §19) |
| Agent execution provenance | IMPLEMENTED AND VERIFIED | Yes — run-level: run.id, LIVE/REPLAY, profile, schema (§20) |
| Detection engineering | PARTIAL | Disclose only — DET-MCP-001 packaged disabled |
| AI agent forensics | PARTIAL | Yes as run reconstruction; not a forensic appliance |
| Enterprise telemetry | PARTIAL | Disclose as coverage matrix, not a live SOC feed |
| SIEM vendor coverage | REFERENCE ONLY | Splunk is the live SIEM; other vendors are not integrations |
| Documentation | IMPLEMENTED BUT NOT FULLY VERIFIED | Yes for LAB-MCP-001; uneven for later checkpoints |
| Accessibility | IMPLEMENTED BUT NOT FULLY VERIFIED | Genuine zoom + axe MEASURED on deployed build; VoiceOver UNTESTED |
| Deployment | IMPLEMENTED BUT NOT FULLY VERIFIED | Existing stack + two Attack Service recreates verified; clean empty-stack NOT VERIFIED |
| Security | IMPLEMENTED AND VERIFIED | Localhost educational posture; no production IAM claim |
| Automated testing | IMPLEMENTED AND VERIFIED | Full pytest 1648 passed / 3 skipped, exit 0 (P1.6 final tree) |

---

## 1. Figma Academy

**Classification:** IMPLEMENTED AND VERIFIED

| Field | Value |
|-------|--------|
| Repository path | `src/agentsec/templates/academy/`, `src/agentsec/static/academy.js`, `src/agentsec/academy_web.py`, `docs/learning-notes/figma-academy.md` |
| Tests | `tests/unit/test_p1_4_academy_pages.py`, `tests/integration/test_p1_4_academy_browser.py`, `tests/security/test_p1_4_academy_security.py`, `tests/integration/test_p1_5_academy_chrome_zoom.py` |
| Evidence | `docs/reviews/AGENTSEC_P1_4_FIGMA_ACADEMY_FINAL_QUALIFICATION.md`, `docs/reviews/p1.6-oct15-evidence/gate_f_rehearsal.json`, screenshots `shot_*.png` |
| Deployment | `http://127.0.0.1:5001/academy` HTTP 200 on the running Attack Service |
| Limitations | One dedicated nine-step workshop (LAB-MCP-001). Figma prototype numbers are not shipped. |
| Oct 15 | Eligible. Open `/academy` → Foundations → Path → LAB-MCP-001. |

MEASURED this phase: all five Academy routes HTTP 200, one `h1`, `#main`, skip link.

---

## 2. Learning paths

**Classification:** PARTIAL

| Field | Value |
|-------|--------|
| Repository path | `learning/academy/curriculum.json`, `src/agentsec/templates/academy/path.html` |
| Tests | `test_path_lists_every_curriculum_lab` |
| Evidence | Curriculum `levels[]` (18 labs) plus 12 checkpoints not in `levels[]` |
| Deployment | `/academy/path` lists labs; only `/academy/labs/LAB-MCP-001` is an Academy workshop |
| Limitations | Other labs launch from Attack Service or Splunk Studio views. Checkpoints are REPLAY / SIMULATED / DOCUMENTED. |
| Oct 15 | Eligible as a map. Do not demo every lab. |

---

## 3. MCP security workshops

**Classification:** PARTIAL

| Lab | Mode in curriculum | Runnable where | Oct 15 |
|-----|--------------------|----------------|--------|
| LAB-MCP-001 Tool Authorization | LIVE | Academy nine-step + Attack Service + `ws_lab_mcp_001` | Primary demo |
| LAB-MCP-003 Scope Escalation | REPLAY | Splunk Studio | Not in 15–20 min path |
| LAB-MCP-004 Parameter / Resource | REPLAY | Splunk Studio | Not in 15–20 min path |
| LAB-MCP-005 Tool Result Trust | REPLAY | Splunk Studio | Do not reopen MCP-005 publication |
| LAB-MCP-CATALOG | REPLAY | Splunk Studio | Not in 15–20 min path |
| LAB-MCP-006 Confused Deputy | REPLAY | Splunk Studio | Not in 15–20 min path |

| Field | Value |
|-------|--------|
| Repository path | `learning/level_1/LAB-MCP-001/`, `src/agentsec/experiment_context.py` |
| Tests | MCP runtime and Academy suites; detections remain disabled |
| Evidence | Committed REPLAY packs `163d11e2-…`, `5e8f55f3-…`, `7a1d37b5-…`; P1.6 LIVE pairs `de60a91c-…` / `b8c432ff-…` and final rehearsal `82423ce2-…` / `2c4e5738-…` |
| Deployment | Academy + AcmeBank MCP authorize path |
| Limitations | In-process JSON-RPC, not a remote MCP product. CTRL-MCP-001 is a lab allow-list. |
| Oct 15 | LAB-MCP-001 only. |

---

## 4. Attack Workbench

**Classification:** IMPLEMENTED AND VERIFIED

| Field | Value |
|-------|--------|
| Repository path | Academy ATTACK/RETEST steps; `POST /api/launch`; `src/agentsec/launch_catalog.py` (closed allowlist) |
| Tests | Launch allowlist tests; Academy duplicate-launch MOCKED client test |
| Evidence | P1.6 LIVE launch JSON in `gate_f_rehearsal.json` (`otlp.ok=true`, `hec.ok=false` by design) |
| Deployment | Attack Service `127.0.0.1:5001` |
| Limitations | Unauthenticated educational localhost service. Profile is server-owned. Browser cannot choose the tool. |
| Oct 15 | Eligible. Prefer REPLAY for timing; LIVE is secondary and must be labelled. |

---

## 5. Evidence Notebook

**Classification:** IMPLEMENTED AND VERIFIED

| Field | Value |
|-------|--------|
| Repository path | `src/agentsec/academy_evidence.py`, `src/agentsec/academy_live_index.py`, Academy INVESTIGATE step |
| Tests | `tests/unit/test_p1_5_academy_live_index.py`; Academy notebook browser tests |
| Evidence | Durable slots after the final P1.6 rehearsal: ATTACK `82423ce2-fae2-4adf-a9eb-39dd10f6c97f`, RETEST `2c4e5738-d845-46f8-98d3-3193956c9876`; 6 references survive two Attack Service recreates (`gate_f_reconcile.json`, `rc_rehearsal.json`) |
| Deployment | `/api/academy/evidence/<uuid>`, `/api/academy/compare`, `/api/academy/live-runs` |
| Limitations | Unknown UUIDs return missing evidence, not SAFE. Predictions stay in the browser. REPLAY packs record schema **1.1.0**; new LIVE records schema **1.9.0**. |
| Oct 15 | Eligible. |

A new-tab Academy session auto-adopts the latest durable LIVE pair. The Attack step includes **Use the recorded pair in this tab (REPLAY)** so the presenter can switch this tab to committed packs without deleting the server index.

P1.6 defect fixed (OBSERVED on deployed image `e193f8b3…`, regression-tested, redeployed as `e5dc7f88…`): once any durable LIVE pair existed, every new tab adopted it and both LIVE launch buttons stayed disabled, so the LIVE demo path could not run. The Attack step now offers **Clear this tab and launch a fresh LIVE pair** (tab-only; server evidence untouched). A RETEST slot is only adopted when it belongs to the adopted ATTACK and is not older than it, because the server picks the two slots independently.

---

## 6. Splunk integration

**Classification:** IMPLEMENTED AND VERIFIED

| Field | Value |
|-------|--------|
| Repository path | Collector HEC `https://agentsec_splunk:8088/services/collector/event`; index `agentsec_telemetry`; sourcetype `otel:agentic:json`; app `splunk_app/agentsec/` |
| Tests | Historical Phase 6E / P1.5 searches; P1.6 `scripts/splunk_cli_csv.py` |
| Evidence | `docs/reviews/p1.6-oct15-evidence/gate_f_splunk.json` |
| Deployment | Exclusive `127.0.0.1:8000` and `127.0.0.1:8088`. Isolation PASS (Phase 6E, unchanged). |
| Limitations | Academy status **Splunk indexing = NOT CHECKED**. `hec.ok` on launch JSON is not an ingest proof. Runtime never sends HEC. Splunk is not the PDP. |
| Oct 15 | Eligible. Search the run.id. Do not present HEC health as a verdict. |

MEASURED this phase with `scripts/p1_6_reconcile_live_evidence.py` (evidence `rc_gate_f_reconcile.json`). A run reconciles only when local and Splunk agree on event count, the single distinct decision, `mcp.started` and `pipeline.stopped` counts, and Splunk holds exactly one decision event.

| Run | Provenance | Local / Splunk events | Decision | Reconciled |
|-----|------------|-----------------------|----------|------------|
| `82423ce2-fae2-4adf-a9eb-39dd10f6c97f` | LIVE ATTACK | 7 / 7 | ALLOW | yes |
| `2c4e5738-d845-46f8-98d3-3193956c9876` | LIVE RETEST | 6 / 6 | DENY | yes |
| `de60a91c-8aa0-411f-8731-2d79d760d427` | LIVE ATTACK | 7 / 7 | ALLOW | yes |
| `b8c432ff-6e2e-4cec-a259-78761b50b969` | LIVE RETEST | 6 / 6 | DENY | yes |
| `163d11e2-e751-4282-9406-19b490542ed4` | REPLAY BASELINE | 7 / 7 | ALLOW | yes |
| `5e8f55f3-eb46-47ee-b979-b72d9c9b1f49` | REPLAY ATTACK | 7 / 7 | ALLOW | yes |
| `7a1d37b5-d589-4dfd-8322-25ebd0152dbc` | REPLAY RETEST | 6 / 6 | DENY | yes |

REPLAY rows are indexed copies of past runs (first events 2026-09-12); they are not new measurements of the control.

`stats count by agentsec.control.decision` can show 6 rows on a 7-event run because the decision field is present on multiple events. Teach the Academy decision fact (one ALLOW or DENY), not that count.

---

## 7. Security controls

**Classification:** IMPLEMENTED AND VERIFIED

| Field | Value |
|-------|--------|
| Repository path | CTRL-MCP-001 in AcmeBank MCP authorize; INV-001 |
| Tests | MCP authorization unit/integration suites (existing) |
| Evidence | Vulnerable ATTACK: ALLOW + handler OBSERVED. Defended RETEST: DENY + handler NOT OBSERVED |
| Deployment | Enforced in AcmeBank before the tool handler |
| Limitations | Lab allow-list. Vulnerable profile is intentional fail-open. ALLOW ≠ execution. DENY ≠ proof the handler never ran if the export is incomplete. |
| Oct 15 | Eligible. This is the control under demonstration. |

Preserved: CTRL-MCP-001 policy authority. MCP-005 publication restrictions unchanged. `ws_lab_mcp_001` not modified.

---

## 8. Detection engineering

**Classification:** PARTIAL

| Field | Value |
|-------|--------|
| Repository path | `splunk_app/agentsec/default/savedsearches.conf`; `learning/level_1/LAB-MCP-001/searches/DET-MCP-001.spl`; `docs/learning-notes/detection-engineering-workshop.md` |
| Tests | Packaged SPL review history; searches `disabled = 1` |
| Evidence | DET-MCP-001 disabled, not an ES notable. Q-RUN / Q-DENY are placeholders. |
| Deployment | Knowledge objects exist; they do not fire. |
| Limitations | Silence is not SAFE. ATTACK fail-open ALLOW is out of DET-MCP-001's DENY-then-start condition. |
| Oct 15 | Mention only if asked. Do not enable or publish. |

---

## 9. AI agent forensics

**Classification:** PARTIAL

| Field | Value |
|-------|--------|
| Repository path | `artifacts/<run_id>/events.jsonl`, Academy evidence derivation, Splunk hunt by `agentsec.run.id` |
| Tests | Evidence integrity tests; UUID-gated live index |
| Evidence | Run reconstruction: decision, handler start, schema version, provenance |
| Deployment | Local artifacts + Splunk copy |
| Limitations | Not a case-management product. No chain-of-custody appliance. No memory dump / model-weight forensics. LLM event count on MCP lab is **0** (no model required). |
| Oct 15 | Eligible as “reconstruct this run from events.” Do not claim an AI forensics platform. |

---

## 10. Enterprise telemetry

**Classification:** PARTIAL

See `docs/reviews/AGENTSEC_P1_6_ENTERPRISE_TELEMETRY_MATRIX.md`.

Live AgentSec sources: OTel agentic JSON, scanner finding plane (Cisco mcp-scanner adapter + packs), garak evaluation packs. Not EDR, NDR, IAM, cloud audit, Kubernetes, DLP, or HR feeds.

---

## 11. SIEM vendor coverage

**Classification:** REFERENCE ONLY (non-Splunk); Splunk itself is IMPLEMENTED AND VERIFIED and is listed under Splunk integration.

No Elastic, Microsoft Sentinel, QRadar, Chronicle, CrowdStrike, Palo Alto, or Okta product integration exists in this repository.

---

## 12. Documentation

**Classification:** IMPLEMENTED BUT NOT FULLY VERIFIED

| Audience | Paths |
|----------|--------|
| Learner | `README.md`, `docs/GETTING_STARTED.md`, `docs/QUICKSTART.md`, Academy pages, `learning/level_1/LAB-MCP-001/` |
| Facilitator | `docs/INSTRUCTOR_GUIDE.md`, `docs/demo/AGENTSEC_OCT15_FACILITATOR_GUIDE.md`, `docs/LIVE_VS_REPLAY.md` |
| Operator | `docs/OPERATIONS.md`, `docs/AGENTSEC_ENVIRONMENT.md`, `scripts/lab-up.sh`, `scripts/lab-ready.sh` |

Limitations: later checkpoints have teaching notes but uneven step-by-step completeness. Oct 15 uses the LAB-MCP-001 beginner package (Academy + lab README + Oct 15 demo docs).

---

## 13. Accessibility

**Classification:** IMPLEMENTED BUT NOT FULLY VERIFIED

| Check | Result | Class |
|-------|--------|--------|
| Genuine Chrome zoom 100/200/400% at 1920×1080, plus 1024×768, on deployed `e5dc7f88…` | 0 overflow, clipping or off-screen controls on 5 pages and 9 steps; menu at 400% opens and returns focus | MEASURED P1.6 (`rc_zoom_deployed.json`) |
| axe-core 4.14.0, WCAG 2.0/2.1/2.2 A+AA tags, on deployed build | 0 violations, 0 incomplete on 5 pages and 9 workshop steps | MEASURED P1.6 (`rc_axe_deployed.json`) |
| Skip link, landmarks, one `h1`, visible 3 px focus outline | Present | MEASURED P1.6 |
| Keyboard workshop flow | Covered by Playwright | MEASURED in tests |
| VoiceOver on macOS | **UNTESTED** — needs a system accessibility setting change and a human listener; no verifiable transcript possible from this session | Not fabricated |

Automated checks are not a substitute for screen-reader testing.

---

## 14. Deployment

**Classification:** IMPLEMENTED BUT NOT FULLY VERIFIED

| Field | Value |
|-------|--------|
| Repository path | `docker-compose.yml`, `scripts/lab-up.sh`, `scripts/lab-ready.sh`, `scripts/academy-restart.sh` |
| Tests | `lab-ready.sh` exit 0 on this stack (MEASURED P1.6, `rc_lab_ready.txt`); Attack Service rebuilt and recreated twice with `--no-deps`, Splunk and volumes untouched |
| Evidence | Containers healthy: attack, acmebank, splunk, otel, ollama. Deployed image `sha256:e5dc7f88…`; served `academy.js` / `academy.css` SHA-256 equal the committed files. Durable LIVE index 4 → 6 references across recreates, evidence still loads. |
| Limitations | Clean empty-stack Compose recreate **NOT VERIFIED** (destructive on the working host; not attempted). `scripts/academy-restart.sh` not re-executed in P1.6 (auto-review classifier errors); recreate via `docker compose up -d --no-deps attack_service` was measured instead. `splunk_hec_init` exited 1; HEC health 200. AcmeBank `degraded`: Ollama reachable=false, `llama3.2:1b` absent → model-dependent LIVE labs DEGRADED; LAB-MCP-001 needs no model. |
| Oct 15 | Use the existing stack. `./scripts/lab-ready.sh`. Do not `down -v`. |

---

## 15. Security

**Classification:** IMPLEMENTED AND VERIFIED (for the educational localhost posture)

| Check | Result |
|-------|--------|
| Committed HEC tokens / passwords | Not introduced in P1.6 |
| Academy cannot authorize | GET-only Academy routes; PDP remains AcmeBank |
| TLS skip-verify | Existing lab collector setting; not newly weakened |
| Isolation | Exclusive AgentSec ports; unrelated apps not modified |
| Unauthorized tools | Launch allowlist closed |
| MCP-005 / `ws_lab_mcp_001` | Unchanged |

This is not production authentication, multi-tenant isolation, or internet-facing hardening.

---

## 16. Testing

**Classification:** IMPLEMENTED AND VERIFIED

P1.5 historical reference (not this phase): pytest 1,642 passed, 3 deselected; Playwright 28 passed.

P1.6 MEASURED on the final tree (Python 3.14 `.venv`, macOS, outside the sandbox):

| Command | Result | Exit |
|---------|--------|------|
| `.venv/bin/python -m pytest -q -p no:cacheprovider -p no:logging -rs` | 1648 passed, 3 skipped (Ollama live; two opt-in live Splunk tests) | 0 |
| `pytest tests/integration/test_p1_4_academy_browser.py` × 5 consecutive | 15 passed each run | 0 |

One flaky browser test was found and fixed in the harness, not the assertion: string `wait_for_function` predicates need in-page `eval`, which the Academy CSP forbids whenever polling is required. They were replaced with Playwright `expect(...).to_contain_text`. Skipped tests are not counted as passed. Ruff is not installed in this environment; lint was not run.

---

## 17. ATTACK/RETEST comparison

**Classification:** IMPLEMENTED AND VERIFIED

| Field | Value |
|-------|--------|
| Repository path | `/api/academy/compare` in `src/agentsec/academy_web.py`; Compare step in `workshop_mcp.html` / `academy.js` |
| Tests | `test_compare_*` in `tests/unit/test_p1_4_academy_evidence.py` (recorded differences only, same run twice, swapped roles, mixed LIVE/REPLAY); `test_compare_rejects_unknown_parameters`; `test_full_replay_workflow_with_mouse_matches_the_committed_evidence` |
| Evidence | `rc_rehearsal.json` on deployed build: REPLAY and LIVE both show decision ALLOW→DENY DIFFERENT, `mcp.started` OBSERVED→NOT OBSERVED, `pipeline.stopped` NOT OBSERVED→OBSERVED, LLM 0/0 SAME, events 7/6; 5 OBSERVED and 2 INFERRED claims |
| Limitations | Mixed-mode pairs (LIVE ATTACK + REPLAY RETEST) are refused by design. One pair is not universal assurance. |
| Oct 15 | Eligible. |

## 18. Progress tracking

**Classification:** PARTIAL

| Field | Value |
|-------|--------|
| Repository path | `academy.js` stepper and `sessionStorage` key `agentsec.academy.mcp.v1` |
| Tests | `test_locked_steps_cannot_be_reached_before_their_prerequisites`; `test_full_replay_workflow_with_mouse_matches_the_committed_evidence` (through completion); reload assertions in the fresh-LIVE regression test |
| Evidence | Rehearsal completion OK on the deployed build |
| Limitations | Browser-tab only. No account, no durable or cross-device progress, no certification. Progress persistence is out of Phase 1 scope. Completion is learning state, not a security verdict. |
| Oct 15 | Eligible; say it is local to the tab. |

## 19. Runtime policy enforcement

**Classification:** IMPLEMENTED AND VERIFIED (CTRL-MCP-001 only)

| Field | Value |
|-------|--------|
| Repository path | AcmeBank MCP authorize path; CTRL-MCP-001; security profile is server-owned |
| Tests | MCP authorization suites; launch allowlist security tests |
| Evidence | Fresh LIVE RETEST `2c4e5738-…`: DENY `tool_not_granted`, `agentsec.mcp.started` count 0, `agentsec.pipeline.stopped` count 1, in both local artifact and Splunk — the decision precedes and prevents the handler. ATTACK `82423ce2-…`: ALLOW `vulnerable_profile_fail_open`, handler started (intentional vulnerable profile). |
| Limitations | Lab allow-list, not a production policy engine. Other controls in other labs are not re-verified in P1.6. |
| Oct 15 | Eligible. |

## 20. Agent execution provenance

**Classification:** IMPLEMENTED AND VERIFIED (run-level)

| Field | Value |
|-------|--------|
| Repository path | `agentsec.run.id`, provenance badges (LIVE/REPLAY), `agentsec.schema.version`, durable LIVE index (UUID-gated) |
| Tests | `tests/unit/test_p1_5_academy_live_index.py`; `tests/unit/test_p1_4_academy_evidence.py`; REPLAY badge assertion in `test_recovered_live_pair_can_switch_this_tab_to_replay` |
| Evidence | Every rehearsal card shows run.id + LIVE/REPLAY; REPLAY packs carry schema 1.1.0, new LIVE 1.9.0; Splunk links use exact run epochs |
| Limitations | No cryptographic signing or attestation of events. No delegation-chain or model-identity provenance on this path (0 LLM events). Cosmetic: provenance line reads "LIVE LIVE —". |
| Oct 15 | Eligible. |
