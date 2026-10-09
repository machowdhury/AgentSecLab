# AGENTSEC P1.4 — Figma Academy final qualification

**Executive decision: CONDITIONAL — FUNCTIONAL WITH DOCUMENTED LIMITATIONS**

The AgentSec Academy on the Attack Service is the primary beginner path for LAB-MCP-001. A learner can complete START → BASELINE → PREDICT → ATTACK → INVESTIGATE → DEFEND → RETEST → COMPARE → EXPLAIN against real REPLAY packs and against LIVE runs this service launched. Splunk remains investigation infrastructure, not a policy decision point. MCP-005 detections were not published.

**Infrastructure isolation: PASS.** AgentSec Splunk stayed on exclusive `127.0.0.1:8000` and `127.0.0.1:8088`. Unrelated host applications were not stopped or reconfigured.

---

## 1. Executive summary

P1.4 was already implemented at `f4f4807`. This qualification confirmed that commit was not sufficient by itself: Attack Service and AcmeBank were not running. They were started without recreating Splunk. Provenance labels, UNAVAILABLE error states, launch timeout, Splunk reachability (not indexing), ExternalEvidence non-applicability, and the MCP-005 publication boundary were added and measured.

Required accessibility gates that need a human or Chrome zoom-extension session remain **UNTESTED**. Viewport stand-ins at 1920, 1024, 320, and 480×270 CSS px passed with no horizontal overflow and no clipped essential content.

## 2. SHAs

| Item | Value |
|------|--------|
| Starting SHA (expected 6E HEAD) | `31965386767eb5a41f24a19555dbb3d64803119b` |
| Known P1.4 implementation | `f4f4807` |
| Local concurrent checkpoint already on develop | `10682b88f344b17505f08f217977ba96428702a0` |
| Implementation SHA | `aff4468aef45af6f484bd64ad933bbe12dadf867` |
| Final report SHA | `e9a9e7e1cf5b6558d0ad7bad0988e8829aa6b6f3` |
| Final remote SHA | `e9a9e7e1cf5b6558d0ad7bad0988e8829aa6b6f3` (`develop` = `origin/develop`) |
| Deployed Attack Service | image `sha256:a0873455016c48f31835a06d796c6691e1345bfbcae70f175085a1ad5c89c02c` built from `aff4468` source |
| Deployed Splunk | original `agentsec_splunk`, healthy, ports unchanged |

Working tree at start of this assignment: `develop` at `3196538`, untracked `.tmp-path-pre/` and `docs/learning-notes/figma-academy.md` (later committed by the owner checkpoint `10682b8`; not modified by this qualification beyond leaving them alone).

## 3. Feature inventory (verified)

| Feature | Existing | Functional | Backend-connected | Accessible | Tested | Class |
|---|---|---|---|---|---|---|
| Academy Home | Yes | Yes | Status API | Landmarks, skip link, 44px actions | Unit + live screenshot | COMPLETE |
| Learning Paths | Yes | Yes | Curriculum JSON | Reflow at 320 CSS px | Unit + live screenshot | COMPLETE |
| MCP Workshop | Yes | Yes | LAB-MCP-001 only | Step briefs + keyboard gating | Browser REPLAY workflow | COMPLETE |
| Attack Workbench | Yes | Yes | Closed `POST /api/launch` | Busy/disabled while launching | LIVE launch MEASURED | COMPLETE |
| Evidence Notebook | Yes | Yes | `/api/academy/evidence/<run_id>` | Tables get explicit roles | REPLAY + LIVE documents | COMPLETE |
| ATTACK/RETEST Compare | Yes | Yes | `/api/academy/compare` | Card-table reflow | REPLAY workflow + LIVE compare | COMPLETE |
| Progress Tracking | Yes | Yes | Browser localStorage only | Reset control labelled | Browser workflow | COMPLETE |
| System Status | Yes | Yes | Attack, AcmeBank, packs, artifacts, Splunk Web | Status text not color-only | Live `/api/academy/status` | COMPLETE |

Figma React prototype screens are **not** shipped. Demo values such as `5ff6c21f`, `LLM calls 4`, and `Today, 09:42` are absent (security test).

Other curriculum labs remain Attack Service or Splunk links and are **not tracked** in Academy progress. That is PARTIAL relative to the Figma “whole catalog inside one app” mock, and intentional.

## 4. Figma design mapping

Source: `docs/design/FIGMA_V2_PRODUCTION_MAPPING.md` and the P1.4 Flask port (`academy.css` navy/teal/8px radius/card layout).

| Design | Production |
|--------|------------|
| React/Vite in-memory app | Flask + one CSS + one JS, strict CSP |
| Hard-coded metrics | Facts from REPLAY packs or LIVE `events.jsonl` |
| Manrope via CDN | System font stack (`Manrope` named, not loaded) — accessibility over pixel match |
| Studio as primary notebook | Academy notebook is primary; Studio is advanced/optional (P1.3) |

Deviations preserve functionality and accessibility. Conflict priority remains REAL EVIDENCE > FIGMA UX.

## 5. Real backend integration

| Capability | Result | Class |
|------------|--------|--------|
| Launch LAB-MCP-001 | LIVE ATTACK `4eab6700-f6c8-4979-b1e3-eb545a04ca5c` schema **1.9.0**, ALLOW, `mcp.started` OBSERVED, 7 events, 0 LLM events | MEASURED |
| LIVE RETEST | `2343f9e1-a48e-45ed-886d-262ab321ad8f` schema **1.9.0**, defended, `completed_denied`, handler count 0 | MEASURED |
| Compare | ALLOW vs DENY; handler OBSERVED vs NOT OBSERVED | MEASURED |
| REPLAY Splunk | BASELINE 7, ATTACK 7, RETEST 6 events in `agentsec_telemetry` | MEASURED |
| Splunk search links | `index=agentsec_telemetry sourcetype=otel:agentic:json` plus run.id and epoch bounds | MEASURED |
| ExternalEvidence 1.0.0 | Documented **not applicable** to LAB-MCP-001 runtime telemetry | MEASURED |
| LIVE vs REPLAY vs UNAVAILABLE | Badged; SYNTHETIC never returned for this lab | MEASURED |
| HEC for the new LIVE ATTACK | `hec.ok=false`, `otlp.ok=true`, `splunk_verified=false` | MEASURED |
| Credentials in browser | None. HEC token not sent to the page | MEASURED |

CTRL-MCP-001 remains the only PDP. After Attack Service recreate, in-memory launcher records for those LIVE ids are gone; disk artifacts remain. That is UNAVAILABLE in the notebook until relaunch, not a fabricated result.

## 6. Accessibility

| Gate | Result |
|------|--------|
| 1920×1080 | PASS, overflowX 0, clipped [] |
| 1024×768 | PASS |
| 320 CSS px | PASS |
| 200% stand-in (960×540) | PASS (viewport stand-in, not `chrome.tabs.setZoom`) |
| 400% stand-in (480×270) | PASS (viewport stand-in, not `chrome.tabs.setZoom`) |
| Genuine 100/200/400% Chrome zoom | **UNTESTED** (extension is in-repo; headed `chrome.tabs.setZoom` session was not completed) |
| Mouse REPLAY workflow | PASS |
| Keyboard skip-link, prediction, focus, Escape menu | PASS (Playwright) |
| Screen reader | **UNTESTED** (ARIA present; not VoiceOver/NVDA) |
| Form labels / errors | PASS for Predict and notebook questions |
| `ws_lab_mcp_001` | Unchanged |

## 7. End-to-end scenarios

**A — Beginner completes the lab (REPLAY):** PASS. `qualification.json` `workflow.complete=true`. Run IDs `5e8f55f3-…` / `7a1d37b5-…`.

**B — Evidence integrity:** PASS for measured runs. No LLM events invented. LIVE and REPLAY not mixed in the successful compare. Splunk index/sourcetype correct. Live Splunk count of the new LIVE ids was **NOT CHECKED** (`hec.ok=false`).

**C — Failure handling:** PASS for launch ERROR (mocked 502), unknown run UNAVAILABLE, unknown lab 404, 45s abort copy, degraded AcmeBank reported AVAILABLE with model=false, Splunk indexing remains NOT CHECKED.

**D — Accessibility:** PASS for mouse/keyboard and viewport stand-ins. UNTESTED for screen reader and genuine browser zoom.

## 8. Tests (MEASURED this assignment)

| Suite | Result |
|--------|--------|
| Focused Academy unit/security | 88 passed, then 56 including browser after Chromium install |
| Playwright Academy | **12 passed** (previously skipped without Chromium) |
| Full `pytest -q` after isolation fix | **1617 passed, 3 skipped** |

Do not treat Phase 6E’s 1602/15 as this qualification.

## 9. Security validation

- Academy routes GET-only; launch is the existing closed POST body.
- CSP `script-src 'self'`; no inline script/style; `textContent` only.
- Unlaunched LIVE ids refused.
- No `agent.super_secret_field`, no `Q-MCP-RESULT-AUTHORITY`, no new MCP-005 publication claim.
- No credentials committed. `.env` unread in this report.

Certificate/TLS: Splunk leaf and HEC material were not rotated. Compose `splunk_hec_init` ran as a dependency of the local overlay and attempted HEC SSL disable; Splunk Web remained healthy on the existing ports. This qualification did not change certificate files.

## 10. Known limitations

1. Genuine Chrome zoom and screen-reader use are UNTESTED.
2. New LIVE runs are bound to the current Attack Service process; restart → notebook UNAVAILABLE for those ids (Splunk may still hold them if indexed).
3. AcmeBank health is **degraded** (`ollama_reachable=false` even though `http://ollama:11434/api/tags` returned 200 from the container). MCP tool-path LIVE still ran.
4. `hec.ok=false` on the measured LIVE ATTACK. Local evidence is LIVE; Splunk indexing of that id is not proven.
5. Only LAB-MCP-001 is an Academy workshop. Other labs are linked, not redesigned.
6. Figma pixel-fidelity and React runtime were not adopted.
7. `splunk` DNS alias is empty on the recovered Splunk container; reachability uses `agentsec_splunk:8000`.

## 11. Evidence archive

`docs/reviews/p1.4-figma-academy-evidence/`

`SHA256SUMS.json` digest `01f2a8eefe5f4d9eeb8c81c0be8e26661c31b357401161f53047163868fca5a0`.

PNG screenshots remain gitignored under `artifacts/p1.4-figma-academy-20261009/screenshots/`; hashes are in `screenshot_sha256.json`.

## 12. Outstanding work

- Headed `chrome.tabs.setZoom` 100/200/400% pass on 1920×1080.
- Assistive-technology review (UNTESTED).
- Owner decision whether to pull the named Ollama model so AcmeBank reports healthy.
- Owner decision on HEC SSL after `splunk_hec_init` (do not treat as P1.4 PDP work).
- Do not publish MCP-005 hunts or dashboards.

## 13. Demo walkthrough

1. Open `http://127.0.0.1:5001/academy`.
2. Optional: AI & Agent Foundations.
3. Open MCP Tool Authorization.
4. Load the recorded baseline; lock a prediction; use recorded ATTACK; investigate; read Defend; use recorded RETEST; compare; write an explanation; mark complete.
5. Advanced: Splunk Search link on the run card. Studio is optional and not required to finish.
6. LIVE: Launch ATTACK then RETEST only if AcmeBank is reachable. Expect schema 1.9.0 local evidence. Do not claim Splunk indexed it unless you search that run.id.

## 14. October 15 readiness

The beginner Academy journey is **demonstrable now** on this host. Qualification is **CONDITIONAL** until genuine zoom and screen-reader testing are done. That is enough for an owner demo of LAB-MCP-001. It is not a claim of formal accessibility conformance or of new MCP-005 publication.

## 15. Publication boundary

**DO NOT PUBLISH** additional MCP-005 SPL, dashboards, or validation-date changes. Historical hunt date remains 2026-09-13. `ws_lab_mcp_001` unchanged.

---

Workspace security rules applied: no credentials, tokens, or private keys were written into the repo. X.509 material was not rotated; existing Splunk certificates remain the Phase 6E inspected set (RSA-2048, SHA-256, lab self-signed DP certs). No banned cryptographic algorithms were added.
