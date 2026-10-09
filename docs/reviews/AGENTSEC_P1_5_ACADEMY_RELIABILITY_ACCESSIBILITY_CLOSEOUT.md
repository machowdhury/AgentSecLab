# AGENTSEC P1.5 — Academy reliability, evidence integrity, and accessibility closeout

**Final verdict: P1.5 CONDITIONAL — FUNCTIONAL WITH REMAINING QUALIFICATION GAPS**

The Figma Academy learner journey is reliable for a 15 October 2026 demonstration: REPLAY and fresh LIVE ATTACK/RETEST complete, notebook state survives Attack Service restart, fresh LIVE telemetry is independently searchable in Splunk, and genuine Chrome zoom at 100/200/400% passed. VoiceOver was **not** executed (UNTESTED). Historical P1.4 LIVE run IDs remain unindexed and were not replayed as original events. A true empty-stack Compose recreate was not performed.

Infrastructure isolation: **PASS.** AgentSec Splunk stayed on exclusive `127.0.0.1:8000` and `127.0.0.1:8088`. Unrelated host applications were not stopped or reconfigured. Phase 6D leftover containers were not touched. `ws_lab_mcp_001` was not modified. MCP-005 publication restrictions remain in place.

---

## 1. Executive summary

P1.4 left a working nine-step LAB-MCP-001 Academy with four operational gaps: LIVE HEC/Splunk integrity, notebook loss after Attack Service restart, genuine Chrome zoom, and Compose startup. P1.5 closed the first three for **new** runs and measured zoom with `chrome.tabs.setZoom`. Screen-reader qualification did not run. Clean Compose from empty remains **NOT FULLY VERIFIED**.

`hec.ok=false` on launch responses is **not** a HEC send from AcmeBank. The runtime never attempts HEC (`hec.attempted=false`); OTLP flush is the only runtime export. Collector HEC to `http://splunk:8088` failed two independent ways: the compose service hostname `splunk` does not resolve on this mesh (`aliases=[]`), and published HEC is TLS (HTTP is reset by peer). After pointing the collector at `https://agentsec_splunk:8088/services/collector/event`, a fresh LIVE pair indexed 7 + 6 events matching local records.

Academy status reports Optional model (Ollama) as **DEGRADED**, not FAILED. MCP tool-path launches do not require the model.

## 2. Starting and final SHAs

| Item | Value |
|------|--------|
| Expected starting HEAD | `99ee64af9a213bb1dc8656455016e66a9241c631` |
| Measured starting HEAD | `99ee64af9a213bb1dc8656455016e66a9241c631` = `origin/develop` |
| Working tree at start | clean, 0/0 |
| Implementation / report commit | recorded after this file is committed (see git log on `develop`) |
| Runtime schema | **1.9.0** |
| ExternalEvidence | **1.0.0**, applicable=false for LAB-MCP-001 |

## 3. Deployment and service status

Measured 2026-10-09 after collector recreate, Attack Service rebuild, and Attack Service restart.

| Service | Status | Ports |
|---------|--------|--------|
| `agentsec_attack_service` | healthy | `127.0.0.1:5001` |
| `agentsec_acmebank` | healthy (runtime `degraded` because model catalog empty) | `127.0.0.1:5000` |
| `agentsec_splunk` | healthy | `127.0.0.1:8000`, `127.0.0.1:8088` |
| `agentsec_otel_collector` | running | `127.0.0.1:4317-4318` |
| `agentsec_ollama` | healthy, **no models listed** | unpublished |
| `agentsec_splunk_hec_init` | `exited 1` (historical). Not recreated. | — |

Academy `http://127.0.0.1:5001/academy` HTTP 200. Attack Service image rebuilt from this tree (`agentseclab-attack_service` digest `sha256:a74b52e02d133fe184edfa608cf07e3a369728d0dcf4bc4433f8ecd77972302f` at build time). Disk free: 502 GiB. Splunk `etc`/`var` volumes were not rotated.

`./scripts/lab-ready.sh` exit 0 against this running stack after the HEC URL fix (MODEL ABSENT logged as DEGRADED).

## 4. HEC failure root cause (MEASURED)

Class: **transport / destination**, not payload rejection, not token logging, not a runtime HEC client.

1. **Reporting semantics.** AcmeBank `export.json` always records `hec.attempted=false`, `hec.ok=false`. `otlp.ok` means SDK emit+flush only. Runtime never observes collector HEC or Splunk indexing.
2. **DNS.** Collector env was `SPLUNK_HEC_ENDPOINT=http://splunk:8088/services/collector/event`. From AcmeBank on the same mesh, `splunk` → `Name or service not known`. `agentsec_splunk` → `172.18.0.2`. Splunk container `aliases=[]`.
3. **TLS vs HTTP.** `http://agentsec_splunk:8088/services/collector/health` → connection reset. `https://agentsec_splunk:8088/services/collector/health` → HTTP 200 `{"text":"HEC is healthy","code":17}`.
4. **Timing for P1.4 IDs.** Collector current process started `2026-10-09T17:02:39Z`. P1.4 ATTACK timestamp `2026-10-09T16:46:11Z`. Those events were not in the collector file archive (file exporter is not on the logs pipeline).

Corrective change (authorized, smallest): default and local lab HEC URL `https://agentsec_splunk:8088/services/collector/event`. Existing `SPLUNK_HEC_TLS_SKIP_VERIFY=true` was **not** newly introduced. TLS was not weakened relative to the prior HTTP attempt. Certificates were not rotated.

`hec.ok` on launch JSON remains false by design. The notebook does not treat it as Splunk confirmation. Status “Splunk indexing” remains **NOT CHECKED**. Independent Splunk search is the indexing proof.

## 5. Historical run-ID reconciliation

Index `agentsec_telemetry`, sourcetype `otel:agentic:json`, `earliest=0`, helper `scripts/splunk_cli_csv.py`. Query time in `docs/reviews/p1.5-academy-closeout-evidence/gate_a_historical_splunk.json` and `gate_a_fresh_splunk.json`.

| Run | Role | Local events.jsonl | Splunk `stats count` | Notes |
|-----|------|--------------------|----------------------|--------|
| `4eab6700-f6c8-4979-b1e3-eb545a04ca5c` | P1.4 LIVE ATTACK | 7 | **0** | Original live events; not replayed |
| `2343f9e1-a48e-45ed-886d-262ab321ad8f` | P1.4 LIVE RETEST | 6 | **0** | Original live events; not replayed |
| `5e8f55f3-eb46-47ee-b979-b72d9c9b1f49` | REPLAY ATTACK pack | 7 | 7 | Control that search works |
| `373bcc54-75bc-4923-bc0d-f6d14d35b1bb` | P1.5 LIVE ATTACK | 7 | 7 | Fresh after HEC URL fix |
| `9cb93b54-b8d1-4194-8bef-d34c21d9dab0` | P1.5 LIVE RETEST | 6 | 6 | Fresh after HEC URL fix |

Local SHA-256 of `events.jsonl` (unchanged after Attack Service restart):

| Run | SHA-256 |
|-----|---------|
| `4eab6700-…` | `ee381d9b1713b969f4e502b52e7cd429fce5d040cc3474d580e7d9dd0ba742ae` |
| `2343f9e1-…` | `7f785cddf9b9e55a6517f11b6a1e23a1332d1e05bd003fbe0c31c4bbeb49f9fc` |
| `373bcc54-…` | `0239d8eb8baad2136be5a7c1508dfabdca112446313ed9a682465b1c90090c3f` |
| `9cb93b54-…` | `4b3f8237e85685a897f5116368508cb955b7d3a3dffd6ab8e0bd4afe799bd6fa` |

Field-split `stats count by event.name` can show duplicate extractions; cardinality used for reconciliation is `stats count as n` vs line count of `events.jsonl`.

No recovery ingestion of the P1.4 IDs was performed.

## 6. Fresh LIVE evidence reconciliation

Launched via closed `POST /api/launch` (`lab_id=LAB-MCP-001`, `specimen_id=MCP-002`, `execution=live`).

| | ATTACK | RETEST |
|--|--------|--------|
| run.id | `373bcc54-75bc-4923-bc0d-f6d14d35b1bb` | `9cb93b54-b8d1-4194-8bef-d34c21d9dab0` |
| profile | vulnerable | defended |
| schema | 1.9.0 | 1.9.0 |
| CTRL-MCP-001 | ALLOW | DENY |
| handler | OBSERVED | NOT OBSERVED |
| LLM events | 0 | 0 |
| local events | 7 | 6 |
| Splunk events | 7 | 6 |
| launch `otlp.ok` | true | true |
| launch `hec.ok` | false (runtime never sets) | false |

Compare API after restart: decision DIFFERENT ALLOW vs DENY; handler OBSERVED vs NOT OBSERVED; LLM 0 vs 0. Academy provenance is LIVE and states the local record does not prove Splunk indexing. Splunk search independently confirmed indexing.

## 7. Notebook restart persistence

Durable index: `artifacts/academy_live_index.json` plus per-run `academy_ref.json`. UUID-gated. No credentials. Duplicate `run_id` replaces in place. Missing/incomplete event records are explicit.

Test: launch pair → `GET /api/academy/live-runs` shows both slots → `docker restart agentsec_attack_service` only → Academy HTTP 200 → same slots → evidence and compare APIs return the same LIVE facts → four `events.jsonl` checksums **UNCHANGED**.

Browser `sessionStorage` is no longer the only history source. `GET /api/academy/live-runs` rehydrates empty workshop state from the index.

## 8. Genuine browser zoom

**Method:** Playwright Chromium **151.0.7922.34** + MV3 helper `tests/support/chrome_zoom_extension` calling `chrome.tabs.setZoom`. OS: macOS 27.0. Viewport 1440×900 at setZoom 1.0 / 2.0 / 4.0. This is not CSS scaling and not a resized viewport.

| Surface | 100% | 200% | 400% |
|---------|------|------|------|
| Academy Home | PASS | PASS | PASS |
| Foundations | PASS | PASS | PASS |
| Learning Path | PASS | PASS | PASS |
| System Status | PASS | PASS | PASS |
| Workshop navigation / Predict / REPLAY ATTACK / notebook | PASS | PASS | PASS |

Suite: `tests/integration/test_p1_5_academy_chrome_zoom.py` **16 passed**. P1.4 viewport suite still **12 passed**. Tests skip (UNTESTED) if the extension cannot set zoom; they did not skip.

## 9. Screen-reader results

**UNTESTED.** `/System/Library/CoreServices/VoiceOver.app` is present. No VoiceOver process was running. VoiceOver was not enabled (would speak on the operator Mac without a captured AT session). Automated AX/ARIA checks and Playwright remain supplementary only. ARIA landmarks, skip link, labelled controls, and status badges with text (not color alone) are present in markup; that is not a screen-reader PASS.

## 10. Compose startup findings

P1.4 30-minute failure: `splunk_hec_init` looping on HTTP HEC to hostname `splunk`, then Compose referencing an AcmeBank container that had already been replaced. `splunk_hec_init` is still `exited 1` on this host.

Applied without recreating Splunk:

- Collector HEC URL `https://agentsec_splunk:8088/...`
- `lab-up.sh`: if Splunk is already healthy, start app services with `--no-recreate` and do not recreate Splunk
- `lab-ready.sh`: HEC health over HTTPS; do not fail the whole ready check solely because the oneshot init container is `exited 1` when HEC health is 200
- `scripts/academy-restart.sh`: Attack Service only

`./scripts/lab-ready.sh` **exit 0** on the running stack. A true `docker compose down` (even without `-v`) was **not** executed. **Clean start from empty: NOT FULLY VERIFIED.**

## 11. Optional service health

Ollama answers `/api/tags` with `"models": []`. `OllamaClient.health()` requires the configured label `llama3.2:1b` in that catalog, so `ollama_reachable=false` and AcmeBank `/health` is `degraded`.

This is an **optional AI enrichment** dependency, not a misconfigured MCP path and not a functional blocker for LAB-MCP-001. Academy adds check **Optional model (Ollama) = DEGRADED**. AcmeBank runtime remains AVAILABLE when status is `healthy` or `degraded`. No model was downloaded. No paid inference was used.

## 12. Regression and browser tests

Newly measured (not the P1.4 historical 1617):

| Suite | Result |
|-------|--------|
| `uv run --extra test python -m pytest tests -q -m "not live_ollama and not live_splunk"` | **1642 passed, 3 deselected** |
| P1.4 Playwright Academy | **12 passed** |
| P1.5 genuine zoom Playwright | **16 passed** |
| Live Academy REPLAY compare | ALLOW vs DENY, handler OBSERVED vs NOT OBSERVED |
| Live Academy LIVE compare (after restart) | same shape, schema 1.9.0, 0 LLM events |

The three deselected tests are the existing live_ollama / live_splunk markers.

## 13. Security and evidence-integrity review

| Check | Result |
|-------|--------|
| Credentials / HEC token committed | No. `.env` not committed. `.env.example` still has the pre-existing lab default token string; only the HEC **URL** changed |
| Browser-exposed secrets | No. Academy CSP unchanged. Launch body still closed JSON without prediction |
| TLS verification weakened | No. Collector already skipped verify; destination changed HTTP→HTTPS |
| Fabricated telemetry | No. Historical P1.4 IDs left at Splunk count 0 |
| Silent replay/live substitution | No. Provenance badges unchanged |
| Unauthorized policy changes | No. CTRL-MCP-001 remains the PDP |
| Destructive evidence modifications | No. Checksums unchanged across restart |
| Unrelated workloads | No. Splunk ports unchanged. Phase 6D leftover containers untouched |
| Speculative SPL published | No |
| MCP-005 restrictions | Unchanged. Workshop still states it does not publish MCP-005 detections |
| Schema | Runtime 1.9.0, ExternalEvidence 1.0.0 applicable false |

Workspace rules applied: no new hardcoded credentials; no embedded certificates; no banned crypto algorithms.

## 14. Evidence paths and SHA-256

Under `docs/reviews/p1.5-academy-closeout-evidence/` (see `SHA256SUMS` in that directory):

- `gate_a_historical_splunk.json` — P1.4 IDs, SPL, counts
- `gate_a_fresh_launch.json` / `gate_a_fresh_splunk.json` — fresh pair
- `gate_b_checksums_before.json` / `gate_b_after_restart.json`
- `gate_d_lab_ready.txt`

Artifact checksums are in section 5. Artifacts themselves are not committed (`artifacts/*`).

## 15. Known limitations and blockers

1. **VoiceOver / NVDA UNTESTED.** Blocks P1.5 PASS.
2. **P1.4 LIVE run IDs are not in Splunk.** Local records remain. Not replayed.
3. **Clean Compose from empty NOT FULLY VERIFIED.**
4. **Ollama model absent.** DEGRADED for LLM enrichment only.
5. **Launch JSON `hec.ok=false`** even when Splunk search succeeds. Honest runtime semantics; do not read it as indexing.
6. **Dashboard Studio at 400% zoom** remains the P1.3 limitation; Academy notebook is the accessible primary path.
7. **`splunk_hec_init` still exited 1.** HEC is healthy; oneshot was not re-run.

## 16. October 15 readiness

**Demo-ready with conditions.** A facilitator can run the nine-step Academy in REPLAY or LIVE, show Splunk searches for the **P1.5** LIVE IDs, restart Attack Service without losing notebook run references, and zoom Chrome to 400%. Do not claim P1.4 LIVE IDs are indexed. Do not claim VoiceOver qualification. Do not claim a from-scratch Compose wipe was proven.

Recommended before a scored accessibility audit: a human VoiceOver pass on the core beginner journey.

---

## Gate rollup

| Gate | Result |
|------|--------|
| 0 Baseline / isolation | PASS |
| A LIVE HEC/Splunk (fresh) | PASS (historical IDs still 0) |
| B Durable notebook | PASS |
| C Genuine Chrome zoom | PASS |
| C Screen reader | **UNTESTED** |
| D Compose startup | PARTIAL — lab-ready 0 on running stack; clean empty start NOT FULLY VERIFIED |
| E Optional Ollama | DEGRADED as designed |
| F E2E + pytest | PASS (1642 passed, 3 deselected; 28 Playwright) |
| G Security / integrity | PASS |
| H Git / report | this document |

**P1.5 CONDITIONAL — FUNCTIONAL WITH REMAINING QUALIFICATION GAPS**
