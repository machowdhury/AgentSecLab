# UI review — LAB-PI-001 Phase 14C guided investigation

**Date:** 2026-09-19  
**Surface:** Dashboard Studio `ws_lab_pi_001` + Attack Service `http://127.0.0.1:5001/`  
**Method:** Playwright 1440 / 1280 / 1024. Screenshots under `docs/screenshots/lab-pi-001/pass2_*.png`.  
**Tokens checked:** Investigate specimen (`run_id`) — Baseline — defended / normal.  
**Tabs checked:** LEARN → PROVE (10/10).

Pass 1 (same day) found Path B overlap (HIGH) and Attack Service browser `/health` using a Docker hostname / cross-origin fetch (HIGH). Pass 2 is after stacked-notebook HUNT + `GET /api/target-health`.

## Pass 2 findings

| ID | Sev | Finding |
|----|-----|---------|
| P2-1 | **FIXED (was HIGH)** | Path B no longer covers Path A. HUNT is sequential: question → Hint 1 → Hint 2 → Solution SPL. OBSERVED `pass2_hunt_try.png`, `pass2_hunt_solution.png`. |
| P2-2 | **FIXED (was HIGH)** | Attack Service shows `AcmeBank security.profile=defended` via same-origin `/api/target-health`. `pass2_attack_service.png`. LIVE RETEST remains disabled. Probe button stays hidden until a run.id exists. |
| P2-3 | MEDIUM | Canonical REPLAY ids are not on this Splunk volume. COMPARE / Path B tables show Studio’s “No search results returned” graphic. Markdown already teaches empty ≠ DENY / ≠ SAFE. Live 14C ids are hunted in Search. |
| P2-4 | MEDIUM | Investigate specimen ellipsizes the UUID. Full ids remain on LEARN / ATTACK / PROVE. |
| P2-5 | MEDIUM | At 1024, LEARN’s last specimen line is below the fold / clipped in the first canvas. Schema **1.9.0**, Splunk ≠ enforcement, and the SOURCE → TELEMETRY ladder remain visible. |
| P2-6 | LOW | HUNT intro documents the Studio hide/show limitation (required honesty). Not a filename dump. |
| P2-7 | LOW | Dashboard description in Studio chrome is clipped. Known chrome. |

No BLOCKER. No remaining HIGH. No pipe-table rendering. No raw view names as learner navigation. No fake RETEST.

### Accessibility (observed)

- Status is in TEXT (LIVE EVIDENCE, DENY, ALLOW, EVIDENCE READY words, LIVE RETEST — not available), not color alone.
- Large Studio markdown. Navy/white.
- Attack Service skip link + `lang="en"`.
- Empty tables remain visible (Studio graphic is a UI limitation, not a SAFE verdict).

### Instructor / SOC checks (observed)

- Path A tells the learner to construct Search from a fresh run.id.
- Path B copyable `Q-RUN-EVENTS` with stage teaching in the solution cell.
- Splunk does **not** ALLOW or DENY (LEARN + workshop description).
- BASELINE is not labeled SAFE.
- Connect the concepts is on PROVE.

### Security-semantics review (observed)

The UI does **not** claim: Splunk blocked the attack; DENY alone proves non-execution; missing event = blocked; HEC success = EVIDENCE READY; BASELINE = safe; LIVE RETEST is available; Attack Service authorizes.
