# UI review — Phase 14E (PI-001 PROVE closure + MCP-001 second reference)

**Date:** 2026-09-19  
**Surface:** Home, `ws_lab_pi_001` PROVE/HUNT, `ws_lab_mcp_001` LEARN→PROVE, Attack Service PI + MCP  
**Method:** Playwright 1440 / 1280 / 1024. Screenshots under `docs/screenshots/lab-pi-001/pass2_prove_*.png`, `docs/screenshots/lab-mcp-001/pass2_*.png`, `docs/screenshots/attack-service-mcp/pass2_viewport_1440.png`, `docs/screenshots/agentsec-home/pass2_home_*.png`.  
**Tokens checked:** Investigate specimen (`run_id`) — Baseline — defended / normal.  
**Tabs checked:** PI 10/10; MCP 10/10. HTTP: Home/PI/MCP/Attack 200; unknown Attack lab 400.

Pass 1 found MCP LEARN trust-path below the 1100px first screen (HIGH). Pass 2 reordered LEARN so the authorization diagram is above the fold.

## Pass 2 findings

| ID | Sev | Finding |
|----|-----|---------|
| P2-1 | **FIXED (was HIGH)** | MCP LEARN trust path (USER/AGENT → CTRL-MCP-001 → HANDLER → SPLUNK) is fully visible at 1440 and 1024. `pass2_learn.png`, `pass2_w1024_learn.png`. |
| P2-2 | **FIXED (was HIGH, 14D leftover)** | PI PROVE at 1440/1280/1024 shows Limitations heading and connect-the-concepts ladder. No clipped critical PROVE teaching. |
| P2-3 | MEDIUM | Investigate specimen ellipsizes the UUID. Canonical ids remain in LEARN Evidence identity. |
| P2-4 | MEDIUM | COMPARE three-column tables wrap UUIDs and reason text. Teaching markdown above the tables is complete. |
| P2-5 | MEDIUM | HUNT first screen shows Investigation 1 Path A + hints. Investigations 2–5 and Path B solution require scrolling the Studio canvas (stacked notebook, same as PI). |
| P2-6 | MEDIUM | Canonical REPLAY ids are on this volume for MCP; empty DETECT left table is 0-row hunt (honest), not SAFE. |
| P2-7 | LOW | Studio chrome description clips at 1024 (`WS-MCP-001 Dashboard Studio workshop…`). Known chrome. |
| P2-8 | LOW | Attack Service first viewport cuts the last prediction `dd` until the learner scrolls. Human title **Tool Authorization** is in the header; lab switch uses human names. |

No BLOCKER. No remaining HIGH. No pipe-table rendering. No raw view names as learner navigation. No fake LIVE.

### Accessibility (observed)

- Status is in TEXT (LIVE EVIDENCE, DENY, ALLOW, INTENTIONALLY VULNERABLE, SAME/DIFFERENT badges with words).
- Large Studio markdown. Navy/white Flask tokens.
- Attack Service skip link + `lang="en"`.
- Empty tables remain visible (Studio graphic is a UI limitation, not a SAFE verdict).

### Instructor / SOC checks (observed)

- Path A: security question, starter index/sourcetype/`run.id`, Open Splunk Search.
- Path B: Hint 1 / Hint 2 / solution SPL from existing Q-MCP-* (stacked, not overlapping).
- Splunk does **not** ALLOW or DENY (LEARN + DETECT).
- ATTACK != ALERT and 0 detection rows != SAFE are on DETECT.
- Attack Service requires prediction cards before launch buttons (teaching, not a scored gate).

### Security-semantics review (observed)

The UI does **not** claim: Splunk blocked the tool; DENY alone proves non-execution; missing event = blocked; HEC success = EVIDENCE READY; BASELINE = safe; Attack Service authorizes; learning metadata is policy.
