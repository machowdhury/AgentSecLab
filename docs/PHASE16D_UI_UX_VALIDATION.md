# Phase 16D UI / UX validation

**Surfaces changed:** Home, global nav, LIVE workshop CONNECT/Path B copy, REPLAY HUNT banners, capstone MISSION/PROVE, Attack Service academy strip.

**Viewports required:** 1440 / 1280 / 1024. 768 diagnostic.

**Design system:** `docs/AGENTSEC_DESIGN_SYSTEM.md`. PortSwigger is pedagogical inspiration, not a visual template.

---

## Contracts checked in XML/HTML (OBSERVED)

- Home tabs START / ORIENT / PATH / SPLUNK; primary action Direct Prompt Injection.
- No GFM pipe tables in Studio markdown builders.
- Nav human labels; no top-level LAB-* or ws_lab_*.
- Status meaning is textual (LIVE, REPLAY, ALLOW, DENY, OBSERVE), not color alone.
- Attack Service: landmarks, skip link, dt/dd facts, “does not authorize”.
- UUIDs remain in evidence contexts; Home/nav use human titles.
- Path B labeled optional / review key.

---

## Playwright / visual review

**OBSERVED 2026-09-21.** Screenshots: `docs/screenshots/agentsec-academy-16d/pass16d_*.png`. Review: `docs/reviews/ui-review-agentsec-academy-16d-2026-09-21.md`.

Viewports 1440 / 1280 / 1024. Home START/ORIENT/PATH/SPLUNK. Nav Foundations / Context Security / Agent Intent / Capstone. PI HUNT Path A/B. Capstone MISSION Before you start. Attack Service Where you are.

**BLOCKER:** none. **HIGH:** none unresolved.

Platform limitation: Splunk Enterprise navigation chrome, login, and Studio markdown renderer are not fully AgentSec-controlled. WCAG certification is **not** claimed.

---

## Accessibility (owned surfaces)

| Check | Result |
|-------|--------|
| Status meaning textual | OBSERVED (LIVE/REPLAY/ALLOW/DENY/OBSERVE words) |
| Headings | Home/Attack Service h1/h2; Studio uses markdown headings |
| Link labels | Start Learning, Open Splunk Search, lab titles |
| Color not sole meaning | SAME/DIFFERENT remain words on COMPARE (pre-existing) |
| Keyboard | Flask skip-link preserved; Studio depends on Splunk |

---

**Defect classification (pass16d OBSERVED)**

- **BLOCKER** — none
- **HIGH** — none unresolved
- **MEDIUM** — Home START leftover block height; Attack Service length / 1024 two-column facts; Path B still visible after hints; capstone PROVE label clip at 1024
- **LOW** — REPLAY tab still named HUNT; Splunk chrome; ASCII `!=` in Studio inequalities
