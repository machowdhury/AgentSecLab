---
name: ui-review
description: >-
  Review AgentSec learner-facing UI (Dashboard Studio, AcmeBank, Attack Service)
  against the AgentSec UI Design System for visual quality, accessibility, and
  teaching clarity. Use when the user says /ui-review or asks for a UI review
  of a lab dashboard or Flask page.
---

# UI Review

Canonical tokens and rules: `docs/AGENTSEC_DESIGN_SYSTEM.md`.

Do **not** modify UI on the first pass. Write a review, then wait for the task to include fixes (or a follow-up).

## Surfaces

Review only learner-facing AgentSec UI:

- Dashboard Studio views under `splunk_app/agentsec/`
- AcmeBank / Attack Service HTML templates
- Screenshots under `docs/screenshots/` when present

Do not restyle Splunk login or Splunk enterprise chrome.

## Roles (all four)

1. SPLUNK ARCHITECT — tokens exist, searches bound, GRID, no invented fields.
2. SOC ANALYST — can hunt a `run.id` without guessing.
3. UX DESIGNER — reading order, density, overflow, empty states.
4. TECHNICAL INSTRUCTOR — ALLOW ≠ execution; SIMULATED labeled; Splunk does not DENY.

Plus **accessibility:** contrast AA for body, labels, focus (where we control it), not color-only severity, empty not hidden.

## Checks

1. Purpose obvious within 5 seconds.
2. Reading order obvious (tabs / top-to-bottom).
3. Grid alignment consistent.
4. Typography readable (≥ body size; no tiny captions that fail AA).
5. Palette matches `docs/AGENTSEC_DESIGN_SYSTEM.md`.
6. Severity not color alone.
7. Visualizations answer a workshop question.
8. Every dataSource exists; every token exists (Studio).
9. JSON/HTML is valid.
10. Every learner query has an explanation.
11. “What happened?” is telemetry, not invented prose.
12. Empty/no-data states explain themselves.
13. Attack vs defended states are labeled (`testbed.mode`, profile).
14. SIMULATED is labeled SIMULATED.
15. Keyboard/focus and contrast on Flask pages we own.
16. No neon, no extra charts, no MLTK purple on first lab.

## Findings format

Classify each finding: **BLOCKER** / **HIGH** / **MEDIUM** / **LOW**.

Write the report to `docs/reviews/` as `ui-review-<surface>-<date>.md` unless the user names another path.

Include: screenshots used (or “JSON-only”), tokens checked, tabs checked.

Do not fix until the review is written. Then fix only BLOCKER and HIGH unless the user asks otherwise.
