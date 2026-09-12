# Phase 2C.4 AgentSec Web UI professionalization

**Date:** 2026-09-11  
**Status:** Evidence closed for COMPLETED + keyboard check. **Not tagged** in `docs/IMPLEMENTATION_STATUS.md` (do not auto-tag).  
**Schema:** `agentsec.security_event` 1.0.0 — unchanged  
**SPL:** unchanged  
**ATK-002 / CTRL-INPUT-001:** unchanged

Parent tokens: `docs/AGENTSEC_DESIGN_SYSTEM.md`.

## COMPLETED run (LIVE)

| Field | Value | Class |
|-------|--------|-------|
| `run.id` | `fc7c5e9a-9078-459c-8a1b-488b740176aa` | OBSERVED UI / MEASURED API |
| UI states | READY → RUNNING → COMPLETED | OBSERVED |
| `GET /api/v1/runs/…` | 22 events; 4 `control.decision=ALLOW`; 4 `llm.started`; 4 `llm.completed`; `agentsec.outcome=completed_allowed`; `testbed.mode=BASELINE` | MEASURED |
| Ollama | Host fallback `OLLAMA_BASE_URL=http://host.docker.internal:11434`, model `llama3.2:1b`. Docker Ollama had **no** pulled model. `/health` `ollama_reachable=true` before the run. | OBSERVED |
| Screenshot | `docs/screenshots/acmebank/pass2_completed.png` | OBSERVED |
| ALLOW as execution | UI says started ≠ approved. Control ALLOW and `llm.started` remain distinct in events (`operation.executed` true only on `llm.started`). | OBSERVED / MEASURED |

No stubbed model. No fabricated COMPLETED.

## Keyboard accessibility

**MEASURED** Playwright Tab/Enter on Chromium: `docs/screenshots/web-ui-keyboard-validation.json`.

Skip link can focus; textarea and Submit / Run ATK-002 reached; Enter activates; RUNNING disables the primary control (second Enter stays RUNNING); `run.id` and Copy reachable; focus outline `2px solid rgb(0, 127, 134)`.

**Limitation:** not a screen-reader test; **not WCAG certified**.

## Screenshots

| Pass | Paths |
|------|--------|
| 1 | `docs/screenshots/acmebank/pass1_*.png`, `docs/screenshots/attack-ui/pass1_*.png` |
| 2 | `docs/screenshots/acmebank/pass2_*.png`, `docs/screenshots/attack-ui/pass2_*.png` including `pass2_completed.png` |
| Keyboard | `docs/screenshots/web-ui-keyboard-validation.json` |

## /ui-review

- Pass 1 (unchanged): `docs/reviews/ui-review-acmebank-2026-09-11.md`, `docs/reviews/ui-review-attack-ui-2026-09-11.md`
- Closure: `docs/reviews/ui-review-web-ui-closure-2026-09-11.md` — no remaining BLOCKER/HIGH

## Residual MEDIUM/LOW (not redesigned)

- Duplicated AcmeBank status sentence (live + summary). Proposed trivial fix: hide summary when identical to live text.
- Attack Service shows Compose URL `http://acmebank:5000`. Proposed trivial copy: add host browser URL as a label only.
- Lab profile in header; header wrap; 390px textarea clip.

Not applied this closure.

## What did not change

Runtime security behavior, schema 1.0.0, validated SPL, ATK-002, CTRL-INPUT-001, operation/evidence semantics. Only local Compose config: `OLLAMA_BASE_URL` in `.env` (documented host fallback).

## Tests

`.venv/bin/python -m pytest`: **84 passed, 1 skipped** (this closure). Security suites were not edited to obtain COMPLETED.
