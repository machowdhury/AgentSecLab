# AgentSec UI Component Patterns

**Status:** Pre-Phase-14 UI/UX remediation (2026-09-18)  
**Implementation:** Dashboard Studio GRID + markdown/table visualizations.

---

## Workshop header

Markdown card. Title, purpose, LIVE/SIMULATED, lab id, schema, tab list as text (Studio tabs remain the control).

## Hunt selector

`input.dropdown` titled **Investigate specimen**.

Items:

- Baseline — defended / normal
- Attack — vulnerable / malicious
- Retest — defended / malicious
- plus domain extras (Unknown, write/recall, scan) when those specimens exist

Value = canonical LIVE run.id / scan.id. Label ≠ value.

## Specimen card

Labeled list (not GFM tables — Studio renders pipes as text):

**Profile** — defended  
**run.id** in backticks. Hashes via `fingerprint_block` when wrapping is required.

## Comparison row

Three third-width cards. Same field names left-to-right. Differences called out in words (SAME / DIFFERENT), not color alone.

## Evidence table

Navy header, white body, `hideWhenNoData: false`, standard empty sentence. No `_raw` in learner tables. Bounded previews only.

## Status chip (markdown)

`**LIVE**` · `**OBSERVE**` · `**ALLOW**` · `**DENY**` · `**SIMULATED**` as text. Optional color in surrounding copy, never instead of the word.

## Empty state

`No indexed event matched this evidence question.` Never SAFE / BLOCKED / PREVENTED / TRUSTED / PASS from zero rows.

## Technical identifier

Monospace markdown. Complete value. Semantic label (`run.id`, task hash, instruction hash). Not editable in learner mode.

## Incorrect-defense callout

Short list on DEFEND. Must not dominate the page.
