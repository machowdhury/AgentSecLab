# UI review — AcmeBank

**Date:** 2026-09-11  
**Surface:** AcmeBank Flask UI (`http://127.0.0.1:5000/`)  
**Pass:** 1 (review written before further UI edits)  
**Screenshots:** `docs/screenshots/acmebank/pass1_*.png` (READY at 1440/1024/768/390; intended RUNNING; ERROR at 1440/390)  
**Evidence class:** screenshot findings are **OBSERVED**. HTTP `/process` on this volume returned `terminal=run_failed`, `error_stage=llm_invocation` (not a new control result). COMPLETED was not observed this pass.

Canonical tokens: `docs/AGENTSEC_DESIGN_SYSTEM.md`.

---

## Roles

### Splunk architect

Not a Studio surface. Shared navy/teal/page tokens match the LAB-PI-001 family. No invented Splunk fields.

### SOC analyst

ERROR still minted a `run.id` with Copy. Full UUID visible at 1440.

### UX designer

Loan form is the primary card. Processing details are collapsed. Mobile stacks. READY is labeled with words.

### Technical instructor

Copy says this page does not fire attacks. ALLOW≠execution is in collapsed pipeline details, not on the ERROR summary. ERROR from `llm_invocation` is not explicitly distinguished from DENY.

### Accessibility

`lang`, skip link, `main`, visible label, 44px teal submit, focus styles in CSS. Status uses a word plus color. Live region repeated the chip text (“ERROR ERROR”).

---

## Findings

### HIGH — Live status repeats the chip

**Where:** `pass1_error.png`  
Chip says ERROR and the adjacent live text also says ERROR. The useful sentence is below. `aria-live` should carry the sentence, not a second copy of the state token.

### HIGH — `llm_invocation` ERROR can be read as a block

**Where:** `pass1_error.png`  
“The application could not be completed. Stage: llm_invocation.” does not say this is **not** CTRL-INPUT-001 DENY and **not** prevention. Design-system rule: do not describe a failed model call as prevention.

### HIGH — RUNNING was not perceivable

**Where:** `pass1_running.png` is already ERROR  
The request finished before a RUNNING frame painted. Required states include RUNNING with duplicate submit disabled. Fast failures skip the progress frame.

### MEDIUM — Lab profile in the header

Necessary for the workshop; it is still security instrumentation on a banking header.

### MEDIUM — COMPLETED not observed

Ollama invocation failed on this volume. Do not treat missing COMPLETED screenshot as a visual defect of the completed-allowed copy.

### LOW — “How this application is processed” is below the fold

Appropriate so banking UX leads. Fine for a lab.

---

## What is already good

- Looks like a bank, not a vulnerable-by-design toy.
- Teal primary action, navy chrome, page `#F6F8FB`.
- `run.id` wraps in a readonly field with Copy.
- 390px: full-width submit, no destructive overflow.
- ERROR still exposes `run.id` (INV-007 teaching).

---

## Pass 2

**Screenshots:** `docs/screenshots/acmebank/pass2_*.png`

HIGH fixes: RUNNING paints with disabled “Submitting…”; live text is a sentence; `llm_invocation` copy says failed model invocation, not DENY/prevention.

Residual **MEDIUM:** the ERROR sentence appears twice (live region and summary). COMPLETED still not observed (Ollama `llm_invocation` on this volume). Lab profile remains in the header.

No remaining BLOCKER/HIGH from pass 1.

