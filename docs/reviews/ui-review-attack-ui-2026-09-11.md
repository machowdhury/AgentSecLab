# UI review — Attack Service

**Date:** 2026-09-11  
**Surface:** Attack Service Flask UI (`http://127.0.0.1:5001/`)  
**Pass:** 1 (review written before further UI edits)  
**Screenshots:** `docs/screenshots/attack-ui/pass1_*.png` (READY at 1440/1024/768/390; intended RUNNING; DENIED at 1440/390)  
**Evidence class:** screenshot findings are **OBSERVED**. Defended ATK-002 returned HTTP 200, `control.decision=DENY`, `llm_call_count=0`, `testbed.mode=ATTACK`, `profile=defended`.

Canonical tokens: `docs/AGENTSEC_DESIGN_SYSTEM.md`.

---

## Roles

### Splunk architect

Investigation guidance names LAB-PI-001 and says Splunk does not ALLOW/DENY. No invented detections.

### SOC analyst

`run.id` is copyable after DENY. Facts include REQUEST SENT and CONTROL DENIED. GOVERNED LLM EXECUTED was correctly omitted (`executed` not true).

### UX designer

Technique → payload → Run ATK-002 → Execution. Not a wall of red. 390 stacks definition list to one column.

### Technical instructor

Lede: sending a request is not success. Empty READY: “Empty is not DENY.” DENIED facts use runtime fields.

### Accessibility

Skip link, headings, labeled run.id, named “Run ATK-002”. DENIED is a word plus color. Duplicate “DENIED DENIED” beside the chip.

---

## Findings

### HIGH — Live status repeats the chip

**Where:** `pass1_denied.png`  
“DENIED” appears twice in the status row. Live text should be the teaching sentence, not a second token.

### HIGH — RUNNING was not perceivable

**Where:** `pass1_running.png` is already DENIED  
Defended DENY returns before a RUNNING paint. Duplicate-click guard exists in JS but was not visible in the screenshot.

### MEDIUM — Target URL is the mesh hostname

`http://acmebank:5000` is correct inside Compose and confusing on the host browser. Label it as the lab service URL the console posts to.

### MEDIUM — Fact-row em dash column

`REQUEST SENT` then a wide gap then `— HTTP 200` from `min-width` on `<strong>`. Readable, slightly awkward.

### LOW — Header meta wraps on desktop

“this console does not call Ollama” wraps in the navy bar. Still readable.

---

## What is already good

- Direct Prompt Injection / ATK-002 / Target AcmeBank are obvious.
- Payload preview is labeled.
- DENIED path did not claim the attack succeeded.
- `llm_call_count=0` shown as a response fact, not as independent prevention proof.
- Shared palette with AcmeBank and LAB-PI-001 (navy, page gray, labeled critical button).

---

## Pass 2

**Screenshots:** `docs/screenshots/attack-ui/pass2_*.png`

HIGH fixes: RUNNING shows disabled “Running ATK-002…”; live text explains DENY without repeating the chip; target labeled as lab service URL.

Residual **MEDIUM:** mesh hostname `acmebank:5000` is still shown (now captioned). Header meta still wraps. Fact labels stack above notes.

No remaining BLOCKER/HIGH from pass 1. GOVERNED LLM EXECUTED still omitted on this defended DENY (correct).

