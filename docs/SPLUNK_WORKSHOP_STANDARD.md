# Splunk Workshop Standard

**Status:** PLANNED (Phase 1C)  
**Layout:** Dashboard Studio GRID, 12 columns  
**First-lab workshop:** WS-001 — Input control before the LLM  
**Level:** 0 (orientation panels) + 1 (prompt/input security)  
**Attack:** ATK-002  
**Control:** CTRL-INPUT-001  
**Invariant:** INV-008 (also INV-007 on evidence)

Reusable conceptual grid. Do **not** write queries in this file. Search questions: `SPLUNK_SEARCH_CONTRACT.md`.

Visual: background `#F6F8FB`, navy header, teal next-step, labels with every color.

Splunk does not submit `/process`. Action rows link to AcmeBank or Attack Service.

---

## When to use this layout

Any guided lab that follows LEARN → BASELINE → ATTACK → OBSERVE → HUNT → DETECT → DEFEND → RETEST → PROVE.

First lab implements **one** instance (WS-001). Later workshops reuse the same twelve rows; unused rows stay hidden rather than filled with fiction.

---

## Header tokens (all rows)

Workshop id, difficulty (GUIDED), progress (step n of 12), estimated time (instructor-set; not measured here), `agentsec.run.id` (and compare.run.id after RETEST).

---

## Twelve-row GRID

Reading order: top to bottom.

### ROW 1 — Title / meta

| Cell | Content |
|------|---------|
| Title | WS-001 Input control before the LLM |
| Difficulty | GUIDED |
| Progress | Step indicator |
| Estimated time | e.g. 45–60 minutes (copy, not telemetry) |
| Run ID | Token; empty until a run exists |

Profile and `testbed.mode` labeled when known. Invariant INV-008. Control CTRL-INPUT-001.

### ROW 2 — What you will learn | Architecture

**What you will learn**

- Untrusted HTTP hits AcmeBank (`acmebank.http_api`).  
- Four sequential in-process roles: intake → credit → risk → compliance (not A2A).  
- CTRL-INPUT-001 runs **before** Ollama.  
- DENY means never invoked: attempted=false, executed=false, outcome=prevented.  
- Splunk does not ALLOW or DENY.  
- Splunk absence of `llm.*` is not proof by itself.

**Architecture / trust boundary**

```text
Attack Service / browser
        │  untrusted payload
        ▼
   AcmeBank API  ── CTRL-INPUT-001 ──► (ALLOW) Ollama
                         │
                      DENY/ERROR: stop, no LLM
        ▼
   OTel → Splunk (observe only)
```

No four-enclave diagram.

### ROW 3 — STEP 1 BASELINE

| Field | First lab |
|-------|-----------|
| Action | Explicit benign loan on AcmeBank `POST /process` (not a ticker). |
| Expected behavior | `testbed.mode=BASELINE`, `execution.mode=LIVE`, `fidelity=OBSERVED`, profile `defended` (or documented), four hops ALLOW, llm.completed, outcome=success, `run.completed` completed_allowed. |
| Observed behavior | Field template for the baseline run.id — or empty state. |
| Why it matters | You need a picture of normal telemetry before ATK-002. |

Empty: “No BASELINE events. Submit a benign loan on AcmeBank. A count of 0 is not all-clear.”

### ROW 4 — STEP 2 ATTACK

| Field | First lab |
|-------|-----------|
| Attack description | ATK-002 direct prompt injection in the loan message. |
| Attack action | Attack Service fires the catalog payload. Splunk does not send it. Predict DENY vs model-ran **before** reveal. |
| Expected vulnerable behavior | `testbed.mode=ATTACK`, `profile=vulnerable`, labeled fail-open ALLOW, LLM may run (`executed=true` if started). Same payload will be RETEST later. |

### ROW 5 — STEP 3 OBSERVE

Telemetry, agent hops, control decisions, LLM execution, what actually happened — the hop-card pattern from `SPLUNK_UX_DESIGN.md`.

Must distinguish the six cases (ALLOW not executed, ALLOW success, ALLOW then error, DENY prevented, ERROR not invoked, incomplete).

Link: open OBSERVE with this run.id.

### ROW 6 — STEP 4 HUNT

| Field | First lab |
|-------|-----------|
| Learner question | For this run.id, did CTRL-INPUT-001 decide before Ollama, and did the LLM start? |
| Search objective | Q-RUN-EVENTS, Q-CONTROL-DECISION, Q-LLM-EXECUTED (contract ids, no SPL here). |
| Hint | Filter `agentsec.run.id`. Look at `event.name`, decision, attempted/executed/outcome. Do not hunt `session.id`. |
| Result validation | Fields match OBSERVE. If Splunk is empty, check export — do not conclude DENY. |

### ROW 7 — STEP 5 DETECT

| Field | First lab |
|-------|-----------|
| Detection objective | DET-001: prevented-before-invoke (plain language). No ML. |
| Expected trigger | Defended RETEST: DENY + prevented + no llm.* **and** completeness not ignored. |
| False-positive considerations | Missing llm.* because HEC failed; llm.failed mistaken for DENY; BASELINE mixed into ATTACK; ALLOW without llm.* called “blocked.” |

### ROW 8 — STEP 6 DEFEND

| Field | First lab |
|-------|-----------|
| Control | CTRL-INPUT-001 input inspection |
| Security property | INV-008 fail-safe; check-before-use |
| Where it executes | AcmeBank, before `acmebank.llm_call` |
| Why placement matters | Output inspection after generate cannot be DENY of that call. Splunk detections do not move the control. |

Profile switch is **lab configuration**, not a Splunk authorize button.

### ROW 9 — STEP 7 RETEST

Same ATK-002 payload. `profile=defended`. `testbed.mode=RETEST`. `execution.mode=LIVE`. `fidelity=OBSERVED`.

Expected: hop 0 DENY, prevented, no llm.*, pipeline.stopped denied, hops 1–3 absent, `run.completed` completed_denied.

Observed difference: field compare with the vulnerable ATTACK run.id.

### ROW 10 — BEFORE / AFTER

Two columns. Labels, not color-only.

| Before (ATTACK, vulnerable) | After (RETEST, defended) |
|----------------------------|---------------------------|
| compare.run.id | run.id |
| decision ALLOW + fail-open reason | DENY + reason |
| executed true if LLM started | executed false, outcome prevented |
| llm.* present if invoked | no llm.* |

If before/after run.ids missing: empty state, do not fabricate.

### ROW 11 — PROVE

Four explicit blocks (not one KPI):

1. **Runtime evidence** — Did AcmeBank invoke Ollama? NOT VERIFIED in Splunk by default. Learner checks runtime / `result.json`.  
2. **Local evidence** — Path `artifacts/<run-id>/` (`events.jsonl`, `result.json`, `export.json`).  
3. **Export completeness** — `export.json` ok or failed. If failed, Splunk cannot prove.  
4. **Splunk evidence** — Indexed events for run.id. Corroboration only.

States: COMPLETE / PARTIAL / FAILED / NOT VERIFIED per block. Never “PROVEN” from index presence alone.

### ROW 12 — FRAMEWORK / INVARIANT / completion

Educational only. Not certification. Not NIST SP 800-17.

| Item | WS-001 |
|------|--------|
| Invariant | INV-008 (placement), INV-007 (evidence) |
| ATLAS / OWASP | Only if a verified mapping row exists; otherwise omit ids |
| Completion | Mark PROGRESS if baseline, attack, retest, and prove steps have run.ids |
| Next lab | None in first lab. Placeholders: Level 2 tools (not built). |

Knowledge check (text, not a scored LMS):

1. Where is the trust boundary?  
2. Can Splunk DENY the LLM call?  
3. If DENY before invoke, what are attempted / executed / outcome?  
4. If Ollama starts then fails, is that prevention?  
5. Why is missing llm.* in Splunk not enough?

---

## Action result micro-block

Reusable after BASELINE, ATTACK, and RETEST:

ACTION · RUN ID · STATUS · WHAT HAPPENED (fields) · AGENTS · CONTROL DECISION · ATTEMPTED / EXECUTED / OUTCOME · WHY IT MATTERS · NEXT STEP

If no events: say so. Do not write a story.

---

## What must not appear on WS-001

- MLTK charts  
- Attack-chain timelines  
- Executive %  
- Run all 51  
- Cisco enforce  
- Absolute-layout ornaments  
- Full prompts  
- `testbed.mode=LIVE`  
- Validated-SPL claims  
- LLM-generated “what happened”

---

## Implementation note

Studio JSON for WS-001 exists in Phase 2C.3: `ws_lab_pi_001`. Tabs map to the twelve-row contract so the page stays readable. Searches remain the validated files in `learning/level_1/LAB-PI-001/searches/`.
