# Splunk Information Architecture

**Status:** PLANNED (Phase 1C UX contract)  
**App id:** `agentsec`  
**Index:** `agentsec_telemetry`  
**Sourcetype:** `otel:agentic:json`  
**Authoritative fields:** `docs/SECURITY_EVENT_MODEL.md` (schema **1.0.0**)  
**Evidence:** `docs/EVIDENCE_MODEL.md`  
**Visual system:** `docs/SPLUNK_DESIGN_SYSTEM.md`  
**Workshop grid:** `docs/SPLUNK_WORKSHOP_STANDARD.md`  
**Search questions:** `docs/SPLUNK_SEARCH_CONTRACT.md`

This file is information architecture. It is not Dashboard Studio JSON, not validated SPL, and not an implementation claim.

Splunk is the telemetry, investigation, detection, learning, later MLTK, and evidence **workbench**. Splunk does **not** authorize Ollama, mint `run.id`, set `security.profile`, or invent outcomes.

Proof order (Phase 1B):

```text
AUTHORITATIVE RUNTIME STATE
  → LOCAL RUN EVIDENCE
  → EXPORTED TELEMETRY
  → SPLUNK REPRESENTATION   (corroborating only)
```

A missing Splunk `llm.*` event does **not** prove non-execution unless completeness for that `run.id` is established.

Predecessor lessons (do not copy): AgentWatch mixed Classic/Studio, `session.id` vs `session_id`, coverage matrices as home, SIMULATED as live proof, and 15 dashboards before a working hunt. AgentSec ships **few pages**, `run.id` as the hunt key, and Studio GRID when dashboards exist.

---

## Capability labels

| Label | Meaning |
|-------|---------|
| **PLANNED** | This IA. No Studio JSON in this phase. |
| **FIRST LAB** | Required to teach ATK-002. |
| **LATER** | Real destination after the first lab. |
| **PLACEHOLDER ONLY** | Visible in nav as disabled / “not in this lab.” No empty dashboard. |
| **NOT NEEDED** | Omit from first-lab chrome. |

Empty Studio shells are forbidden. Pages light up only after their searches are validated against real events.

---

## Navigation (long-term order)

```text
HOME
LEARN
ATTACK LAB
OBSERVE
INVESTIGATION
DETECTION LAB
CONTROL VALIDATION
ATTACK CHAINS
MLTK LAB
ADVANCED TOOLS
COMPLIANCE
EXECUTIVE GOVERNANCE
PROGRESS
```

Always available outside this list: native Splunk **Search**. Instructors send analysts to Search when a view would invent SPL.

| Destination | Classification | First lab? |
|-------------|----------------|------------|
| HOME | FIRST LAB | Yes |
| LEARN | FIRST LAB | Yes (WS-001 only) |
| ATTACK LAB | FIRST LAB | Yes (ATK-002 orientation; fire is Attack Service) |
| OBSERVE | FIRST LAB | Yes |
| INVESTIGATION | FIRST LAB | Yes |
| DETECTION LAB | FIRST LAB | Yes (workflow; no SPL in this phase) |
| CONTROL VALIDATION | FIRST LAB | Yes (prove prevention) |
| ATTACK CHAINS | PLACEHOLDER ONLY | No |
| MLTK LAB | PLACEHOLDER ONLY | No (Level 5) |
| ADVANCED TOOLS | PLACEHOLDER ONLY | No (MCP/A2A/RAG/memory/Cisco) |
| COMPLIANCE | LATER | No (invariant row lives on the workshop) |
| EXECUTIVE GOVERNANCE | NOT NEEDED | No |
| PROGRESS | FIRST LAB | Yes (minimal checklist) |

**DECISION:** Lifecycle nav, not “all dashboards equal.”  
**ALTERNATIVES:** AgentWatch peer tabs; Coverage as home.  
**WHY:** Learners skipped baseline; SIMULATED filled matrices.  
**SECURITY:** Live proof and placeholders stay separable.  
**LEARNING:** HOME → LEARN → ATTACK → OBSERVE → HUNT → DETECT → DEFEND → RETEST → INVESTIGATE → PROVE.

---

## Global tokens (when a view has data)

| Token | Purpose |
|-------|---------|
| Time picker | Window; default last 60 minutes in the lab |
| `agentsec.run.id` | Primary hunt key. Equals `incident.id`. |
| `agentsec.compare.run.id` | RETEST / before-after pair |
| `agentsec.security.profile` | `defended` \| `vulnerable` |
| `agentsec.testbed.mode` | `BASELINE` \| `ATTACK` \| `RETEST` |
| `agentsec.hop.index` | Optional hop drill (0–3) |

Do **not** token `LIVE` as a testbed mode. First lab: `execution.mode=LIVE`, `telemetry.fidelity=OBSERVED` as **labels**, not filters that invent other modes.

---

## Learning levels (planning labels)

| Level | Name | First lab |
|-------|------|-----------|
| 0 | Orientation | Required (HOME + architecture panel) |
| 1 | Prompt and Input Security | Required (WS-001 / ATK-002) |
| 2 | Tool / MCP Security | Later |
| 3 | Agent / Delegation Security | Later |
| 4 | Memory / RAG Security | Later |
| 5 | Detection / MLTK | Later |
| 6 | Governance / Advanced Validation | Later |

---

## Suggested journeys

| Journey | Path |
|---------|------|
| First lab | HOME → LEARN (WS-001) → ATTACK LAB → OBSERVE → INVESTIGATION → DETECTION LAB → CONTROL VALIDATION → PROGRESS |
| Analyst after a run id | HOME → INVESTIGATION → OBSERVE → CONTROL VALIDATION |
| Instructor demo | HOME → LEARN (project workshop) → OBSERVE |

Splunk never POSTs to `/process`. AcmeBank (`:5000`) and Attack Service (`:5001`) are **external lab** links.

---

# FIRST LAB pages

Each page answers **one** primary question. Learner chrome always makes these five things findable: what this is, why it matters, what happened, what evidence supports it, what to do next.

---

## HOME

**PAGE NAME:** Home  
**PRIMARY USER:** First-time learner, returning student, instructor opening a class  
**PRIMARY QUESTION:** Where am I, is the lab honest about its status, and what is the one next action?  
**WHY IT EXISTS:** Orient. Do not become a wall of charts.  
**ENTRY POINT:** App default.  
**INPUTS / TOKENS:** None required. Optional last `run.id` from PROGRESS.  
**DATA REQUIRED:** Optional: last event timestamp for `agentsec.lab.id`. Honesty if none.  
**MAIN PANELS:** Purpose (range, not product ATO); current level (0–1); current lab (WS-001); lifecycle strip LEARN→…→PROVE; recent runs (run.id, testbed.mode, profile, evidence state); next recommended activity.  
**EXPECTED USER ACTION:** Start LEARN (WS-001) or resume PROGRESS.  
**WHAT HAPPENED SECTION:** None on HOME. Point to recent-run row → OBSERVE.  
**EVIDENCE SECTION:** One line: Splunk is corroborating; runtime is authoritative. Recent-run evidence chip (NOT VERIFIED / PARTIAL / …).  
**NEXT STEP:** LEARN.  
**EMPTY / NO-DATA STATE:** “No events in this window. Start AcmeBank, submit a benign loan, then return. A zero count is not all-clear.”  
**FAILURE STATE:** HEC/index unknown — “Ingest not verified. Do not hunt.”  
**WHAT MUST NOT BE SHOWN:** Coverage heatmaps, 51-count KPIs, MLTK, framework pass %, executive matrices, fake zeros, MCP/A2A tiles as live.  
**RELATED PAGES:** LEARN, ATTACK LAB, INVESTIGATION, PROGRESS.

---

## LEARN

**PAGE NAME:** Learn  
**PRIMARY USER:** Novice to practitioner; instructor projecting  
**PRIMARY QUESTION:** What should I understand before I attack, and how do I prove it?  
**WHY IT EXISTS:** Catalog + one workshop (WS-001).  
**ENTRY POINT:** HOME “Start LEARN”; PROGRESS resume.  
**INPUTS / TOKENS:** Workshop id (WS-001). On the workshop: run.id, profile, testbed.mode, compare.run.id.  
**DATA REQUIRED:** For workshop steps, events for the selected run.id. Catalog itself needs no events.  
**MAIN PANELS:** Catalog row (WS-001 only in first lab; later workshops listed as LATER). Selected workshop uses `SPLUNK_WORKSHOP_STANDARD.md` (12-row GRID).  
**EXPECTED USER ACTION:** Complete WS-001 top to bottom. Do not skip to COMPLIANCE.  
**WHAT HAPPENED SECTION:** Rows 5 and 10 of the workshop; field-driven; see UX design.  
**EVIDENCE SECTION:** Workshop row 11 (PROVE).  
**NEXT STEP:** ATTACK LAB when the workshop says fire; OBSERVE after a run.id exists.  
**EMPTY / NO-DATA STATE:** Baseline/attack steps explain “no BASELINE/ATTACK events — submit on AcmeBank / Attack Service.”  
**FAILURE STATE:** Events exist but schema.version missing or ≠ 1.0.0 — “Contract mismatch. Do not treat as first-lab proof.”  
**WHAT MUST NOT BE SHOWN:** Fire-all-techniques, Cisco/MLTK chrome, executive scores, chain timelines, Attack Service iframe, validated-SPL claims.  
**RELATED PAGES:** ATTACK LAB, OBSERVE, INVESTIGATION, CONTROL VALIDATION, PROGRESS.

---

## ATTACK LAB

**PAGE NAME:** Attack Lab  
**PRIMARY USER:** Learner in the offense step; instructor demo  
**PRIMARY QUESTION:** Which first-lab action do I run, under which profile, and where is the run.id afterward?  
**WHY IT EXISTS:** Offense door. Splunk does not send the payload.  
**ENTRY POINT:** LEARN step 2; HOME.  
**INPUTS / TOKENS:** profile, testbed.mode (ATTACK vs RETEST).  
**DATA REQUIRED:** None to choose the action. After fire: run.id from AcmeBank response / evidence pack (pasted).  
**MAIN PANELS:** ATK-002 card (direct prompt injection); profile selector copy (`vulnerable` vs `defended` is lab config, not Splunk); expected prediction **before** reveal; link to Attack Service `:5001`; reminder first baseline is an explicit benign AcmeBank submit (`testbed.mode=BASELINE`). Labels: `execution.mode=LIVE`, `telemetry.fidelity=OBSERVED`.  
**EXPECTED USER ACTION:** Predict ALLOW vs DENY. Fire ATK-002 outside Splunk. Paste `run.id` into OBSERVE / LEARN.  
**WHAT HAPPENED SECTION:** Not here (no invented narrative). After paste, “Open OBSERVE.”  
**EVIDENCE SECTION:** “Proof is not this page. Next: OBSERVE then CONTROL VALIDATION.”  
**NEXT STEP:** OBSERVE.  
**EMPTY / NO-DATA STATE:** Normal before a fire.  
**FAILURE STATE:** User expects Splunk to POST — copy: “Splunk cannot call Ollama or AcmeBank.”  
**WHAT MUST NOT BE SHOWN:** SIMULATED fire as live proof; Run all 51; second LLM client; `testbed.mode=LIVE`; hunt tables; detection editors.  
**RELATED PAGES:** LEARN, OBSERVE, INVESTIGATION.

---

## OBSERVE

**PAGE NAME:** Observe  
**PRIMARY USER:** Learner after a run exists  
**PRIMARY QUESTION:** For this run.id, what did each hop do — control, then LLM or not?  
**WHY IT EXISTS:** Make pipeline → hop → control → LLM understandable without OTel internals.  
**ENTRY POINT:** After ATTACK LAB paste; LEARN row 5; INVESTIGATION drill.  
**INPUTS / TOKENS:** `agentsec.run.id` (required), hop.index (optional).  
**DATA REQUIRED:** Events for that run: `run.*`, `hop.*`, `control.decision`, `llm.*` if any, `pipeline.stopped` if any.  
**MAIN PANELS:** Run header (run.id, incident.id same value, profile, testbed.mode, attack.id, schema 1.0.0); four hop cards (intake 0 … compliance 3); each card: agent id, delegator (hops 1–3 only), control decision+reason, attempted/executed/outcome, llm.started/completed/failed or “no LLM event”; pipeline stop reason if present.  
**EXPECTED USER ACTION:** Read hops in order. Note hop 0 DENY means hops 1–3 must not appear.  
**WHAT HAPPENED SECTION:** Per-hop field summary; six-way outcome legend (see UX design).  
**EVIDENCE SECTION:** Chip: Splunk indexed vs NOT VERIFIED completeness.  
**NEXT STEP:** INVESTIGATION (same run.id) or CONTROL VALIDATION.  
**EMPTY / NO-DATA STATE:** “No events for this run.id. Confirm AcmeBank ran and ingest is up. Absence is not DENY.”  
**FAILURE STATE:** ALLOW on a hop with neither llm.* nor export warning — “Incomplete or still in flight. Do not call this prevention.”  
**WHAT MUST NOT BE SHOWN:** Raw span dumps as the primary view; tools/MCP; full prompts; LLM-written story; A2A language for delegator.  
**RELATED PAGES:** LEARN, INVESTIGATION, CONTROL VALIDATION.

---

## INVESTIGATION

**PAGE NAME:** Investigation  
**PRIMARY USER:** SOC-style learner; instructor reconstructing  
**PRIMARY QUESTION:** For this run.id, who started it, what was the experiment, what did controls decide, did the LLM execute, where did it stop, and is telemetry complete?  
**WHY IT EXISTS:** Run-centric hunt. Not an enterprise SOC console.  
**ENTRY POINT:** OBSERVE “Hunt”; LEARN row 6; HOME recent run.  
**INPUTS / TOKENS:** run.id (required), time, testbed.mode, profile.  
**DATA REQUIRED:** All first-lab event types for that run.id.  
**MAIN PANELS:** Identity (user.id, principal); experiment (testbed.mode, attack.id, profile, execution.mode, fidelity); timeline of `event.name` + sequence; hop table; control table; LLM activity table; stop/outcome; completeness panel (four-layer status).  
**EXPECTED USER ACTION:** Reconstruct. Distinguish DENY-prevented vs llm.failed vs missing export.  
**WHAT HAPPENED SECTION:** Data-driven block from fields only (UX design).  
**EVIDENCE SECTION:** Four-layer status; never a single “PROVEN” from index hit count.  
**NEXT STEP:** DETECTION LAB or CONTROL VALIDATION.  
**EMPTY / NO-DATA STATE:** “No events — check HEC / whether the run occurred.” Never a green zero.  
**FAILURE STATE:** Mixed schema versions; incident.id ≠ run.id — show as contract break.  
**WHAT MUST NOT BE SHOWN:** Workshop quiz, executive KPIs, MLTK fit, coverage matrix, chain.id, session.id, tool columns.  
**RELATED PAGES:** OBSERVE, DETECTION LAB, CONTROL VALIDATION.

---

## DETECTION LAB

**PAGE NAME:** Detection Lab  
**PRIMARY USER:** Learner turning a hunt into a repeatable question  
**PRIMARY QUESTION:** What security question are we asking, which fields answer it, and what would a true positive vs negative look like?  
**WHY IT EXISTS:** Teach detection as a question, not a dashboard sparkline. No SPL in this phase.  
**ENTRY POINT:** INVESTIGATION “Build detection”; LEARN row 7.  
**INPUTS / TOKENS:** run.id (example), testbed.mode.  
**DATA REQUIRED:** Same fields as the search contract. Searches stay unvalidated until a later phase runs them.  
**MAIN PANELS:** One detection at a time (DET-001 first lab). Workflow: question → required fields → baseline behavior → attack behavior → logic (plain language) → expected TP → expected negative → FP discussion → tuning → investigation next step. Badge: “SPL not written / not validated.”  
**EXPECTED USER ACTION:** Explain DET-001 in words. Do not enable a saved search.  
**WHAT HAPPENED SECTION:** Optional example run.id illustrating TP/negative.  
**EVIDENCE SECTION:** “A detection firing is not a control. A hunt is not proof of DENY.”  
**NEXT STEP:** CONTROL VALIDATION.  
**EMPTY / NO-DATA STATE:** “No example run. Complete WS-001 ATTACK first.”  
**FAILURE STATE:** Treating missing llm.* as the detection’s only TP without completeness.  
**WHAT MUST NOT BE SHOWN:** MLTK purple as default; 51-row matrices; attack firing UI; “validated” unless a search was actually run.  
**RELATED PAGES:** INVESTIGATION, CONTROL VALIDATION.

---

## CONTROL VALIDATION

**PAGE NAME:** Control Validation  
**PRIMARY USER:** Learner proving INV-008 placement  
**PRIMARY QUESTION:** Did CTRL-INPUT-001 decide before Ollama, and do attempted/executed/outcome match that decision?  
**WHY IT EXISTS:** Check-before-use. Fail the page if DENY is shown after a successful LLM call.  
**ENTRY POINT:** LEARN rows 8–11; INVESTIGATION.  
**INPUTS / TOKENS:** run.id, compare.run.id (vulnerable ATTACK vs defended RETEST).  
**DATA REQUIRED:** `control.decision` events; llm.* presence/absence; hop outcomes; for PROVE, learner confirmation of local `export.json` / `result.json` (Splunk cannot read the disk).  
**MAIN PANELS:** Control id/type/decision/reason; attempted/executed/outcome; boundary `acmebank.http_api` / `acmebank.llm_call`; invariant INV-008; before/after two run.ids; four-layer evidence; expected vs actual from fields.  
**EXPECTED USER ACTION:** Compare vulnerable ATTACK vs defended RETEST same payload. Confirm runtime/local evidence outside Splunk.  
**WHAT HAPPENED SECTION:** Pair table: profile, testbed.mode, decision, executed, outcome, llm.* count.  
**EVIDENCE SECTION:** Required. States COMPLETE / PARTIAL / FAILED / NOT VERIFIED per layer.  
**NEXT STEP:** PROGRESS (mark WS-001) or INVESTIGATION.  
**EMPTY / NO-DATA STATE:** Need two run.ids for before/after; one run still useful for a single decision.  
**FAILURE STATE:** DENY + llm.completed on same hop = product bug banner. llm.failed labeled “executed, error — not prevention.”  
**WHAT MUST NOT BE SHOWN:** Certification banners; mixing SYNTHETIC with ATTACK DENY KPIs; Splunk-only “PROVEN.”  
**RELATED PAGES:** OBSERVE, INVESTIGATION, LEARN, PROGRESS.

---

## PROGRESS

**PAGE NAME:** Progress  
**PRIMARY USER:** Learner; instructor checking a single student  
**PRIMARY QUESTION:** Which first-lab steps have I completed with a run.id, versus skipped?  
**WHY IT EXISTS:** Resume. Not a certificate.  
**ENTRY POINT:** HOME; end of CONTROL VALIDATION.  
**INPUTS / TOKENS:** Stored run.ids (lab-local; not secrets).  
**DATA REQUIRED:** Checklist state; optional event confirmation those ids exist.  
**MAIN PANELS:** WS-001 steps (baseline, vulnerable attack, hunt, defended retest, prove); stored run.ids labeled BASELINE / ATTACK / RETEST; evidence chips.  
**EXPECTED USER ACTION:** Resume next incomplete step.  
**WHAT HAPPENED SECTION:** None.  
**EVIDENCE SECTION:** List artifacts path pattern `artifacts/<run-id>/`.  
**NEXT STEP:** LEARN or HOME.  
**EMPTY / NO-DATA STATE:** “No completed steps. Start LEARN.”  
**FAILURE STATE:** Do not show NIST/compliance completion.  
**WHAT MUST NOT BE SHOWN:** Other users’ PII; executive heatmaps as personal scores; live attack console.  
**RELATED PAGES:** HOME, LEARN.

---

# PLACEHOLDER / LATER / NOT NEEDED

These destinations may appear in nav as **disabled** with one sentence. No Studio JSON. No fake data.

### ATTACK CHAINS — PLACEHOLDER ONLY

Multi-stage `chain.id` is not in the first lab. First lab: `incident.id` = `run.id`. Do not reuse AgentWatch kill-chain dashboards.

### MLTK LAB — PLACEHOLDER ONLY

Level 5. Purple track cue only when that lab exists. MLTK is not a control.

### ADVANCED TOOLS — PLACEHOLDER ONLY

MCP, A2A, RAG, memory, Cisco overlays. Absent from first lab. Do not regex-simulate them in chrome.

### COMPLIANCE — LATER

Educational mapping only after verified rows exist. Workshop row 12 carries INV-008 for WS-001. No “compliance %.” Never NIST SP 800-17.

### EXECUTIVE GOVERNANCE — NOT NEEDED (first lab)

CISO tour uses HOME + CONTROL VALIDATION. No ATO page.

---

## Native Search

Not a custom view. Use when a dashboard would guess fields. Questions live in `SPLUNK_SEARCH_CONTRACT.md`. SPL is written only in a later validation phase.

---

## What this file is not

- Not Dashboard Studio JSON  
- Not validated SPL, macros, or saved searches  
- Not runtime or schema changes  
- Not an implementation of the `agentsec` app
