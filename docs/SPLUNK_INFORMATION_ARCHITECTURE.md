# Splunk Information Architecture

**Status:** PLANNED. No Dashboard Studio JSON in this phase.  
**Roles used:** Splunk architect, SOC analyst, security product designer, technical instructor.  
**Related:** `SPLUNK_ARCHITECTURE.md`, `SPLUNK_DESIGN_SYSTEM.md`, `SECURITY_EVENT_MODEL.md`, `ATTACK_CONTROL_MODEL.md`

This is the **target** AgentSec app navigation (`agentsec`). Pages light up only after their SPL is validated. Empty Studio shells are forbidden.

Phase 1 may ship Search plus HOME copy only. The rest stays PLANNED until events exist.

---

## Product intent (four hats)

| Role | What this IA must do |
|------|----------------------|
| Splunk architect | One app, GRID, macros (`agentsec_index`), tokens (`agentsec.run.id`, `agentsec.testbed.mode`, `agentsec.security.profile`). No `join`-heavy landing pages. |
| SOC analyst | Every page answers one investigation or detection question. “What happened?” comes from fields, not prose. |
| Security product designer | Severity is a **label** (ALLOW / DENY / …) plus color. SIMULATED never looks like a live block. |
| Technical instructor | Nav order is the lifecycle. Next page is obvious. Knowledge check before governance scores. |

---

## Global navigation (locked order)

```text
HOME
LEARN
ATTACK LAB
INVESTIGATION
DETECTION LAB
MLTK LAB
CONTROL VALIDATION
ATTACK CHAINS
ADVANCED TOOLS
COMPLIANCE
EXECUTIVE GOVERNANCE
PROGRESS
```

Always available outside this list: Splunk **Search** (not a custom view). Instructors send analysts to Search when a dashboard would invent SPL.

**Global tokens (when a view has data):** time picker, `agentsec.run.id`, `agentsec.security.profile`, `agentsec.testbed.mode` (attack KPIs default `NOT BASELINE`; SIMULATED is a visible badge, not mixed into “blocked” counts).

**DECISION:** Lifecycle nav, not “all dashboards equal.”  
**ALTERNATIVES:** AgentWatch-style many peer tabs; Coverage as home.  
**WHY CHOSEN:** Learners skipped baseline; SIMULATED filled matrices.  
**SECURITY CONSEQUENCE:** Live proof and simulated emits stay separable.  
**LEARNING VALUE:** HOME → LEARN → ATTACK → INVESTIGATE → DETECT → … → PROGRESS.

---

## HOME

**WHO USES IT?** First-time learner, returning student, instructor opening a class, CISO on a tour who should not start in MLTK.

**WHAT QUESTION DOES IT ANSWER?** Where am I, is the lab healthy, and what is the one next action?

**WHAT ACTION SHOULD THE USER TAKE?** Confirm telemetry is arriving (or see an honest empty state). Click **Start LEARN** (first workshop) or **Resume** if PROGRESS has a checkpoint.

**WHAT MUST BE VISIBLE?**

- AgentSec is a learning range, not a product ATO.
- Lab health: last event time, `agentsec.lab.id`, profile (`defended` / `vulnerable`) as a **label**.
- Three doors: LEARN (guided), ATTACK LAB (offense), INVESTIGATION (hunt).
- Link to AcmeBank `:5000` and Attack Service `:5001` as **external lab**, not Splunk panels pretending to be those apps.

**WHAT SHOULD NOT BE ON THIS PAGE?**

- Technique coverage heatmaps, 51-count KPIs, MLTK forecasts, framework “pass %”, executive risk matrices, unvalidated SPL, fake zeros that look like all-clear.

**WHAT IS THE NEXT LOGICAL PAGE?** LEARN.

---

## LEARN

**WHO USES IT?** Novice to practitioner following a workshop. Instructor projecting a lesson.

**WHAT QUESTION DOES IT ANSWER?** What should I understand before I attack, and how do I prove it in Splunk?

**WHAT ACTION SHOULD THE USER TAKE?** Pick one workshop. Complete baseline → attack → hunt → knowledge check. Do not skip to COMPLIANCE.

**WHAT MUST BE VISIBLE?**

- Workshop catalog (title, difficulty GUIDED / PRACTITIONER / CHALLENGE, invariants).
- For the selected workshop: the standard flow from `SPLUNK_DESIGN_SYSTEM.md` (see wireframe below).
- Action result block after each learner action: ACTION, RUN ID, STATUS, WHAT HAPPENED (from telemetry), AGENTS, CONTROL DECISION, TELEMETRY, WHY IT MATTERS, NEXT STEP.
- SPL explanation: what we are asking, how the search works, what you should see.

**WHAT SHOULD NOT BE ON THIS PAGE?**

- Fire-all-techniques buttons, Cisco/MLTK chrome, executive scores, attack-chain timelines for other campaigns, raw Attack Service iframe.

**WHAT IS THE NEXT LOGICAL PAGE?** ATTACK LAB (to run the live action named in the workshop), then back to LEARN for “what happened,” or INVESTIGATION to hunt the same `agentsec.run.id`.

---

## ATTACK LAB

**WHO USES IT?** Learner in the offense step, red-team style operator, instructor triggering a demo.

**WHAT QUESTION DOES IT ANSWER?** Which live (or labeled SIMULATED) action do I run, against which agent, under which profile?

**WHAT ACTION SHOULD THE USER TAKE?** Choose ATK-00x (or later catalog). Confirm `defended` vs `vulnerable`. Run. Copy `agentsec.run.id` into LEARN / INVESTIGATION.

**WHAT MUST BE VISIBLE?**

- Mode badges: LIVE / HYBRID / SIMULATED / BASELINE.
- Target agent, technique id (if any), expected control decision (prediction **before** reveal).
- Honest copy: SIMULATED does not prove a control.
- Link out to Attack Service for the actual HTTP fire (Splunk does not bypass AcmeBank).

**WHAT SHOULD NOT BE ON THIS PAGE?**

- Full SOC hunt tables, detection rule editors, compliance mappings, MLTK, “Run all 51” as a default primary button.

**WHAT IS THE NEXT LOGICAL PAGE?** LEARN (guided “what happened”) or INVESTIGATION (analyst path).

---

## INVESTIGATION

**WHO USES IT?** SOC analyst, learner after first attack, instructor showing reconstruction.

**WHAT QUESTION DOES IT ANSWER?** For this `agentsec.run.id` (or time window), what happened, who/what/why, did the dangerous operation run?

**WHAT ACTION SHOULD THE USER TAKE?** Paste run id. Reconstruct using event-model fields. Decide: control held, missed, or SIMULATED-only.

**WHAT MUST BE VISIBLE?**

- Timeline of `event.name` for one run / one trace.
- Table columns aligned to `SECURITY_EVENT_MODEL.md`: initiator, principal, agent, model, tool, operation, scopes, control, decision, reason, `operation.executed`, technique, boundary, invariant, incident/chain if present.
- Filter: testbed mode, profile, DENY vs ALLOW vs OBSERVE vs SANITIZE.
- Empty state: “No events — check HEC / baseline,” never a green zero.

**WHAT SHOULD NOT BE ON THIS PAGE?**

- Workshop lesson prose, knowledge-check quizzes, executive KPIs, MLTK `fit`, framework certification language, coverage matrices.

**WHAT IS THE NEXT LOGICAL PAGE?** DETECTION LAB (turn this hunt into a saved question) or CONTROL VALIDATION (if the question is “did the control fire before the tool/LLM”).

---

## DETECTION LAB

**WHO USES IT?** Detection engineer, advanced learner, instructor teaching SPL hygiene.

**WHAT QUESTION DOES IT ANSWER?** What is the security question, which fields prove it, and does this search hold up (FP/FN notes)?

**WHAT ACTION SHOULD THE USER TAKE?** Write or inspect a hunt. Require QUERY ID, required fields, expected vs actual (once validated). Disable-by-default saved searches.

**WHAT MUST BE VISIBLE?**

- One detection at a time: question, SPL, field list from the event model, explanation of each major command.
- LIVE vs SIMULATED split.
- Link: “Not yet validated” if the search was not run on representative data.

**WHAT SHOULD NOT BE ON THIS PAGE?**

- Workshop storytelling, CISO tiles, MLTK purple charts as the main view, attack firing UI, 51-row unfiltered matrices.

**WHAT IS THE NEXT LOGICAL PAGE?** CONTROL VALIDATION (control vs detection) or MLTK LAB (only if the question is behavioral/anomaly, not regex/control).

---

## MLTK LAB

**WHO USES IT?** Optional advanced track: detection engineers comparing reference controls vs statistical/ML signals.

**WHAT QUESTION DOES IT ANSWER?** Does token/time-series behavior look anomalous **after** we already know the control decision?

**WHAT ACTION SHOULD THE USER TAKE?** Run a labeled MLTK experiment. Record evidence class (MEASURED only if MLTK actually ran).

**WHAT MUST BE VISIBLE?**

- Purple track cue (`#6B46C1`) plus text “MLTK optional.”
- Dependency: MLTK (and CTSM if used) installed or an honest “app missing” state.
- Same `agentsec.run.id` as the control path for comparison.
- No fake `mltk.detected` from Python.

**WHAT SHOULD NOT BE ON THIS PAGE?**

- First-win workshop, compliance %, Attack Service, treating MLTK as the authorization control.

**WHAT IS THE NEXT LOGICAL PAGE?** DETECTION LAB or CONTROL VALIDATION. Not HOME skip-ahead.

---

## CONTROL VALIDATION

**WHO USES IT?** Control owner, security architect, learner proving INV placement.

**WHAT QUESTION DOES IT ANSWER?** Which control, which decision, **why**, and did `agentsec.operation.executed` match the decision (DENY ⇒ false)?

**WHAT ACTION SHOULD THE USER TAKE?** Pick a run or technique. Compare expected vs actual control result. Fail the page if DENY is shown after a successful LLM/tool call.

**WHAT MUST BE VISIBLE?**

- `agentsec.control.id`, `decision`, `reason`, `operation.executed`.
- Trust boundary and invariant ids.
- Profile `vulnerable` vs `defended` labeled.
- Before/after when a workshop retest exists.

**WHAT SHOULD NOT BE ON THIS PAGE?**

- Framework “certified” banners, MLTK, executive portfolio, SIMULATED counts in the same KPI as LIVE DENY.

**WHAT IS THE NEXT LOGICAL PAGE?** ATTACK CHAINS (multi-step) or COMPLIANCE (educational mapping of this evidence).

---

## ATTACK CHAINS

**WHO USES IT?** Investigator, Tier-3 learner, instructor telling a multi-stage story.

**WHAT QUESTION DOES IT ANSWER?** How do stages of `agentsec.chain.id` share `agentsec.incident.id`, and which stages were LIVE vs SIMULATED?

**WHAT ACTION SHOULD THE USER TAKE?** Select a chain. Walk stage_num. Hunt one incident. Do not treat HYBRID OTel-only legs as live control proof.

**WHAT MUST BE VISIBLE?**

- Stage list, technique per stage, decision per stage, mode badge.
- Shared incident id; per-stage `agentsec.run.id` if runs differ.
- Actor/agent sequence (`gen_ai.agent.id`).

**WHAT SHOULD NOT BE ON THIS PAGE?**

- Single-technique workshop chrome, MLTK, executive readiness %, “all 51 complete.”

**WHAT IS THE NEXT LOGICAL PAGE?** INVESTIGATION (deep dive one run) or CONTROL VALIDATION (per-stage placement).

---

## ADVANCED TOOLS

**WHO USES IT?** Optional Cisco / adapter / MAESTRO track. Architects comparing reference controls vs vendor-shaped signals.

**WHAT QUESTION DOES IT ANSWER?** What extra tooling is **on**, is it teach-mode or enforce (only if tested), and how do fields map to `norm_*` later?

**WHAT ACTION SHOULD THE USER TAKE?** Enable overlay outside Splunk. In Splunk, compare labeled Cisco/adapter events to AcmeBank OTel. Never use this page to ALLOW a loan.

**WHAT MUST BE VISIBLE?**

- Track status: absent / teach / (enforce only if implemented and tested).
- Honest “scanner not installed.”
- Link to INVESTIGATION with `service.name` / sourcetype filters.

**WHAT SHOULD NOT BE ON THIS PAGE?**

- Core first workshop, fake enforce DENY, claiming DefenseClaw is in-process.

**WHAT IS THE NEXT LOGICAL PAGE?** MLTK LAB or DETECTION LAB. Core learners skip this page (HOME should not push it).

---

## COMPLIANCE

**WHO USES IT?** GRC-curious learner, auditor **in a teaching role**, mapping workshop.

**WHAT QUESTION DOES IT ANSWER?** How does this **verified** mapping connect a technique/control/invariant to an allowed framework id — not “are we certified?”

**WHAT ACTION SHOULD THE USER TAKE?** Open one mapping row: official title, why it applies, invariant, test, evidence class. Read the disclaimer.

**WHAT MUST BE VISIBLE?**

- Allow-listed frameworks only (no NIST SP 800-17).
- Evidence class: OBSERVED / MEASURED / SIMULATED / …
- “Educational mapping. Not certification or compliance.”

**WHAT SHOULD NOT BE ON THIS PAGE?**

- A single “compliance %” that mixes SIMULATED coverage, MLTK, and LIVE DENY.
- Attack firing, live shell, executive traffic-light without definitions.

**WHAT IS THE NEXT LOGICAL PAGE?** EXECUTIVE GOVERNANCE (same evidence, less technical) or PROGRESS (what you personally mapped).

---

## EXECUTIVE GOVERNANCE

**WHO USES IT?** CISO-style visitor, manager, instructor’s last five minutes.

**WHAT QUESTION DOES IT ANSWER?** In plain language: are we learning the loop, where are LIVE gaps, what is labeled SIMULATED, what is not attested?

**WHAT ACTION SHOULD THE USER TAKE?** Read four tiles max. Drill to CONTROL VALIDATION or INVESTIGATION. Do not “sign off” the lab as an ATO.

**WHAT MUST BE VISIBLE?**

- Readiness as **coverage of taught LIVE paths**, excluding BASELINE noise and unlabeled SIMULATED.
- HITL / profile / registry language only when those events exist.
- Links down to evidence, not the other way around.

**WHAT SHOULD NOT BE ON THIS PAGE?**

- Raw SPL, MLTK math, 51-row matrices, Attack Service, workshop quizzes.

**WHAT IS THE NEXT LOGICAL PAGE?** PROGRESS (class) or HOME (tour over).

---

## PROGRESS

**WHO USES IT?** Learner, instructor checking a cohort, the student themselves.

**WHAT QUESTION DOES IT ANSWER?** Which workshops/detections/controls have **I** completed with evidence (`agentsec.run.id` / artifacts), vs skipped?

**WHAT ACTION SHOULD THE USER TAKE?** Resume the next incomplete LEARN item. Export nothing that looks like a certificate of NIST compliance.

**WHAT MUST BE VISIBLE?**

- Checklist: LEARN workshops, one hunt, one control validation, optional MLTK/advanced.
- Stored run ids (not raw session secrets).
- Mode labels on completed items (LIVE vs SIMULATED).

**WHAT SHOULD NOT BE ON THIS PAGE?**

- Live attack console, executive risk heatmaps as personal scores, other users’ PII.

**WHAT IS THE NEXT LOGICAL PAGE?** LEARN (next workshop) or HOME.

---

## Suggested journeys

| Journey | Path |
|---------|------|
| First 30 minutes | HOME → LEARN (workshop) → ATTACK LAB → LEARN (what happened) → INVESTIGATION → PROGRESS |
| Analyst | HOME → INVESTIGATION → DETECTION LAB → CONTROL VALIDATION |
| Optional vendor/ML | DETECTION LAB → MLTK LAB → ADVANCED TOOLS |
| Teaching GRC | CONTROL VALIDATION → COMPLIANCE → EXECUTIVE GOVERNANCE |

---

# Workshop wireframe (Markdown GRID)

**Workshop:** Input control before the LLM (ATK-002 / INV-008)  
**Nav owner:** LEARN  
**Layout:** Dashboard Studio **GRID** (12 columns). Not absolute. **No JSON.**  
**SPL:** Placeholders only. Do not treat as validated. Actual searches wait for live fields.

Reading order is **top to bottom, left to right**. Background `#F6F8FB`. Navy header. Decision labels always include the word ALLOW/DENY/… not color alone.

### Row 1 — Header (columns 1–12)

```text
+----------------------------------------------------------------------------------------+
|  LEARN  ·  Workshop 01  ·  Input control before the LLM                                |
|  Profile: defended   Mode: LIVE   Invariant: INV-008   Control: CTRL-INPUT-001         |
|  [Time]  [Run ID token]  [Profile]  [testbed.mode]                                     |
+----------------------------------------------------------------------------------------+
```

### Row 2 — What you will learn | Architecture (6 + 6)

```text
+---------------------------------------+---------------------------------------+
| WHAT YOU WILL LEARN                   | ARCHITECTURE / TRUST BOUNDARY         |
| • Untrusted HTTP hits AcmeBank        | Attacker → Attack Service → AcmeBank  |
| • Input control runs BEFORE Ollama    | API → CTRL-INPUT-001 → Ollama         |
| • DENY means operation.executed=false | Splunk observes; it does not ALLOW    |
| Knowledge: predict DENY or INJECT     | No A2A. One sequential intake agent   |
+---------------------------------------+---------------------------------------+
```

### Row 3 — Baseline (columns 1–12)

```text
+----------------------------------------------------------------------------------------+
| BASELINE                                                                               |
| Action: Submit a normal loan on AcmeBank (or wait for baseline tick).                  |
| Empty state: “No BASELINE events in window — start AcmeBank traffic.”                  |
| Do not show 0 as healthy.                                                              |
+----------------------------------------------------------------------------------------+
```

### Row 4 — Baseline query | Explanation (6 + 6)

```text
+---------------------------------------+---------------------------------------+
| QUERY (not validated)                 | EXPLANATION                           |
| `agentsec_index`                      | WHAT ARE WE ASKING? Did a benign      |
| agentsec.testbed.mode=BASELINE        | intake run exist?                     |
| | stats count by gen_ai.agent.id      | HOW: filter mode, count agents.       |
|   agentsec.control.decision           | SHOULD SEE: count>0, ALLOW.           |
|                                       | NEXT: fire ATK-002.                   |
+---------------------------------------+---------------------------------------+
```

### Row 5 — Execute attack (columns 1–12)

```text
+----------------------------------------------------------------------------------------+
| EXECUTE ATTACK                                                                         |
| Predict first: [ ] DENY before LLM   [ ] Model ran anyway                              |
| Then: ATTACK LAB → ATK-002 (prompt injection catalog) → copy agentsec.run.id           |
| Splunk does not send the payload. Attack Service does.                                 |
+----------------------------------------------------------------------------------------+
```

### Row 6 — What happened (action result) (columns 1–12)

```text
+----------------------------------------------------------------------------------------+
| WHAT HAPPENED  (from telemetry only — if no events, say so)                            |
| ACTION: ATK-002     RUN ID: ________      STATUS: (from latest event)                  |
| AGENTS: gen_ai.agent.id                                                                |
| CONTROL: agentsec.control.id / decision / reason                                       |
| operation.executed: true|false                                                         |
| WHY IT MATTERS: DENY+executed=true is a product bug, not a win.                        |
| NEXT STEP: Hunt the same run id.                                                       |
+----------------------------------------------------------------------------------------+
```

### Row 7 — Hunt query | Explanation (6 + 6)

```text
+---------------------------------------+---------------------------------------+
| HUNT QUERY (not validated)            | EXPLANATION                           |
| `agentsec_index`                      | Asking: for this run, was DENY        |
| agentsec.run.id=$run_id$              | before the LLM?                       |
| | table timestamp event.name          | Commands: filter run, table           |
|   user.id gen_ai.agent.id             | reconstruction fields.                |
|   agentsec.control.decision           | SHOULD SEE: DENY, executed=false,     |
|   agentsec.operation.executed         | technique AML.T0054.                  |
|   agentsec.technique.id               |                                       |
+---------------------------------------+---------------------------------------+
```

### Row 8 — Build detection (6 + 6)

```text
+---------------------------------------+---------------------------------------+
| BUILD DETECTION                       | EXPLANATION                           |
| Question: LIVE input DENY with        | Detection ≠ control.                  |
| operation.executed=false              | Same fields as CONTROL VALIDATION.    |
| (placeholder SPL only)                | After class: DETECTION LAB.           |
+---------------------------------------+---------------------------------------+
```

### Row 9 — Enable control | Retest (6 + 6)

```text
+---------------------------------------+---------------------------------------+
| ENABLE CONTROL                        | RETEST / WHAT CHANGED                 |
| This workshop: defended profile       | Repeat ATK-002. Compare run ids.      |
| already on. Vulnerable lab is a       | BEFORE/AFTER: executed flag.          |
| different LEARN item.                 |                                       |
+---------------------------------------+---------------------------------------+
```

### Row 10 — Before / after (6 + 6)

```text
+---------------------------------------+---------------------------------------+
| BEFORE (vulnerable or miss)           | AFTER (defended DENY)                 |
| Label both. No color-only.            | decision=DENY executed=false          |
+---------------------------------------+---------------------------------------+
```

### Row 11 — Evidence | Framework mapping (6 + 6)

```text
+---------------------------------------+---------------------------------------+
| EVIDENCE                              | FRAMEWORK MAPPING (educational)       |
| artifacts/<run-id>/                   | Not certification.                    |
| evidence.class = MEASURED only        | Invariant INV-008                     |
| if this run was live.                 | ATLAS id only if verified.            |
|                                       | Next: COMPLIANCE page, not a cert.    |
+---------------------------------------+---------------------------------------+
```

### Row 12 — Knowledge check (columns 1–12)

```text
+----------------------------------------------------------------------------------------+
| KNOWLEDGE CHECK                                                                        |
| 1. Where is the trust boundary?                                                        |
| 2. Can Splunk DENY the LLM call?                                                       |
| 3. If decision is DENY, what must operation.executed be?                               |
| Next page: INVESTIGATION (same run) or PROGRESS (mark workshop complete).              |
+----------------------------------------------------------------------------------------+
```

**Not on this workshop page:** MLTK charts, chain timelines, executive %, Run All 51, Cisco enforce, absolute-layout ornaments.

---

## What this file is not

- Not Dashboard Studio JSON  
- Not validated SPL  
- Not an implementation of the `agentsec` app
