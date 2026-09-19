# Splunk as a security workbench 101

**Status:** PLANNED (Phase 1C UX contract). No dashboards or validated SPL in this phase. Event semantics: `SECURITY_EVENT_MODEL.md` schema **1.0.0**.

---

## WHAT IS IT?

Splunk is AgentSec’s **workbench**: where you look at telemetry, hunt a `run.id`, learn detections, and talk about evidence.

It is not AcmeBank. It is not the Attack Service. It is not Ollama. It does not decide ALLOW or DENY.

## WHY DOES IT EXIST?

If the only UI is the bank app, you never practice SOC skills. If the only UI is fifteen coverage dashboards, you skip baseline and treat SIMULATED rows as blocked attacks (AgentWatch lesson).

AgentSec uses Splunk to walk:

LEARN → BASELINE → ATTACK → OBSERVE → HUNT → DETECT → DEFEND → RETEST → INVESTIGATE → MEASURE → PROVE

First lab: one benign loan, ATK-002, CTRL-INPUT-001, two profiles.

## HOW DOES IT WORK?

AcmeBank emits security events (OpenTelemetry → collector → HEC → index `agentsec_telemetry`). You hunt with `agentsec.run.id` (same value as `incident.id`).

Pages have one job each: HOME orients, LEARN runs WS-001, ATTACK LAB points at the Attack Service, OBSERVE shows hops, INVESTIGATION reconstructs, DETECTION LAB turns a question into a detection (no ML), CONTROL VALIDATION proves placement, PROGRESS stores your run.ids.

“What happened?” is filled from fields: decision, attempted, executed, outcome. Not from a paragraph someone wrote. Not from an LLM narrator.

## WHERE DOES IT SIT IN AGENTSEC?

```text
Runtime (authoritative: did Ollama start?)
  → Local artifacts/<run-id>/
  → Export (may fail)
  → Splunk (copy)
```

Splunk is the last box. A copy can be incomplete.

## WHAT IS THE TRUST BOUNDARY?

`observability.export` — Splunk is **outside** authorization. Seeing a DENY in the index did not stop the model. Missing `llm.*` did not stop the model either.

## WHAT COULD AN ATTACKER CONTROL?

The loan text (preview/hash in events). Not `run.id`, profile, control decision, operation flags, or schema version. They also cannot make Splunk a backdoor to Ollama.

## WHAT CAN GO WRONG?

- Treating “no LLM event in Splunk” as proof of DENY.  
- Calling `llm.failed` a blocked call (`executed` is true, outcome is error).  
- Filtering `testbed.mode=LIVE` (LIVE is how it ran, not the experiment).  
- Painting DENY red without the word DENY.  
- Empty dashboard shells for MCP/MLTK.  
- Inventing SPL before events exist.

## WHAT TELEMETRY SHOULD EXIST?

First-lab names only: `run.*`, `hop.*`, `control.decision`, `llm.*`, `pipeline.stopped`. Schema name + version on every event. Default content: preview + hash.

## HOW WILL SPLUNK SHOW IT?

Hop cards under one run.id. Control then LLM. Evidence chips: COMPLETE / PARTIAL / FAILED / NOT VERIFIED per layer. Never a single “PROVEN” tile because the index had rows.

Searches are **questions** in `SPLUNK_SEARCH_CONTRACT.md` until someone validates SPL later.

## WHAT CONTROL COULD CHANGE THE RESULT?

CTRL-INPUT-001 on AcmeBank. Vulnerable ATTACK vs defended RETEST, same payload. Splunk detections do not move that control.

## WHAT TEST PROVES THE LOGIC?

Stub LLM: DENY ⇒ zero generate calls. That is a runtime test. A Splunk test does not exist until a query is written **and run**. This note does not claim either Splunk or live Ollama succeeded.

---

## What I should now be able to explain

1. Why Splunk is a workbench and not a control plane.  
2. The four-layer evidence hierarchy and why missing `llm.*` is not proof.  
3. What `operation.executed` means (started, not succeeded).  
4. Why ALLOW is not execution, and why `llm.failed` is not DENY.  
5. BASELINE vs ATTACK vs RETEST versus `execution.mode=LIVE`.  
6. How hop cards show pipeline → hop → control → LLM without OTel jargon.  
7. Why CONTROL VALIDATION needs a RETEST run.id and local `export.json`.  
8. What DET-001 is asking, without writing SPL.  
9. Why HOME has no coverage heatmap.  
10. Which nav items are first lab versus placeholder (chains, MLTK, MCP, executive).
