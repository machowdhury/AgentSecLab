# LAB-PI-001 evidence requirements

Prevention and reconstruction use a **hierarchy**. A later layer cannot overrule an earlier one.

```text
1. Runtime          did AcmeBank invoke Ollama?
2. Local pack       artifacts/<run-id>/  (complete for this process)
3. Export           OTLP / HEC (lossy)
4. Splunk           corroborating copy of what arrived
```

Do not skip to Splunk and declare the lab proven.

## Gates

| Gate | What must be true | BASELINE reference | Defended ATK-002 reference | Fail closed |
|------|-------------------|--------------------|----------------------------|-------------|
| G1 Runtime | Hop table / spy / live client matches expected invoke vs prevent | Four live generates (2B run); 2A also `3367455f-…` (not exported) | Zero LLM calls; DENY before generate (`78f05d1b-…`; 2A also `9bdb542c-…` not exported) | If unknown, **NOT VERIFIED** — do not infer from Splunk |
| G2 Local completeness | `events.jsonl` sequences 1..N, no gaps, terminal event present | 22 events, `completed_allowed` | 6 events, `completed_denied`, zero `llm.*` | Incomplete pack → Splunk cannot prove |
| G3 Export honesty | `export.json` does not set `splunk.verified` from `otlp.ok` | `splunk.verified=false` on 2B packs; Splunk checked separately | same | Treat as NOT VERIFIED for Splunk until a search ran |
| G4 Splunk completeness | `stats count` / `dc(_raw)` equals local event count for that `run.id` | 22=22 MEASURED | 6=6 MEASURED | If unequal, Splunk is PARTIAL. Missing `llm.*` is not DENY |
| G5 Field contract | Indexed names from 2C.1; collapse mv copies | Q-* VALIDATED | Q-* VALIDATED | Hunting a non-indexed stand-in for `event.name` returns nothing — that is a query error, not safety |
| G6 Contract hunt | Q-LLM-AFTER-DENY on a **complete** copy | 0 rows (no DENY) | 0 rows (no llm after DENY in this copy) | 0 rows without G4 ≠ proof. SIMULATED one-row fixture is not OBSERVED |

## Required local files (INV-007)

Every `/process` run must write:

| File | Why |
|------|-----|
| `manifest.json` | schema 1.0.0, run/incident ids, profile, dimensions |
| `events.jsonl` | every security event |
| `request.json` | length, hash, preview ≤200 (not full prompt by default) |
| `result.json` | hops, attempted / executed / outcome |
| `export.json` | OTLP/HEC attempted and ok; Splunk not inferred |
| `limitations.json` | stub vs live, export loss, regex limits |

No `splunk_result.json` unless a query was actually run.

## What each layer is allowed to claim

| Claim | Allowed from |
|-------|----------------|
| “Ollama was not called” | Runtime (spy or live client) + complete local `events.jsonl` |
| “Splunk’s complete copy has no `llm.*`” | G4 + Q-LLM-EXECUTED |
| “No DENY-then-LLM sequence in this Splunk copy” | G4 + Q-LLM-AFTER-DENY |
| “The model approved the loan” | Not in scope; live wording is nondeterministic and not a control |
| “Detection DET-001 fired” | **Not claimed.** Detections are not implemented |

## Validated run ids for this lab

Use these when walking the workshop without a fresh export:

- BASELINE: `b3611d56-0d3f-4b2e-9a51-75ae36628155`
- Defended ATK-002: `78f05d1b-728e-4e70-8993-f5e365871f87`

Fresh runs are allowed if you repeat G1–G4. Do not mix Phase 2A never-exported ids into Splunk hunts.

## SIMULATED fixture

`searches/Q-LLM-AFTER-DENY-POSITIVE-CONTROL.spl` uses `| makeresults`. Index leak check for `simulated-q-llm-after-deny-0001` was **0**. Evidence class **SIMULATED**. It must not appear in a PROVE block as runtime behavior.

## Count pitfall (not an evidence failure)

`stats count by "agentsec.run.id"` → 66 / 18. Unique events remain 22 / 6 (`stats count`, `dc(_raw)`). Documented in `docs/SPLUNK_DATA_VALIDATION.md`. Do not reopen Phase 2B completeness for that inflation.
