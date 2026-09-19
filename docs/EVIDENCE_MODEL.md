# Evidence Model

**Status:** Phase 1B contract. Phase 2A writes `artifacts/<run-id>/` for every completed/failed `/process` run. Splunk export is **not attempted / NOT VERIFIED**.  
**Path:** `artifacts/<run-id>/`  
**Parent:** `docs/SECURITY_EVENT_MODEL.md`

Evidence reconstructs **one** `/process` experiment. It is not a control. Splunk is not authoritative for whether the LLM was invoked.

`src/agentsec/evidence.py` implements this contract for Phase 2A.

---

## Evidence hierarchy

```text
AUTHORITATIVE RUNTIME STATE     (did AcmeBank invoke Ollama?)
  → LOCAL RUN EVIDENCE          artifacts/<run-id>/  (complete for this process)
  → EXPORTED TELEMETRY          OTLP / HEC (lossy)
  → SPLUNK REPRESENTATION       corroborating only
```

| Layer | Role |
|-------|------|
| Runtime | Authoritative for invocation vs prevention (call attempted/executed). |
| Local bundle | Authoritative lab record **if** `events.jsonl` is complete for the run. |
| Export | What left the box. |
| Splunk | Index view. Missing `llm.*` **does not** prove DENY unless completeness for that `run.id` is established (`export.json` ok + expected events present). |

---

## Lifecycle

```text
AcmeBank finishes the run (runtime state already decided)
  → write artifacts/<run-id>/   always, even if OTLP/HEC fails
  → collector may copy events to Splunk
  → PROVE uses runtime + local bundle; Splunk only if export succeeded
```

---

## Directory

`artifacts/<agentsec.run.id>/`

---

## Content storage (default)

| Stored | Not stored by default |
|--------|------------------------|
| Sanitized preview (≤200 chars) | Complete prompts / full request body |
| SHA-256 content hash | `.env`, HEC tokens, Flask secrets |

Full content capture is an **explicit future lab configuration**, not required for evidence in this contract.

---

## Minimum files

| File | Purpose |
|------|---------|
| `manifest.json` | Research-integrity metadata + schema version |
| `events.jsonl` | Every security event, schema 1.0.0 |
| `request.json` | `input.length`, `input.hash`, `input.preview` only |
| `result.json` | Hop table with attempted / executed / outcome |
| `export.json` | OTLP/HEC attempted and ok |
| `limitations.json` | Nondeterministic LLM, export loss, stub vs live, Splunk not authoritative for invocation |

No `splunk_result.json` unless a query was **actually run**.

---

## `manifest.json` required keys

| Key | Rule |
|-----|------|
| `schema.name` | `agentsec.security_event` |
| `schema.version` | `1.0.0` |
| `run.id` / `incident.id` | Equal UUIDs |
| `lab.id` | e.g. `agentsec-local` |
| `agentsec.version` | Producer version |
| `model` | Configured Ollama model |
| `security.profile` | `defended` \| `vulnerable` |
| `testbed.mode` | `BASELINE` \| `ATTACK` \| `RETEST` |
| `execution.mode` | First lab: `LIVE` |
| `telemetry.fidelity` | First lab: `OBSERVED` |
| `attack.id` | `ATK-001` \| `ATK-002` as applicable |
| `expected.behavior` / `actual.behavior` | From runtime + events, not invented Splunk prose |
| `control.result` | Decision that governed the last blocking or final hop |
| `llm.invoked.count` | Count of hops with `operation.executed=true` (includes invocations that later failed) |
| `llm.completed.count` | Count of `llm.completed` |
| `blocked` | Pipeline stopped before four successful ALLOW completions |
| `evidence.class` | OBSERVED / MEASURED / … with scope stated |
| `splunk.validated` | `false` unless a real Splunk transcript is attached |
| `workflow.entry` | `/process` |
| `runtime.authoritative` | `true` (invocation recorded by AcmeBank) |

Local events are MEASURED **against the local file**, not Splunk.

---

## `export.json`

Layered export status. Each layer is independent. Sequence F (export failed) is proven when `otlp.ok` is false **or** when a later independent observation shows collector/HEC/Splunk failure.

Runtime fields:

| Field | Set by runtime? | Meaning |
|-------|-----------------|---------|
| `otlp.attempted` | yes | At least one event was handed to the OTLP logger |
| `otlp.flush_ok` | yes | `LoggerProvider.force_flush` returned true |
| `otlp.ok` | yes | SDK emit + flush succeeded. **Not** collector/HEC/Splunk |
| `collector.observed` | no (always false) | Requires collector file or metrics |
| `hec.ok` | no (always false) | Requires independent HEC observation |
| `splunk.verified` | no (always false) | Requires an independent Splunk search |

`otlp.ok` MUST NOT be recorded as collector received, HEC accepted, Splunk indexed, or Splunk verified. Splunk searches are invalid as prevention proof when export failed or completeness for that `run.id` is not established.

---

## `result.json` hop rows

| Field | DENY before invoke | LLM success | LLM started then failed |
|-------|--------------------|-------------|-------------------------|
| `control.decision` | DENY | ALLOW | ALLOW |
| `operation.attempted` | false | true | true |
| `operation.executed` | false | true | true |
| `operation.outcome` | prevented | success | error |
| `llm.started` | false | true | true |
| `llm.completed` | false | true | false |

Hop 1–3 rows include `delegator.agent.id`. Hop 0 omits it.

---

## Splunk completeness (corroboration only)

A Splunk hunt for a `run.id` may be treated as **complete corroboration** only when:

1. `export.json` records successful export for that run, and
2. The indexed event set for that `run.id` matches the local `events.jsonl` (same `event.name` sequence / count).

Otherwise Splunk is an incomplete copy. Missing `llm.*` is not prevention.

Exact SPL is out of scope for this phase.

---

## Forbidden

- Using Splunk “no llm events” as sole DENY proof
- Storing complete prompts by default
- Labeling SYNTHETIC export as OBSERVED live proof
- Secrets in the bundle
- `operation.executed=false` on a hop that emitted `llm.started` or `llm.failed`
