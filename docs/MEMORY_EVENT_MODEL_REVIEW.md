# Agent memory — event model review

**Status:** Phase 11A **DESIGN**. Schema **1.6.0 unchanged**. No emitter. No SPL.

Parents: `docs/SCHEMA_1_6_0.md`, `docs/RAG_EVENT_MODEL_REVIEW.md`, `.cursor/rules/33-splunk-agent-skills.mdc`, `.cursor/skills/splunk-ko-review/SKILL.md`.

Governance: SECURITY QUESTION → EVIDENCE → VALIDATED TELEMETRY → INDEXED FIELD DISCOVERY → FIELD CONTRACT → SPL. This file stops at **evidence requirement**. Do not invent fields as indexed evidence. Do not write searches.

Official skills consulted for **design** (no KO created): Knowledge Object Governance (reuse later), Field Extraction and CIM Mapping (CIM NOT APPLICABLE until events exist), Splunk Search (questions before SPL), Dashboard (future consumer only).

---

## Verdict

**SCHEMA BUMP JUSTIFIED** (proposed **1.7.0** in a later implementation phase if 11B emits live memory observation).

Schema 1.6.0 is **closed** (`additionalProperties: false`). It can represent the **follow-on** hop honestly. It **cannot** honestly represent memory write, memory recall, memory id, source/destination run, or a memory observation control.

Do **not** bump schema in Phase 11A.

---

## Need vs 1.6.0

| Need | 1.6.0 today | Classification |
|------|-------------|----------------|
| Follow-on CTRL-MCP-001 ALLOW/DENY | `control.decision` + `mcp_allowlist` | **SUPPORTED** |
| Follow-on execution | `mcp.started` / completed / failed | **SUPPORTED** |
| Fail-open reason string | `control.reason` | **SUPPORTED** (if 11B emits it on recall) |
| Hash / preview **fields exist** | `content.hash`, `content.preview` | **PARTIAL** — exist, **unbound** to memory |
| Correlation within one run | `run.id`, `sequence` | **SUPPORTED** for the recall run only |
| Agent identity | `gen_ai.agent.id` | **PARTIAL** — one agent; no writer≠reader |
| RAG observation | `rag_context_trust` / RAG-CONTEXT-001 | **NOT APPLICABLE** — wrong channel |
| Result / metadata trust | `mcp.result.trust` / `mcp.metadata.trust` | **NOT APPLICABLE** |
| Memory write event | none | **MISSING** |
| Memory recall event | none | **MISSING** |
| Memory id | none (must not stuff into tool name) | **MISSING** |
| Memory provenance | none | **MISSING** |
| Memory trust class | none | **MISSING** |
| Source run (write) | `run.id` is **this** run only | **MISSING** as a link field |
| Destination run (recall) | `run.id` is this run | **PARTIAL** — recall run is `run.id`; write run not linked |
| `session.id` | schema forbids / “No session.id” | **NOT APPLICABLE** — do not add for this lab |
| `trusted_memory` | absent | **NOT APPLICABLE** — must not add |
| Full memory body | preview only | **NOT APPLICABLE** to index |

Reusing CTRL-RAG-CONTEXT-001 or RAG document id for memory is **FORBIDDEN**.

---

## Splunk security questions (no SPL)

| # | Question | Classification |
|---|----------|----------------|
| Q1 | What memory was written? | **REQUIRES NEW TELEMETRY** |
| Q2 | Who/what wrote it? | **REQUIRES NEW TELEMETRY** (bind writer agent) |
| Q3 | What was its provenance? | **REQUIRES NEW TELEMETRY** |
| Q4 | What was its fingerprint? | **PARTIAL** — hash field exists, unbound |
| Q5 | Which later run recalled it? | **REQUIRES NEW TELEMETRY** (destination vs source run) |
| Q6 | Was recalled memory classified as data? | **REQUIRES NEW TELEMETRY** (observation control) |
| Q7 | Did recall influence a privileged request? | **PARTIAL** — tool request on recall run; influence not a boolean field |
| Q8 | What tool/scope was requested? | **SUPPORTED NOW** on recall run (Q-MCP-AUTHZ later) |
| Q9 | ALLOW or DENY? | **SUPPORTED NOW** on recall run |
| Q10 | Did the handler start? | **SUPPORTED NOW** |
| Q11 | Complete/fail? | **SUPPORTED NOW** |
| Q12 | Did ATTACK and RETEST recall the same memory? | **REQUIRES NEW TELEMETRY** (stable memory.id + hash across runs) |
| Q13 | Can we prove the memory itself authorized anything? | **NOT APPLICABLE** as a positive proof — teaching: it must **not**; evidence is DENY vs overlay ALLOW |
| Q14 | Reconstruct write → recall → request → authz → execution? | **REQUIRES NEW TELEMETRY** for the write↔recall join |

Until 11B+ field discovery: **TELEMETRY GAP — QUERY NOT DEFENSIBLE** for Q1–Q6, Q12, Q14 as indexed hunts.

No-data semantics (later): zero rows ≠ safe; missing start ≠ blocked.

CIM: **NOT APPLICABLE**. Do not map memory records to Authentication or Malware.

KO duplication: none. Do not create Q-MEMORY-* in 11A. Prefer later one hunt (e.g. Q-MEMORY-AUTHORITY) after discovery, plus Q-MCP reuse.

Dashboard: future only. Tokens would need **write run** and **recall run**, unlike RAG’s single run.id.

Performance: not applicable (no SPL).

---

## Correlation model (design)

Join keys **when they exist**: `memory.id` + `content.hash` + write `run.id` + recall `run.id`.

Do not invent `invocation.id`. Do not add `session.id` to force a session abstraction. Two UUIDs are enough for the lab.

---

## Minimal additive 1.7.0 (proposal only — not implemented)

If 11B emits live observation:

1. `agentsec.schema.version` const **1.7.0**.
2. `agentsec.attack.id` additive **`MEMORY-001`**.
3. `agentsec.control.type` additive **`memory_context_trust`**.
4. When that type: `control.id` const **`CTRL-MEMORY-CONTEXT-001`**. Decisions: **OBSERVE** on honest recall (and write classification if emitted). Vulnerable ALLOW stays on **CTRL-MCP-001**.
5. `agentsec.trust_boundary` additive **`agent.memory.store`**.
6. Memory trust enum **`untrusted_data`**. Provenance enum **`agentsec.memory.fixture`**.
7. Opaque `memory.id`. Reuse `content.hash` / `content.preview` for the **body**.
8. Link field for the **other** run (write run id on recall events, or explicit source/destination). Exact names are an 11B contract, not 11A indexed facts.
9. Optional `gen_ai.workflow.name` additive `memory_lab`. Optional `content.influence.kind` additive `recalled_memory`.

**Do not add:** `trusted_memory`, `memory_allowed_tools`, full body, PII, `session.id`, scanner fields on `otel:agentic:json`.

1.6.0 field **meanings stay unchanged**.

---

## 11B resolution (implemented)

Phase 11B confirmed SCHEMA BUMP JUSTIFIED and implemented **1.7.0** as specified above.

Exact names chosen:

- `agentsec.memory.id`
- `agentsec.memory.provenance` = `agentsec.memory.fixture`
- `agentsec.memory.trust` = `untrusted_data`
- `agentsec.memory.source_run_id` = write run
- current `agentsec.run.id` on recall = destination run (no `destination_run_id`)
- `event.name`: `agentsec.memory.written` / `agentsec.memory.recalled`

This section records the contract; it does not rewrite the 11A design history above.

