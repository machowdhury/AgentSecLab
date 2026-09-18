# PHASE 11D — LAB-MEMORY-001 detection engineering analysis

**Date:** 2026-09-18  
**Type:** DESIGN / ANALYSIS ONLY  
**Primary verdict:** **DETECTION ANALYZED — NO NEW DETECTOR**  
**Schema:** `agentsec.security_event` **1.7.0** unchanged  
**DET-MCP-001:** unchanged  
**Q-MEMORY-CONTEXT-AUTHORITY:** KEEP AS-IS (documented limitations; not rewritten)  
**New detector:** none (`DET-MEMORY` not created)  
**New SPL:** none

Evidence class: 11B runtime + 11C Splunk = **DOCUMENTED** from LIVE field contracts. This file does **not** claim a new LIVE detection run. Pytest does **not** prove detection effectiveness.

Do not treat this as Phase 11E, a notable, Dashboard Studio, vector memory, LangChain, identity, rug-pull, or A2A.

**Phase 11E not started.**

No Agent Scan. No rug-pull. No A2A. No ML implementation.

---

## Security question

What should a SOC **detect** versus **hunt** versus retain as **context** for persistent-memory / INV-003?

Not “was malicious memory detected?” Named states A–H and planes 1–5 in `docs/MEMORY_RUNTIME_EVIDENCE_PLANES.md`.

---

## Evidence planes

| Plane | Question | Evidence type |
|-------|----------|----------------|
| 1 Persistence | What was written, by which run, fingerprint? | CONTEXT (persistence evidence) |
| 2 Recall / trust | Later recall, same hash, CTRL-MEMORY-CONTEXT-001 | CONTEXT + CONTROL EVIDENCE (OBSERVE) |
| 3 Influence / request | Did recall produce a privileged REQUEST? | HUNT / CONTEXT |
| 4 Authorization | CTRL-MCP-001 ALLOW / DENY | CONTROL EVIDENCE |
| 5 Execution | mcp.* + runtime handler count | EXECUTION EVIDENCE |

A production-quality detection must name which plane(s) it covers. 11C hunts already reconstruct each plane. 11D does not add SPL.

---

## LIVE ATTACK / RETEST evidence (from 11C, not re-ingested)

**SAME MEMORY. SAME REQUEST. DIFFERENT AUTHORIZATION.**

Malicious SHA-256 (emitted, not fixture-name inference): `sha256:1dc7335c3fd8c54326e36194d783536d944c6d527660eb1bda4a36a9cb5ed1b9`. Provenance `agentsec.memory.fixture`. Follow-on `lookup_customer_tier` / `customer:read`.

| | ATTACK write `05f1d8d0-28b7-40ac-bbb9-1dc64b4ba464` / recall `b8737cd9-9b6b-48f2-acfa-178ae1446ddc` | RETEST write `060a0a72-ceb5-4b99-8330-98de81d8ae5e` / recall `5d5b9d1b-092d-4ddb-8422-4092d289cd49` |
|--|--------------------------------------------------|--------------------------------------------------|
| Plane 1 | MALICIOUS write (defended store-only) | **same memory.id / SHA-256 / provenance** |
| Plane 2 | CONTEXT-001 OBSERVE `untrusted_data` | **same OBSERVE** |
| Plane 3 | hop-1 `lookup_customer_tier` | **same REQUEST** |
| Plane 4 | ALLOW overlay | DENY `tool_not_granted` |
| Plane 5 | handler **1**; `mcp.started` + `mcp.completed` | handler **0**; no `mcp.started` on COMPLETE copy |

**Discriminator is Plane 4, then Plane 5 — not the stored bytes.**

### Reconstruction

**BASELINE** A write `a8407246-7992-4ad8-bd02-cb701e150f30` / recall `914c41ce-5123-49eb-892c-c948295dbc46`: NORMAL hash `sha256:ee41410ab03d53a4f979cb3196619abb2aceedc69b41106ddd3a4e15599b340b`; OBSERVE; no unauthorized follow-on; handler **0**. Not SAFE.

**ATTACK:** write → later recall → OBSERVE → REQUEST → ALLOW → START → COMPLETE  
**RETEST:** write → later recall → OBSERVE → REQUEST → DENY → no START

Malicious content ≠ authorization bypass. Overlay ALLOW ≠ automatic success. Missing Splunk start ≠ independent prevention.

B is an **INTENTIONALLY VULNERABLE LAB PROFILE**. Memory did not authorize the tool.

---

## DET-MCP-001 reuse

Exact predicate: DENY then later `mcp.started` for the same `run.id` + tool.

11C MEASURED 0/0/0 on A/B/C **recall** run IDs. Correct:

- BASELINE: no DENY
- ATTACK: no DENY (ALLOW path)
- RETEST: DENY respected (no later start)

**0 rows is CORRECT BEHAVIOR.** **DET-MCP-001 silence is correct. It does NOT mean SAFE.** Do not broaden into a memory detector. Do not describe this as missed attack or detector failure.

DET-MCP-001 detects execution-after-DENY. It is not a memory-poisoning detector.

Secondary statement (not the phase verdict): **EXISTING DETECTOR SUFFICIENT FOR THE SPECIFIC INVARIANT** of execution-after-DENY only.

---

## New detector decision

**A. DETECTION ANALYZED — NO NEW DETECTOR**

Not B: a later “ungranted tool executed after untrusted recall” detector is **not** justified now. Grant snapshot is missing; overlay reason is lab-only; instruction-like preview is production-weak; identity isolation is absent.

Not C: DET-MCP-001 is sufficient **only** for DENY-then-start. 11A’s “NO DETECTOR JUSTIFIED” still holds after LIVE 11C.

Implementation of DET-MEMORY would require a separate explicit phase even if a future candidate later passed the bar. This phase does **not** implement one.

---

## Detection candidate matrix

See `docs/MEMORY_DETECTION_ENGINEERING_MODEL.md` for full rows.

| ID | Candidate | Classification |
|----|-----------|----------------|
| A | Memory write | **CONTEXT** |
| B | Memory recall | **CONTEXT** |
| C | Untrusted memory recall | **CONTEXT** |
| D | Recall + privileged REQUEST | **CONTEXT / HUNT** |
| E | Recall + DENY | **CONTEXT** |
| F | Recall + ALLOW | **REJECT AS PRODUCTION SIGNAL** |
| G | Recall + execution | **HUNT**; **REJECT** detector without grant snapshot |
| H | Write → later recall → REQUEST → execution | **HUNT** (Q-MEMORY); **REJECT** as detector |
| I | Rare/new provenance → request | **FUTURE BEHAVIORAL** / **TELEMETRY GAP** |
| J | Rare recall → tool sequence | **FUTURE BEHAVIORAL ANALYTICS** |
| K | Memory-write burst | **FUTURE BEHAVIORAL ANALYTICS** |
| L | Fingerprint change write→recall | **HUNT** (already); not DETECTION JUSTIFIED |
| M | Cross-agent / cross-tenant access | **TELEMETRY GAP** / FUTURE identity |
| N | Overlay reason string | **REJECT AS PRODUCTION SIGNAL** |
| O | AGENT MEMORY NOTE regex | **REJECT AS PRODUCTION SIGNAL** |

---

## Detection bar

Defined in `docs/MEMORY_DETECTION_ENGINEERING_MODEL.md`. Unmet. `allowed_tools`, tenant, and writer≠reader are **TELEMETRY GAP**. Do not invent them in SPL.

---

## Correlation quality

Phase 11C key: `memory.id` + SHA-256 + `source_run_id` + destination `run.id` + `gen_ai.agent.id` + `sequence`.

| Scope | Quality |
|-------|---------|
| This LAB, single agent, one memory per specimen | **ADEQUATE** (11C VALIDATED) |
| Multiple memories / multiple recalls | **PARTIAL** — `memory.id` is fixture id; bind specific write+recall tokens |
| Multi-agent / multi-user / multi-tenant | **TELEMETRY GAP** |
| Distributed / vector memory | **TELEMETRY GAP** (not instrumented) |

Do not invent `session.id` or `invocation.id`. Future requirements: grant snapshot, tenant, writer vs reader principal, corpus version / overwrite policy — as real fields in a later schema, not aliases.

---

## False positive analysis

Legitimate persistent preferences, user personalization, workflow state, expected recall before a tool call, authorized privileged requests, shared templates, repeated memory values, administrative workflows, benign unusual provenance (when more than one enum exists), new application releases, and legitimate agent behavior drift all look like candidates A–D. Prompt-injection-like language has **weak production specificity**. Overlay ALLOW as a notable would fire on any system that copied AgentSec’s reason string, and would miss real grants that lack that string.

Do not invent production statistics.

---

## False negative analysis

Current telemetry does **not** solve: semantic memory poisoning without the closed marker; paraphrased instructions; memory changed after telemetry capture; lost write or recall ingest; lost `mcp.started`; missing identity context; cross-agent memory use; external/vector stores not instrumented; multi-step delayed influence; LLM forming a different tool request; tool execution outside the instrumented runtime.

Do not claim 1.7.0 + this hunt closes those gaps.

---

## Existing hunt review

**KEEP AS-IS** with **DOCUMENT LIMITATION**. No new search file.

| Search | Answers | 11D action |
|--------|---------|------------|
| Q-MEMORY-CONTEXT-AUTHORITY | write → recall; recall → request; request → authz; indexed execution observation | KEEP AS-IS |
| Q-MCP-AUTHZ (recall `run.id`) | request → authorization | KEEP AS-IS |
| Q-MCP-TOOL / EXECUTED | authorization → execution (corroboration) | KEEP AS-IS |
| Q-MCP-AFTER-DENY / DET-MCP-001 | DENY then start | KEEP AS-IS |

No demonstrated correctness or security defect. Combining OBSERVE + overlay ALLOW in one notable would invite a fake detector.

---

## Behavioral / ML future path (DESIGN ONLY — not implemented)

| Idea | Possible later tool | Constraint |
|------|---------------------|------------|
| New memory provenance for this agent | Statistical SPL (`rare`) | Enum must grow first |
| Memory recalled unusually often | `timechart` | Needs population |
| Recall followed by a rarely used tool | Statistical SPL; later MLTK | Sensitive-tool list FUTURE |
| Novel retrieve/recall → tool sequence | MLTK clustering | Needs population |
| Memory-write volume spike | `timechart`; later Cisco Time Series Model (CDTSM) Feature Preview | Metric series required |
| Privileged-request frequency after recall | Statistical SPL | High FP |
| Unusual resources after recall | Out of this lab | Resource chapter already exists separately |
| Cross-agent memory relationship change | Identity / A2A first | Do not fake A2A |

**ANOMALY != INCIDENT.**  
**ML MAY PRIORITIZE INVESTIGATION.**  
**ML MUST NOT GRANT OR DENY AUTHORITY.**  
Do not implement ML in Phase 11D.

---

## Identity / A2A boundary (FUTURE / TELEMETRY GAP)

Do not implement identity or A2A. Honest gaps:

- writer ≠ reader
- agent A writes memory consumed by agent B
- tenant A memory recalled in tenant B
- principal mismatch / delegated identity mismatch
- cross-agent authority propagation

These cannot be solved with the current single-agent fixture store. Do not invent correlation ids to paper over them.

---

## Framework mapping

Conservative revalidation of `docs/MEMORY_PREDECESSOR_ANALYSIS.md` / `docs/MEMORY_SECURITY_MODEL.md`. Attack taxonomy ≠ detection proof.

| Item | Status |
|------|--------|
| INV-003 | **SUPPORTED** by runtime + hunts, not by a new detector |
| INV-002 | **RELATED** (supporting; content ≠ grant) |
| OWASP Agentic ASI06 memory path | **RELATED** (taxonomy of the attack class; do not map all of ASI06 onto one notable) |
| OWASP LLM01:2025 indirect PI | **RELATED** (memory as persistence layer) |
| OWASP LLM08 / LLM04 | **RELATED** (not this lab’s proof) |
| NIST AI 600-1 indirect PI / data poisoning | **RELATED** |
| MITRE ATLAS AML.T0080 / AML.T0080.000 Memory | **UNMAPPED / REQUIRES REVALIDATION** (no live official ATLAS page claimed) |
| New ATLAS IDs | **not forced** |

---

## Splunk ES future model (DESIGN ONLY)

If a later phase ever passed the detection gate, a finding would need **separate provenance** for:

- memory persistence (writer run, id, SHA-256, provenance)
- memory recall/trust (destination run, OBSERVE, `untrusted_data`)
- authorization (CTRL-MCP-001 decision/reason, requested vs coded scope)
- execution (handler count; mcp.* as corroboration)

Plus `gen_ai.agent.id` and drilldown to `Q-MEMORY-CONTEXT-AUTHORITY` + `Q-MCP-AUTHZ`. CIM **NOT APPLICABLE**.

Do **not** create savedsearches, notables, risk events, findings, investigations, or playbooks in 11D. Do not invent a risk score.

---

## Splunk knowledge-object review

`docs/reviews/splunk-ko-review-memory-detection-2026-09-18.md`

| Class | Item |
|-------|------|
| REQUIRED | None |
| RECOMMENDED | Keep `Q-MEMORY-CONTEXT-AUTHORITY` as hunt; keep DET-MCP-001 disabled and narrow; bind Q-MCP to the recall `run.id` |
| OPTIONAL | Teaching overlay positive-control (SIMULATED), not indexed |
| DEFERRED | ES finding/risk, grant-snapshot field, `gen_ai.tool.call.id`, identity/tenant fields, behavioral models, Studio (Phase 11E) |
| REJECT | DET-MEMORY, overlay-reason detector, instruction-regex detector, extra Q-MEMORY files, CIM force-map, `session.id` / `invocation.id` |

---

## Tests

`uv run --extra test python -m pytest tests -q --tb=line -m "not live_ollama and not live_splunk"` → **609 passed, 2 deselected** (2026-09-18).

**Pytest proves repository consistency only. It does not prove detection effectiveness.** This phase did not manufacture a positive control to justify a detector.

---

## Security semantics (preserved)

This analysis does **not** claim: memory written = compromise; memory recalled = attack; `untrusted_data` = malicious; suspicious text = exploit; request = grant; ALLOW = execution; `mcp.started` = success; DENY = proof of prevention; missing Splunk row = blocked; NORMAL = safe; known malicious hash = compromise; DET-MCP-001 silence = safe; anomaly = incident; Splunk = enforcement; ML = authorization authority.

---

## Maturity

| Object | Maturity |
|--------|----------|
| Q-MEMORY-CONTEXT-AUTHORITY | LAB VALIDATED (11C) as hunt, not detection |
| DET-MCP-001 | LAB VALIDATED for DENY-then-start |
| Candidates A–O as detections | EXPERIMENTAL / REJECT / GAP / FUTURE |
| Any memory notable | **Not** PRODUCTION CANDIDATE |

---

## Verdict

**DETECTION ANALYZED — NO NEW DETECTOR**

STOP. Phase 11E not started. No Dashboard Studio. No DET-MEMORY even as a candidate. No Phase 12. No identity, A2A, vector memory, rug-pull, autonomous red team, or behavioral-analytics implementation.

### Files created

- `docs/PHASE11D_MEMORY_DETECTION_ANALYSIS.md`
- `docs/MEMORY_DETECTION_ENGINEERING_MODEL.md`
- `docs/MEMORY_RUNTIME_EVIDENCE_PLANES.md`
- `docs/learning-notes/memory-detection-vs-hunting.md`
- `docs/reviews/splunk-ko-review-memory-detection-2026-09-18.md`
- `tests/unit/test_phase11d_design.py`

### Files modified

- `docs/IMPLEMENTATION_STATUS.md`
- `docs/AGENTSEC_ROADMAP_2026.md`
- `docs/AGENTSEC_LEARNING_ARCHITECTURE.md`
- `docs/MEMORY_DETECTION_MODEL.md` (11D pointer only; 11A “NO DETECTOR JUSTIFIED” retained)
- `docs/SPLUNK_KNOWLEDGE_OBJECT_INVENTORY.md` (11D review pointer; no new objects)

Runtime, schema 1.7.0, DET-MCP-001, Q-MEMORY, Q-MCP, and Studio were **not** changed.

### Limitations

- No new LIVE ingest; 11C contracts remain authoritative.
- Pytest does not prove detector effectiveness.
- Grant snapshot / tenant / writer≠reader remain TELEMETRY GAP.
- Overlay ATTACK is a labeled lab fail-open, not a production incident class.
