# PHASE 10D — RAG / retrieved-context detection engineering analysis

**Date:** 2026-09-16  
**Type:** DESIGN / ANALYSIS ONLY  
**Primary verdict:** **DETECTION ANALYZED — NO NEW DETECTOR**  
**Schema:** `agentsec.security_event` **1.6.0** unchanged  
**DET-MCP-001:** unchanged  
**Q-RAG-CONTEXT-AUTHORITY:** KEEP AS-IS (documented limitations; not rewritten)  
**New detector:** none (`DET-RAG` not created)

Evidence class: 10B runtime + 10C Splunk = **DOCUMENTED** from LIVE field contracts. This file does **not** claim a new LIVE detection run. Pytest does **not** prove detection effectiveness.

Do not treat this as Phase 10E, a notable, Dashboard Studio, embeddings, memory, rug-pull, or A2A.

**Phase 10E not started.**

No Agent Scan. No rug-pull. No A2A.

---

## Security question

What should a SOC **detect** versus **hunt** versus retain as **context** for retrieved-context / indirect prompt injection?

Not “was RAG poisoned?” At least states A–J in `docs/RAG_RUNTIME_EVIDENCE_PLANES.md`.

---

## Evidence planes

| Plane | Question | Sourcetype / source |
|-------|----------|---------------------|
| 1 Retrieval | What was retrieved, from where, fingerprint? | `otel:agentic:json` CONTEXT-001 document.id / hash / provenance |
| 2 Trust / influence | Classified how, and did it shape a REQUEST? | CTRL-RAG-CONTEXT-001 OBSERVE + hop-1 request fields |
| 3 Authorization | Was the request granted? | hop-1 CTRL-MCP-001 ALLOW/DENY/reason |
| 4 Execution | Did the handler begin/complete/fail? | Runtime handler counts; `mcp.started`/`completed`/`failed` |

A production-quality detection must name which plane(s) it covers. 10C hunts already reconstruct each plane. 10D does not add SPL.

---

## LIVE ATTACK / RETEST evidence (from 10C, not re-ingested)

Same malicious document: `doc.lending-policy.malicious`, hash `sha256:c565f364c7c5fba3cf25d235bb8e2bee7d9433daa9f07d5e097ab6d2a82a97ef`, provenance `rag.local.fixture`, follow-on `lookup_customer_tier` / `customer:read`.

| | ATTACK `3a43d24f-9281-42f6-8375-1fb2efaa80ac` | RETEST `bea97bae-491b-4b36-b52f-1417d2bad01b` |
|--|-----------------------------------------------|-----------------------------------------------|
| Plane 1 | MALICIOUS retrieve | **same document / hash / provenance** |
| Plane 2 | CONTEXT-001 OBSERVE `untrusted_data` | **same OBSERVE** |
| Plane 2 request | hop-1 `lookup_customer_tier` | **same REQUEST** |
| Plane 3 | ALLOW overlay | DENY `tool_not_granted` |
| Plane 4 | handler **1**; `mcp.started` + `mcp.completed` | handler **0**; no `mcp.started` on COMPLETE copy |

**Discriminator is Plane 3, then Plane 4 — not the retrieved document.**

### Reconstruction

**ATTACK:** retrieve → OBSERVE → REQUEST → ALLOW → START → COMPLETE  
**RETEST:** retrieve → OBSERVE → REQUEST → DENY → no START

Malicious content ≠ authorization bypass. Overlay ALLOW ≠ automatic success (`mcp.started` ≠ success). Missing Splunk start ≠ independent prevention (handler count is authoritative).

BASELINE A `51f70fb9-994e-4dd4-9b36-cac6fb1e8232`: NORMAL retrieve, OBSERVE, no follow-on. Not SAFE.

---

## DET-MCP-001 reuse

Exact predicate: DENY then later `mcp.started` for the same `run.id` + tool (`eventstats` by `run_id, tool`; `sequence>deny_sequence`).

10C MEASURED 0/0/0 on A/B/C. Correct:

- BASELINE: no DENY
- ATTACK: no DENY (ALLOW path)
- RETEST: DENY respected (no later start)

**DET-MCP-001 silence is correct. It does NOT mean SAFE.** Do not broaden into a RAG detector.

Secondary statement (not the phase verdict): **EXISTING DETECTOR SUFFICIENT FOR THE SPECIFIC INVARIANT** of execution-after-DENY only.

---

## New detector decision

**A. DETECTION ANALYZED — NO NEW DETECTOR**

Not B: a later “ungranted tool executed after untrusted retrieval” detector is **not** justified now. Grant snapshot is missing; overlay reason is lab-only; instruction-like preview is production-weak.

Not C as the overall RAG/INV-002 property: DET-MCP-001 is sufficient **only** for DENY-then-start.

10A’s “DETECTION CANDIDATE (later)” remains a **future** bar, not a 10D implementation warrant.

---

## Detection candidate matrix

See `docs/RAG_DETECTION_ENGINEERING_MODEL.md` for full rows.

| ID | Candidate | Classification |
|----|-----------|----------------|
| A | untrusted_data retrieved | **CONTEXT** |
| B | Instruction-like retrieved text | **REJECT** detector; **HUNT** later |
| C | Known malicious hash | **CONTEXT** |
| D | Retrieval + privileged REQUEST | **CONTEXT / HUNT** |
| E | Retrieval + DENY | **CONTEXT** |
| F | Retrieval + ALLOW | **REJECT** detector |
| G | Retrieval + execution | **HUNT**; **REJECT** detector without grant snapshot |
| H | Content + REQUEST + ALLOW | **REJECT** production (lab overlay) |
| I | Content + REQUEST + execution | **TELEMETRY GAP** as “unauthorized” detector |
| J | DENY then execution | **DETECTION** — DET-MCP-001 |
| K | Rare tool after retrieval | **FUTURE BEHAVIORAL / ML** |
| L | Novel source + privileged op | **FUTURE BEHAVIORAL / ML** / **TELEMETRY GAP** |
| M | Abnormal retrieve→tool sequence | **FUTURE BEHAVIORAL / ML** |
| N | Retrieval burst + sensitive ops | **FUTURE BEHAVIORAL / ML** |

---

## False positive analysis

Legitimate retrieved instructions, policy runbooks, “note to staff,” workflow automation, authorized follow-on tools, shared hashes, repeated retrieval, admin documents, and this lab’s own fixtures all look like candidates A–D. Prompt-injection-like language has **weak production specificity**: corpora are full of imperatives. Overlay ALLOW as a notable would fire on any system that copied AgentSec’s reason string, and would miss real grants that lack that string.

---

## False negative analysis

Current telemetry does **not** solve: semantic injection without the closed marker; obfuscation; multilingual instructions; content changed after fingerprint (check/use is in-run frozen, not a corpus pin); missing/incomplete ingest; influence without an immediate tool request; multi-hop reasoning; **memory-mediated** influence (INV-003, not this lab); same-tool follow-on (no `gen_ai.tool.call.id`); **cross-run** influence; model behavior that never emits a tool request; retrieval through external RAG stacks (embeddings/LangChain not in 10B).

Do not claim 1.6.0 + this hunt closes those gaps.

---

## Severity analysis

No invented score. Malicious-looking content ≠ exploit ≠ unauthorized request ≠ authz failure ≠ unauthorized execution ≠ successful privileged operation. Incident-grade evidence needs grant context or DET-MCP-001’s DENY-then-start.

---

## Production detection bar

Defined in `docs/RAG_DETECTION_ENGINEERING_MODEL.md`. Unmet. `allowed_tools` and `gen_ai.tool.call.id` are **TELEMETRY GAP**. Do not invent them in SPL.

---

## Q-RAG-CONTEXT-AUTHORITY review

**KEEP AS-IS** with **DOCUMENT LIMITATION**.

Adequately reconstructs retrieval, trust, follow-on request, authorization, and indexed execution observation for one `run.id`. Limitations already in the hunt `.md`: no grant snapshot; `derived_authority` is a lab helper; hop-1 hash ≠ document hash; missing start ≠ handler proof; no two-run join; hop 0 is observation not `lookup_policy`.

No defect that requires a rewrite. 10D does **not** change the file.

Q-MCP-AUTHZ / TOOL / EXECUTED / AFTER-DENY: **KEEP AS-IS** (documented extra CONTEXT-001 rows from 10C).

---

## Behavioral / ML future path (DESIGN ONLY — not implemented)

| Idea | Possible later tool | Constraint |
|------|---------------------|------------|
| Rare privileged tool after retrieval | Splunk statistical SPL (`rare`, baselines) | Hunt first; high FP |
| New retrieve→tool sequence | Statistical SPL; later MLTK clustering | Needs population |
| Novel retrieval source | rare `rag.context.provenance` | Enum must grow first |
| Unusual document→tool relationship | Lookups / reports | Not a detector first |
| Agent-specific deviation | MLTK / time series | Per-agent baseline |
| Retrieval burst then sensitive action | `timechart`; later Cisco Time Series Model (CDTSM) Feature Preview | Metric series required |
| New sensitive tool for an established agent | Statistical SPL + sensitive-tool list | List is FUTURE |
| Cross-agent propagation | Out of 10D; A2A not started | Do not fake A2A |

ML/anomaly detection may **prioritize investigation**. ML must **never** grant or deny authority. Do not build these models now.

---

## Framework mapping

Conservative revalidation of `docs/RAG_CONTEXT_SECURITY_MODEL.md`. Attack taxonomy ≠ detection evidence.

| Item | Status |
|------|--------|
| OWASP LLM01:2025 indirect prompt injection | **DIRECT** (taxonomy of the attack class) |
| OWASP LLM08 / LLM04 | **RELATED** (not this lab’s proof) |
| OWASP Agentic ASI06 / ASI02 | **RELATED** |
| NIST AI 600-1 indirect PI | **RELATED** |
| MITRE ATLAS AML.T0070 RAG Poisoning | **UNMAPPED / REQUIRES REVALIDATION** (atlas URL 404 on 2026-09-16) |
| MITRE ATLAS AML.T0020 | **UNMAPPED** (training data, not retrieve) |
| INV-002 | **SUPPORTED** by runtime, not by a new detector |

---

## Splunk ES future model (DESIGN ONLY)

If a later phase ever passed the detection gate, a finding would need: named plane(s), retrieval provenance + document hash (not preview as join), `gen_ai.agent.id`, requested tool, CTRL-MCP-001 decision/reason, execution evidence, control ids, `run.id` drilldown to `Q-RAG-CONTEXT-AUTHORITY` + `Q-MCP-AUTHZ`. CIM **NOT APPLICABLE**.

Do **not** create savedsearches, notables, risk events, findings, ES detections, or correlation searches in 10D. Do not invent risk scores.

---

## External tool positioning (not integrated)

| Tool | Role if later used | Class |
|------|--------------------|-------|
| garak | Probe model obedience to retrieved instructions | **ATTACK GENERATION** / **EVALUATION** — **NOT AUTHORIZATION** |
| Promptfoo | RAG/injection eval suites | **EVALUATION** / **ATTACK GENERATION** — **NOT AUTHORIZATION** |
| PyRIT | Orchestrated red-team probes | **ATTACK GENERATION** — **NOT AUTHORIZATION** |
| NeMo Guardrails retrieval rails | Chunk inspect/transform | **CONTENT ANALYSIS** / **RUNTIME EVIDENCE** (independent) — **NOT AUTHORIZATION** |
| Cisco AI Defense inspect | Prompt/response inspect | **CONTENT ANALYSIS** — inspect FAIL ≠ DENY |
| Cisco mcp-scanner | Catalog YARA | **NOT RELEVANT** to RAG retrieve |
| Foundation-Sec / Foundation8 | Content/security models where relevant | **HUNT ASSIST** / **CONTENT ANALYSIS** — **NOT AUTHORIZATION** (not newly validated here) |

Capabilities above are **DOCUMENTED** from 10A research, not re-validated in 10D. Do not claim live integration.

---

## Existing search review

| Search | Role in 10D | Gap? |
|--------|-------------|------|
| Q-RAG-CONTEXT-AUTHORITY | Planes 1–4 reconstruction | Grant snapshot; two-run hash is CLI not join |
| Q-MCP-AUTHZ | Plane 3 (+ extra OBSERVE row) | No rag.context.* columns |
| Q-MCP-TOOL / EXECUTED | Plane 4 | Empty-tool OBSERVE row; missing start ≠ handler |
| Q-MCP-AFTER-DENY | Hunt form of DET-MCP-001 | 0 rows on A/B/C |
| DET-MCP-001 | Plane 3+4 after DENY | Intentionally misses ATTACK B |

**No new SPL.** Combining OBSERVE + overlay ALLOW in one notable would invite a fake detector.

KO recommendations: REQUIRED none. RECOMMENDED keep hunts; keep DET-MCP-001 disabled and narrow. OPTIONAL teaching overlay positive-control (SIMULATED), not indexed. DEFERRED ES, grant-snapshot field, behavioral models, Studio (10E).

---

## Security semantics (preserved)

This analysis does **not** claim: `untrusted_data` = malicious; malicious content = exploit; retrieval = execution; request = authorization; ALLOW = execution; DENY = prevention proof by itself; missing Splunk event = blocked; `mcp.started` = success; `mcp.failed` = prevention; known malicious hash = current compromise; LLM obedience = security invariant; Splunk = authorization; ML anomaly = policy decision.

---

## Maturity

| Object | Maturity |
|--------|----------|
| Q-RAG-CONTEXT-AUTHORITY | LAB VALIDATED (10C) as hunt, not detection |
| DET-MCP-001 | LAB VALIDATED for DENY-then-start |
| Candidates A–I as detections | EXPERIMENTAL / REJECT / GAP |
| Any RAG notable | **Not** PRODUCTION CANDIDATE |

---

## Verdict

**DETECTION ANALYZED — NO NEW DETECTOR**

STOP. Phase 10E not started. No Dashboard Studio. No DET-RAG.
