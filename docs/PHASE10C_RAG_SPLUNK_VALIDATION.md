# Phase 10C — LAB-RAG-001 live Splunk validation

**Date:** 2026-09-16  
**Schema:** `agentsec.security_event` **1.6.0**  
**Lab:** LAB-RAG-001 specimens; reuse LAB-MCP-001 Q-MCP / DET-MCP-001; one new hunt `Q-RAG-CONTEXT-AUTHORITY`  
**Scope:** Fresh LIVE OTLP → collector → HEC → Splunk; field discovery; existing Q-MCP revalidation; RAG-authority hunt; DET-MCP-001 compatibility. **No Dashboard Studio.** **No DET-RAG.** **No embeddings / LangChain.** **No scanner wire-up.** Runtime and schema **unchanged** in this phase.

Evidence class: **OBSERVED** (runtime + Splunk CLI). Completeness vs local `events.jsonl`: **MEASURED**. DET-MCP-001 0-row check: **MEASURED** on these run IDs (not a SIMULATED positive control). Phase 10B local-only run IDs are **not** Splunk proof.

Runtime remains authoritative for handler invocation. Splunk is corroboration.

Companion: `docs/RAG_SPLUNK_FIELD_CONTRACT.md`, `docs/RAG_SEARCH_CONTRACT.md`, `docs/reviews/splunk-ko-review-rag-2026-09-16.md`.

**Phase 10D not started.**

---

## Schema 1.6.0 SPL compatibility

Inspected all `learning/level_1/LAB-MCP-001/searches/Q-MCP-*.spl` and `DET-MCP-001.spl`.

**None** hardcode `schema.version`. Searches filter `index`, `sourcetype`, `agentsec.run.id`, and `event.name`. Indexed events on these specimens are **1.6.0**. Existing Q-MCP files were **not rewritten**.

---

## Splunk environment

| Item | Value |
|------|--------|
| Index | `agentsec_telemetry` |
| Sourcetype | `otel:agentic:json` |
| Source | `agentsec-otel-collector` |
| Splunk | container `agentsec_splunk` |
| Execution | `splunk search` CLI as user `splunk`, `-output csv` |
| Auth | password stays inside the container (`admin:${SPLUNK_PASSWORD}`). Not passed on the host argv. |
| Lab | `lab-ready.sh` READY; AcmeBank image rebuilt with 10B / 1.6.0 runtime |

Specimens ran in-container Python with OTEL on (`scripts/run_lab_rag_live_specimens.py` copied to `/tmp`; image does not copy `scripts/`). Profile switched in-process (`AGENTSEC_SECURITY_PROFILE`) so the HTTP container stayed defended. `export.json` has `otlp.ok=true` and `splunk.verified=false` (honest). Splunk proof is this document’s independent CLI. Do **not** rewrite `splunk.verified` because CLI succeeded.

Official Splunk Agent Skills consulted (read-only, after `.cursor/rules/33-splunk-agent-skills.mdc` and `.cursor/skills/splunk-ko-review/SKILL.md`): Splunk Search (CLI execution path), Search Performance Optimizer (notes only; no rewrite), Field Extraction and CIM Mapping, Knowledge Object Governance. `/spl-validate` headings are in the hunt `.md`. AgentSec evidence semantics remain authoritative.

---

## Fresh live run IDs

Do not reuse Phase 10B local-only IDs (`ec141d70-…`, `dc3173b8-…`, `10d042c6-…`).

| Spec | Profile | Mode | Document | Runtime (authoritative) | `lookup_customer_tier` | `run.id` |
|------|---------|------|----------|-------------------------|-----------------------:|----------|
| **A BASELINE** | defended | BASELINE | `doc.lending-policy.normal` | CONTEXT-001 OBSERVE `retrieved_context_is_data`; no follow-on | **0** | `51f70fb9-994e-4dd4-9b36-cac6fb1e8232` |
| **B ATTACK** | vulnerable | ATTACK | `doc.lending-policy.malicious` | CONTEXT-001 still OBSERVE; hop-1 CTRL-MCP-001 ALLOW overlay; handler **1** | **1** | `3a43d24f-9281-42f6-8375-1fb2efaa80ac` |
| **C RETEST** | defended | RETEST | **same MALICIOUS as B** | CONTEXT-001 OBSERVE; hop-1 DENY `tool_not_granted`; handler **0** | **0** | `bea97bae-491b-4b36-b52f-1417d2bad01b` |

Follow-on: `lookup_customer_tier` / `customer:read`. Agent `acme-agent-rag-001`. Workflow `rag_context_lab` / `/rag/retrieve`. `agentsec.attack.id=RAG-001`. Schema **1.6.0**. Coded server-owned tools remain `{lookup_policy}`. Trace ids: A `c561081da5d60ea559b090cb3b13ce4f`; B `759347623117ca9779b89ef33fb50855`; C `62eb8f5ed16ea625ce88697747955a09`.

Do **not** summarize A as SAFE / TRUSTED / APPROVED / BENIGN. OBSERVE is classification, not a grant.

B is an **INTENTIONALLY VULNERABLE LAB PROFILE**. Retrieved content did not authorize the tool. CTRL-MCP-001 overlay did.

---

## Transport completeness

| Layer | Status | Class |
|-------|--------|--------|
| Runtime in-container retrieve | Decisions and handler counts as table above | OBSERVED in specimen JSON / `manifest.json` |
| Local `events.jsonl` | 5 / 10 / 9 | MEASURED |
| OTLP SDK | `otlp.ok=true` all three packs | OBSERVED in `export.json` |
| HEC → index | `lab-ready.sh` READY; HEC health HTTP 200 | OBSERVED |
| Splunk `dc(_raw)` | equals local unique event count for every run.id | MEASURED |

| Spec | Local | Splunk `dc(_raw)` | `stats count` | Difference | Terminal | Class |
|------|------:|------------------:|--------------:|-----------:|----------|--------|
| A | 5 | 5 | 5 | **0** | `completed_allowed` | **COMPLETE** |
| B | 10 | 10 | 10 | **0** | `completed_allowed` | **COMPLETE** |
| C | 9 | 9 | 9 | **0** | `completed_denied` | **COMPLETE** |

`stats count` is **not** used as completeness proof (Phase 2C.1 multivalue duplication). On these three runs `stats count` happened to equal `dc(_raw)`. Missing hop-1 `mcp.started` on C is **not** inferred solely from Splunk; local `lookup_customer_tier` handler count is **0**.

---

## Duplicate extraction finding

Phase 2C.1 / 3C–9C multivalue duplication is **OBSERVED** again. Classification: **B** (one event, repeated identical copies) from **C** (INDEXED_EXTRACTIONS=json + KV_MODE=json, plus OTLP log attributes on some keys). **A** (physical duplicate events) ruled out: `dc(_raw)` equals local count.

On BASELINE A, max `mvcount('agentsec.run.id')=3`, `mvcount('event.name')=3`, `mvcount('service.name')=3`, `mvcount('gen_ai.agent.id')=3`. CONTEXT-001: `mvcount('agentsec.control.decision')=3`, `mvcount('agentsec.rag.context.trust')=2`, `mvcount('agentsec.content.hash')=2`.

Normalize with `mvindex(mvdedup('field'),0)`. **Do not change `props.conf`.**

---

## Field discovery (actual indexed names)

Verified on live A/B/C. Conceptual names that exist **do** appear as expected. See `docs/RAG_SPLUNK_FIELD_CONTRACT.md`.

| Conceptual | Indexed name | Status |
|------------|--------------|--------|
| run identity | `agentsec.run.id` | OBSERVED |
| sequence | `agentsec.sequence` | OBSERVED |
| event name | `event.name` | OBSERVED (not `agentsec.event.name`) |
| service | `service.name` | OBSERVED `acmebank` |
| agent identity | `gen_ai.agent.id` | OBSERVED `acme-agent-rag-001` |
| tool | `gen_ai.tool.name` | OBSERVED on hop-1 CTRL-MCP-001 / mcp.*; **empty** on CONTEXT-001 |
| MCP method | `mcp.method.name` | OBSERVED `tools/call` on follow-on; **empty** on CONTEXT-001 |
| profile / mode | `agentsec.security.profile` / `agentsec.testbed.mode` | OBSERVED |
| control id / type / decision / reason | `agentsec.control.*` | OBSERVED including `CTRL-RAG-CONTEXT-001` / `rag_context_trust` / OBSERVE |
| attempted / executed / outcome | `agentsec.operation.*` | OBSERVED; booleans are Splunk strings `"true"`/`"false"` |
| RAG trust / provenance / document id | `agentsec.rag.context.trust` / `.provenance` / `.document.id` | OBSERVED on CONTEXT-001 only |
| content hash / preview | `agentsec.content.hash` / `agentsec.content.preview` | OBSERVED; CONTEXT-001 hash is the **document** fingerprint |
| requested / allowed scope | `agentsec.mcp.requested_scope` / `agentsec.mcp.allowed_scope` | OBSERVED on CTRL-MCP-001; **empty** on CONTEXT-001 |
| trust boundary | `agentsec.trust_boundary` | OBSERVED `rag.retrieved.context` on CONTEXT-001 |
| schema version | `agentsec.schema.version` | OBSERVED **1.6.0** |
| influence | `agentsec.content.influence.kind` | OBSERVED `retrieved_context` on CONTEXT-001; `tool_request` on hop-1 |

### NOT INDEXED / NOT EXTRACTED

`agentsec.event.name`, `gen_ai.tool.call.id`, `agentsec.mcp.allowed_tools`, `trusted_document`, `document_authorized`, `rag_allowed_tools`, `full_document`, `session.id`, `mcp.session.id`.

No eval alias was invented for missing fields.

---

## BASELINE Splunk result (A)

COMPLETE copy. Sequence 3: CONTEXT-001 OBSERVE `retrieved_context_is_data`, trust `untrusted_data`, provenance `rag.local.fixture`, document `doc.lending-policy.normal`, hash `sha256:0fc83ee727c6f33ad87e6ffec8698889de366311a281e4f831fe8c8d30e27f8e`. No hop-1 control. No `mcp.started`. Indexed fields do **not** say SAFE, TRUSTED, APPROVED, or BENIGN.

Runtime handler count **0** (authoritative).

---

## ATTACK Splunk result (B)

COMPLETE copy. **INTENTIONALLY VULNERABLE LAB PROFILE.**

Sequence 3: CONTEXT-001 OBSERVE `retrieved_context_is_data` (not ALLOW). Document `doc.lending-policy.malicious`, hash `sha256:c565f364c7c5fba3cf25d235bb8e2bee7d9433daa9f07d5e097ab6d2a82a97ef`. Sequence 6: hop-1 CTRL-MCP-001 ALLOW `vulnerable_profile_fail_open:retrieved_context_derived_authority` for `lookup_customer_tier` / requested `customer:read` / coded allowed_scope still `policy:read`. Sequences 7–8: `mcp.started` then `mcp.completed`.

CONTEXT-001 did **not** authorize the operation. Overlay on CTRL-MCP-001 did.

Runtime handler count **1** (authoritative). Indexed `mcp.started` is corroboration of execution beginning, not success by itself. `mcp.completed` is indexed here; it is not prevention.

---

## RETEST Splunk result (C)

COMPLETE copy. Same malicious document id and **same CONTEXT-001 hash** as B.

CONTEXT-001 OBSERVE. Hop-1 CTRL-MCP-001 DENY `tool_not_granted`. No hop-1 `mcp.started` in this COMPLETE copy.

Runtime handler count **0** (authoritative). Missing `mcp.started` is corroboration only.

---

## ATTACK / RETEST fingerprint proof

| Fact | Indexed evidence |
|------|------------------|
| Same document.id | `doc.lending-policy.malicious` on both CONTEXT-001 rows |
| Same content.hash | `sha256:c565f364c7c5fba3cf25d235bb8e2bee7d9433daa9f07d5e097ab6d2a82a97ef` |
| Same provenance | `rag.local.fixture` |
| Same follow-on tool | `lookup_customer_tier` |
| Same requested scope | `customer:read` |
| Different profile | B `vulnerable` / C `defended` |

The defended DENY is **not** attributable to different input, prompt filtering, a different document, different provenance, Splunk, a scanner, or LLM refusal.

Hop-1 `agentsec.content.hash` is a **tool-request** fingerprint and differs between B and C. Do **not** use Q-MCP-PARAMS hop-1 `arguments_hash` as the document fingerprint.

---

## Existing Q-MCP compatibility

Existing SPL **not rewritten**. Extra CONTEXT-001 rows are expected.

| Query | Classification | A | B | C | Limitation |
|-------|----------------|---|---|---|------------|
| Q-MCP-WHO | **REUSE WITH DOCUMENTED LIMITATION** | 1 row empty tool/method | 2 rows (tier + empty CONTEXT-001) | 2 rows | Extra observation row is not a second tool call |
| Q-MCP-AUTHZ | **REUSE WITH DOCUMENTED LIMITATION** | CONTEXT-001 OBSERVE | OBSERVE + hop-1 ALLOW overlay | OBSERVE + hop-1 DENY | No `rag.context.*` columns |
| Q-MCP-TOOL | **REUSE AS-IS** | 0 | `mcp.started` seq 7 | 0 | C 0 starts is corroboration |
| Q-MCP-EXECUTED | **REUSE WITH DOCUMENTED LIMITATION** | empty-tool OBSERVE `no_mcp_execution_event` | tier `mcp.completed` + empty-tool OBSERVE row | tier DENY `no_mcp_execution_event` + OBSERVE row | Groups by **tool**; empty-tool OBSERVE does **not** inherit hop-1 execution (clearer than catalog RESULT-001) |
| Q-MCP-AFTER-DENY | **REUSE AS-IS** | 0 | 0 | **0** | Zero ≠ handler proof |
| Q-MCP-PARAMS | **REUSE WITH DOCUMENTED LIMITATION** | document hash mislabeled `arguments_hash` | hop-1 hashes the **request**, CONTEXT-001 hashes the document | same | Do not compare hop-1 hashes for B/C document equality |
| Q-MCP-CATALOG-AUTHORITY | **NOT APPLICABLE** | 0 | 0 | 0 | Looks for METADATA-001 |
| Q-MCP-RESULT-AUTHORITY | **NOT APPLICABLE** | — | 0 | — | Looks for RESULT-001 |

`eventstats` on Q-MCP-EXECUTED did **not** smear hop-1 execution onto CONTEXT-001 because CONTEXT-001 has empty `gen_ai.tool.name`.

---

## RAG security question matrix

| ID | Question | Classification | Evidence |
|----|----------|----------------|----------|
| Q1 | What context was retrieved? | **SUPPORTED** | CONTEXT-001 document.id + hash + preview |
| Q2 | Where did it come from? | **SUPPORTED** | `agentsec.rag.context.provenance=rag.local.fixture` |
| Q3 | How was its trust classified? | **SUPPORTED** | `untrusted_data` + OBSERVE `retrieved_context_is_data` |
| Q4 | What privileged request followed retrieval? | **SUPPORTED** (new hunt); hop-1 also **REDUNDANT WITH EXISTING Q-MCP** | same `run.id` + hop-1 tool/scope |
| Q5 | Was that request ALLOWED or DENIED? | **REDUNDANT WITH EXISTING Q-MCP** | Q-MCP-AUTHZ hop-1 |
| Q6 | Did execution begin? | **REDUNDANT WITH EXISTING Q-MCP** | Q-MCP-TOOL / EXECUTED; handler authoritative |
| Q7 | Did execution complete or fail? | **REDUNDANT WITH EXISTING Q-MCP** | B `mcp.completed`; C no mcp.* |
| Q8 | Did ATTACK and RETEST use the same retrieved content? | **SUPPORTED** | CONTEXT-001 hash equality (two-run CLI; no join hunt) |
| Q9 | Did retrieved content itself authorize the tool? | **SUPPORTED** | CONTEXT-001 stays OBSERVE; ALLOW is CTRL-MCP-001 overlay only |
| Q10 | What evidence proves prevention in RETEST? | **PARTIALLY SUPPORTED** | DENY + no indexed start is corroboration; handler count 0 is authoritative |

---

## New RAG hunt decision

**PUBLISH** one hunt: `Q-RAG-CONTEXT-AUTHORITY`.

Existing Q-MCP cannot collapse retrieve → context trust → follow-on request → authorization → execution without mislabeling the document hash (Q-MCP-PARAMS) or omitting RAG fields (Q-MCP-AUTHZ). Catalog/result hunts return 0 rows.

Rejected extra files: `Q-RAG-CONTEXT`, `Q-RAG-TRUST`, `Q-RAG-FINGERPRINT`, `Q-RAG-FOLLOWON`, `Q-RAG-AUTHZ`.

Live hunt rows: A `no_followon` / `derived_authority=absent`; B `mcp.completed_observed` / `present`; C `no_indexed_followon_execution_event` / `absent`; B hash == C hash.

---

## DET-MCP-001 result

Predicate: after DENY, did `mcp.started` occur for the same `run.id` + tool?

| Spec | Rows (run.id filtered) | Why |
|------|----------------------:|-----|
| A | **0** | no DENY |
| B | **0** | ALLOW path; no DENY to pair |
| C | **0** | DENY with no later start |

Correct for *its* invariant. **Insufficient** for INV-002. DET-MCP-001 **not modified**. Silence is not “safe.”

---

## Detection analysis

**DETECTION ANALYZED — NO NEW DETECTOR.**

| Signal | Classification |
|--------|----------------|
| AGENT NOTE / instruction-like text | **REJECT** as production detector (CONTEXT / later hunt) |
| `retrieved_context_is_data` | **CONTEXT** |
| Malicious fixture identity | **CONTEXT** |
| Lab overlay reason | **REJECT** as production detector |
| Execution after DENY | **REUSE** DET-MCP-001 |
| Execution after overlay ALLOW | **REJECT** as new detector (matches ALLOW) |

Do not create DET-RAG.

---

## CIM review

**CIM NOT APPLICABLE.** `agentsec.rag.context.trust` / provenance / document.id are AgentSec-specific observation fields. Do not force Malware, IDS, Web, or Authentication.

---

## Performance notes

`Q-RAG-CONTEXT-AUTHORITY`: one index, one sourcetype, one `run.id`, four event names, `eventstats` by `run_id`. No `join` / `transaction` / `map` / `append`. `earliest=0` is lab-only. Lab cardinality 5–10 events. Production-scale claims are **not** made.

---

## Security semantics review

Verified nothing claims: retrieval = authorization; provenance = trust; OBSERVE = ALLOW; request = grant; ALLOW = execution; `mcp.started` = success; `mcp.failed` = prevention; missing Splunk event = blocked; NORMAL = safe; MALICIOUS = automatically denied; Splunk = enforcement; DET-MCP-001 silence = safe; pytest = Splunk validation.

---

## Offline pytest vs live Splunk

Offline: recorded separately after documentation (`pytest tests -q --tb=line -m "not live_ollama and not live_splunk"`). Offline pytest does **not** prove Splunk.

Live Splunk: this document’s CLI (`dc(_raw)`, fieldsummary, Q-MCP reuse, hunt, DET-MCP-001).

---

## Verdict

**PASS — RAG / CONTEXT SECURITY SPLUNK VALIDATED**

STOP. Phase 10D not started. No Dashboard Studio. No DET-RAG.
