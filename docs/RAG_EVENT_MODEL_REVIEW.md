# RAG retrieved-context — event model review

**Status:** Phase 10A **DESIGN**. Schema **1.5.0 unchanged**. No emitter. No SPL.

Parents: `docs/SCHEMA_1_5_0.md`, `docs/MCP_CATALOG_POISONING_EVENT_MODEL_REVIEW.md`, `.cursor/rules/33-splunk-agent-skills.mdc`.

Governance: SECURITY QUESTION → EVIDENCE → VALIDATED TELEMETRY → INDEXED FIELD DISCOVERY → FIELD CONTRACT → SPL. This file stops at **evidence requirement**. Do not invent fields in searches.

---

## Verdict

**SCHEMA BUMP JUSTIFIED.**

Schema 1.5.0 is **closed** (`additionalProperties: false`) and its enums cannot honestly carry a RAG observation. Overloading `mcp_result_trust` or `mcp_metadata_trust` would lie about the channel.

Do **not** implement the bump in Phase 10A. Proposed label: **1.6.0** in Phase 10B if that phase emits live CTRL-RAG-CONTEXT-001.

---

## What 1.5.0 can already represent

| Need | Today | Honest for RAG? |
|------|-------|-----------------|
| Follow-on CTRL-MCP-001 ALLOW/DENY | `control.decision` + `mcp_allowlist` | **Yes** — same as MCP-005 / catalog |
| Follow-on execution | `mcp.started` / completed / failed | **Yes** |
| Fail-open reason string | `control.reason` | **Yes**, if 10B emits it |
| Hash / preview **fields exist** | `content.hash`, `content.preview` (≤200) | Fields exist; **unbound** to retrieved documents |
| Correlation keys | `run.id`, `sequence`, `gen_ai.agent.id` | **Yes** for in-run retrieve → request → authz → execute |
| Result trust | `mcp.result.trust` | **Wrong channel.** Do not overload. |
| Catalog metadata trust | `mcp.metadata.trust` | **Wrong channel.** Do not overload. |
| Influence kind | `user_message` / `prior_agent_output` / `tool_request` | **No retrieved_context** value |
| Workflow | `loan_pipeline` \| `mcp_tool_lab` | **No** `rag_context_lab` |
| Attack id | no `RAG-001` | Cannot label the attack honestly |
| Trust boundary | no `rag.retrieved.context` | Cannot label the boundary honestly |
| Control type | no `rag_context_trust` | Cannot emit CTRL-RAG-CONTEXT-001 |

Reusing RESULT-001 or METADATA-001 for documents is **FORBIDDEN**.

---

## What 1.5.0 cannot honestly represent

| Need | Gap |
|------|-----|
| Observation that retrieved bytes are data | `control.type` enum closed |
| Provenance `rag.local.fixture` | no `rag.context.provenance` |
| Trust `untrusted_data` on a document | no `rag.context.trust` |
| Document fixture id | no bound identity (must not stuff into tool name) |
| Query identity | no bound query hash |
| Retrieval-as-influence | `content.influence.kind` closed |
| Dedicated retrieve event name | optional; control.decision preferred first |

If 10B shipped without a bump: **evidence-file-only** classification. Do not emit illegal events.

---

## Minimal additive 1.6.0 (proposal only — not implemented)

Smallest honest bump if 10B emits live observation telemetry:

1. `agentsec.schema.version` const **1.6.0**.
2. `agentsec.attack.id` additive **`RAG-001`**.
3. `agentsec.control.type` additive **`rag_context_trust`**.
4. When type is `rag_context_trust`: `control.id` const **`CTRL-RAG-CONTEXT-001`**. Decisions: **OBSERVE** for every valid document (BASELINE, ATTACK, RETEST). ERROR for malformed / retrieval failure. Vulnerable ALLOW is **not** on this control; it is CTRL-MCP-001 overlay only. Never SANITIZE/QUARANTINE unless content is actually transformed or consumption blocked.
5. `agentsec.trust_boundary` additive **`rag.retrieved.context`**.
6. `agentsec.rag.context.trust` enum **`untrusted_data`** (required on RAG-CONTEXT-001). Do **not** add `trusted_document`.
7. `agentsec.rag.context.provenance` enum **`rag.local.fixture`** (required on RAG-CONTEXT-001). Configured source ≠ trusted instructions.
8. Reuse existing **`agentsec.content.hash`** + **`agentsec.content.preview`** for the **document body**. Hash = SHA-256 over canonical UTF-8. Preview ≤200. Interpreter inspects full body; preview is not the authorization input.
9. Additive **`agentsec.rag.document.id`** string (fixture ids `doc.lending-policy.normal` / `doc.lending-policy.malicious`). Required on RAG-CONTEXT-001. Do not invent a parallel hash field.
10. Optional later: `agentsec.rag.query.hash` if query text must be correlated without storing the query. Not required for the two-document exact-id retriever.
11. Optional later: `content.influence.kind` additive `retrieved_context`. Not required if follow-on is a normal `tool_request`.
12. Optional later: `gen_ai.workflow.name` additive `rag_context_lab`. Prefer this over overloading `mcp_tool_lab` if the retrieve hop is first-class.
13. Optional later: `event.name=agentsec.rag.retrieved` if hunters cannot work from `control.decision` alone. Prefer control.decision first (MCP-005 / catalog style).

**Do not add:** `trusted_document`, full document body, full prompt, PII fields, scanner fields on `otel:agentic:json`, `invocation.id`, `session.id`, SANITIZE/QUARANTINE enums beyond existing control.decision values.

1.5.0 field **meanings stay unchanged**.

---

## Privacy

Retrieved documents can contain policy text, and in production PII or secrets.

| Emit | Do not emit by default |
|------|------------------------|
| `document.id` | Full document / full chunk |
| SHA-256 (`content.hash`) | Full user question (unless separately justified and hashed) |
| Preview ≤200 | Customer/account identifiers, credentials |
| provenance + trust enums | Client-supplied `trusted=true` |

Production redaction would additionally require: DLP on chunks before index, prompt/response redaction, tenant-isolated vector stores, and a ban on full-chunk HEC.

CIM: **NOT APPLICABLE** for `rag.context.trust` / `rag.context.provenance` (lab-specific, like catalog metadata trust). Do not force Authentication or Malware data models.

---

## Correlation

| Stream | Key | Sufficient? |
|--------|-----|-------------|
| Retrieval observation → follow-on request → CTRL-MCP-001 → mcp.started | `run.id` + `sequence` + `agent.id` | **Yes** if 10B keeps one run in-process (same as MCP-005) |
| ATTACK vs RETEST same document | `content.hash` once bound | Requires 1.6.0 bind |
| Host-wide corpus scan | **Not** `run.id` | Out of scope |

Do **not** invent `invocation.id` / `session.id`. No demonstrated contract hole requires them if retrieve and follow-on share `run.id`.

Sequence sketch (planned):

```
run.started
  rag observation (CTRL-RAG-CONTEXT-001)
  [optional llm.* for the answer — not the invariant]
  control.decision CTRL-MCP-001  (follow-on)
  mcp.started | (absent on DENY)
run.completed
```

---

## Splunk questions — DESIGN ONLY, no SPL

Field-contract gate: if required telemetry is absent, **STOP**. Record TELEMETRY GAP. Do not proxy.

| ID | Question | Evidence needed | 1.5.0 today? | Classification |
|----|----------|-----------------|--------------|----------------|
| Q1 | What content did the agent retrieve? | document id + hash + preview | hash/preview fields exist, **unbound** | **REQUIRES NEW TELEMETRY** |
| Q2 | What was its provenance? | `rag.context.provenance` | absent | **REQUIRES NEW TELEMETRY** |
| Q3 | Was the content classified as untrusted? | `rag.context.trust` + RAG-CONTEXT-001 OBSERVE | absent | **REQUIRES NEW TELEMETRY** |
| Q4 | Did retrieved content correlate with a follow-on privileged request? | same `run.id` + document hash + follow-on tool | follow-on **yes**; join to retrieval **no** | **REQUIRES NEW TELEMETRY** (join); follow-on half is **SUPPORTED BY CURRENT TELEMETRY** once 10B runs |
| Q5 | Was the request ALLOW or DENY? | CTRL-MCP-001 | **Yes** | **SUPPORTED BY CURRENT TELEMETRY** (after 10B emits it) |
| Q6 | Did execution begin? | `mcp.started` + handler spy | **Yes** | **SUPPORTED BY CURRENT TELEMETRY** |
| Q7 | Did ATTACK and RETEST use the same malicious content hash? | bound `content.hash` on both runs | unbound | **REQUIRES NEW TELEMETRY** |
| Q8 | Can we distinguish retrieval from authorization? | `control.type` rag_context_trust vs mcp_allowlist | no rag type | **REQUIRES NEW TELEMETRY** for the retrieval half; authz half **SUPPORTED** |

**Not BLOCKED** in the “impossible forever” sense — blocked only until the bump + 10B emitters + indexed field discovery.

Do not create KOs, macros, or Studio datasources in 10A. Future KOs require `/splunk-ko-review` after live field discovery.

Dashboard Studio implications (later): GRID tabs can bind Q-MCP-AUTHZ / Q-MCP-EXECUTED immediately after 10B; retrieval tab cannot bind until 1.6.0 fields exist **and** are indexed. Zero rows ≠ safe.

---

## Knowledge-object implications (later, not now)

| Artifact | 10A | Later |
|----------|-----|-------|
| Q-MCP-AUTHZ / Q-MCP-EXECUTED | Reuse design | Bind after 10C field discovery |
| Q-RAG-CONTEXT-AUTHORITY (hunt) | Do not write | Only after indexed `rag.context.*` |
| DET-MCP-001 | Unchanged | Still execution-after-DENY only |
| DET-RAG-* | **Do not create** | See detection model |
| CIM tags / data models | N/A | Do not force |
