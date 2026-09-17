# RAG retrieved-context Splunk investigation (Phase 10C)

**Status:** Phase 10C live Splunk validated. No Dashboard Studio. No DET-RAG.  
**Parents:** `docs/PHASE10C_RAG_SPLUNK_VALIDATION.md`, `docs/learning-notes/rag-context-runtime.md`.

---

## WHAT IS IT?

Live proof that schema **1.6.0** RAG observation fields actually extract in Splunk, and that one hunt can reconstruct retrieve → classify → request → authorize → execute without inventing fields.

## WHY DOES IT EXIST?

10B proved the runtime invariant locally. Splunk is the SOC evidence plane. Field names in a schema file are not indexed fields until live discovery.

## HOW DOES IT WORK?

Fresh A/B/C runs with OTEL on went OTLP → collector → HEC → `index=agentsec_telemetry`. Completeness used `dc(_raw)` vs `events.jsonl`. Fields were collapsed with `mvindex(mvdedup(…),0)`. Existing Q-MCP searches were reused unchanged. One new hunt, `Q-RAG-CONTEXT-AUTHORITY`, binds CONTEXT-001 to hop-1 CTRL-MCP-001.

## WHERE DOES IT SIT IN AGENTSEC?

After LAB-RAG-001 runtime (10B) and before any workshop (10D not started). Same index/sourcetype as MCP labs. Different control (`CTRL-RAG-CONTEXT-001`) than catalog metadata or tool-result trust.

## WHAT IS THE TRUST BOUNDARY?

Indexed `agentsec.trust_boundary=rag.retrieved.context` on CONTEXT-001. Authorization remains `acmebank.mcp.authorize` on hop-1 CTRL-MCP-001. Splunk does not sit on that boundary.

## WHAT COULD AN ATTACKER CONTROL?

Retrieved fixture text (mode-selected). Not grants, not profile, not indexed `control.decision`. Splunk cannot be used to mint ALLOW.

## WHAT CAN GO WRONG?

Treating OBSERVE as ALLOW; comparing hop-1 request hashes as document fingerprints; treating DET-MCP-001 silence as “safe”; treating missing `mcp.started` as prevention; labeling NORMAL SAFE; publishing overlay-reason detections.

## WHAT TELEMETRY SHOULD EXIST?

CONTEXT-001: trust, provenance, document.id, hash, preview, OBSERVE. Hop-1: CTRL-MCP-001 ALLOW/DENY. Optional `mcp.started`/`completed`. All were **OBSERVED** live.

## HOW WILL SPLUNK SHOW IT?

Q-MCP-AUTHZ shows the OBSERVE row plus hop-1. The new hunt adds RAG columns and collapses one row per `run.id`. DET-MCP-001 stays 0 on A/B/C.

## WHAT CONTROL COULD CHANGE THE RESULT?

`AGENTSEC_SECURITY_PROFILE`. Splunk only records it.

## WHAT TEST PROVES THE LOGIC?

Live `dc(_raw)` COMPLETE; B CONTEXT-001 hash == C hash; hunt A `no_followon`, B `mcp.completed_observed`, C `no_indexed_followon_execution_event`; runtime handler 0/1/0.

---

## What I should now be able to explain

1. Why schema 1.6.0 field names still needed live field discovery.
2. Why `dc(_raw)` is the completeness metric, not `stats count`.
3. Why CONTEXT-001 OBSERVE is indexed on ATTACK as well as BASELINE.
4. Why Q-MCP-PARAMS hop-1 hash is not the document fingerprint.
5. Why one Q-RAG hunt was justified and five extra Q-RAG files were not.
6. Why DET-MCP-001 is silent on the preferred ATTACK.
7. Why missing `mcp.started` is only corroboration.
8. Why provenance is not trust and OBSERVE is not ALLOW.
9. Why CIM does not map `rag.context.trust`.
10. Why Phase 10D / Studio / DET-RAG must not start from this file.
