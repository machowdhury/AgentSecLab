# Splunk knowledge-object review — Context Security

**Date:** 2026-09-23
**Scope:** `ws_lab_rag_context`, `ws_lab_memory_security`, and their existing Q-* dependencies
**Verdict:** PASS

## Search-change audit

No SPL file changed.

- `Q-RAG-CONTEXT-AUTHORITY.spl`: old and new search are byte-identical; presentation binding still substitutes only `run_id`.
- `Q-MEMORY-CONTEXT-AUTHORITY.spl`: old and new search are byte-identical; presentation binding still substitutes only WRITE and RECALL run IDs.
- `Q-MCP-WHO.spl`, `Q-MCP-AUTHZ.spl`, `Q-MCP-TOOL.spl`, `Q-MCP-EXECUTED.spl`, and `Q-MCP-AFTER-DENY.spl`: old and new searches are byte-identical.
- `DET-MCP-001-POSITIVE-CONTROL.spl`: unchanged and remains explicitly SIMULATED where shown.

The build changed layout and explanatory markdown only. No evidence claim was broadened and no detector was created or enabled.

## Fresh LIVE validation

RAG:

- ATTACK `7b56cfe5-428c-44a6-a92a-ab4155df1461`: Q-RAG returned untrusted fixture provenance, context OBSERVE, MCP ALLOW, and `mcp.completed_observed`; local/Splunk count `10/10`.
- RETEST `d36ffabd-f4b1-4df8-ad3d-cfdfe38c487a`: Q-RAG returned the same content hash, context OBSERVE, MCP DENY, and no indexed follow-on execution event; runtime handler count was 0 and local/Splunk count `9/9`.

Memory:

- ATTACK WRITE/RECALL `de84708e-cf9d-4526-9553-3972aa5b0c12` / `f1bdcab9-67dd-44b9-b2b8-1bfddfed400f`: Q-MEMORY returned a linked source relationship, identical write/recall hash, memory OBSERVE, MCP ALLOW, and `mcp.completed_observed`; counts `5/5` and `11/11`.
- RETEST WRITE/RECALL `81373c39-8307-406f-ae2f-85cf0befbc37` / `e7207a70-c628-4866-ac0b-0deb0da80aa7`: Q-MEMORY returned a linked source relationship, identical hash, memory OBSERVE, MCP DENY, and no indexed follow-on execution event; runtime handler count was 0 and counts `5/5` and `10/10`.

## Semantic checks

- Splunk is described as corroborative evidence, never the PDP.
- Empty tables do not mean SAFE, DENY, or PREVENTED.
- Context OBSERVE is separate from MCP authorization.
- Indexed absence is interpreted only after event-count completeness.
- Memory WRITE and RECALL counts remain separate.
- HEC HTTP 200 is not used as completeness evidence.

## Studio limitations

Dashboard Studio does not accept a fresh Attack Service run ID through a cross-application token write. Learners open Search for fresh IDs or select canonical REPLAY specimens in Studio. Path B is an optional tab because brittle custom browser scripts were rejected.
