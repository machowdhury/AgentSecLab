# Logic proof — RAG context-security workbench

**Date:** 2026-09-23
**Scope:** UX and investigation presentation for canonical `LAB-RAG-CONTEXT`; runtime behavior unchanged.

## Security property

INV-002: retrieved content cannot independently authorize privileged actions.

`RETRIEVED != TRUSTED` and `PROVENANCE != AUTHORITY`.

## Actual evidence chain

```text
closed document.id
→ exact-id fixture retrieval
→ retrieved bytes + SHA-256 + rag.local.fixture provenance
→ CTRL-RAG-CONTEXT-001 OBSERVE retrieved_context_is_data
→ closed follow-on lookup_customer_tier / customer:read request
→ CTRL-MCP-001 tool authorization
→ ToolRegistry handler
→ runtime events / local evidence / Splunk copy
```

## Model answers

1. **Attacker-controlled input:** the closed malicious document bytes selected through the allowlisted `RAG-001` specimen. The browser cannot submit document bytes, profile, trust, grants, policy, or decisions.
2. **Retrieved object:** `doc.lending-policy.malicious` from the exact-id fixture retriever.
3. **Provenance:** `rag.local.fixture`; it identifies the source and does not establish trust or authority.
4. **Context control:** `CTRL-RAG-CONTEXT-001`, which returns `OBSERVE retrieved_context_is_data` for valid retrieved context in both profiles.
5. **Decision semantics:** OBSERVE only. It never ALLOWs or DENYs a tool and never mints an AllowTicket.
6. **Downstream operation:** a closed `lookup_customer_tier` / `customer:read` follow-on request may reach `CTRL-MCP-001`; the dangerous operation is the ToolRegistry handler invocation.
7. **Execution proof:** `lookup_customer_tier_handler_count` / `handler_invoke_count` is authoritative. `mcp.started` corroborates execution on a complete telemetry copy.
8. **ATTACK vs RETEST:** same document id, bytes, content hash, provenance, follow-on tool, and requested scope. Server-owned profile changes; `CTRL-MCP-001` changes from labeled fail-open ALLOW to DENY `tool_not_granted`; handler count changes 1 to 0. The RAG control remains OBSERVE.
9. **Fingerprint:** `input_fingerprint` is SHA-256 of the canonical malicious document bytes. Equality proves only equality of those bytes.
10. **Splunk role:** reconstruct retrieval classification, influenced request, tool authorization, and indexed MCP lifecycle. It does not establish provenance truth independently and does not enforce.
11. **Falsification:** different ATTACK/RETEST content hashes, RETEST MCP ALLOW, `mcp.started` after RETEST DENY, or runtime handler count greater than zero on RETEST.
12. **Failure behavior:** malformed retrieval/control failures are ERROR and do not mint an overlay or invoke the handler.

## Trust boundaries and decision points

- Browser → Attack Service: four-field closed launch contract.
- Attack Service → AcmeBank `/rag/retrieve`: server-owned document id and ExperimentContext.
- Retrieved context → authority: `CTRL-RAG-CONTEXT-001` classifies data; it is not the PDP.
- Follow-on request → tool handler: `CTRL-MCP-001` is the PDP and runs before the handler.
- Runtime → Splunk: evidence transport, not enforcement.

## Tests before UX implementation

MEASURED: 95 focused RAG/Memory model tests passed, including trust, telemetry, evidence, launch, and negative-boundary tests.

## Postbuild proof result

- **ATTACK:** `7b56cfe5-428c-44a6-a92a-ab4155df1461`; fingerprint `sha256:c565f364c7c5fba3cf25d235bb8e2bee7d9433daa9f07d5e097ab6d2a82a97ef`; context OBSERVE; MCP ALLOW; handler count 1; local events 10; Splunk `dc(_raw)=10`.
- **RETEST:** `d36ffabd-f4b1-4df8-ad3d-cfdfe38c487a`; same document fingerprint; context OBSERVE; MCP DENY `tool_not_granted`; handler count 0; local events 9; Splunk `dc(_raw)=9`.
- Validated Q-RAG-CONTEXT-AUTHORITY reconstructed the source, trust, hash, request, control, and execution observation for both fresh IDs.
- Browser validation found no horizontal overflow at 1920/1440/1280/1024 or CSS 200% zoom, Copy Run ID worked, keyboard reached launch controls, and no console error occurred before the explicitly SIMULATED 503 error state.
- MCP reference-page browser regression passed at the same widths and zoom with no console/page error.

## Residual limitation

Screen-reader behavior is PARTIAL because no assistive-technology session was performed. RETEST non-execution is proved for this deterministic run by runtime handler count 0; it is not a universal RAG-security claim.
