# Logic proof — Capstone investigation workbench

**Date:** 2026-09-24  
**Lab:** `LAB-AGENTSEC-CAPSTONE-001`  
**Evidence class:** DOCUMENTED from code/tests; OBSERVED focused pytest result

## Security property

Untrusted retrieved and persisted data may influence a later request, but it cannot independently grant tool authority. The server-owned MCP policy decision must occur before `lookup_customer_tier` executes.

## Actual causal chain

`closed RAG document → RETRIEVE → CTRL-RAG-CONTEXT-001 OBSERVE → WRITE exact bytes → later RECALL → CTRL-MEMORY-CONTEXT-001 OBSERVE → lookup_customer_tier request → CTRL-MCP-001 → handler → local telemetry → Splunk copy`

Goal Integrity and Identity/Delegation are not active causal stages in this packet. Their event-family absence can help rule them out only within this instrumented experiment.

## Model reconstruction

1. **Attack begins:** the closed malicious RAG fixture is retrieved.
2. **Attacker-controlled:** only the allowlisted fixture bytes represented by `doc.lending-policy.malicious`.
3. **Server-owned:** ExperimentContext, profile, fixture selection, coded grants, control decisions, IDs, policy, persistence path, handler registry, and telemetry emission.
4. **Retrieved context:** yes. `CTRL-RAG-CONTEXT-001` classifies it as `untrusted_data` and returns `OBSERVE retrieved_context_is_data`.
5. **Persistent memory:** yes. The retrieved bytes are written unchanged, then recalled in a distinct run.
6. **Identity/delegation:** no active identity/delegation control or claim packet is emitted. Authentication remains NOT MODELED.
7. **Goal/instruction integrity:** no Goal Integrity control is active in this packet.
8. **Sensitive request:** `lookup_customer_tier`, scope `customer:read`, resource `cust-001`.
9. **OBSERVE controls:** `CTRL-RAG-CONTEXT-001` and `CTRL-MEMORY-CONTEXT-001`.
10. **ALLOW/DENY control:** `CTRL-MCP-001`.
11. **Final-operation PDP:** `CTRL-MCP-001` is the sole tool PDP.
12. **Order:** RAG OBSERVE; memory write; memory recall and OBSERVE; request construction; MCP decision; conditional handler; evidence.
13. **ATTACK execution:** the privileged handler executes once after labeled lab fail-open ALLOW.
14. **RETEST execution:** the privileged handler does not execute after `DENY tool_not_granted`.
15. **Execution proof:** runtime `lookup_customer_tier_handler_count` / `handler_invoke_count`; indexed `mcp.started` is corroboration on a complete copy.
16. **Primary run IDs:** each launch's RECALL run ID; `run_id == recall_run_id`.
17. **Sibling IDs:** RETRIEVE and WRITE run IDs. Recall `source_run_id` identifies the WRITE run.
18. **Fingerprints:** `content.hash` / `input_fingerprint`.
19. **Fingerprint scope:** SHA-256 of the closed RAG document bytes, which are persisted unchanged. Equality does not prove whole-experiment identity.
20. **ATTACK→RETEST change:** server-owned vulnerable versus defended ExperimentContext; MCP result ALLOW versus DENY; handler 1 versus 0; outcome achieved versus prevented.
21. **Intentionally identical:** malicious document bytes, persisted bytes, memory/request influence, requested tool/scope/resource, RAG OBSERVE, and memory OBSERVE.
22. **Splunk corroborates:** emitted event copies, control IDs/decisions, hashes, cross-run linkage, request fields, and execution-start events when export is complete.
23. **Splunk does not prove:** enforcement, authentication, universal resistance, local-to-index completeness without counting, or non-execution from absence alone.
24. **Falsifiers:** privileged handler count not 1 in ATTACK; privileged handler count not 0 in RETEST; RETEST MCP decision not DENY; ATTACK/RETEST input fingerprints differ; an operation occurs before its MCP decision; or expected cross-run hash/source linkage fails.

## Trust boundaries

- External/retrieved bytes → agent context.
- Retrieved bytes → persistent memory.
- Recalled data → later request.
- Tool request → server-owned MCP PDP.
- PDP decision → ToolRegistry handler.
- Runtime evidence → telemetry transport → Splunk.

Splunk is after execution on the evidence plane.

## Control map

- `CTRL-RAG-CONTEXT-001`: classifies retrieved context; OBSERVE only; does not grant a tool.
- `CTRL-MEMORY-CONTEXT-001`: classifies recalled context; OBSERVE only; does not grant a tool.
- `CTRL-MCP-001`: evaluates tool, scope, and resource against effective server-owned authority; sole tool PDP.
- ToolRegistry handler count: authoritative execution evidence; not an authorization decision.
- Splunk: reconstructed evidence; not enforcement.

## Code path and validation

`LaunchService._launch_capstone()` invokes `/rag/retrieve`, `/memory/write`, then `/memory/recall`. The RAG and memory pipelines bind the server-owned ExperimentContext and reject mismatches. The memory recall path constructs the closed follow-on request. MCP authorization occurs before ToolRegistry invocation.

The browser launch contract contains only `lab_id`, `specimen_id`, `mode`, and `execution`. Authority-bearing fields are rejected or never accepted from the browser.

## Failure safety

Retrieve, write, or recall dependency failure returns ERROR. Content-hash mismatch returns ERROR. Missing or mismatched ExperimentContext cannot become ALLOW. ERROR is not rendered as DENY. No dangerous operation is invoked before the tool PDP.

The intentionally vulnerable ATTACK overlay is an explicit lab condition. It does not mutate `coded_policy()` and is not data-derived authority.

## Security challenge

- Dangerous operation before validation: **No supported path found.**
- Missing context becomes ALLOW: **No; mismatch/missing context errors.**
- One agent inherits another authority: **No identity/delegation chain is active here.**
- Telemetry reports DENY after execution: **No supported path found; PDP precedes handler.**
- Important assertion lacking a direct UI test before this build: the Capstone workbench must distinguish influence, intent, authority, and execution while preserving three-run correlation and ERROR semantics.

## Tests run before implementation

```text
uv run --extra test python -m pytest \
  tests/unit/test_phase16b_capstone_learning_loop.py \
  tests/splunk/test_lab_agentsec_capstone_dashboard.py \
  -q --tb=line

20 passed in 0.54s
```

This result verifies deterministic contracts only. It does not prove live Splunk completeness or production security effectiveness.
