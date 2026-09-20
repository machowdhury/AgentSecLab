# Learning note — tool authorization learning loop (Phase 14E)

## WHAT IS IT?

LAB-MCP-001 teaches that a **tool request is not a tool grant**. The learner predicts, launches a closed LIVE experiment, investigates in Splunk Search, then RETESTs the **same** ungranted `lookup_customer_tier` request under a defended ExperimentContext.

## WHY DOES IT EXIST?

PI-001 proved the learning loop on untrusted **text**. MCP-001 proves the same loop on a different trust boundary: **tool authorization**. CTRL-MCP-001 is still the PDP. Splunk is still not enforcement.

## HOW DOES IT WORK?

1. LEARN: REQUEST ≠ GRANT, ALLOW ≠ EXECUTION, missing `mcp.started` ≠ prevention.
2. PREDICT: will CTRL-MCP-001 ALLOW or DENY? Will the handler start?
3. Launch ATTACK (LIVE): server owns tool/scope/args/profile=vulnerable.
4. Investigate Path A (construct SPL) or Path B (reuse Q-MCP-*).
5. DEFEND: enable the defended RETEST experiment, not a Splunk search.
6. Launch RETEST (LIVE): same request fingerprint, profile=defended, new run.id.
7. COMPARE and PROVE: classify SUPPORTED / CORROBORATED / NOT PROVEN / INCORRECT.

## WHERE DOES IT SIT IN AGENTSEC?

Second reference lab after LAB-PI-001. Attack Service `/labs/LAB-MCP-001`. Studio `ws_lab_mcp_001`. Runtime `POST /mcp/invoke` with optional `experiment_id`.

## WHAT IS THE TRUST BOUNDARY?

`acmebank.mcp.authorize` — CTRL-MCP-001 — **before** the tool handler.

## WHAT COULD AN ATTACKER CONTROL?

Tool name, requested_scope, arguments, user_id on the **direct** invoke path. The Attack Service browser path cannot send those; the server fills them from the catalog.

## WHAT CAN GO WRONG?

Fail-open ALLOW on vulnerable. Treating DENY as non-execution. Treating detector silence as SAFE. Treating Splunk as the PDP.

## WHAT TELEMETRY SHOULD EXIST?

control.decision (CTRL-MCP-001), optionally mcp.started / completed / failed, handler_invoke_count, content hash of the canonical request JSON.

## HOW WILL SPLUNK SHOW IT?

Q-MCP-WHO, Q-MCP-AUTHZ, Q-MCP-TOOL, Q-MCP-EXECUTED, Q-MCP-AFTER-DENY. DET-MCP-001 only for DENY-then-start.

## WHAT CONTROL COULD CHANGE THE RESULT?

CTRL-MCP-001 defended vs labeled vulnerable fail-open. Same request bytes.

## WHAT TEST PROVES THE LOGIC?

Offline: `tests/unit/test_phase14e_learning_loop.py` (fingerprint, closed launch, handler counts). LIVE pair: ATTACK `bf5109de-bcc0-4ca0-9916-cf4b63e77ef4` (handler 1, 7=7) and RETEST `0cd82b2a-cefe-4fe5-86f3-4751929c3d1f` (handler 0, 6=6), fingerprint `sha256:431e7baaa0e7206b8671e6f81613e16848ccbcaf0f16d90d0e0da4c3b3fcc70d`.

## What I should now be able to explain

1. Why a tool request is not a grant.
2. Where CTRL-MCP-001 runs relative to the handler.
3. Why ALLOW is not execution.
4. Why DENY is not automatic proof of non-execution.
5. Why missing Splunk `mcp.started` is corroboration only.
6. Why ATTACK is not an alert, and why DET-MCP-001 stays silent on fail-open ALLOW.
7. What the browser may send to Attack Service, and what it may not.
8. How ATTACK and RETEST prove SAME request + DIFFERENT defense.
9. Why Path A and Path B must both exist.
10. How this lab’s trust boundary differs from prompt injection, RAG, memory, and identity labs.
