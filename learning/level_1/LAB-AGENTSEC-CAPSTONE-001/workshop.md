# Workshop flow — lending assistant investigation

Mission first. Question: **how did untrusted retrieved content persist, influence a later request, and reach a privileged tool — and where did authority enter?**

Do not label BASELINE SAFE. Do not blame Goal Integrity or Identity without evidence.

## MISSION

A lending assistant accessed customer-tier information while processing lending-policy material.

Determine origin, trust, persistence, later request, authority, PDP, execution, RETEST change, and Splunk limits.

## ARCHITECTURE

User / Task → Retriever → RAG Context → Memory Store → Later Recall → Agent Request → CTRL-MCP-001 → Tool → Business Data.

Telemetry from each stage → Splunk (evidence, not inline enforcement).

## PREDICT

Write ATTACK and RETEST predictions before launch. Influence can remain without becoming authority.

## ATTACK

LIVE retrieve / write / recall. **INTENTIONALLY VULNERABLE LAB PROFILE**. RAG OBSERVE. Memory OBSERVE. CTRL-MCP-001 ALLOW labeled fail-open. lookup_customer_tier handler 1.

## INVESTIGATE

Path A: security question, index/sourcetype, run.ids, Open Search, Hint 1, Hint 2.

Path B is an answer key. It is not policy.

CAP-I1–I16.

## TRACE

SOURCE → PROVENANCE → TRUST BOUNDARY → INFLUENCE → REQUEST. Hash join retrieve→write. source_run_id write→recall.

## AUTHORITY

Coded grants. CTRL-MCP-001 decision. Handler count. OBSERVE != ALLOW. ALLOW != EXECUTION.

## DEFEND

Do not sanitize everything, delete memory, block all RAG, or ask Splunk to block. Remove the lab overlay. Keep the same adversarial bytes.

## RETEST

Same hash. RAG OBSERVE. Memory OBSERVE. CTRL-MCP-001 DENY tool_not_granted. ToolRegistry invocation count 0.

## COMPARE

SAME ADVERSARIAL INFLUENCE. DIFFERENT AUTHORIZATION. DIFFERENT INVOCATION, COMPLETION, AND OUTCOME.

## PROVE

Classify SUPPORTED / CORROBORATED / NOT PROVEN / INCORRECT.

ToolRegistry count proves process-local invocation began, not successful completion. Use `mcp.completed` / `mcp.failed` plus hop/outcome for completion and result evidence. CTRL-MCP-001 = authorization. Splunk = reconstructed telemetry, not enforcement. One RETEST != universal resistance.

## Learning connection

PI: untrusted input can influence. MCP: request is not grant. RAG: retrieved context is data. MEMORY: stored context is not authority. GOAL: authorized tool does not imply authorized purpose. IDENTITY: claims do not mint grants. CAPSTONE: multiple influence planes may exist; authority still requires an enforcement decision.

This packet does not replay every previous vulnerability.
