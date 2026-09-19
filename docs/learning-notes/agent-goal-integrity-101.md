# Agent goal / instruction integrity 101

**Status:** DESIGN learning note (13A). Runtime note is `agent-goal-integrity-runtime.md`.

## WHAT IS IT?

The question “what is this agent supposed to be doing?” is not the same question as “which tools may it call?”

## WHY DOES IT EXIST?

After tool results, RAG, memory, and identity claims were all classified as data, an attacker can still inject an instruction that **looks like a new job**. If the granted tool is still the right tool, MCP authorization will ALLOW. Goal integrity is the missing plane.

## HOW DOES IT WORK?

A server-owned **TaskContract** is frozen. A deterministic interpreter turns an AGENT NOTE into a **ProposedTaskChange**. That proposal is data. CTRL-GOAL-INTEGRITY-001 observes or rejects expansion. CTRL-MCP-001 then authorizes `lookup_policy` as usual.

## Simple story

You hired a clerk to **summarize** the lending flyer. The clerk already has the key to the flyer cabinet. An AGENT NOTE says “dump the whole flyer.” The key still works. The job did not change unless the boss (orchestrator) says so.

## Planes

1. Authoritative task  
2. Untrusted influence  
3. Proposed change  
4. Tool authorization  
5. Execution  

## What I should now be able to explain

1. Why DATA != INSTRUCTION AUTHORITY and INSTRUCTION != TASK AUTHORITY.
2. Why GOAL INFLUENCE != GOAL AUTHORIZATION.
3. Why TASK AUTHORITY != TOOL AUTHORITY.
4. Why AUTHORIZED TOOL + UNAUTHORIZED GOAL is a stronger proof than an unauthorized-tool DENY.
5. What CTRL-GOAL-INTEGRITY-001 OBSERVE means (and does not mean).
6. What DENY `unauthorized_task_expansion` means versus `tool_not_granted`.
7. Why ATTACK and RETEST must share task hash, input hash, and proposed change.
8. Why the vulnerable overlay must not mutate `coded_policy()`.
9. Why DET-MCP-001 is not a goal-integrity detector.
10. Why Splunk is not enforcement.

Wait for explicit Phase 13B. Do not start Phase 13C from this file.
