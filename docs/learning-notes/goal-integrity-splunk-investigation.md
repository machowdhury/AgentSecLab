# Agent goal / instruction integrity Splunk investigation (Phase 13C)

**Status:** Phase 13C live Splunk validated. No Dashboard Studio. No DET-GOAL.  
**Parents:** `docs/PHASE13C_GOAL_INTEGRITY_SPLUNK_VALIDATION.md`, `docs/learning-notes/agent-goal-integrity-runtime.md`.

---

## WHAT IS IT?

Live proof that schema **1.9.0** goal/task/instruction fields actually extract in Splunk, and that one hunt can reconstruct:

authoritative task → untrusted instruction → proposed action → goal-integrity decision → effective action → MCP authorization → execution

without treating MCP ALLOW as proof the agent's goal was authorized.

## WHY DOES IT EXIST?

13B proved locally: AUTHORIZED TOOL + UNAUTHORIZED GOAL. The same server-owned task and the same malicious instruction produce the same proposed expansion (`extract_full_policy`). ATTACK permits it through an intentionally vulnerable profile. RETEST rejects it and still ALLOWs `lookup_policy` for the original summarize task. Splunk is the SOC evidence plane. Field names in a schema file are not indexed fields until live discovery.

## HOW DOES IT WORK?

Fresh A/B/C runs with OTEL on went OTLP → collector → HEC → `index=agentsec_telemetry`. Completeness used `dc(_raw)` vs `events.jsonl` (10=10=10, **COMPLETE**). Fields were collapsed with `mvindex(mvdedup(…),0)`. Existing Q-MCP searches were reused unchanged. One new hunt, `Q-GOAL-INTEGRITY-AUTHORITY`, binds `__RUN_ID__`.

Instruction hash, proposed-change fingerprint, and effective action are **not** first-class. On these specimens the complete SHA-256 / action ids are visible in the 200-character `agentsec.content.preview`. The hunt tables those previews instead of inventing `rex` aliases.

## WHERE DOES IT SIT IN AGENTSEC?

After LAB-AGENT-GOAL-INTEGRITY-001 runtime (13B) and before workshop (not started). Same index/sourcetype as MCP labs. Different control (`CTRL-GOAL-INTEGRITY-001`) than CTRL-MCP-001. DET-MCP-001 stays the only operational detector.

## WHAT IS THE TRUST BOUNDARY?

Indexed `agentsec.trust_boundary=agent.task.contract` on GOAL-INTEGRITY-001. Tool authorization remains `acmebank.mcp.authorize` on hop-1 CTRL-MCP-001. Splunk does not sit on either boundary.

## WHAT COULD AN ATTACKER CONTROL?

The untrusted instruction (fixture note). Not the TaskContract, not coded grants, not profile, not indexed `control.decision`. Splunk cannot be used to mint ALLOW or redefine the task.

## WHAT CAN GO WRONG?

Treating OBSERVE as ALLOW; treating MCP ALLOW as goal authorization; treating `gen_ai.tool.name` on the GOAL hop as an MCP tool; treating overlay reason or `AGENT NOTE` as a production IOC; treating DET-MCP-001 silence as “safe”; treating missing `mcp.started` as prevention; inventing `session.id` / `trusted_instruction` / `task_authorized`; rewriting Q-MCP because GOAL rows have empty MCP fields.

## WHAT TELEMETRY SHOULD EXIST?

GOAL-INTEGRITY-001: task id/hash/provenance, `untrusted_instruction`, proposed action, OBSERVE/DENY, snapshot hash. Hop-1: CTRL-MCP-001 ALLOW `lookup_policy`. Optional `mcp.started`/`completed`. All were **OBSERVED** live. First-class instruction hash / effective action were **not** indexed (**NOT EXTRACTED**; preview-bounded).

## HOW WILL SPLUNK SHOW IT?

Q-MCP-AUTHZ shows the GOAL row plus hop-1 ALLOW. Q-MCP-WHO shows the proposed action id as `gen_ai.tool.name`. The new hunt adds task/instruction/proposed columns and collapses one row per specimen. DET-MCP-001 stays 0 on A/B/C, including RETEST.

## WHAT CONTROL COULD CHANGE THE RESULT?

`AGENTSEC_SECURITY_PROFILE` on that run. Splunk only records it. CTRL-MCP-001 still ALLOWs `lookup_policy` when the tool is granted.

## WHAT TEST PROVES THE LOGIC?

Live `dc(_raw)` COMPLETE on three IDs; B task hash == C; B instruction hash == C (preview); B proposed fingerprint == C (preview); hunt A OBSERVE + summarize + MCP ALLOW; B overlay OBSERVE + extract + MCP ALLOW; C DENY + summarize effective + MCP ALLOW; runtime handlers 1/0, 0/1, 1/0; DET-MCP-001 0/0/0.

---

## What I should now be able to explain

1. Why schema 1.9.0 field names still needed live field discovery.
2. Why `dc(_raw)` is the completeness metric, not `stats count`.
3. Why GOAL-hop `gen_ai.tool.name` is a proposed action id, not `lookup_policy`.
4. Why CTRL-MCP-001 ALLOWs on ATTACK and RETEST while effective actions differ.
5. Why instruction hash is in `content.preview` and not `agentsec.instruction.hash`.
6. Why one Q-GOAL-INTEGRITY-AUTHORITY hunt was justified and extra Q-GOAL-* files were not.
7. Why DET-MCP-001 is silent on RETEST goal DENY followed by `lookup_policy` start.
8. Why OBSERVE is not ALLOW and MCP ALLOW is not goal authorization.
9. Why overlay reason and `AGENT NOTE` must not become production IOCs.
10. Why handler counts remain the runtime proof of wrong-goal non-execution, and why Phase 13D / Studio must not start from this file.
