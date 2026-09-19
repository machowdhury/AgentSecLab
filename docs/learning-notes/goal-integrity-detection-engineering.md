# Goal integrity detection engineering (Phase 13D)

**Status:** Detection analyzed — no new detector. Workshop designed, not implemented.  
**Parents:** `docs/PHASE13D_GOAL_INTEGRITY_DETECTION_ANALYSIS.md`, `docs/learning-notes/goal-integrity-splunk-investigation.md`.

---

## WHAT IS IT?

A SOC detection-engineering pass over LIVE 13C evidence for **authorized tool + unauthorized goal**, plus the contract for a later ten-tab workshop. No new detector. No Studio.

## WHY DOES IT EXIST?

13C proved Splunk can reconstruct the chain. 13D answers: should that chain become DET-GOAL? **No.** And: how should a learner be taught the difference between a tool grant and a task grant?

## HOW DOES IT WORK?

Five planes (task, instruction, goal decision, tool authz, execution) stay separate. Candidates A–G are classified CONTEXT / HUNT / DETECTION / FUTURE RESEARCH / REJECT. DET-MCP-001 stays the only operational detector and stays silent 0/0/0 for a **correct** reason. `Q-GOAL-INTEGRITY-AUTHORITY` is reused. Overlay reason and `AGENT NOTE` are rejected as production IOCs.

## WHERE DOES IT SIT IN AGENTSEC?

After 13C Splunk validation. Before 13E workshop implementation. Same index/sourcetype. Different security question than MCP-001 (tool allow-list) and MCP-006 (ambient deputy).

## WHAT IS THE TRUST BOUNDARY?

`agent.task.contract` for goal integrity. `acmebank.mcp.authorize` for the tool. Splunk sits on neither.

## WHAT COULD AN ATTACKER CONTROL?

The untrusted instruction. Not the TaskContract, not coded grants, not Splunk.

## WHAT CAN GO WRONG?

Alerting on untrusted instructions (BASELINE fires). Treating goal DENY as an incident. Treating MCP ALLOW as goal authorization. Broadening DET-MCP-001 so RETEST looks like execution-after-DENY. Teaching `AGENT NOTE` regex. Assigning HIGH severity to a proposal. Letting ML grant authority.

## WHAT TELEMETRY SHOULD EXIST?

What 13C already indexed, plus (future) first-class effective action and permitted-action id if production wants detector E. Do not invent them in 13D.

## HOW WILL SPLUNK SHOW IT?

13E will bind existing hunts to 13C tokens. DETECT tab titles **DETECTION ANALYZED — NO NEW GOAL DETECTOR** and shows DET-MCP-001 0/0/0 as correct, not safe.

## WHAT CONTROL COULD CHANGE THE RESULT?

`AGENTSEC_SECURITY_PROFILE`. Splunk only records it. Defense preserves `lookup_policy` for the original task.

## WHAT TEST PROVES THE LOGIC?

13C LIVE completeness and hunt output (DOCUMENTED). 13D pytest proves design documents exist and no DET-GOAL/Studio shipped — not detector effectiveness.

---

## What I should now be able to explain

1. Why MCP ALLOW does not mean the agent's goal was authorized.
2. Why DET-MCP-001 is silent on RETEST and why that is correct.
3. Why `untrusted_instruction` is CONTEXT, not DETECTION.
4. Why overlay reason and `AGENT NOTE` are REJECT as production signals.
5. Why authorized-tool + out-of-task effective action is FUTURE RESEARCH / TELEMETRY DEPENDENT.
6. Why runtime handler counts remain the authoritative wrong-goal proof.
7. Why Q-GOAL-INTEGRITY-AUTHORITY is reused instead of four extra Q-GOAL files.
8. Why CIM is NOT APPLICABLE.
9. Why ANOMALY != INCIDENT and ML must not grant authority.
10. What the 13E LEARN first canvas must say, and why 13E is not started yet.
