# Human-in-the-loop approval design

## What it is

A design for a later lesson about human approval. It describes a simulated approval record. It does not add an approval button or a new control to the running lab.

## Why it exists

A name such as `approver-sam`, or a field that says APPROVE, is easy to treat as proof that a person authorized the action that ran. Those are different facts.

## How it works

The proposed lesson keeps one approval fixed: `lookup_policy` for `lending-basics`. ATTACK and RETEST submit `executive-restricted` after that approval. BASELINE submits `lending-basics`. CTRL-MCP-001 still makes the tool decision. The approval record does not.

## Where it sits

After the A2A workshop and before L8 privacy, if a later workshop is authorized. Levels L0–L10 stay as they are.

## Trust boundary

The approval artifact crosses from a claimed approver into a proposed tool call. It does not cross into tool authorization. CTRL-MCP-001 remains that boundary.

## What an attacker could control

In a real system, an attacker might change parameters after a person approved a narrower action. This design does not implement that runtime attack. It specifies a static packet so the learner can see the mismatch.

## What can go wrong

Treating `applicant-web` or `approver-sam` as an authenticated human. Treating MCP-004 resource events as approvals. Treating APPROVE as ALLOW. Treating a tool start as a resource change.

## Telemetry

Today there is no approval event. The useful existing events are CTRL-MCP-001 and `agentsec.mcp.started`. Completion and resource outcome need their own rows when they exist.

## How Splunk shows it

Splunk can display a future simulated packet and can search historical tool events. A displayed approval row is not an approval grant.

## What control could change the result

CTRL-MCP-001. The binding check can say MISMATCH while the vulnerable teaching row still ALLOWs. The corrected teaching row DENYs the same mutated submission.

## What test proves the logic

No runtime test can prove this yet, because no approval control exists. A later workshop would need repository tests that the packet stays simulated and that CTRL-MCP-001 is unchanged. This design does not add those tests.

## What I should now be able to explain

1. Why is an approval request different from an approval decision?
2. Why does a named approver not prove a human clicked approve?
3. What does approval authority add beyond authentication?
4. How can the same tool name still be a parameter mutation?
5. Why is binding MATCH not the same as CTRL-MCP-001 ALLOW?
6. Why are ATTACK and RETEST the same submission while BASELINE is not?
7. Why is an approval expiry different from a credential expiry?
8. Why is MCP-004’s resource fail-open not already a HITL lesson?
9. What would a replay be, and why is it not the first attack?
10. Which claims stay NOT PROVEN even after the simulated packet is read?
