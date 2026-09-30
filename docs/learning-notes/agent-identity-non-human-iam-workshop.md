# Agent Identity and Non-Human IAM workshop

The workshop is a REPLAY investigation between L7 and L8. It uses the indexed workflow `agentsec.workflow.entry=/identity/delegate` with `agentsec.lab.id=agentsec-local`. It does not launch an attack and it does not authenticate anyone.

## What it is

A learner workbench that separates a claimed name, an identity observation, a tool decision, and execution evidence.

## Why it exists

A name in a log is easy to treat as a person who logged in and approved a tool. Those are different claims. This workshop makes the learner keep them apart on evidence that already exists.

## How it works

The learner starts from a security question, finds candidate runs, and classifies each claim. CTRL-IDENTITY-001 only observes a claim. CTRL-MCP-001 is the tool decision. `event.name=agentsec.mcp.started` is execution evidence. Splunk displays the rows. Splunk does not authenticate.

## Where it sits

L7 threat modeling, then this workshop, then L8 privacy. Levels L0–L10 stay numbered as they are. The workshop is not on the Attack Service allowlist.

## Trust boundary

The identity claim crosses from the caller label into the tool decision. The vulnerable reason `caller_identity_derived_authority` is a labeled authorization fault on CTRL-MCP-001. It is not a proof of delegated authority.

## What an attacker could control

In the vulnerable teaching profile, a caller identity claim can be treated as a reason to allow one closed tool use. That is a lab fault in the tool decision. It is not production IAM.

## What can go wrong

Reading `agentsec.principal.type=user` as an authenticated human. Treating `gen_ai.agent.id` as execution. Treating a run count as the authorization decision. Calling an empty result SAFE.

## Telemetry

Look for `agentsec.principal.id`, `agentsec.principal.type`, caller and callee identity fields, `agentsec.control.id`, the decision and reason, `agentsec.sequence`, and `agentsec.mcp.started`.

## How Splunk shows it

Search the workflow entry. Group by run and mode. Put the identity control and the tool control in different rows. Count starts separately.

## What a control can change

CTRL-MCP-001 can ALLOW or DENY the tool. That change does not create an authenticated principal. CTRL-IDENTITY-001 does not authorize the tool.

## What test proves the logic

`tests/splunk/test_agent_identity_nhi_workshop.py` checks placement, REPLAY mode, the missing run identifier, the claim boundaries, and the unchanged schema. It does not prove a live Splunk result.

## What I should now be able to explain

1. Why is `applicant-web` not an authenticated human?
2. What does CTRL-IDENTITY-001 actually decide?
3. Which control is the tool policy decision point?
4. Which event is execution evidence, and what does it not prove?
5. Why can `agentsec.principal.type=user` appear on a callee event?
6. What is `caller_identity_derived_authority` if it is not legitimate delegation?
7. Why do identical run counts across ATTACK, RETEST, and BASELINE fail to prove the same authorization?
8. Which production identity facts are still NOT MODELED?
9. Why is a Splunk row not an authentication?
10. What later topics stay FUTURE and are not in this runtime?
