# Human approval and action binding

## What is it?

A simulated record that a named approver accepted one specific action: tool, resource, action reference, audience, and time window.

## Why does it exist?

An approval can be real for one action and then be presented with a different action. The dangerous case in this workshop is post-approval parameter mutation: the approved resource is `lending-basics`, and the submitted resource is `executive-restricted`.

## How does it work?

The packet is SIMULATED / REPLAYED. ATTACK and RETEST submit the same mutated action. BASELINE submits the approved action. CTRL-MCP-001 remains the tool decision. Splunk does not approve the tool.

## Where does it sit?

After A2A Authentication and Delegation, before L8. View `ws_lab_hitl_approval`. It is not a LIVE lab.

## Trust boundary

The approval record, the submitted action, and the tool decision are different evidence. A match between approval and submission is not an ALLOW.

## What could an attacker control?

The submitted tool, resource, or action reference after an approval was recorded.

## What can go wrong?

A vulnerable teaching profile accepts the mismatched action. The secure comparison denies it. Neither row proves the approver was authenticated or had approval authority.

## Telemetry

This workshop does not emit a new runtime event. A contrast search labels historical resource decisions as not approvals.

## How Splunk shows it

The CONTRAST tab runs `Q-APPROVAL-CONTRAST.spl` and stamps `HISTORICAL RESOURCE DECISION — NOT AN APPROVAL`.

## What control could change the result?

Binding the submitted action to the approved action before CTRL-MCP-001 allows the tool. That control is not implemented in `authorize.py`.

## What test proves the logic?

`tests/splunk/test_hitl_approval_workshop.py` checks the packet, the replay placement, and the unchanged schema. It does not prove a runtime approval service.

## What I should now be able to explain

1. Why is approval not authentication?
2. Why is approval not authorization?
3. What is the same in ATTACK and RETEST?
4. What is different in BASELINE?
5. Why is a MATCH not an ALLOW?
6. Why is the ATTACK ALLOW reason not the MCP-004 resource reason?
7. Why must RETEST not infer execution?
8. Why is approver type not `principal.type=human`?
9. Why is resource impact NOT PROVEN?
10. Why is replay deferred?
