# Short-lived credential lifetime

## What is it?

A synthetic reference that stands in for a credential: who it names, who it is for, what scope it claims, when it starts, and when it expires.

## Why does it exist?

A privileged request can arrive with a credential that is already expired. Expiry is evidence. It is not, by itself, the tool decision.

## How does it work?

ATTACK and RETEST present `sim-cred-expired-001` with `lookup_customer_tier` / `cust-001`. ATTACK allows that only as a labeled teaching fault. RETEST denies it. BASELINE presents a current reference with an in-scope tool, and CTRL-MCP-001 grants the tool. The current reference did not authorize the tool.

## Where does it sit?

After Human Approval and before L8. View `ws_lab_credential_lifetime`.

## Trust boundary

The credential reference, the approval clock, and the tool decision are separate. Approval expiry in the HITL packet is not this credential's expiry.

## What could an attacker control?

Which reference is presented, and which tool is requested after the reference has expired.

## What can go wrong?

A vulnerable teaching profile accepts the expired reference. Revocation and rotation are named and not demonstrated.

## Telemetry

No runtime credential event is emitted. The absence search labels indexed credential lifetime as NOT OBSERVED.

## How Splunk shows it

`Q-CREDENTIAL-ABSENCE.spl` stamps `credential_lifetime="NOT OBSERVED"`. Empty is not safe.

## What control could change the result?

Rejecting an expired reference before CTRL-MCP-001 allows the tool. That check is not in `authorize.py`.

## What test proves the logic?

`tests/splunk/test_credential_lifetime_workshop.py` checks the packet and that `expired_credential` is not in the runtime authorizer.

## What I should now be able to explain

1. Why is identity not a credential?
2. Why is a credential not authority?
3. Why is a current credential not tool authorization?
4. What is the same in ATTACK and RETEST?
5. Why is the BASELINE request different?
6. Why is approval expiry a different clock?
7. Why is rotation NOT DEMONSTRATED?
8. Why does an empty Splunk result not mean credentials are safe?
9. Why are there no real secrets in the packet?
10. Why is resource impact NOT PROVEN?
