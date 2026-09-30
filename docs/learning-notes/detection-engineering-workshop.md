# Detection engineering workshop

The Detection Engineering workshop is a REPLAY checkpoint after L6. It is not a new academy level and not a LIVE lab.

## What it is

A learner writes a candidate detection for one behavior: a tool start after CTRL-MCP-001 denied that same tool. They compare ATTACK, RETEST, and BASELINE, then write a coverage statement.

## Why it exists

A SPL file is not a detector. DET-MCP-001 is disabled and at maturity LOGIC_VALIDATED. Its same-tool logic can be right and still miss the fail-open ALLOW path that the indexed ATTACK specimens use. The search note does not call it an operational detection.

## How it works

The learner starts with no run id. A broad search correlates only on `agentsec.run.id`. A tuned search adds the same `gen_ai.tool.name`, a later `agentsec.sequence`, and `agentsec.control.id=CTRL-MCP-001` on the decision event only. `agentsec.mcp.started` does not carry the control id.

The shipped `DET-MCP-001.spl` does not filter the control id. The workshop does not edit that file or `savedsearches.conf`.

## Where it sits

L5, then the Splunk Defender Bridge, then L6, then this workshop, then later investigation material. Level ids stay L0–L10.

## Trust boundary

CTRL-MCP-001 decides. Splunk investigates. A detection row does not authorize a tool. Scanner and garak evidence stay adjacent.

## What an attacker can control

In this lab, the vulnerable profile can receive ALLOW instead of DENY. The detection that looks only for DENY-then-start does not see that path.

## What can go wrong

Run-id-only correlation flags an earlier start of a different, allowed tool. Zero rows get reported as a safety verdict. A simulated `makeresults` row gets treated as a live attack. The saved search's 24-hour window is mistaken for `earliest=0`.

## Telemetry

`event.name`, `agentsec.run.id`, `gen_ai.tool.name`, `agentsec.sequence`, `agentsec.control.decision`, `agentsec.control.id` on the decision, `agentsec.control.reason`, `agentsec.testbed.mode`.

## How Splunk shows it

Search over `index=agentsec_telemetry` with `earliest=0`. The workshop page does not enable a scheduled search.

## What control could change the result

CTRL-MCP-001 returning DENY instead of fail-open ALLOW would change which rows exist. This workshop does not change that control.

## What test proves the logic

`tests/splunk/test_detection_engineering_workshop.py` checks the page, the searches, and the disabled detector. It does not dispatch SPL and does not prove a browser rendered the view.

## What I should now be able to explain

1. Why is a query not a detector?
2. Why does same-run correlation flag `lookup_policy` in a run that denies `lookup_customer_tier`?
3. Why is that `lookup_policy` start not after the DENY?
4. Why does `DET-MCP-001.spl` not prove it filtered on CTRL-MCP-001?
5. Why can a correct DENY-then-start predicate miss the principal ATTACK?
6. What does a BASELINE non-match fail to prove?
7. Why is `operation.outcome=prevented` not proof that no tool started?
8. Why must the simulated positive stay labeled SIMULATED?
9. What would still be required before the saved search could be enabled?
10. Why is a detection match not an incident?
