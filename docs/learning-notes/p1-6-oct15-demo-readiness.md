# P1.6: qualifying a demonstration without expanding the product

## In one paragraph

P1.6 does not add a new attack domain. It asks whether AgentSec can be shown on 15 October 2026 without lying: one Academy workshop, real CTRL-MCP-001 decisions, real Splunk copies when they exist, and honest labels for REPLAY versus LIVE. The hard part is not the click path. It is refusing to upgrade a sample parser into a vendor integration, a disabled detection into an SOC alert, or an untested screen reader into a WCAG claim.

## WHAT IS IT?

A delivery-qualification phase: inventory, curriculum coverage, enterprise telemetry honesty, a 15–20 minute script, rehearsal, and a GO / CONDITIONAL GO / NO-GO / BLOCKED verdict.

## WHY DOES IT EXIST?

A mixed audience will remember whatever you over-claim. Beginners need request ≠ grant. Practitioners need handler evidence. Leaders need residual risk. The same lab can serve all three if the facilitator does not collapse LIVE into REPLAY or Splunk into the PDP.

## HOW DOES IT WORK?

1. Academy serves LAB-MCP-001 in nine steps.
2. Evidence comes from committed REPLAY packs or authorized LIVE `artifacts/<run_id>/`.
3. Splunk search corroborates a copy. Academy status does not claim indexing.
4. After a LIVE launch, a new tab may auto-adopt that LIVE pair. The presenter either discloses LIVE or switches **this tab** to the recorded pair.
5. To record a **new** LIVE pair, the presenter clears this tab first. Clearing never deletes server references or artifacts.

## What rehearsal found that tests had not

Rehearsing on the deployed build exposed a real blocker. Once any LIVE pair existed on the server, every new tab adopted it and both LIVE launch buttons stayed disabled ("one run per mode per tab"). The written LIVE demo path could not run. Two lessons:

- **Recovery features change entry conditions.** The durable index (P1.5) was correct on its own, but it silently made "this tab has no ATTACK yet" false for every new tab.
- **Independent slots need a pairing rule.** The server picks the latest ATTACK and the latest RETEST separately. A new ATTACK must not be shown beside an older RETEST, or Compare would contrast two unrelated experiments. The client now adopts a RETEST only when it is not older than the adopted ATTACK.

A second lesson came from the test suite. A browser test that had passed in earlier P1.6 runs failed once in the final full run. String `wait_for_function` predicates need in-page `eval`, and the Academy CSP forbids it, so the test only passed when the condition was already true on the first check. The fix was the waiting mechanism, not the assertion.

## WHERE DOES IT SIT IN AGENTSEC?

After P1.4 (Academy) and P1.5 (HEC routing, durable notebook, zoom). Before any v1.0 tag, `main` merge, Phase 2, or PyRIT.

## WHAT IS THE TRUST BOUNDARY?

CTRL-MCP-001 in AcmeBank. The demo script is not a control.

## WHAT COULD AN ATTACKER CONTROL?

In the lab: the ungranted tool request on the vulnerable profile. In a briefing: the facilitator’s wording.

## WHAT CAN GO WRONG?

Calling 0 Splunk rows “blocked.” Calling `hec.ok` ingest. Calling DET-MCP-001 an alert. Calling VoiceOver tested. Mixing run.ids.

## WHAT TELEMETRY SHOULD EXIST?

`agentsec.run.id`, `agentsec.control.decision`, `event.name` including `agentsec.mcp.started` on ATTACK, schema version, provenance badge.

## HOW WILL SPLUNK SHOW IT?

`index=agentsec_telemetry sourcetype=otel:agentic:json "agentsec.run.id"=<id> | stats count as n`

## WHAT CONTROL COULD CHANGE THE RESULT?

Defended profile: DENY `tool_not_granted` before the handler.

## WHAT TEST PROVES THE LOGIC?

Academy compare: ALLOW vs DENY and OBSERVED vs NOT OBSERVED on the same specimen, two run.ids.

## What I should now be able to explain

1. Why visibility is not authorization.
2. Why ALLOW is not execution.
3. Why NOT OBSERVED is not SAFE if the export may be incomplete.
4. Why REPLAY packs can be schema 1.1.0 while new LIVE is 1.9.0.
5. Why DET-MCP-001 would not fire on fail-open ALLOW even if it were enabled.
6. Why scanner/garak packs are not LAB-MCP-001 evidence.
7. Why other SIEM vendors are REFERENCE ONLY.
8. Why VoiceOver UNTESTED blocks a WCAG claim but not necessarily the demo.
9. Why a tab switch to REPLAY must not be described as a live launch.
10. Why a GO for the demonstration is not permission to release a production product.
11. Why recovering durable LIVE slots blocked new LIVE launches, and why clearing one tab is safe for evidence.
12. Why a newer ATTACK must never be compared with an older RETEST.
