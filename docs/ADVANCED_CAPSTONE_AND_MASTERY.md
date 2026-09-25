# L10 — Advanced capstone and mastery

**Lab:** `LAB-ADVANCED-CAPSTONE-MASTERY-001`
**Incident:** MASTER-2026-001
**Mode:** REPLAY
**Schema:** 1.9.0 unchanged
**ExternalEvidence:** 1.0.0 unchanged
**Tool PDP:** CTRL-MCP-001 unchanged

This is not AGENT-2026-009 and not a new security domain. The investigative problem is the validated goal-integrity lending-policy packet: the granted tool stays `lookup_policy`, while the effective objective does not.

## Business context

AcmeBank's assistant summarizes lending policy options. The authorized task is `summarize_lending_policy_options`. The permitted action is `summarize_lending_policy`. The granted tool is `lookup_policy` (`policy:read`, resource `lending-basics`).

Security Operations has an operational note for **2026-09-18T22:47:40Z through 2026-09-18T22:48:10Z**, plus a scanner export and an evaluation export. Cause and customer impact are unknown. The mission does not start from a run identifier.

## What the learner must separate

Real signal, benign `lookup_policy` use, a goal-control gap on the vulnerable profile, a goal DENY on the defended retest, unrelated external evidence, duplicate indexed copies, and at least one customer-impact question that stays **NOT PROVEN**.

## Reference disposition

Path B holds the reference. It is a review key, not policy.

| Hypothesis | Disposition |
| --- | --- |
| H1 Untrusted instruction expanded the objective and that objective executed while the goal control only observed | SUPPORTED |
| H2 CTRL-MCP-001 denied the tool, so execution was an authorization bypass | REFUTED |
| H3 Scanner HIGH caused the runtime event, or garak PASS cleared it | REFUTED |

ATTACK and RETEST share the task hash and the instruction hash. They do not share the goal decision or the effective action. Same hash is not the same execution.

## Evidence class

Runtime decisions and distinct-event counts for the three window runs are prior validated telemetry, remeasured in this phase as indexed copies versus `dc(_raw)`. Handler counts for the wrong-goal path are DOCUMENTED from the goal-integrity runtime validation, not a new live execution. No events were fabricated for L10.

## Explicitly not built

No new scanner, PDP, detector installation, runtime attack, SOAR, IAM, cryptographic delegation, human-approval engine, compliance engine, AI-BOM, attack graph, risk score, or RC2.
