# Splunk Defender Bridge

The Splunk Defender Bridge is a named checkpoint between L5 and L6. It is not a new level id and it is not an eighth LIVE lab.

## Why it exists

L1 through L5 often hand the learner a `run.id` and a starter search. L6, L9, and L10 expect an investigation that starts from a security question. The bridge teaches that transition: hypothesis, evidence source, time scope, fields, candidate activity, a discovered run identifier, sequence, authorization versus execution, and a bounded conclusion.

## Placement

L5 Capstone → Splunk Defender Bridge → L6 Blue Team.

Academy menu order matches that placement. Level ids remain L0–L10. The checkpoint is `checkpoints` in `learning/academy/curriculum.json`. It is not an Attack Service lab.

## Prerequisites

L5 Capstone (Lending Assistant Investigation), including enough Path A practice to read a control decision and a tool event.

## Learning objectives

Start without a supplied run identifier. Form a bounded hypothesis. Choose `index=agentsec_telemetry` and `sourcetype=otel:agentic:json`. Discover real fields. Derive a candidate `agentsec.run.id` from denied CTRL-MCP-001 decisions. Reconstruct only the stages that are present. Write one `stats` command. Compare ATTACK, RETEST, and BASELINE. Reject a scanner or garak result as an authorization decision. State at least one NOT PROVEN claim and one NOT MODELED claim.

## LIVE versus REPLAY

Classification: **REPLAY / static**. The workbench searches evidence already indexed in the lab. It does not launch an attack. A row on the page is not a new measured experiment. If you later launch a LIVE lab yourself, that launch is a separate measurement.

## Evidence source

Runtime telemetry: `index=agentsec_telemetry`, `sourcetype=otel:agentic:json`.

Adjacent external evidence, used only as a false lead: `sourcetype=agentsec:scanner:finding` and `sourcetype=agentsec:external:evaluation`.

How evidence was obtained (MEASURED, OBSERVED, DOCUMENTED, REPLAYED, SIMULATED) is not the same vocabulary as what a claim may say (PROVEN, SUPPORTED, OBSERVED, INFERRED, NOT OBSERVED, NOT MODELED, NOT PROVEN, REFUTED). This checkpoint teaches the distinction. It does not rename the product evidence model.

## Limitations

- Empty results mean NO EVIDENCE FOUND for that search and time range.
- Indexed row count is not an execution count. Duplicate indexed copies are not extra executions. HEC acceptance is not searchable completeness.
- CTRL-MCP-001 remains the tool policy decision point. Splunk does not authorize. Scanner severity and garak results do not authorize.
- This checkpoint does not enable DET-MCP-001, create an alert, or claim a candidate search is a validated detection.
- L6 remains the deeper threat-hunting workshop.

## Relationship to later workshops

L6 hunts an incident in more depth. L9 and L10 expect the same independent habits on harder evidence. The bridge stops once the learner can reach a candidate investigation and a bounded conclusion.
