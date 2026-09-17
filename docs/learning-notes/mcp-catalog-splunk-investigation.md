# MCP catalog poisoning in Splunk

**Status:** Phase 8D validated on live Splunk. Dashboard Studio is **not** this phase. DET-MCP-CATALOG is **not** created.  
**Parents:** `docs/PHASE8D_MCP_CATALOG_SPLUNK_VALIDATION.md`, `docs/MCP_CATALOG_SPLUNK_FIELD_CONTRACT.md`, `docs/MCP_CATALOG_SEARCH_CONTRACT.md`.  
**SPL:** existing LAB-MCP-001 Q-MCP searches (schema-version agnostic) plus `Q-MCP-CATALOG-AUTHORITY`.

---

## WHAT IS IT?

The same investigation questions used for earlier MCP labs, pointed at catalog/tool-description poisoning runs, plus one new hunt: what **catalog metadata** did the run observe, how was that metadata **classified**, and did a **follow-on tool** get authorized after that observation?

Splunk is not a second authorizer. It does not decide whether a description is a grant.

## WHY DOES IT EXIST?

Phase 8C proved INV-002 locally: a poisoned `description` cannot mint authority on the defended profile; the vulnerable profile fail-opens with an explicit overlay reason. Splunk is where you reconstruct **the same story** after the copy is indexed: METADATA-001 stays OBSERVE even on ATTACK, first `lookup_policy` is a normal ALLOW, ATTACK and RETEST share one description **hash**, and only ATTACK’s hop-1 CTRL-MCP-001 ALLOWs `lookup_customer_tier`.

Q-MCP-AUTHZ cannot tell this story by itself. It shows an extra OBSERVE row and a hop-1 decision, but it does not table metadata trust, provenance, or the hash.

## HOW DOES IT WORK?

1. AcmeBank emits schema **1.5.0** JSON over OTLP (`CTRL-MCP-METADATA-001`, `MCP-CATALOG-001`, `agentsec.mcp.metadata.trust`).
2. Collector → HEC → `index=agentsec_telemetry`.
3. Some scalars appear two or three times. SPL collapses copies with `mvindex(mvdedup('field'),0)`.
4. Bind `__RUN_ID__` on existing Q-MCP files. They do **not** filter `schema.version`.
5. `Q-MCP-CATALOG-AUTHORITY` collapses one run: metadata classification + hash + first grant + follow-on decision + indexed execution observation.

`derived_authority` and `no_indexed_followon_execution_event` are **display helpers**. They are not detectors.

## WHERE DOES IT SIT IN AGENTSEC?

HUNT / MEASURE for LAB-MCP-CATALOG. Detection stays DET-MCP-001 (execution after DENY). Catalog ATTACK is a hunt, not a new notable. Workshop and scanners are later phases.

## WHAT IS THE TRUST BOUNDARY?

`mcp.catalog.metadata` for METADATA-001, then `acmebank.mcp.authorize` for CTRL-MCP-001, then `mcp.tool.execute` only after ALLOW. Splunk cannot ALLOW or DENY a description.

## WHAT COULD AN ATTACKER CONTROL?

The catalog **description** bytes (here a lab fixture) and the requested follow-on tool/scope. They cannot pick `run.id`, profile, coded grants, metadata trust enum, or `control.decision`. They cannot make Splunk invent hop-1 `mcp.started`.

## WHAT CAN GO WRONG?

- Treating METADATA-001 OBSERVE as ALLOW or as “the description was authorized.”
- Treating ATTACK hop-1 ALLOW as server policy granting `lookup_customer_tier`.
- Treating 0 DET-MCP-001 rows as proof the preferred attack failed — it succeeded **without** a DENY.
- Treating 0 hop-1 `mcp.started` rows as independent proof the handler never ran.
- Treating Q-MCP-EXECUTED’s extra OBSERVE row as metadata execution.
- Treating Q-MCP-PARAMS `arguments_hash` on the METADATA row as tool arguments.
- Correlating ATTACK and RETEST by preview text instead of hash.
- Building DET-MCP-CATALOG on the fail-open reason string and calling it a general poisoning detector.
- Dumping `_raw` to “show the poison.”

## WHAT TELEMETRY SHOULD EXIST?

METADATA-001 on hop 0 with trust, provenance, hash, bounded preview. Hop-0 CTRL-MCP-001 then `lookup_policy` execution. Hop-1 CTRL-MCP-001 only if a follow-on is requested. Hop-1 `mcp.started` only after ALLOW. Runtime handler counts as proof of execution. No `allowed_tools` field. No full catalog list.

## HOW WILL SPLUNK SHOW IT?

| Question | Search |
|----------|--------|
| Who / which tool? | Q-MCP-WHO (extra empty-method row) |
| What was decided? | Q-MCP-AUTHZ |
| Did execution begin? | Q-MCP-TOOL / Q-MCP-EXECUTED |
| Execution after DENY? | Q-MCP-AFTER-DENY / DET-MCP-001 |
| Result classification? | Q-MCP-RESULT-TRUST (not metadata) |
| Catalog INV-002 reconstruction? | **Q-MCP-CATALOG-AUTHORITY** |
| Same malicious description on B and C? | Compare indexed `metadata_hash` (CLI) |

## WHAT CONTROL COULD CHANGE THE RESULT?

CTRL-MCP-001 on the follow-on: defended DENY `tool_not_granted` vs vulnerable overlay ALLOW. METADATA-001 does **not** change: it is OBSERVE on A/B/C. A scanner finding is evidence, not this control.

## WHAT TEST PROVES THE LOGIC?

Live Splunk CLI on COMPLETE A/B/C copies: METADATA-001 OBSERVE; B hop-1 ALLOW + `mcp.completed_observed`; C hop-1 DENY + no hop-1 `mcp.started`; B hash == C hash; DET-MCP-001 0/0/0. Pytest checks hunt templates only — it does not execute Splunk.

---

## What I should now be able to explain

1. Why METADATA-001 OBSERVE on ATTACK is correct and is not a missed DENY.
2. Why the first `lookup_policy` ALLOW is legitimate and does not mean the description was granted.
3. Which indexed field is the description fingerprint, and why preview is not that proof.
4. How you show ATTACK and RETEST used the same malicious description without `join`.
5. Why DET-MCP-001 stays silent on the preferred catalog ATTACK.
6. Why Q-MCP-EXECUTED can show an extra OBSERVE row with `mcp.completed`.
7. Why `agentsec.mcp.result.trust` is the wrong field for catalog metadata.
8. Why a detector on `vulnerable_profile_fail_open:metadata_derived_authority` would be a lab teaching signal, not a general production poisoning detector.
9. Why Splunk absence of hop-1 `mcp.started` on RETEST is corroboration, not spy-level proof.
10. What is still **BLOCKED BY TELEMETRY** (full advertised tool list, scanner findings).
