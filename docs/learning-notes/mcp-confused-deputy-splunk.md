# MCP confused deputy in Splunk

**Status:** Phase 7C validated on live Splunk. Dashboard Studio is **not** this phase. DET-MCP-006 is **not** created.  
**Parents:** `docs/MCP006_SPLUNK_VALIDATION.md`, `docs/MCP006_SPLUNK_FIELD_VALIDATION.md`, `docs/MCP006_DETECTION_VALIDATION.md`.  
**SPL:** existing LAB-MCP-001 Q-MCP searches (schema-version agnostic) plus `Q-MCP-DELEGATION`.

---

## WHAT IS IT?

The same investigation questions used for earlier MCP labs, pointed at MCP-006 runs, plus one new hunt: did a **deputy** run a tool using **ambient deputy authority** while the **caller’s delegated grant** did not cover that tool?

Splunk is not a second authorizer.

## WHY DOES IT EXIST?

Phase 7B proved INV-001 on a two-agent path with handler spies. Splunk is where you reconstruct **the same story** after the copy is indexed: same ATTACK/RETEST request, hop-0 caller vs hop-1 deputy, `authority.source` delegated vs ambient, CTRL-DELEGATION-001 ALLOW vs DENY, downstream MCP separate from delegation.

Q-MCP-WHO cannot tell this story by itself. It shows two agents on ALLOW paths and does not name caller vs deputy or authority source.

## HOW DOES IT WORK?

1. AcmeBank emits schema **1.4.0** JSON over OTLP (`CTRL-DELEGATION-001`, `MCP-006`, `delegation.authority.source`).
2. Collector → HEC → `index=agentsec_telemetry`.
3. Some scalars appear two or three times. SPL collapses copies with `mvindex(mvdedup('field'),0)`.
4. Bind `__RUN_ID__` on existing Q-MCP files. They do **not** filter `schema.version`.
5. `Q-MCP-DELEGATION` collapses one run: caller, deputy observation, authority source, delegation decision, MCP decision, execution observation.

`deputy_not_on_indexed_hop1` and `no_indexed_mcp_execution_event` are **display helpers**. They are not detectors.

## WHERE DOES IT SIT IN AGENTSEC?

HUNT / MEASURE for LAB-MCP-006. Detection stays DET-MCP-001 (execution after DENY). Confused-deputy ATTACK is a hunt, not a new notable.

## WHAT IS THE TRUST BOUNDARY?

Still `acmebank.mcp.authorize`, now with CTRL-DELEGATION-001 **before** CTRL-MCP-001 **before** the handler. Splunk cannot ALLOW or DENY a deputy call.

## WHAT COULD AN ATTACKER CONTROL?

The requested tool / scope / arguments on the lab invoke. They cannot pick `run.id`, profile, coded grants, caller id, deputy id, or `authority.source`. They cannot make Splunk invent hop-1 `mcp.started`.

## WHAT CAN GO WRONG?

- Treating hop-1 MCP ALLOW as proof the **caller** was delegated the tool.
- Treating ATTACK execution as authorization.
- Treating `profile=vulnerable` as ambient authority without reading `authority.source`.
- Treating 0 DET-MCP-001 rows as proof the preferred attack failed — it succeeded **without** a DENY.
- Treating 0 `mcp.started` rows as independent proof the handler never ran.
- Parsing hop-0 preview JSON as an `allowed_tools` field.
- Treating `mvcount=2` as two decisions.
- Building DET-MCP-006 on the fail-open reason / enum alone.

## WHAT TELEMETRY SHOULD EXIST?

CTRL-DELEGATION-001 on hop 0 with `authority.source`. Hop-1 CTRL-MCP-001 and `mcp.started` only after delegation ALLOW. Runtime handler counts as proof of execution. No `allowed_tools` field in this schema.

## HOW WILL SPLUNK SHOW IT?

| Question | Search |
|----------|--------|
| Who / which agents? | Q-MCP-WHO (two agents on A/B) |
| ALLOW / DENY + reason? | Q-MCP-AUTHZ (both controls) |
| Requested vs allowed **scope**? | Q-MCP-SCOPE (equality helper; hop-1 ambient CSV is not MCP-003) |
| Did execution begin? | Q-MCP-TOOL / Q-MCP-EXECUTED |
| Caller, deputy, source, both decisions? | **Q-MCP-DELEGATION** |
| DENY then start? | Q-MCP-AFTER-DENY / DET-MCP-001 |

BASELINE: source `delegated`, delegation ALLOW, MCP ALLOW, `mcp.completed_observed`.  
ATTACK: source `ambient_deputy`, delegation ALLOW, MCP ALLOW, execution observed — **not** caller authorization.  
RETEST: same request as ATTACK, delegation DENY, `deputy_not_on_indexed_hop1`, `no_indexed_mcp_execution_event`.

## WHAT CONTROL COULD CHANGE THE RESULT?

`AGENTSEC_SECURITY_PROFILE=defended` vs `vulnerable` on the **same** `lookup_customer_tier` request. Splunk will show DENY vs ambient ALLOW. Coded delegated tools stay `{lookup_policy}`.

## WHAT TEST PROVES THE LOGIC?

Live CLI in `docs/MCP006_SPLUNK_VALIDATION.md`. Pytest only checks search files, field names, and that DET-MCP-006 was not created. Handler counts in `manifest.json` remain the non-execution proof.

---

## What I should now be able to explain

1. Why deputy authority is not caller authority, even when both identities are authentic.
2. Why MCP ALLOW after a confused-deputy ALLOW is not proof the caller was delegated the tool.
3. Why runtime handler count and Splunk `mcp.started` have different evidence roles.
4. What Splunk can prove from `authority.source` and what it still cannot prove without `allowed_tools`.
5. Why DET-MCP-001 is silent on the preferred MCP-006 ATTACK.
6. Why RETEST `deputy_not_on_indexed_hop1` is not a missing-identity incident by itself.
7. Why `no_indexed_mcp_execution_event` is not “handler definitely never ran.”
8. Why Phase 7C created a hunt and not DET-MCP-006.
9. Why duplicate JSON copies are not duplicate runtime decisions.
10. Why schema 1.4.0 was required for honest CTRL-DELEGATION-001 / authority.source bytes in Splunk.
