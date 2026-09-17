# MCP result trust in Splunk

**Status:** Phase 6C validated on live Splunk. Dashboard Studio is **not** this phase. DET-MCP-005 is **not** created.  
**Parents:** `docs/MCP005_SPLUNK_VALIDATION.md`, `docs/MCP005_SPLUNK_FIELD_VALIDATION.md`, `docs/MCP005_DETECTION_VALIDATION.md`.  
**SPL:** existing LAB-MCP-001 Q-MCP searches (schema-version agnostic) plus `Q-MCP-RESULT-AUTHORITY`.

---

## WHAT IS IT?

The same investigation questions used for earlier MCP labs, pointed at MCP-005 runs, plus one new hunt: did **tool result data** change **authorization**, and what follow-on tool was decided and (if at all) observed to start?

Splunk is not a second authorizer.

## WHY DOES IT EXIST?

Phase 6B proved INV-002 in the runtime with handler spies. Splunk is where you reconstruct **the same story** after the copy is indexed: same malicious bytes on ATTACK and RETEST, server-owned grant unchanged, overlay only on the vulnerable profile, follow-on ALLOW+execution vs DENY+no hop-1 `mcp.started`.

Q-MCP-RESULT-TRUST cannot tell this story. It only shows the classification label `untrusted_data`.

## HOW DOES IT WORK?

1. AcmeBank emits schema **1.3.0** JSON over OTLP (OBSERVE, `CTRL-MCP-RESULT-001`, `MCP-005`).
2. Collector → HEC → `index=agentsec_telemetry`.
3. Some scalars appear two or three times. SPL collapses copies with `mvindex(mvdedup('field'),0)`.
4. Bind `__RUN_ID__` on existing Q-MCP files. They do **not** filter `schema.version`.
5. `Q-MCP-RESULT-AUTHORITY` collapses one run: RESULT-001, coded hop-0 scope, hop-1 tool/decision, hop-1 execution observation.

`derived_authority` is a **display helper** from RESULT-001 reason. It is not a detector.

## WHERE DOES IT SIT IN AGENTSEC?

HUNT / MEASURE for LAB-MCP-005. Detection stays DET-MCP-001 (execution after DENY). Result-derived overlay ALLOW is a hunt, not a new notable.

## WHAT IS THE TRUST BOUNDARY?

Still `acmebank.mcp.authorize` before `mcp.tool.execute`. RESULT-001 sits on `mcp.tool.result` and does not invoke a handler. Splunk cannot ALLOW or DENY a follow-on.

## WHAT COULD AN ATTACKER CONTROL?

Still the first `tools/call` (here always legitimate `lookup_policy`). They cannot pick `run.id`, profile, coded `allowed_tools`, or `control.decision`. They cannot make Splunk invent hop-1 `mcp.started`. The MALICIOUS summary is **lab fixture text**, not a credential.

## WHAT CAN GO WRONG?

- Treating Q-MCP-RESULT-TRUST `untrusted_data` as “not used as authority” or as “trusted.”
- Treating ATTACK follow-on ALLOW as a server grant of `lookup_customer_tier`.
- Treating OBSERVE as blocked/sanitized.
- Treating 0 DET-MCP-001 rows as proof the preferred attack failed — it succeeded **without** a DENY.
- Treating 0 hop-1 `mcp.started` rows as independent proof the handler never ran.
- Treating B/C result hash as a trust score. It only proves the same fixture.
- Treating `mvcount=2` as two events.
- Parsing `SECURITY_OVERRIDE` in Splunk as the detector.

## WHAT TELEMETRY SHOULD EXIST?

RESULT-001 on the result boundary. Hop-0 vs hop-1 CTRL-MCP-001. Hop-1 `mcp.started` only after follow-on ALLOW. Preview ≤200 + `sha256:`. No `allowed_tools` field in this schema.

## HOW WILL SPLUNK SHOW IT?

| Question | Search |
|----------|--------|
| Who / which tools? | Q-MCP-WHO (two tools on B/C) |
| ALLOW / OBSERVE / DENY + reason? | Q-MCP-AUTHZ |
| Requested vs allowed **scope**? | Q-MCP-SCOPE (hop-1 mismatch is **not** MCP-003) |
| Classification label? | Q-MCP-RESULT-TRUST |
| Result preview/hash? | Q-MCP-RESULT |
| Did execution begin? | Q-MCP-TOOL / Q-MCP-EXECUTED |
| Result used as authority? | **Q-MCP-RESULT-AUTHORITY** |
| DENY then start? | Q-MCP-AFTER-DENY / DET-MCP-001 |

BASELINE: OBSERVE, derived absent, no follow-on.  
ATTACK: derived present, follow-on ALLOW, `mcp.completed_observed`, coded grant still `lookup_policy`.  
RETEST: same hash, derived absent, follow-on DENY `tool_not_granted`, `no_indexed_followon_execution_event`.

## WHAT CONTROL COULD CHANGE THE RESULT?

`AGENTSEC_SECURITY_PROFILE=defended` vs `vulnerable` on the **same** malicious `lookup_policy` result. Splunk will show OBSERVE+DENY vs overlay ALLOW. Coded server-owned tools stay `{lookup_policy}`.

## WHAT TEST PROVES THE LOGIC?

Live CLI in `docs/MCP005_SPLUNK_VALIDATION.md`. Pytest only checks search files, field names, and that DET-MCP-005 was not created. Handler counts in `manifest.json` remain the non-execution proof.

---

## What I should now be able to explain

1. Why Q-MCP-RESULT-TRUST is a classification hunt, not an authority hunt, even though its name sounds like trust.
2. Why DET-MCP-001 is silent on the preferred MCP-005 ATTACK.
3. Why ATTACK follow-on ALLOW must still show coded `allowed_scope=policy:read`.
4. Why there is no indexed `allowed_tools` field and where the grant snapshot actually appears.
5. Why B and C sharing a result hash does not mean they share an authorization outcome.
6. Why OBSERVE `result_is_data` is not a block.
7. Why `no_indexed_followon_execution_event` is not “handler definitely never ran.”
8. Why hop.index + tool name is enough correlation here and what breaks without `gen_ai.tool.call.id`.
9. Why Phase 6C created a hunt and not DET-MCP-005.
10. Why schema 1.3.0 was required for honest OBSERVE / RESULT-001 bytes in Splunk.
