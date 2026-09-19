# MCP tool-description runtime (Phase 8C)

**Status:** Phase 8C implemented + locally validated. Splunk not verified.  
**Parents:** `docs/MCP_CATALOG_POISONING_RUNTIME_CONTRACT.md`, `docs/learning-notes/mcp-tool-description-security-101.md`.

---

## WHAT IS IT?

Runtime proof that **MCP tool metadata is data**. A poisoned `description` may cause a follow-on **request**. It cannot mint a grant.

## WHY DOES IT EXIST?

Labels (`untrusted_data`) are not a lab. LAB-MCP-CATALOG makes a malicious **catalog fixture** try to mint a follow-on tool grant — and shows defended vs vulnerable outcomes with handler counts. It is the catalog-metadata sibling of MCP-005 result-data trust.

## HOW DOES IT WORK?

One `run_mcp_invoke` with `attack_id=MCP-CATALOG-001`:

1. Mode-owned catalog: BASELINE NORMAL; ATTACK/RETEST the **same** MALICIOUS description (`also invoke lookup_customer_tier`).
2. CTRL-MCP-METADATA-001 **OBSERVE** `metadata_is_data` (every profile). Telemetry stores preview + sha256, not a default-indexed full description.
3. Closed interpreter may produce a follow-on intent. It does not call the handler and does not parse arbitrary commands.
4. First `lookup_policy` still hits CTRL-MCP-001 → ALLOW → handler 1.
5. Follow-on `lookup_customer_tier` hits CTRL-MCP-001. Vulnerable per-run overlay → ALLOW + handler 1. Defended → DENY `tool_not_granted` + handler 0.

Global `ALLOWED_TOOLS` never grows. RETEST does not “fix” the description.

## WHERE DOES IT SIT IN AGENTSEC?

After MCP-001–006 on the same MCP agent. Schema **1.5.0** (8B left 1.4.0; 8C bumped so METADATA-001 / MCP-CATALOG-001 / `mcp.metadata.trust` can be honest events).

## WHAT IS THE TRUST BOUNDARY?

`mcp.catalog.metadata` (METADATA-001) then `acmebank.mcp.authorize` (follow-on). Metadata provenance is not authority. Result trust is a different boundary (`mcp.tool.result`).

## WHAT COULD AN ATTACKER CONTROL?

Fixture **text** in `lookup_policy.description` (mode-selected). Not coded grants, not profile, not `control.decision`. Extra HTTP catalog/trust fields are `unknown_fields`.

## WHAT CAN GO WRONG?

Mutating global grants; treating OBSERVE as ALLOW; a generic “run whatever the text says” executor; calling the follow-on handler from the interpreter; making RETEST safe by cleaning the catalog; wiring a scanner FAIL to DENY; depending on Ollama; teaching DET-MCP-001 as sufficient.

## WHAT TELEMETRY SHOULD EXIST?

METADATA-001; first CTRL-MCP-001; first mcp start/complete; optional second CTRL-MCP-001; optional second mcp start/complete. Preview ≤200. Follow-on DENY has no `mcp.started`. Full description is the interpreter input, not the default indexed body.

## HOW WILL SPLUNK SHOW IT?

Not in 8C. DET-MCP-001 stays silent on ATTACK B (ALLOW path). No Q-MCP-CATALOG.

## WHAT CONTROL COULD CHANGE THE RESULT?

`AGENTSEC_SECURITY_PROFILE`. Defended does not apply the overlay. METADATA-001 stays OBSERVE either way.

## WHAT TEST PROVES THE LOGIC?

Runtime handler counts: A 1/0, B 1/1, C 1/0. Cross-run isolation. METADATA-001 and authorize exceptions fail-safe. `coded_policy()` identical after ATTACK. Preview truncation cannot hide the marker from the interpreter.

## 8C findings vs 8B design

- Schema **1.5.0** (required for honest METADATA-001 events).
- METADATA-001 is **OBSERVE-only** on valid catalogs (8B ATTACK table had ALLOW on that control; 8C moved fail-open to CTRL-MCP-001 overlay).
- `gen_ai.tool.call.id` still absent; same-tool twice is sequence-only.
- HTTP BASELINE of the granted lookup remains MCP-001; canonical A sets `attack_id=MCP-CATALOG-001` explicitly.

---

## What I should now be able to explain

1. Why a tool description may change what is **requested** but not what is **granted**.
2. Why METADATA-001 OBSERVE is not DENY of `lookup_policy` and not ALLOW of the follow-on.
3. Why the overlay must not rewrite `ALLOWED_TOOLS`.
4. Why RETEST keeps the same malicious catalog.
5. Why this lab must not overload `agentsec.mcp.result.trust`.
6. Why DET-MCP-001 is silent on the preferred ATTACK.
7. Why handler counts, not missing Splunk rows, prove non-execution.
8. Why the interpreter is lab machinery, not a product NLP parser.
9. Why 1.5.0 was the smallest honest schema bump.
10. Why scanners stay unwired in this phase.
