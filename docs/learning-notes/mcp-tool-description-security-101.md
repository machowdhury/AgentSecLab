# MCP tool-description security 101

**Status:** Phase 8B learning note. Design only. Runtime **absent**.  
**Parents:** `docs/MCP_CATALOG_POISONING_SECURITY_MODEL.md`, `docs/MCP_CATALOG_POISONING_LAB_SPECIFICATION.md`.

---

## WHAT IS IT?

A teaching lab about **MCP tool metadata** (`description` on `tools/list`) as **untrusted data**. A legitimate tool can still carry instruction-like text that tries to make an agent request another tool.

## WHY DOES IT EXIST?

MCP-001–004 taught grants. MCP-005 taught **results** are not grants. Confused deputy taught **which authority set** was used. Catalog poisoning is the next surface: **the advertisement**, not the return value.

## HOW DOES IT WORK?

Invariant Labs (2025-04-01) described Tool Poisoning Attacks: hidden instructions in descriptions. AgentSec will (later) use a **harmless** description that asks for `lookup_customer_tier`. Defended: classify as data, CTRL-MCP-001 DENY follow-on. Vulnerable: per-run overlay only.

## WHERE DOES IT SIT IN AGENTSEC?

After LAB-MCP-006 in the learning line. Lab id **LAB-MCP-CATALOG**, not automatic MCP-007. Rug-pull is a **later** lab.

## WHAT IS THE TRUST BOUNDARY?

Metadata → planner intent → **CTRL-MCP-001**. Scanners sit **beside** that path, not on it.

## WHAT COULD AN ATTACKER CONTROL?

The `description` string (and, in the real protocol, schema text / annotations). Not coded `allowed_tools`.

## WHAT CAN GO WRONG?

Treating scanner FAIL as DENY; cleaning the catalog on RETEST; reusing MCP-005’s result marker; dumping full descriptions into Splunk; bumping schema “to look ready.”

## WHAT TELEMETRY SHOULD EXIST?

METADATA-001 + existing MCP control/tool events + description **hash/preview**. 1.4.0 cannot emit `mcp_metadata_trust` yet — **proposed 1.5.0**.

## HOW WILL SPLUNK SHOW IT?

Not in 8B. Several questions are **BLOCKED BY TELEMETRY**. Follow-on authz/execution can reuse Q-MCP-* **after** 8C.

## WHAT CONTROL COULD CHANGE THE RESULT?

Stop minting the overlay (defended). CTRL-MCP-001 stays the only execution gate.

## WHAT TEST PROVES THE LOGIC?

8B: document tests only. 8C (later): spy on follow-on handler 1 vs 0 with the **same** malicious description.

---

## What I should now be able to explain

1. Why metadata is data (INV-002) even from “our” MCP server.
2. The five properties: integrity, metadata trust, selection, authorization, execution.
3. Why RETEST keeps the poisoned description.
4. Why DET-MCP-001 is silent on the preferred ATTACK.
5. Why Cisco mcp-scanner and Snyk Agent Scan (Invariant lineage) are evidence, not DENY.
6. Why rug-pull is a different lab (`list_changed`).
7. Why we must not invent `grant_tool=` in the catalog.
8. Why `mcp.result.trust` must not be overloaded for descriptions.
9. Why full descriptions should not be default-indexed.
10. What “BLOCKED BY TELEMETRY” means for Splunk.
