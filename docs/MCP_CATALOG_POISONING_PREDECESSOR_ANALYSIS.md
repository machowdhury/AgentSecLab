# MCP catalog poisoning — predecessor analysis

**Status:** Phase 8B DESIGN. Not runtime.  
**Evidence class:** DOCUMENTED (inventory + AgentSec source). AgentWatch Range is READ-ONLY.

Parents: `docs/MIGRATION_INVENTORY.md`, `docs/MCP_PREDECESSOR_ANALYSIS.md`, `docs/MCP005_PREDECESSOR_ANALYSIS.md`.

---

## What this lab is not copying

LAB-MCP-CATALOG teaches **static tool-description poisoning**: MCP `Tool.description` (and, in protocol, other tool metadata) is **data**. It must not widen server-owned grants.

It is **not**:

- MCP-001 tool allow-list
- MCP-005 **result** trust (`SECURITY_OVERRIDE` in handler output)
- Regex “poisoned manifest” theater
- Cisco/Snyk scanner-as-DENY
- Rug-pull (`notifications/tools/list_changed`) — Phase 9

---

## AgentWatch / predecessor components

| Component | What it actually did | Looked like catalog protection? | Decision |
|-----------|----------------------|--------------------------------|----------|
| `mcp_gateway.py` | Regex / substring block of shell-like **tool name strings**. Unknown tools **pass**. | Weakly. “Poisoned manifests” in inventory purpose text. | **DROP** as catalog authorization. Placement idea (check **before** invoke) already **REUSED** as CTRL-MCP-001. |
| `data/mcp/acme_banking_mcp.json` | Static JSON catalog for **optional Cisco scan**. Not a live `tools/list` server. | Yes — a file named like MCP. | **REDESIGN**: AgentSec catalog must be an in-process MCP-shaped snapshot (`name` / `description` / `inputSchema`), not an unused JSON souvenir. Optional later: export that snapshot for `mcp-scanner static`. |
| `should_block_from_cisco_scan` | Dead / unwired scan-to-block. | Yes — implied scanner enforcement. | **DROP**. Scanner FAIL ≠ runtime DENY. |
| Skill Scanner / `UNSIGNED_SKILL` | String flag. Not a catalog control. | No. | **DROP** for this lab. |
| AI BOM manifest | Inventory, did not gate execution. | No. | **REFERENCE** for Level 4 supply chain, not 8B. |
| AcmeGate / input regex | Prompt injection before LLM. | No. | **REUSE** placement pattern only (CTRL-INPUT-001 already exists). Do **not** regex tool descriptions as if they were user prompts granting tools. |
| AcmeSentinel output regex | After inference. | No. | **DROP** for catalog. Post-hoc is not metadata trust. |
| AgentSec `ToolSpec` | Name, scopes, keys, handler. **No `description` field today.** | Catalog without metadata. | **REFACTOR** (future 8C): add MCP `description` + `inputSchema` on the lab catalog **without** treating them as grants. |
| AgentSec MCP-005 `result_trust.py` | Result text → per-run overlay. | Closest **honest** analogue (INV-002, overlay, no global mutation). | **REUSE pattern, REDESIGN surface**: same overlay/fail-open **shape**, different **source** (description vs result). Do **not** reuse `SECURITY_OVERRIDE:` as a fake grant protocol in metadata. |
| AgentSec `coded_policy()` | Frozen `allowed_tools` / scopes / policy ids. | Real authorization. | **REUSE** unchanged. Catalog text must not rewrite it. |

---

## Predecessor behavior that only LOOKED like tool-poisoning protection

1. **Gateway regex on tool names** — never inspected `description`. Passing an unknown name was fail-open. That is not INV-002 on metadata.
2. **Static MCP JSON + optional Cisco scan** — a scan file is not a control. Inventory already classified the catalog as dead data.
3. **`should_block_from_cisco_scan`** — implied enforcement that was not wired. AgentSec must not revive this as CTRL-*.

---

## AgentSec current surface (OBSERVED in source)

| Fact | Source |
|------|--------|
| JSON-RPC `tools/call` only | `src/agentsec/mcp/protocol.py` — no `tools/list` |
| Tools have no description | `ToolSpec` in `tools.py` |
| Grants are coded | `policy.py` `ALLOWED_TOOLS = {lookup_policy}` |
| Result overlay exists | `result_trust.py` / `authorize.py` overlay consult |
| Schema 1.4.0 `control.type` enum has no metadata trust | `schemas/security_event.schema.json` |

Smallest honest 8C extension: in-process **catalog snapshot** shaped as MCP `tools/list` **result** (not a full initialize/handshake, not `list_changed`).
