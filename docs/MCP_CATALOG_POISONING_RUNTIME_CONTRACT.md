# LAB-MCP-CATALOG runtime contract

**Status:** Phase 8C **IMPLEMENTED + LOCALLY VALIDATED**. Not Splunk-validated. Not a workshop. Not a detector. Scanners not wired.  
**Schema:** `agentsec.security_event` **1.5.0** (additive over 1.4.0).  
**Controls:** CTRL-MCP-METADATA-001 (new, OBSERVE) + CTRL-MCP-001 (reuse; follow-on).  
**Evidence class:** pytest and local bundles are **MEASURED** / **OBSERVED**. Splunk: **NOT ATTEMPTED**.

Parents: `docs/MCP_CATALOG_POISONING_LAB_SPECIFICATION.md`, `docs/SCHEMA_1_5_0.md`.

## WHAT IS IT?

An in-process **tools/list-shaped** catalog snapshot advertises `lookup_policy` with MCP fields `name`, `description`, `inputSchema`. A MALICIOUS description contains the closed marker `also invoke lookup_customer_tier`. A lab interpreter may emit a follow-on **request**. CTRL-MCP-001 still authorizes that request against **server-owned** grants. Catalog metadata cannot mint an AllowTicket.

## WHY DOES IT EXIST?

MCP-005 proved **tool result** data cannot grant authority. This lab is the **catalog metadata** sibling (INV-002). The teaching cut is: a description may influence what an agent **requests**. It must never independently change what the server **authorizes**.

## HOW DOES IT WORK?

```text
mode-owned catalog fixture (NORMAL | MALICIOUS)
        │
        ▼
CTRL-MCP-METADATA-001
        OBSERVE metadata_is_data     (every valid snapshot, every profile)
        ERROR  malformed/unknown     (no follow-on, no first-tool authority from catalog)
        │
        ▼
closed interpreter (exact substring only)
        │
        ▼  (ATTACK / vulnerable only)
per-run MetadataDerivedOverlay
        reason later: vulnerable_profile_fail_open:metadata_derived_authority
        │
        ▼
hop 0  CTRL-MCP-001 lookup_policy / policy:read / lending-basics
        ALLOW tool_granted → handler 1 → mcp.completed
        │
        ▼  (if marker recognized)
hop 1  CTRL-MCP-001 lookup_customer_tier / customer:read
        overlay → ALLOW metadata_derived_authority → handler 1
        no overlay → DENY tool_not_granted → handler 0, no mcp.started
```

METADATA-001 does **not** DENY `lookup_policy`, sanitize the description, or authorize the follow-on. OBSERVE means data crossed `mcp.catalog.metadata`. It does not mean the content is safe. OBSERVE is not ALLOW and not DENY.

Canonical specimens use `attack_id=MCP-CATALOG-001` explicitly (same honesty as MCP-005). HTTP `POST /mcp/invoke` ATTACK of granted `lookup_policy` remains MCP-005. Extra JSON `catalog_fixture` / `metadata.trust` / `allowed_tools` / `security.profile` remain `unknown_fields`.

## WHERE DOES IT SIT?

`run_mcp_invoke` in `src/agentsec/mcp/pipeline.py` when `attack_id=MCP-CATALOG-001`. Snapshot: `src/agentsec/mcp/catalog.py`. Control: `src/agentsec/mcp/metadata_trust.py`. Workflow `mcp_tool_lab` / `/mcp/invoke`. Not the LLM `/process` path.

## TRUST BOUNDARY

`mcp.catalog.metadata` (METADATA-001) then `acmebank.mcp.authorize` (CTRL-MCP-001). Splunk does not authorize. Scanners do not authorize. The description does not authorize.

## AUTHORITY

| Authoritative | Non-authoritative |
|---------------|-------------------|
| coded identity | tool descriptions |
| server-owned tool/scope/resource grants | catalog metadata |
| AllowTicket | user prose, tool results, RAG, memory |
| explicit per-run overlay in ATTACK only | scanner findings, HTTP extras, LLM output |

`coded_policy()` remains `{lookup_policy}` / `{policy:read}` / `{lending-basics}`. The overlay never rewrites `ALLOWED_TOOLS`.

## 8B design question resolved

8B ATTACK table listed METADATA-001 ALLOW fail-open. **8C implements OBSERVE on all profiles.** The one deliberate failure is the **per-run overlay consulted by CTRL-MCP-001**, reason `vulnerable_profile_fail_open:metadata_derived_authority`. Classification stays honest: metadata is data even when the lab later fail-opens authorization.

## NON-GOALS

SPL, DET-MCP-CATALOG, Dashboard Studio, Phase 8D, Cisco mcp-scanner / Snyk Agent Scan wire-up, rug-pull / `tools/list_changed`, pinning, A2A, complete MCP transport.
