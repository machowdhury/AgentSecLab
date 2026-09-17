# MCP catalog poisoning — event model review

**Status:** Phase 8B DESIGN + Phase 8C **1.5.0 implemented**. Splunk **NOT ATTEMPTED**.

---

## What 1.4.0 can already represent

| Need | Today | Honest? |
|------|-------|---------|
| Follow-on CTRL-MCP-001 ALLOW/DENY | `agentsec.control.decision` + `mcp_allowlist` | Yes |
| Follow-on execution | `agentsec.mcp.started` / completed / failed | Yes |
| Fail-open reason string | `agentsec.control.reason` | Yes, if emitted |
| Content hash/preview fields exist | `agentsec.content.hash` (`sha256:…`), `agentsec.content.preview` | Fields exist; **no catalog event binds them** |
| Result trust | `agentsec.mcp.result.trust` | **Result channel only.** Do not overload for descriptions. |
| Correlation | `agentsec.run.id`, `agentsec.sequence` | Yes for in-run catalog snapshot |

## What 1.4.0 cannot honestly represent

| Need | Gap |
|------|-----|
| `control.type = mcp_metadata_trust` | Enum closed: `input_inspection`, `schema_validation`, `mcp_allowlist`, `mcp_result_trust`, `mcp_delegation` |
| Catalog observation event | `event.name` enum has no catalog/list event |
| Scanner findings | Wrong sourcetype; closed schema `additionalProperties: false` |
| Catalog identity outside a run | Must **not** fake `run.id` |

Reusing `mcp_result_trust` for descriptions is **FORBIDDEN** (wrong channel).

---

## Proposal only — future 1.5.0 (not implemented)

Smallest additive bump **if** 8C emits live control telemetry:

1. Add `mcp_metadata_trust` to `agentsec.control.type`.
2. Bind CTRL-MCP-METADATA-001: `control.id=CTRL-MCP-METADATA-001`, decisions OBSERVE / ALLOW / ERROR as specified.
3. Reuse **existing** `agentsec.content.hash` + `agentsec.content.preview` for the **description** (preview truncated; hash over canonical UTF-8 description bytes). Do not add a parallel hash field without need.
4. Optional later: `event.name=agentsec.mcp.catalog.observed` if control.decision is not enough for hunters. Prefer control.decision first (MCP-005 style).

Scanner JSON: **separate sourcetype** (e.g. `agentsec:scanner:json`), not stuffed into `otel:agentic:json`. Field contract before any hunt.

If 8C ships before 1.5.0: **evidence-file-only** catalog classification. Do not emit illegal events.

---

## Privacy / telemetry

Descriptions may contain instructions, URLs, or accidental secrets.

| Emit | Do not emit by default |
|------|------------------------|
| tool `name` | Full description |
| SHA-256 fingerprint (`content.hash`) | Scanner raw payload in the security_event body |
| Short preview (existing preview budget) | Client-supplied “trusted=true” |

Hashing is ordinary integrity, not a new crypto protocol.

---

## Correlation

| Stream | Key |
|--------|-----|
| In-run catalog + invoke + follow-on | `agentsec.run.id` + `sequence` |
| Host-wide scanner job | **Not** `run.id` unless the scan was requested as part of that experiment |
| Future pin/rug-pull | Catalog fingerprint × tool name × time — Phase 9 |

Do not invent `invocation.id` for 8B.

---

## Splunk questions — no SPL

Governance: QUESTION → EVIDENCE → TELEMETRY → FIELD CONTRACT → SPL. Not dashboard-first.

| ID | Security question | Evidence needed | Fields today? | Status |
|----|-------------------|-----------------|---------------|--------|
| Q-CATALOG-WHAT-WAS-ADVERTISED | Which tool names were in the snapshot? | Catalog list | **No** indexed catalog | **BLOCKED BY TELEMETRY** |
| Q-CATALOG-METADATA-TRUST | How was metadata classified? | METADATA-001 | `control.type` lacks metadata | **BLOCKED BY TELEMETRY** (until 1.5.0 or evidence files) |
| Q-CATALOG-FINGERPRINT | What is the description hash? | hash | `content.hash` exists but unused for this | **BLOCKED BY TELEMETRY** until bound |
| Q-CATALOG-SCANNER-FINDINGS | What did a scanner say? | Imported JSON | Wrong sourcetype; not ingested | **BLOCKED BY TELEMETRY** |
| Q-CATALOG-FOLLOWON | Did a follow-on tool get requested/authorized? | control.decision + tool name | **Yes** (same as MCP-005 hunts) | Defensible **after** 8C runtime exists; reuse Q-MCP-AUTHZ / Q-MCP-EXECUTED, do not invent SPL now |
| Q-CATALOG-AUTHZ | What did CTRL-MCP-001 decide on the follow-on? | control.decision | **Yes** | Same |
| Q-CATALOG-EXECUTED | Did `lookup_customer_tier` handler begin? | mcp.started + spy | **Yes** once 8C runs | Same |
| Q-CATALOG-CHANGED | Did description hash change after approval? | two snapshots | **No** | **BLOCKED** — Phase 9 rug-pull, not 8B |

Do not create these KOs in 8B. Future KOs require `/splunk-ko-review`.
