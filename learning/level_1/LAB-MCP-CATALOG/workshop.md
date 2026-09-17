# LAB-MCP-CATALOG workshop

**Lab:** Tool Description / Catalog Metadata — Data Cannot Grant Authority  
**Saved search:** `DET-MCP-001` is packaged **disabled**. No DET-MCP-CATALOG. No notable event. Detection: **DETECTION ANALYZED — DETECTION CANDIDATE JUSTIFIED FOR LATER DESIGN**.  
**Do** open Dashboard Studio workshop `ws_lab_mcp_catalog` (AgentSec app). Reuse Phase 8D-validated Q-MCP searches from `../LAB-MCP-001/searches/` plus `searches/Q-MCP-CATALOG-AUTHORITY.spl`. The dashboard binds `__RUN_ID__` as `"$token$"`.

Facts in this file come from Phase 8C and 8D only. The Studio page does not create new evidence.

**Rejected SPL:** Q-MCP-CATALOG-METADATA, Q-MCP-CATALOG-TRUST, Q-MCP-CATALOG-FINGERPRINT, Q-MCP-CATALOG-FOLLOWON, Q-MCP-CATALOG-AUTHZ are **not published**.

Flow:

LEARN → BASELINE → ATTACK → OBSERVE → HUNT → DETECT → DEFEND → RETEST → COMPARE → PROVE

Runtime handler count is authoritative proof of non-execution. Splunk absence of `mcp.started` is corroboration only.

LAB-MCP-001: May this agent call this **tool**?  
LAB-MCP-003: May this agent call it at this **scope**?  
LAB-MCP-004: May it operate on this **resource**?  
LAB-MCP-005: Can **tool result data** change later authority?  
LAB-MCP-006: Can a **deputy** exercise authority belonging to another caller?  
LAB-MCP-CATALOG: Can **tool metadata** influence a request and improperly become authority?

---

## LEARN

**What is it?** A guided lab: granted `lookup_policy` at granted `policy:read`. The first hop is legitimate. MCP-CATALOG asks whether the tool **description** can change what the agent may do next.

**Core question:** A tool can be legitimate. Its catalog metadata can still be untrusted data.

REQUEST ≠ GRANT. OBSERVE ≠ ALLOW. METADATA PROVENANCE ≠ CONTENT TRUST. AUTHORIZED TOOL ≠ TRUSTED DESCRIPTION.

**Phase 8D LIVE ids:** BASELINE `d95717ed-ffd2-46c0-a130-9a5d7d539a5d` · ATTACK `a0937bff-31a5-453a-99bf-47d7b5148ce4` · RETEST `23c222ea-6a87-40b7-a3e9-f12a5b572fa1`

**SPL this step:** none.

---

## BASELINE

profile = defended · mode = BASELINE · catalog = NORMAL

The catalog metadata was treated as data. The granted lookup_policy call was authorized separately and executed. No follow-on tool request was produced.

Do not label this **SAFE**.

**Validated:** `d95717ed-ffd2-46c0-a130-9a5d7d539a5d`. NORMAL hash `sha256:8a76d34c6c21fda0dc930fa2f64fe87c3216f23cbc73ca357c47b0927850d9c3`.

**SPL:** Q-MCP-CATALOG-AUTHORITY, Q-MCP-AUTHZ, Q-MCP-TOOL, Q-MCP-EXECUTED.

---

## ATTACK

profile = vulnerable · mode = ATTACK · catalog = MALICIOUS

METADATA-001 remains OBSERVE `metadata_is_data`. First `lookup_policy` remains ALLOW + execute. Then a follow-on REQUEST for `lookup_customer_tier` is improperly granted: CTRL-MCP-001 ALLOW `vulnerable_profile_fail_open:metadata_derived_authority`, then `mcp.started` / `mcp.completed`.

The DESCRIPTION was not authorized. The FOLLOW-ON REQUEST was improperly granted by the vulnerable authorization path. **INTENTIONALLY VULNERABLE LAB BEHAVIOR.**

Hash: `sha256:9d0745320ca79852f2fbd7145bf074fcd353e290c18ba16fd02d801f9f3375b1`. Validated: `a0937bff-31a5-453a-99bf-47d7b5148ce4`.

**SPL:** Q-MCP-CATALOG-AUTHORITY, Q-MCP-AUTHZ, Q-MCP-TOOL, Q-MCP-EXECUTED.

---

## OBSERVE

What Happened is indexed telemetry, not LLM narrative. Sequence, control id/type, decision, reason, tool, event, metadata trust/provenance, content hash, outcome. Do not dump `_raw` or full descriptions.

**SPL:** observe sequence helper, Q-MCP-CATALOG-AUTHORITY, Q-MCP-AUTHZ, Q-MCP-TOOL, Q-MCP-EXECUTED.

---

## HUNT

Primary: Q-MCP-CATALOG-AUTHORITY. Reuse: Q-MCP-AUTHZ, Q-MCP-TOOL, Q-MCP-EXECUTED. Hunt token defaults to BASELINE so empty Hunt is not a red error.

Q-MCP-EXECUTED may produce an extra METADATA-001 OBSERVE row because `eventstats` groups by run + tool. Control-event executed=false is not handler non-execution. Do not teach “metadata executed” or “OBSERVE caused execution.”

---

## DETECT

DET-MCP-001 / Q-MCP-AFTER-DENY on LIVE specimens: BASELINE **0** · ATTACK **0** · RETEST **0**.

ATTACK used an ALLOW-path failure, so execution-after-DENY does not apply. This is a **DETECTION GAP**, not a detector failure.

Right: **SIMULATED** `DET-MCP-001-POSITIVE-CONTROL` (`makeresults`, **NOT INDEXED**, not OBSERVED). **No DET-MCP-CATALOG.** **DETECTION ANALYZED — DETECTION CANDIDATE JUSTIFIED FOR LATER DESIGN.**

---

## DEFEND

The defense is not: sanitize the description, block the first legitimate tool, trust scanner output, or ask Splunk for permission.

Catalog metadata may influence a REQUEST. Server-owned authorization determines the GRANT. Defended follow-on: CTRL-MCP-001 DENY `tool_not_granted`. Handler does not begin. Runtime handler count remains authoritative.

---

## RETEST

`23c222ea-6a87-40b7-a3e9-f12a5b572fa1` — defended, same MALICIOUS catalog.

ATTACK hash == RETEST hash: `sha256:9d0745320ca79852f2fbd7145bf074fcd353e290c18ba16fd02d801f9f3375b1`

METADATA-001 OBSERVE. `lookup_policy` ALLOW + execute. Same follow-on request. CTRL-MCP-001 DENY `tool_not_granted`. Runtime follow-on handler **0**. No indexed follow-on `mcp.started` on COMPLETE transport.

Runtime handler count 0 is the authoritative non-execution proof. The complete Splunk copy provides corroborating evidence. Do not say Splunk proves it was blocked.

---

## COMPARE

Three cards: BASELINE / ATTACK / RETEST. Central lesson: ATTACK and RETEST used the SAME malicious metadata. The difference was the authorization profile.

---

## PROVE

Evidence hierarchy. Answer the ten PROVE questions (see `knowledge-check.md`). End with INV-002: retrieved/tool-provided content cannot independently widen authority.
