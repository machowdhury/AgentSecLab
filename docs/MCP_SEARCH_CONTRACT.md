# MCP search contract (LAB-MCP-001)

**Status:** Phase 3C **VALIDATED** against live Splunk (2026-09-12).  
**Not:** notables, MCP-003+, Cisco. One operational detection `DET-MCP-001` is Phase 3E (`docs/PHASE3E_MCP_DETECTION.md`).  
**Runtime remains authoritative.** Splunk is the analytical/evidence surface.

Stored SPL: `learning/level_1/LAB-MCP-001/searches/`. Token: `__RUN_ID__`.

Index: `agentsec_telemetry`. Sourcetype: `otel:agentic:json`. Source: `agentsec-otel-collector`.

---

## Query catalog

| Query ID | Security question | Zero results means |
|----------|-------------------|--------------------|
| **Q-MCP-WHO** | Which principal / agent requested which MCP tool? | No indexed `control.decision` for that run. Not DENY. |
| **Q-MCP-AUTHZ** | What authorization decision was made? | No indexed control decision. ERROR is not DENY. |
| **Q-MCP-TOOL** | Which tool executions actually began? (`mcp.started`) | No indexed start. **Not** automatically DENY. |
| **Q-MCP-SCOPE** | Requested vs coded allowed scope | No control event. `allowed_scope` is coded policy, not a rewritten grant. |
| **Q-MCP-PARAMS** | What arguments were supplied? | No control content snapshot. Not “empty arguments.” |
| **Q-MCP-EXECUTED** | Did the governed MCP operation begin? | No control event. `no_mcp_execution_event` is corroboration, not spy proof. |
| **Q-MCP-AFTER-DENY** | MCP event after DENY same run/tool? | **0 = no indexed violation found.** Does **not** independently prove non-execution. |
| **Q-MCP-AFTER-DENY-POSITIVE-CONTROL** | Can the invariant query fire? | N/A — **SIMULATED** `makeresults` only. |
| **Q-MCP-RESULT** | What result metadata exists? | No `mcp.completed`/`mcp.failed`. Full payloads are not a dedicated schema. |
| **Q-MCP-RESULT-TRUST** | How is returned content classified? | No `mcp.completed`. Preparatory; not MCP-005. |

Each query’s full contract (required fields, SPL, line-by-line, expected/actual, limitations) lives next to the `.spl` file.

---

## Authority split

| Question | Authoritative surface |
|----------|------------------------|
| Did the handler run? | Runtime `ToolRegistry` / `handler_invoke_count` / local `events.jsonl` |
| Was the decision ALLOW/DENY/ERROR? | Runtime control event; Splunk corroborates when the copy is complete |
| Did Splunk receive the sequence? | Splunk `dc(_raw)` vs local count (**MEASURED** in Phase 3C) |

Do not infer prevention from missing Splunk events.

---

## SPL quality rules

Prefer: index/sourcetype, `event.name`, `agentsec.run.id`, `stats` / `eventstats` / `streamstats`, `fields` / `table`, `mvindex(mvdedup(…),0)`.

Avoid unless required: `join`, `transaction`, `map`, `append`, large subsearches. Phase 3C used none of these. `eventstats` expresses AFTER-DENY and EXECUTED sequence/state.

`earliest=0` is lab-only.

---

## Required output columns (validated)

| Query | Columns |
|-------|---------|
| Q-MCP-WHO | run.id, principal, agent, tool, method, profile, mode |
| Q-MCP-AUTHZ | run.id, tool, control.id, decision, reason, requested scope, allowed scope, attempted, executed, outcome |
| Q-MCP-TOOL | run.id, tool, event.name, sequence, executed, outcome |
| Q-MCP-SCOPE | run.id, tool, requested scope, allowed scope, decision (+ display `scope_relation`) |
| Q-MCP-PARAMS | run.id, tool, origin, influence, hash, preview |
| Q-MCP-EXECUTED | run.id, tool, decision, control executed/outcome, has_started/completed/failed, execution_state |
| Q-MCP-AFTER-DENY | run.id, tool, deny_seq, sequence, event.name, decision |
| Q-MCP-RESULT | run.id, tool, event.name, sequence, outcome, hash, trust, provenance, preview |
| Q-MCP-RESULT-TRUST | run.id, tool, result_trust, provenance, outcome |

---

## MCP-003 reuse (Phase 4C)

LAB-MCP-003 **reuses** these query IDs. Do not add Q-MCP-003. Live proof: `docs/PHASE4C_MCP003_SPLUNK_VALIDATION.md`.

Q-MCP-WHO, Q-MCP-AUTHZ, Q-MCP-TOOL, Q-MCP-EXECUTED, and Q-MCP-AFTER-DENY were **reused unchanged**.

Q-MCP-SCOPE is the same query ID. Phase 4C documented a helper-order gap (`ERROR` must be `not_a_grant` before `requested != allowed`) and corrected `case()` accordingly. That is not a new search.

`scope_relation` remains a display helper. ERROR is not DENY. `known_but_ungranted` is not a detector.

---

## MCP-004 reuse and resource hunt (Phase 5C)

LAB-MCP-004 **reuses** the same Q-MCP IDs. They are schema-version **agnostic** (no `schema.version=1.1.0` filter). Live proof: `docs/PHASE5C_MCP004_SPLUNK_VALIDATION.md`.

Q-MCP-SCOPE is **not** the resource hunt. On MCP-004 ATTACK, requested scope still equals allowed scope.

**Q-MCP-RESOURCE-AUTHZ** (`learning/level_1/LAB-MCP-004/searches/`) answers requested resource vs coded grant vs decision. `resource_relation` is a display helper. ERROR is `not_a_grant`. Fail-open ALLOW with `resource_not_granted` in the reason is `known_but_ungranted`, not granted.

Q-MCP-PARAMS remains preview/hash provenance. Not the resource-authorization hunt.

DET-MCP-001 reused unchanged. No DET-MCP-004.

---

## MCP-006 reuse and delegation hunt (Phase 7C)

LAB-MCP-006 **reuses** the same Q-MCP IDs. They are schema-version **agnostic** (no `schema.version` filter). Live proof: `docs/MCP006_SPLUNK_VALIDATION.md`.

Q-MCP-WHO / Q-MCP-AUTHZ show two hops but do not label caller vs deputy or `authority.source`.

**Q-MCP-DELEGATION** (`learning/level_1/LAB-MCP-006/searches/`) answers CTRL-DELEGATION-001, caller, deputy observation, `delegation.authority.source`, downstream CTRL-MCP-001, and indexed execution observation. Display helpers: `deputy_not_on_indexed_hop1`, `no_downstream_mcp_control_event`, `no_indexed_mcp_execution_event`. Hop-0 `allowed_scope` is coded delegated **scope**, not `allowed_tools`.

DET-MCP-001 reused unchanged. No DET-MCP-006.

---

## MCP-CATALOG reuse and catalog-authority hunt (Phase 8D)

LAB-MCP-CATALOG **reuses** the same Q-MCP IDs. They are schema-version **agnostic** (no `schema.version` filter). Live proof: `docs/PHASE8D_MCP_CATALOG_SPLUNK_VALIDATION.md`.

Q-MCP-WHO / Q-MCP-AUTHZ gain an extra METADATA-001 row (OBSERVE `metadata_is_data`; empty `mcp.method.name` / scopes). Q-MCP-EXECUTED extra OBSERVE row for `lookup_policy` inherits that tool’s `mcp.completed` because `eventstats` is `by run_id, tool`. Q-MCP-PARAMS labels the description hash as `arguments_hash`. Do **not** rewrite those files for catalog.

**Q-MCP-CATALOG-AUTHORITY** (`learning/level_1/LAB-MCP-CATALOG/searches/`) answers METADATA-001 classification, description hash, first `lookup_policy` grant, follow-on CTRL-MCP-001, and indexed follow-on execution observation. Display helpers: `derived_authority`, `no_followon`, `no_indexed_followon_execution_event`. Hash is the fingerprint. Do not correlate by preview.

DET-MCP-001 reused unchanged. No DET-MCP-CATALOG.

---

## Splunk knowledge-object engineering

This contract is the field/question catalog. It is not a substitute for KO review.

For Splunk knowledge-object work:

read:

`.cursor/rules/33-splunk-agent-skills.mdc`

then use:

`.cursor/skills/splunk-ko-review/SKILL.md`

and consult the applicable official Splunk Agent Skills.

For learner-facing UI also read:

`.cursor/rules/32-ui-design-system.mdc`

and run:

`/ui-review`

For evidence/security reasoning run:

`/logic-proof`

Inventory: `docs/SPLUNK_KNOWLEDGE_OBJECT_INVENTORY.md`. Process: `docs/SPLUNK_ENGINEERING_GOVERNANCE.md`.

