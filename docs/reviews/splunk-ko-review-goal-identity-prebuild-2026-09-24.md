# Splunk knowledge-object review — Goal and Identity prebuild

**Date:** 2026-09-24
**Scope:** `ws_lab_agent_goal_integrity`, `ws_lab_agent_delegation`, and their existing data sources
**Status:** REVISE PRESENTATION; preserve validated SPL

## ws_lab_agent_goal_integrity

- **Purpose:** teach reconstruction of Goal decision, effective action, separate MCP decision, and operation-specific execution.
- **Inputs:** allowlisted specimen/run context through existing dashboard tokens.
- **Expected output:** one selected experiment with task/instruction fingerprints, Goal control, MCP control, and wrong-goal/in-task execution counts.
- **Evidence claim:** the defended run may execute an allowed supporting lookup while the prohibited `extract_full_policy` objective remains unexecuted.
- **Required Path A:** Question → Starting Search → Goal event hint → operation-specific execution hint → investigation.
- **Required Path B:** existing validated searches, expected shapes, interpretation, and limits.
- **SPL decision:** no semantic rewrite is needed. Preserve each existing query byte-for-byte.
- **Risk:** any-handler aggregation would make a legitimate RETEST lookup appear equivalent to prohibited-goal execution.

## ws_lab_agent_delegation

- **Purpose:** teach reconstruction of untrusted identity/delegation claims, separate tool authority, and handler execution.
- **Inputs:** allowlisted specimen/run context through existing dashboard tokens.
- **Expected output:** one selected experiment with claimed principal/caller/callee, requested delegation authority, Identity OBSERVE, MCP decision, and privileged handler count.
- **Evidence claim:** the claim is classified and attributable but not authenticated; only CTRL-MCP-001 decides tool authority.
- **Required Path A:** Question → Starting Search → claim fields hint → authority/control hint → investigation.
- **Required Path B:** existing validated searches, expected shapes, interpretation, and explicit NOT MODELED authentication.
- **SPL decision:** no semantic rewrite is needed. Preserve each existing query byte-for-byte.
- **Risk:** presenting principal strings as established identities or Identity OBSERVE as authorization.

## Shared findings

1. Existing queries are evidence engineering and have established regression tests.
2. The ten-tab structure causes solution leakage and weakens investigative sequence.
3. Dashboard Studio is evidence visualization, not a PDP.
4. `dc(_raw)` completeness is meaningful only against a known local primary event count.
5. HEC 200 and detector silence cannot prove completeness, prevention, or safety.

## Validation gates

- Build and lint each generated dashboard.
- Prove every data source remains referenced after regrouping.
- Prove no SPL byte changes.
- Run focused Studio and SPL tests.
- Validate existing searches against fresh Goal/Identity run IDs.
- Capture MISSION, INVESTIGATE, EVIDENCE, and PATH B states.
