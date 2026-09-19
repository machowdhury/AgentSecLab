# Goal integrity event model review

**Status:** DESIGN. 13A does **not** bump schema. 13B implements 1.9.0 if accepted.

Review of schema **1.8.0** against goal-integrity questions.

## Field-name decisions

| Need | Classification |
|------|----------------|
| Authoritative task id / hash / preview / provenance | **REQUIRES NEW TELEMETRY** |
| Instruction trust / provenance | **REQUIRES NEW TELEMETRY** |
| Proposed action / goal decision / reason | **REQUIRES NEW TELEMETRY** |
| Control type for task integrity | **REQUIRES NEW TELEMETRY** (`goal_integrity`) |
| Attack id GOAL-001 | **REQUIRES NEW TELEMETRY** |
| Workflow `goal_integrity_lab` / `/goal/evaluate` | **REQUIRES NEW TELEMETRY** |
| Trust boundary `agent.task.contract` | **REQUIRES NEW TELEMETRY** |
| Influence kind `untrusted_instruction` | **REQUIRES NEW TELEMETRY** |
| run.id / sequence / control.* / MCP events | **SUPPORTED NOW** |
| Full prompts / JWT / session.id / tenant.id | **NOT APPLICABLE** (privacy reject) |
| Grant snapshot `allowed_tools` | **DEFER** (existing TELEMETRY GAP) |

## Proposed 1.9.0 (13B only)

ADDED: `agentsec.task.id`, `.hash`, `.preview`, `.provenance`, `agentsec.instruction.trust`=`untrusted_instruction`, `agentsec.instruction.provenance`, `agentsec.goal.proposed`, `.decision`, `.reason`, control type `goal_integrity` / `CTRL-GOAL-INTEGRITY-001`, attack `GOAL-001`.

REJECTED: `trusted_instruction`, `task_authorized` from the client, token fields, `agentsec.session.id`.

SCHEMA BUMP JUSTIFIED for 13B. 13A keeps 1.8.0 UNCHANGED.

UNMAPPED / REQUIRES REVALIDATION: ATLAS technique for GOAL-001 (do not invent a mapping in design).
