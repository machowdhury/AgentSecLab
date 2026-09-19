# Goal integrity Splunk field contract

**Status:** Phase 13C **VALIDATED** (live Splunk CLI, 2026-09-18).  
**Schema:** `agentsec.security_event` **1.9.0**  
**Index:** `agentsec_telemetry`  
**Sourcetype:** `otel:agentic:json`  
**Lab:** LAB-AGENT-GOAL-INTEGRITY-001 / GOAL-001

Parents: `docs/SCHEMA_1_9_0.md`, `docs/PHASE13C_GOAL_INTEGRITY_SPLUNK_VALIDATION.md`.

Do not invent aliases. If an expected 1.9.0 name is missing, that is a STOP — not a `eval` rewrite. On these specimens the first-class goal/task/instruction **names matched**. Instruction hash, proposed-change fingerprint, and effective action are **preview-bounded**, not first-class.

---

## Observed indexed names

| Conceptual | Indexed name | GOAL-INTEGRITY-001 hop 0 | CTRL-MCP-001 hop 1 | Notes |
|------------|--------------|--------------------------|--------------------|-------|
| schema | `agentsec.schema.version` | OBSERVED `1.9.0` | OBSERVED `1.9.0` | |
| run | `agentsec.run.id` | OBSERVED | OBSERVED | mvcount 3 |
| sequence | `agentsec.sequence` | OBSERVED | OBSERVED | |
| event | `event.name` | OBSERVED `agentsec.control.decision` | OBSERVED | not `agentsec.event.name` |
| service | `service.name` | OBSERVED `acmebank` | OBSERVED | |
| agent | `gen_ai.agent.id` | OBSERVED orchestrator | OBSERVED goal agent | |
| control | `agentsec.control.id` | `CTRL-GOAL-INTEGRITY-001` | `CTRL-MCP-001` | |
| control type | `agentsec.control.type` | `goal_integrity` | `mcp_allowlist` | |
| decision | `agentsec.control.decision` | OBSERVE or DENY | ALLOW | OBSERVE ≠ ALLOW |
| reason | `agentsec.control.reason` | cannot-redefine / overlay / `unauthorized_task_expansion` | `tool_granted` | overlay is LAB-ONLY |
| tool / action id | `gen_ai.tool.name` | proposed **action id** | `lookup_policy` | not the same plane |
| task id | `agentsec.task.id` | OBSERVED | **NOT APPLICABLE** (empty) | |
| task hash | `agentsec.task.hash` | OBSERVED | empty | |
| task preview | `agentsec.task.preview` | OBSERVED | empty | objective, not full prompt |
| task provenance | `agentsec.task.provenance` | `agentsec.orchestrator.task_contract` | empty | |
| instruction trust | `agentsec.instruction.trust` | `untrusted_instruction` | empty | |
| instruction provenance | `agentsec.instruction.provenance` | `agentsec.goal.fixture` | empty | |
| proposed action | `agentsec.goal.proposed` | OBSERVED | empty | |
| goal decision/reason | `agentsec.goal.decision` / `.reason` | OBSERVED | empty | mirrors control |
| GOAL snapshot | `agentsec.content.hash` | OBSERVED | different MCP payload | compare GOAL hash for B/C |
| bounded preview | `agentsec.content.preview` | instruction_hash + proposed_action | effective_action + proposed_fingerprint | 200 chars; hashes complete on these specimens |
| trust boundary | `agentsec.trust_boundary` | `agent.task.contract` | `acmebank.mcp.authorize` | |
| attack | `agentsec.attack.id` | `GOAL-001` | `GOAL-001` | |
| method | `mcp.method.name` | **empty** | `tools/call` | |
| requested/allowed scope | `agentsec.mcp.requested_scope` / `.allowed_scope` | empty | `policy:read` | |
| resource | `agentsec.mcp.resource.id` | empty | `lending-basics` | OBSERVED on this lab |
| attempted/executed | `agentsec.operation.attempted` / `.executed` | `"false"` | control `"false"`; `mcp.started` `"true"` | |
| outcome | `agentsec.operation.outcome` | `prevented` on RETEST DENY | `success` on completed | |
| workflow / entry | `gen_ai.workflow.name` / `agentsec.workflow.entry` | `goal_integrity_lab` / `/goal/evaluate` | same | |
| profile / mode | `agentsec.security.profile` / `agentsec.testbed.mode` | OBSERVED | OBSERVED | |

## NOT INDEXED / NOT EXTRACTED

`session.id`, `gen_ai.tool.call.id`, `trusted_instruction`, `task_authorized`, `goal_authorized`, `allowed_tools`, `agentsec.instruction.hash`, `agentsec.goal.effective`, `agentsec.event.name`.

Full instruction body (`AGENT NOTE` …) is **NOT INDEXED** (privacy).

## Multivalue

Class **B** (one physical event, repeated extracted values). `dc(_raw)` equals local `events.jsonl`. Typical `mvcount` 2–3. Normalize with `mvindex(mvdedup('field'),0)`. **Do not change `props.conf`.**

## Correlation keys

`agentsec.run.id` is the specimen key. ATTACK/RETEST equality uses GOAL `agentsec.task.hash`, GOAL `content.hash`, GOAL `goal.proposed`, plus instruction_hash / proposed_fingerprint **inside** the indexed previews. Do not join on `gen_ai.tool.name` alone (GOAL hop is an action id; MCP hop is `lookup_policy`).
