# Phase 15D — Goal Integrity Attack Service launch contract

Closed catalog lab: `LAB-AGENT-GOAL-INTEGRITY-001`.

Runtime route: `goal_evaluate` = `POST /goal/evaluate` with closed `{instruction_id, user_id, experiment_id}`.

Browser selects only BASELINE / ATTACK / RETEST. Browser cannot send profile, grants, allowed_tools, allowed_scopes, task contract, trusted_instruction, goal decision, instruction body, Python, shell, SPL, or environment variables.

Unknown fields → ERROR. Malformed experiment → ERROR. Unknown experiment → ERROR. ERROR is not DENY and not ALLOW.

## Before launch the page teaches

WHAT IS GOAL / INSTRUCTION INTEGRITY, WHY ATTACK IT, WHAT IS THE AUTHORITATIVE TASK, WHAT THE UNTRUSTED INSTRUCTION CAN INFLUENCE, WHAT IT MUST NOT CHANGE, WHAT YOU PREDICT, and the misconception: "If MCP allowed the tool, the action must have been authorized."

That statement is false. CTRL-MCP-001 answers tool authority. CTRL-GOAL-INTEGRITY-001 answers task/goal authority.

## Result UX

Launch ATTACK (LIVE). Copy ATTACK run.id. Open ATTACK in Splunk Search.

After DEFEND: Launch RETEST (LIVE). Copy RETEST run.id. Open RETEST in Search. Open ATTACK vs RETEST in Search.

No learner-supplied SPL. No Studio token writes from custom JavaScript.

Evidence lifecycle: LAUNCHING → TELEMETRY SENT → WAITING FOR SPLUNK → EVIDENCE READY.

HEC acceptance != searchable evidence. Timeout != attack failure. Missing Splunk event != prevention.
