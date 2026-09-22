# Phase 15D — Goal Integrity guided investigations

Learning metadata only. `not_authorization=true`. These objects do not authorize, deny, or detect.

Sequence (`learning/level_1/LAB-AGENT-GOAL-INTEGRITY-001/investigations.json`):

| ID | Question | Teach |
|----|----------|-------|
| GOAL-I1 | What events belong to this experiment? | run.id correlation |
| GOAL-I2 | What was the agent actually authorized to accomplish? | task contract != instruction |
| GOAL-I3 | What instruction influenced the proposed action? | instruction influence != task authority |
| GOAL-I4 | What action did the instruction cause the agent to propose? | proposal != authorization |
| GOAL-I5 | What did CTRL-GOAL-INTEGRITY-001 decide? | goal/task authorization plane |
| GOAL-I6 | Did CTRL-MCP-001 allow the tool? | YES in ATTACK and RETEST |
| GOAL-I7 | Which effective action/handler ran? | ALLOW != execution; authorized tool != authorized use |
| GOAL-I8 | What stayed the same and what changed? | SAME TASK / INSTRUCTION / PROPOSED GOAL / TOOL; DIFFERENT GOAL DECISION / EFFECTIVE ACTION |
| GOAL-I9 | What can you prove? | SUPPORTED / CORROBORATED / NOT PROVEN / INCORRECT |

Path A: SECURITY QUESTION, START HERE, WHAT FIELDS, HINT 1, HINT 2, Open Splunk Search. Do not immediately reveal complete SPL.

Path B: existing Q-GOAL-INTEGRITY-AUTHORITY and Q-MCP-AUTHZ / TOOL / EXECUTED / WHO. No new Q-GOAL-* hunts. No DET-GOAL.

Bound Studio tables use canonical REPLAY. Fresh LIVE remains Search.

GOAL-I6 is the critical teaching moment: MCP ALLOW on both experiments does not authorize the goal.
