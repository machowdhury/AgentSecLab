# Phase 15C — cross-run evidence model

Correlation keys that exist:

- memory.id
- content.hash
- agentsec.memory.source_run_id
- current recall run.id
- gen_ai.agent.id
- agentsec.sequence

Do not invent session.id or invocation.id.

WRITE READY ≠ RECALL READY ≠ EXPERIMENT READY.

Privacy: index memory.id, SHA-256, bounded preview, provenance, agent ids, source/recall run ids, trust. Do not index full memory body, credentials, secrets, PII, or full conversation history.

Official LIVE pair (MEASURED Q-MEMORY-CONTEXT-AUTHORITY): ATTACK write `ad850327-07c8-4b2d-b817-6c1bc964b41c` linked to recall `e686da75-64c0-41a3-9bde-c932d268ed28`; RETEST write `a3ae94ba-0ffc-4838-912a-c90bef331b16` linked to recall `87bd07c5-324d-40fb-b3be-797763877095`. `write_recall_linked=linked` on both. Same malicious `content.hash`.
