# Phase 16B — Cross-run correlation

Schema **1.9.0**. No new field.

## Edges

| Relationship | How it is proven |
|--------------|------------------|
| retrieve → write | Same SHA-256 of frozen RAG-001 bytes. Launch ERROR if retrieve hash ≠ write hash ≠ experiment fingerprint. |
| write → recall | `agentsec.memory.source_run_id` on recall equals write `run.id`. Same `memory.id`. |
| recall → MCP request | Same recall `run.id`. Follow-on tool rows sit on the recall run. |

Recall `source_run_id` on the official ATTACK packet equals write `348c8f18-fdfb-4501-ad8a-3f1bcda64c34`. RETEST recall `source_run_id` equals write `3f8d6305-2d3b-4988-9e65-dc99b7ac10de`. Q-MEMORY-CONTEXT-AUTHORITY MEASURED `write_recall_linked=linked` on both.

Retrieve → write has no schema field. Official ATTACK/RETEST hashes MATCH `sha256:c565f364c7c5fba3cf25d235bb8e2bee7d9433daa9f07d5e097ab6d2a82a97ef`.

Do not invent session.id or invocation.id.

## Launch JSON

Returns `retrieve_run_id`, `write_run_id`, `recall_run_id`. `run_id` equals the recall UUID for compatibility with the existing last-run field.
