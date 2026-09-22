# AgentSec v1.0.0-rc1 — Splunk validation

Completeness model: local `local_event_count` from launch JSON vs Splunk `dc(_raw)` on the **primary** launch `run.id`.

All seven LIVE ATTACK/RETEST primary ids **matched** (MEASURED). JSON: `V1_0_0_RC1_LIVE_PAIRS.json`.

Sibling memory/capstone write/retrieve ids were searchable (`dc(_raw)=5` each, MEASURED). Local sibling counts were not separately exported in the launch `local_event_count` field (that field is the recall/primary run). Treat sibling completeness as **MEASURED searchability**, not a second local==dc proof.

Hunts: existing Q-* only. MCP ATTACK vs RETEST reconstructed as CTRL-MCP-001 ALLOW vs DENY on 17D smoke; RC1 MCP pair handler 1 vs 0 MEASURED at runtime.

| Question | Answerability |
|----------|----------------|
| WHO / WHAT / WHEN / RUN | PROVEN from indexed events when complete |
| TRUST/PROVENANCE | PROVEN where fields exist (RAG/memory) |
| REQUEST vs CONTROL vs AUTHZ vs EXECUTION | PROVEN for MCP path |
| ATTACK vs RETEST | PROVEN (distinct run.ids, same fingerprint, different profile) |
| Cryptographic agent identity | NOT MODELED |
| Production authn | NOT MODELED |

HEC HTTP 200 is not this table.
