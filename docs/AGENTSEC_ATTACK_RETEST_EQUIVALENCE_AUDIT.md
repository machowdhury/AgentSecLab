# AgentSec ATTACK / RETEST equivalence audit

**Status:** Phase 17C. Prefer existing official measured pairs. **No new attacks minted.** Schema **1.9.0**.  
**Do not start Phase 17D from this file.**

Fixture-name equality is not byte-equivalence proof. Use the domain fingerprint.

| Lab | Fingerprint object | Official pair hash / fingerprint | ATTACK vs RETEST discriminator | Equivalence class | Limitation |
|-----|--------------------|----------------------------------|--------------------------------|-------------------|------------|
| LAB-PI-001 | input hash | `sha256:88a1ceab989683389193e0aa5f27e7d5ba34fb64a8dd2b5f4af8e4a6caf4b5a5` both | CTRL-INPUT-001 ALLOW fail-open vs DENY `input_pattern_matched`; 4 LLM vs 0 | MEASURED (14D) | Regex RETEST is not universal PI resistance |
| LAB-MCP-001 | request hash | `sha256:431e7baaa0e7206b8671e6f81613e16848ccbcaf0f16d90d0e0da4c3b3fcc70d` both | CTRL-MCP-001 ALLOW overlay vs DENY `tool_not_granted`; handler 1 vs 0 | MEASURED (14E) | Overlay reason is a lab label |
| LAB-RAG-CONTEXT | document content hash | `sha256:c565f364c7c5fba3cf25d235bb8e2bee7d9433daa9f07d5e097ab6d2a82a97ef` both | CONTEXT OBSERVE both; MCP ALLOW overlay vs DENY; handler 1 vs 0 | MEASURED (15B) | Hash is retrieve identity, not hop-1 MCP request hash. Exact-id fixtures, not a vector DB |
| LAB-MEMORY-001 | memory content hash | `sha256:1dc7335c3fd8c54326e36194d783536d944c6d527660eb1bda4a36a9cb5ed1b9` | WRITE+RECALL both; memory OBSERVE both; recall MCP ALLOW vs DENY; handler 1 vs 0 | MEASURED (15C) | Two run.ids per mode. Missing MCP on RETEST is not independent prevention |
| LAB-AGENT-GOAL-INTEGRITY-001 | instruction + task + proposed hashes | instruction `sha256:15a1c5fa…`; task `sha256:6f95aaf2…`; proposed `sha256:6326e3be…` | GOAL OBSERVE overlay vs DENY; **MCP ALLOW both**; wrong-goal handler 1 vs in-task 1 | MEASURED (15D) | RETEST is **not** MCP DENY. Instruction/proposed hashes in Splunk are PARTIALLY SUPPORTED via preview |
| LAB-AGENT-DELEGATION-001 | claim fingerprint | `sha256:56179e463b2faf18c056389ebff32a61e346dd0b4010fb82e8826c4508790dfd` | IDENTITY OBSERVE both; MCP ALLOW overlay vs DENY; handler 1 vs 0 | MEASURED (15E) | WHO AUTHENTICATED = NOT PROVEN / NOT MODELED |
| LAB-AGENTSEC-CAPSTONE-001 | retrieve content.hash (malicious = 15B hash) | malicious `sha256:c565f364…`; normal `sha256:0fc83ee7…` | retrieve/write OBSERVE; recall MCP ALLOW vs DENY; handler 1 vs 0 | MEASURED (16B) | Three run.ids. Telemetry `attack.id` enum is RAG-001. Goal/Identity 0 rows = NOT PRESENT in packet |

REPLAY workshops (MCP-003/004/005/006/catalog/scanner) have historical packs only. Equivalence is **REPLAYED / DOCUMENTED**, not a 17C remint.

## Home fingerprint teaching (17C correction)

Matching fingerprints support **equivalent hashed bytes of the named object**. They do not prove same fixture name, hop, grant, or request hash unless those fields are also compared.
