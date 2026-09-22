# AgentSec reusable learning architecture (Phase 14E)

**Status:** IMPLEMENTED for three reference labs as of Phase 15B (`LAB-PI-001`, `LAB-MCP-001`, `LAB-RAG-CONTEXT`). Schema **1.9.0**. Learning metadata is **not** authorization.

Parents: `docs/PHASE14E_LEARNING_LOOP_GENERALIZATION.md`, `docs/AGENTSEC_LEARNING_ARCHITECTURE.md`.

## What is reusable (proven by PI-001, MCP-001, and RAG in 15B)

| Contract | Kind | Authority? |
|----------|------|------------|
| `lab-manifest.json` | Learning metadata | No |
| `investigations.json` | Security-question Path A/B | No (`not_authorization=true`) |
| `ExperimentDefinition` / `ExperimentContext` | Server-owned specimen + profile + fingerprint | Selects a predefined experiment; does not grant tools |
| `LaunchCatalog` + `POST /api/launch` | Closed launcher | Browser may send only lab_id, specimen_id, mode, execution |
| Search handoff | Fresh run.id → Splunk Search | No |
| Studio stacked Path A/B notebook | Syllabus | No |

## What is lab-specific

| Piece | PI-001 | MCP-001 | RAG-CONTEXT (15B) |
|-------|--------|---------|-------------------|
| Runtime route | `POST /process` | `POST /mcp/invoke` | `POST /rag/retrieve` |
| Observation control | — | — | CTRL-RAG-CONTEXT-001 OBSERVE |
| Tool PDP | CTRL-INPUT-001 | CTRL-MCP-001 | CTRL-MCP-001 |
| Dangerous operation | Ollama generate | Tool handler | `lookup_customer_tier` handler |
| Fingerprint | attack input bytes | MCP request JSON | malicious document bytes / `content.hash` |
| Execution evidence | `llm.started` | `mcp.started` / `handler_invoke_count` | `mcp.started` / `lookup_customer_tier_handler_count` |
| Governed hunts | Q-RUN-EVENTS, Q-CONTROL-DECISION, Q-LLM-* | Q-MCP-* | Q-RAG-CONTEXT-AUTHORITY + Q-MCP-* |
| Detector | none on this lab | existing DET-MCP-001 (DENY-then-start only) | none new (DET-MCP-001 reused; 0 rows ≠ SAFE) |

## Explicit non-goals

Do not store grants, profiles, or SPL as learner authority.
Do not let Studio or Splunk ALLOW/DENY.
Do not create a detector because a new workshop exists.
Do not convert remaining labs in this phase.
Phase 15B migrates RAG only. Memory, goal integrity, and identity remain unmigrated.
