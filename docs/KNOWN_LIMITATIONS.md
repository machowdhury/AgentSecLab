# Known limitations (v1.0)

These remain visible on purpose.

- Educational localhost Attack Service (unauthenticated)
- Not production authentication or multi-tenant isolation
- Studio Path B is often visible without a reveal control
- Dashboard Studio layout/platform constraints
- CTRL-INPUT-001 is regex-class educational inspection, not a general LLM firewall
- RAG uses exact-id fixtures, not a production retriever
- Memory is in-process; not a durable vector store
- Identity authentication is not modeled (no OAuth/OIDC/SPIFFE)
- No real A2A protocol implementation
- Splunk indexing delay; HEC health ≠ searchable events
- LIVE vs REPLAY must not be collapsed
- Missing event is not prevention
- One RETEST is not universal security
- No learner progress persistence
- No certification
- DET-MCP-001 is packaged disabled; no DET-CAPSTONE / DET-RAG / DET-MEMORY / DET-GOAL
- ATLAS labels require revalidation (educational, not verified MITRE mappings)
- Hardware minimums NOT BENCHMARKED
- Clean-room install was not fully proven (see `docs/releases/V1_0_0_RC1_REPRODUCIBILITY.md`)
