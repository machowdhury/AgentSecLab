# Known limitations (v1.0.0-rc2)

These remain visible on purpose. Creating the RC2 candidate does not remove them. The RC1 reproducibility note is still the clean-room record.

- Screen-reader coverage is partial and not fully tested. This is not a WCAG conformance claim.
- Early LIVE mission cards may state the expected ATTACK outcome before the learner investigates
- Path B is visible pedagogical guidance, not access control
- Splunk practice still begins with a pasted `run.id`. The move to independent search at L6 is abrupt
- Two evidence vocabularies remain: how evidence was obtained, and how strong a claim is
- `ollama/ollama:latest` is not pinned
- The garak pin license line is not closed external validation (`docs/EXTERNAL_VALIDATION_BACKLOG.md`)
- The GitHub default branch remains `main` (RC1). RC2 is `develop` and tag `v1.0.0-rc2`
- External findings do not authorize tool execution
- Production delegation, production IAM, human approval, and cryptographic identity are not modeled
- Empty or negative search results are not proof of safety

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
