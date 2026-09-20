# PI-001 vs MCP-001 common-component analysis (Phase 14E)

Promoted into the reusable framework **only** because both reference labs demonstrate the piece.

## COMMON COMPONENTS (promoted)

- LabManifest prediction block (what changes / does not / expected evidence)
- Guided investigation Path A (Search) + Path B (Q-* solution)
- Server-owned ExperimentContext (no process-env mutation)
- Closed Attack Service launch fields
- Independent ATTACK and RETEST run.ids with measured fingerprint equality
- Search handoff (copy run.id, Open Splunk Search)
- Studio = syllabus; Search = workbench; runtime = enforcement
- Honest LIVE/REPLAY capability flags

## LAB-SPECIFIC COMPONENTS (not promoted)

- Loan input string vs MCP tool/scope/arguments
- CTRL-INPUT-001 regex vs CTRL-MCP-001 allow-list
- Q-LLM-* vs Q-MCP-*
- DET-MCP-001 (MCP invariant only)
- AcmeBank `/process` vs `/mcp/invoke`

## SECURITY-SEMANTIC COMPONENTS (must stay lab-owned)

- Grants, allowed_tools, allowed_scopes
- Profile defended vs vulnerable fail-open reasons
- Handler vs LLM execution authority

## UI-ONLY COMPONENTS

- Tab copy, card wording, Attack Service lab switcher
- Investigation titles

## RUNTIME COMPONENTS

- Per-request `settings_for_experiment`
- Route-specific bind (`bind_experiment_for_process` vs `bind_experiment_for_mcp`)

Do not build a giant generic framework. Later labs should adopt these contracts when their runtime can support honest LIVE.
