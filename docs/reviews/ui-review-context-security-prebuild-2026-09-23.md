# UI review — Context Security prebuild

**Date:** 2026-09-23
**Surfaces:** Attack Service RAG and Memory pages; `ws_lab_rag_context`; `ws_lab_memory_security`
**Evidence:** DOCUMENTED / current templates, generated Studio definitions, and existing screenshots
**Verdict:** REVISE — 0 BLOCKER / 4 HIGH

## Roles

### Splunk architect

Existing Q-RAG, Q-MEMORY, and Q-MCP searches are validated and token-bound. The problem is presentation, not a missing field contract. Preserve SPL.

### SOC analyst

The evidence questions are correct, but the current ten-tab Studio flow fragments one investigation across LEARN, OBSERVE, HUNT, RETEST, COMPARE, and PROVE. Memory’s write/recall relationship is technically present but not visually primary.

### UX designer

Both Attack Service pages use the legacy long-column template. Orientation, predictions, fixture details, launch controls, multiple UUIDs, runtime facts, comparison, and raw JSON compete vertically. The learner reaches the experiment controls after substantial prose.

### Technical instructor

The text correctly says OBSERVE is not ALLOW, but structure still encourages learners to read RAG or Memory as MCP with an extra introductory section. RAG needs a source/retrieval/context story. Memory needs an explicit time-separated WRITE→RECALL story.

## HIGH findings

1. **RAG initial viewport does not present the context boundary as a workbench.** The source, retrieved artifact, provenance, context classification, downstream request, PDP, and execution evidence are separated by long cards.
2. **Memory’s cross-run causality is buried.** WRITE run, RECALL run, and `source_run_id` exist, but not as the dominant visual explanation.
3. **ATTACK↔RETEST comparisons are not domain-specific enough.** The current generic fallback emphasizes a first-hop decision and can obscure that context controls remain OBSERVE while MCP authorization changes.
4. **Studio Path A and Path B compete in one long HUNT notebook.** The solution material is technically labeled but visually follows the learner path in the same layout.

## Required corrections

- Reuse the accepted compact workbench grammar and shared CSS.
- Give RAG a `SOURCE → RETRIEVAL → CONTEXT → CONTROL → EFFECT → AUTHORIZATION → EXECUTION → EVIDENCE` story.
- Give Memory a `WRITE → PERSIST → RECALL → SOURCE LINK → CONTROL → REQUEST → AUTHORIZATION → EXECUTION` story.
- Make all relevant run IDs explicit and copyable without relabeling write events as recall events.
- Separate Studio into MISSION, INVESTIGATE, EVIDENCE, and PATH B · ANSWERS.
- Keep existing SPL unchanged.
- Retain raw responses under Evidence / Advanced.

## Accessibility gate

Validate textual status labels, keyboard order, visible focus, wrapping, no horizontal overflow, and 200% zoom. Screen-reader behavior remains PARTIAL without an assistive-technology session.
