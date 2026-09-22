# Phase 15B — RAG security boundary review

**Invariant:** INV-002 Data Cannot Grant Authority.

## Path

USER QUESTION → RETRIEVER → RETRIEVED DOCUMENT → AGENT CONTEXT (`trust=untrusted_data`) → FOLLOW-ON REQUEST → CTRL-MCP-001 → ALLOW / DENY → HANDLER → OTLP → HEC → SPLUNK.

## Trust boundary

Retrieved content crosses into agent context as **untrusted data**. Configured retriever ≠ trusted instructions. Known knowledge base ≠ authorization. Provenance (`rag.local.fixture`) is source identity, not trust.

CTRL-RAG-CONTEXT-001 classifies. It does not grant tools.

CTRL-MCP-001 is the only tool PDP. The ATTACK overlay reason `vulnerable_profile_fail_open:retrieved_context_derived_authority` is a labeled lab fail-open on a server-owned ExperimentContext. It is not stored in the document. It is not coded_policy.

## What the attacker controls

The closed malicious fixture bytes (catalog `doc.lending-policy.malicious`).

## What the attacker / learner does not control

profile, allowed_tools, allowed_scope, grants, policy, document trust labels, arbitrary document body via HTTP, Python, shell, SPL, environment variables.

## What ATTACK vs RETEST changes

Server-owned experiment/authorization configuration only.

## What does not change

malicious document, `document.id`, `content.hash`, provenance, requested tool, requested scope, retriever, Splunk search, coded grants.

## Incorrect claims (do not teach)

- Splunk prevented the attack.
- The document is safe.
- `untrusted_data` means malicious.
- Known malicious hash means compromise.
- No `mcp.started` means prevention by itself.
- DET-MCP-001 returned zero so the run was safe.
- Retrieved content authorized the tool.
- Sanitize the document and the problem is solved.

## Schema / detector

Schema remains 1.9.0. No new field. No DET-RAG. Existing ATLAS mappings unchanged. No certification claim.
