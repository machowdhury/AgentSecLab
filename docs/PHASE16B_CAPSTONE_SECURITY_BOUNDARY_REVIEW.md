# Phase 16B — Security boundary review

## Planes

- RAG classifier: OBSERVE. Data.
- Memory classifier: OBSERVE. Data.
- MCP tool PDP: CTRL-MCP-001. Sole authorization for the privileged tool.
- Splunk: evidence copy. Not a PDP.
- Attack Service: closed launcher. Not a PDP.
- Learning metadata: not policy.

## ATTACK overlay

Official LIVE ATTACK overlay reason MEASURED: `vulnerable_profile_fail_open:memory_derived_authority`. RETEST DENY MEASURED: `tool_not_granted`. Health after the pair OBSERVED `security.profile=defended`.

## RETEST

Same adversarial bytes. No overlay. DENY `tool_not_granted`. Handler 0.

## Out of scope (not failures in this packet)

Goal Integrity, Identity/Delegation, real A2A, OAuth/OIDC/JWT/SPIFFE, HITL, MLTK, DET-CAPSTONE.

## Privacy

Index identifiers, hashes, bounded previews, decisions. Do not index full documents, full memory bodies, credentials, tokens, PII, or full conversations.
