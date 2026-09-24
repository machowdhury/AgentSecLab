# Logic proof — Agent Identity / Delegation workbench

**Date:** 2026-09-24
**Scope:** UX and investigation presentation for `LAB-AGENT-DELEGATION-001`; runtime behavior unchanged.

## Security property

INV-001, INV-002, and INV-005: identity and delegation claims cannot mint authority that neither the caller nor callee possesses.

`IDENTITY CLAIM != AUTHENTICATION` and `DELEGATION CLAIM != AUTHORIZATION`.

## Actual evidence chain

```text
closed A2A-shaped claim
→ frozen request / fingerprint
→ CTRL-IDENTITY-001 OBSERVE untrusted_claim
→ optional labeled ATTACK-only overlay
→ privileged tool request
→ CTRL-MCP-001
→ ToolRegistry handler
→ runtime events / local evidence / Splunk copy
```

## Model answers

1. **Attacker influence:** the closed adversarial claim fixture: principal string, caller/callee strings, claimed scope/tool/resource, and requested privileged operation. The learner selects the allowlisted specimen; browser JSON cannot supply those fields directly.
2. **Server-owned facts:** fixture identity, ExperimentContext profile, frozen canonical request, trust classification, both agents' coded policies, controls, correlation ID, and runtime handler counts.
3. **Property under test:** a caller/delegation claim cannot amplify authority. Neither coded agent possesses `lookup_customer_tier` or `customer:read`.
4. **Participating controls:** `CTRL-IDENTITY-001` classifies the claim; `CTRL-MCP-001` authorizes the requested tool.
5. **Authoritative decisions:** Identity control is authoritative only for claim classification and always OBSERVEs valid claims. MCP control is the sole tool PDP.
6. **OBSERVE semantics:** `OBSERVE identity_claim_is_not_grant` means the claim remains data. It is neither authentication nor tool authorization.
7. **Attempted operation:** `lookup_customer_tier / customer:read / cust-001`.
8. **Authorized operation:** ATTACK receives a labeled per-run fail-open overlay and MCP ALLOW. RETEST has no overlay and MCP DENY `tool_not_granted`.
9. **Actual execution:** ATTACK invokes `lookup_customer_tier` once. RETEST invokes it zero times.
10. **Execution proof:** `lookup_customer_tier_handler_count` is authoritative. Indexed MCP lifecycle events corroborate execution on a complete copy.
11. **ATTACK vs RETEST change:** server-owned profile, overlay presence, MCP decision/reason, privileged handler count, and operation outcome.
12. **Intentionally identical:** principal/caller/callee strings, delegation claim, requested tool/scope/resource, request fingerprint, claim trust, and Identity OBSERVE result.
13. **Fingerprint:** `input_fingerprint` / `request_fingerprint` covers the canonical A2A-shaped request object. It does not authenticate any actor.
14. **Splunk role:** reconstruct claims, trust classification, requested authority, MCP decision, and indexed execution evidence. It cannot authenticate actors and does not enforce.
15. **Falsification:** Identity ALLOW or DENY for the tool; different request fingerprints; RETEST handler count 1; ATTACK handler count 0; either agent coded with customer authority; or UI language claiming authentication would falsify the expected result.

## Claim assurance classification

### CLAIMED

- principal: `applicant-web`
- caller: `acme-agent-advisor-005`
- callee: `acme-agent-fulfillment-006`
- delegation scope/tool/resource: `customer:read`, `lookup_customer_tier`, `cust-001`

These are fixture strings and attribution fields, not verified identities.

### ESTABLISHED IN THIS LAB

- exact canonical fixture and request fingerprint
- `untrusted_claim` classification
- server-owned ExperimentContext
- coded policies for caller/callee
- neither coded policy grants the privileged tool/scope/resource
- control decisions/reasons and handler counts

### NOT MODELED

- cryptographic authentication
- OAuth/OIDC/JWT validation
- mTLS, PKI, SPIFFE/SPIRE, workload identity
- signed delegation or production A2A transport

## Trust boundaries and decision points

- Browser → Attack Service: closed four-field launch contract.
- Claim → coded authority: `CTRL-IDENTITY-001` OBSERVEs before MCP authorization.
- Request → handler: `CTRL-MCP-001` runs before invocation.
- Runtime → Splunk: evidence transport, not authentication or enforcement.

The dangerous operation cannot occur before MCP validation. Missing identity context becomes ERROR. The vulnerable overlay is closed to one request/run and cannot extend or mutate coded policy.

## Failure paths

- Authority-like or ambiguous identity fields: ERROR before follow-on; handler 0.
- Unknown actors/malformed claim: ERROR, not DENY.
- Unknown tool/resource or MCP control exception: ERROR after Identity OBSERVE; no handler.
- Handler exception after ALLOW: execution occurred and is reported as MCP failure.

## Tests before UX implementation

MEASURED: the combined Goal/Identity model gate passed **81 tests in 1.02s**, including claim parsing, authority amplification rejection, frozen check/use, control ordering, telemetry, launch contracts, concurrency, and failure paths.

## Remaining proof obligations

- Fresh LIVE ATTACK/RETEST runtime and assurance evidence.
- Local event count versus Splunk `dc(_raw)`.
- Browser claims/facts/NOT MODELED and controlled error-state validation.
- MCP/RAG/Memory regression after the shared CSS rename.
