# Logic proof: L8 privacy data handling

Date: 2026-09-25

## Claim

For the bounded task, changing from a full synthetic record to a purpose-
minimized record changes data exposure without changing tool authorization or
expected execution.

## Deterministic proof

Both specimens request `prepare_support_contact` with scope
`support:contact:prepare` under the same immutable L8 policy. CTRL-MCP-001
returns `ALLOW / tool_granted`; each handler invocation count is one and each
run reaches `mcp.completed`.

The full specimen's received fields additionally contain synthetic email,
postal address, account-balance band, and internal case note. The minimized
specimen contains only `customer_id` and `preferred_channel`. Their content
hashes differ, and the bounded previews show the corresponding field sets.

Malformed, missing-required-field, secret-shaped, and non-synthetic fixtures
fail before handler execution.

## Invariants

- Default `coded_policy()` is unchanged.
- CTRL-MCP-001 remains the tool PDP.
- Authorization remains before handler invocation.
- No `PRIVACY-001` attack ID is emitted because the schema enum is unchanged.
- Runtime schema remains `1.9.0`.
- ExternalEvidence remains `1.0.0`.
- Splunk is downstream evidence, not enforcement.

## Limits

This proves fixture and control-flow semantics only. It does not prove
production privacy, provider behavior, tenant isolation, retention, deletion,
RAG or memory behavior, a breach, or universal control effectiveness.
