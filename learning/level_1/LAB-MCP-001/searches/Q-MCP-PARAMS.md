# Q-MCP-PARAMS

| Item | Value |
|------|--------|
| Query ID | `Q-MCP-PARAMS` |
| Security question | What arguments were supplied to the tool? |
| Validation status | **VALIDATED** |
| Validation date | 2026-09-12 |
| SPL file | `Q-MCP-PARAMS.spl` |

There is **no** indexed `gen_ai.tool.call.arguments` field. Phase 3B intentionally emits preview + hash only.

## Required fields (indexed names)

`event.name`, `agentsec.run.id`, `gen_ai.tool.name`, `agentsec.content.origin.type`, `agentsec.content.influence.kind`, `agentsec.content.hash`, `agentsec.content.preview`

## SPL

See `Q-MCP-PARAMS.spl`. Uses control-event content fields (request JSON preview/hash), not `_raw`.

## Line-by-line explanation

1. Control decision carries the request snapshot (`influence.kind=tool_request`, origin user).
2. `agentsec.content.hash` is `sha256:…` of the canonical request JSON.
3. `agentsec.content.preview` is a **200-character** truncation of that JSON. It is not a structured argument map and must not be treated as a secret dump.

Do not add `_raw` or reconstruct full payloads to make this query prettier.

## Expected result

One row per authorize-path invoke, with hash + preview of `{tool, arguments, requested_scope}`. HTTP schema malformed: zero rows (request never became a control content snapshot).

## Actual result

**VALIDATED.** Lab fixtures only (`policy_id=lending-basics`, `customer_id=cust-001`). Hashes differ when arguments differ. HTTP malformed: empty CSV.

## Validated run.id / test data

A `sha256:d95414011908979ffd98dc1f0bd12a04d1743bd38283a2ba758444f826939b66`. B/C share the customer-tier request hash.

## Performance notes

One event.

## Known limitations

Preview can include lab fixture keys. Production secrets must never be placed in arguments in this lab. No dedicated per-key argument fields.

## No-data semantics

Zero rows: no control content in this copy. Not proof that the caller sent no arguments.
