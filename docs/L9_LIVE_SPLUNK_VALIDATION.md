# L9 live Splunk validation

Date: 2026-09-25

Evidence class: `MEASURED` queries against the local Splunk instance.

## Canonical packet

Distinct `_raw` counts matched the validated local event-pack expectations:

- ATTACK retrieve `2a248113-7436-46a7-9b1d-0243489ac000`: 5 distinct;
- ATTACK write `348c8f18-fdfb-4501-ad8a-3f1bcda64c34`: 5 distinct;
- ATTACK recall `2437f64a-fff4-424f-8a83-0f04285662e4`: 11 distinct;
- RETEST retrieve `f9015037-651d-4207-ac57-4f3ea1abc673`: 5 distinct;
- RETEST write `3f8d6305-2d3b-4988-9e65-dc99b7ac10de`: 5 distinct;
- RETEST recall `8d2c016f-cadc-4463-939a-23a183221b3d`: 10 distinct.

Each had three indexed copies after local evidence replay/restaging: 15, 15,
33, 15, 15, and 30 rows respectively. These duplicate rows are not additional
runtime executions.

## Authorization, execution, and baseline

ATTACK recall showed:

- `lookup_customer_tier`;
- requested `customer:read`, allowed `policy:read`;
- Memory `OBSERVE` and CTRL-MCP-001 `ALLOW`;
- `mcp.started` and `mcp.completed`;
- 11 distinct events.

RETEST recall showed the same tool/scope mismatch, Memory `OBSERVE`,
CTRL-MCP-001 `DENY`, no `mcp.started`, and 10 distinct events. Authoritative
runtime evidence records handler count zero.

The benign comparison showed `lookup_policy`, requested and allowed
`policy:read`, CTRL-MCP-001 ALLOW, and expected MCP execution. Its separate
Goal `DENY` row illustrates why a broad “any DENY or any execution” rule would
produce incorrect conclusions.

## External evidence pivot

The current volume contained:

- adversarial evaluation: 1 distinct event / 8 indexed rows,
  `identity_tuple`;
- static findings: 6 distinct events / 27 indexed rows, `hash_join`;
- scanner description hashes
  `sha256:8a76d34c6c21fda0dc930fa2f64fe87c3216f23cbc73ca357c47b0927850d9c3`
  and
  `sha256:9d0745320ca79852f2fbd7145bf074fcd353e290c18ba16fd02d801f9f3375b1`.

Neither scanner description hash matches the incident fingerprint
`sha256:c565f364c7c5fba3cf25d235bb8e2bee7d9433daa9f07d5e097ab6d2a82a97ef`.
The garak plane has no AgentSec runtime run ID. No causal relationship is
proven.

## Search limitation

The exact bounded timestamp discovery query is packaged and already derives
from the live-validated Blue-Team search. Shell CLI quoting of multivalue
field references returned no displayed rows in one invocation, while direct
run-ID and timestamp inspection confirmed the ATTACK control timestamp
`2026-09-20T19:37:46Z` lies inside the specified window. This CLI rendering
issue is not represented as a successful exact-query measurement.

## Transport note

The Splunk CLI reported disabled server-certificate hostname validation in the
local lab. No certificate was added or validated in L9. This is not a
production transport-security claim.
