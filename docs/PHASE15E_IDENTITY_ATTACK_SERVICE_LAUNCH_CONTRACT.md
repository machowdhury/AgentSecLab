# Phase 15E — Identity Attack Service launch contract

Closed catalog lab: `LAB-AGENT-DELEGATION-001`.

Allowlisted launches:

| lab_id | specimen_id | mode | execution | experiment_id | profile (server-owned) |
|--------|-------------|------|-----------|---------------|------------------------|
| LAB-AGENT-DELEGATION-001 | A2A-BASELINE | BASELINE | live | LAB-AGENT-DELEGATION-001:BASELINE | defended |
| LAB-AGENT-DELEGATION-001 | A2A-001 | ATTACK | live | LAB-AGENT-DELEGATION-001:ATTACK | vulnerable |
| LAB-AGENT-DELEGATION-001 | A2A-001 | RETEST | live | LAB-AGENT-DELEGATION-001:RETEST | defended |

Browser JSON may contain only: `lab_id`, `specimen_id`, `mode`, `execution`.

AcmeBank HTTP `POST /identity/delegate` may contain only: `claim_id`, `user_id`, `experiment_id`.

Rejected as ERROR (`unknown_fields`), not DENY/ALLOW:

- profile, allowed_tools, allowed_scope, grants, roles, permissions
- identity_verified, authenticated, delegated_grant, approved
- A2A body / caller / callee / principal substitution
- SPL, Python, environment variables

Unknown experiment or claim mismatch: ERROR.

Missing `experiment_id` keeps auto-mode (process-env profile). Default defended: IDENTITY OBSERVE, MCP DENY on the privileged claim, handler 0.

Attack Service does not evaluate CTRL-IDENTITY-001 or CTRL-MCP-001. It launches. AcmeBank enforces.

Studio token binding: NOT SUPPORTED / DO NOT BUILD.

WHO AUTHENTICATED is never a launch field. It is NOT PROVEN / NOT MODELED.
