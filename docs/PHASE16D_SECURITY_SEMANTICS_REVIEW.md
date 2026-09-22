# Phase 16D security semantics review

Educational UI must not become policy. 16D did not change authorization.

**Schema:** 1.9.0. No bump was required. No telemetry field was added.

---

## Controls (semantics unchanged)

| Control | Role | 16D |
|---------|------|-----|
| CTRL-INPUT-001 | HTTP input PDP (PI) | Unchanged |
| CTRL-MCP-001 | Sole tool PDP | Unchanged; still `lookup_policy` / `policy:read` |
| CTRL-RAG-CONTEXT-001 | OBSERVE classifier | Unchanged; not a grant |
| CTRL-MEMORY-CONTEXT-001 | OBSERVE classifier | Unchanged; not a grant |
| CTRL-GOAL-INTEGRITY-001 | Goal/instruction plane | Unchanged; RETEST is not MCP DENY |
| CTRL-IDENTITY-001 | OBSERVE identity claim | Unchanged; not authentication |

`coded_policy()` is unchanged. Overlays remain lab-only. Attack fixture bytes unchanged. Historical LIVE packs unchanged.

---

## Attack Service

Closed allowlist: seven LIVE labs. Browser still cannot send profile, grant, tool, scope, trust, policy, SPL, Python, shell, environment, or arbitrary payload.

New copy (“Where you are”, attacker-does-not-control, server-owned) is HTML. It does not call `coded_policy()`.

Curriculum `next_lab` is learning metadata. It is not an authorization graph.

---

## Inequalities that remain true

DATA ≠ AUTHORITY. REQUEST ≠ GRANT. IDENTITY CLAIM ≠ AUTHENTICATION. DELEGATION CLAIM ≠ AUTHORIZATION. PROVENANCE ≠ TRUST. STORED ≠ TRUSTED. OBSERVE ≠ ALLOW. ALLOW ≠ EXECUTION. AUTHORIZED TOOL ≠ AUTHORIZED GOAL. MISSING EVENT ≠ PREVENTION. ANOMALY ≠ INCIDENT. SPLUNK ≠ ENFORCEMENT. REPLAY ≠ LIVE. ATTACK SUCCESS ≠ UNIVERSAL VULNERABILITY. RETEST SUCCESS ≠ UNIVERSAL SECURITY. BASELINE ≠ SAFE. 0 rows ≠ SAFE.

DET-MCP-001 unchanged. No DET-CAPSTONE / DET-RAG / DET-MEMORY / DET-GOAL / DET-A2A.

---

## Schema gate

No 16D item required a new field. If completeness or retrieve→write correlation still uses hashes + `source_run_id`, that remains the 16B honesty model. Do not invent a join field here.
