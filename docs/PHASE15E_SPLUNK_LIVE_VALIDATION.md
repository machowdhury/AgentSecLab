# Phase 15E — Splunk LIVE validation (Identity / Delegation)

Official LIVE pair after Attack Service `POST /api/launch` (`LAB-AGENT-DELEGATION-001` / A2A-001). Schema **1.9.0**. Completeness is local event count vs Splunk `dc(_raw)`. HEC HTTP 200 is not this table. Launch JSON returned `WAITING_FOR_EVIDENCE` (honest default). Searchable copy MEASURED via Splunk CLI after index.

Do not infer completeness from HEC alone. Timeout ≠ attack failure. Missing Splunk event ≠ prevention.

Hunt reuse: `Q-AGENT-DELEGATION-AUTHORITY`, `Q-MCP-AUTHZ`, `Q-MCP-TOOL`, `Q-MCP-EXECUTED`. DET-MCP-001 unchanged. No DET-A2A.

## Official LIVE pair

Launch: concurrent Attack Service `POST /api/launch` ATTACK and RETEST (two threads, not serialized to hide architecture). Closed fixture `identity.claim.malicious`. Request fingerprint `sha256:56179e463b2faf18c056389ebff32a61e346dd0b4010fb82e8826c4508790dfd`.

AcmeBank health after the pair: `security.profile=defended`. `coded_policy()` unchanged (`lookup_policy` / `policy:read` only).

| Mode | run.id | Class | Result |
|------|--------|-------|--------|
| ATTACK | `110dd7a6-58b5-472a-ae80-aec76e11bf4e` | OBSERVED + LIVE SPLUNK | experiment `LAB-AGENT-DELEGATION-001:ATTACK`, profile=vulnerable, CTRL-IDENTITY-001 **OBSERVE** `identity_claim_is_not_grant` / `untrusted_claim`, overlay `vulnerable_profile_fail_open:caller_identity_derived_authority`, CTRL-MCP-001 **ALLOW**, lookup_customer_tier handler **1**, lookup_policy handler **0**, local **10** = Splunk `dc(_raw)` **10**, schema **1.9.0**, `who_authenticated=NOT PROVEN / NOT MODELED` |
| RETEST | `7e4f74a8-84bf-4d18-abe1-0dcc7f0ab58a` | OBSERVED + LIVE SPLUNK | experiment `LAB-AGENT-DELEGATION-001:RETEST`, profile=defended, IDENTITY **OBSERVE** `identity_claim_is_not_grant` / `untrusted_claim`, CTRL-MCP-001 **DENY** `tool_not_granted`, lookup_customer_tier handler **0**, lookup_policy handler **0**, no `mcp.started`, local **9** = Splunk `dc(_raw)` **9**, schema **1.9.0**, `who_authenticated=NOT PROVEN / NOT MODELED` |
| Fingerprint | both | MEASURED | same request fingerprint `sha256:56179e463b2faf18c056389ebff32a61e346dd0b4010fb82e8826c4508790dfd` |
| Actors | both | MEASURED | principal `applicant-web`, caller `acme-agent-advisor-005`, callee `acme-agent-fulfillment-006` |
| Q-AGENT-DELEGATION-AUTHORITY | both | LIVE SPLUNK | 1 row each; same principal/caller/callee/claimed_scope/hash; ATTACK MCP ALLOW overlay + `mcp.completed_observed`; RETEST MCP DENY + `no_indexed_followon_execution_event` |
| Q-MCP-AUTHZ | both | LIVE SPLUNK | 2 rows: hop CTRL-IDENTITY-001 OBSERVE + hop CTRL-MCP-001 (ATTACK ALLOW overlay / RETEST DENY `tool_not_granted`) |
| Q-MCP-TOOL | ATTACK | LIVE SPLUNK | 1 `mcp.started` `lookup_customer_tier` |
| Q-MCP-TOOL | RETEST | LIVE SPLUNK | **0 rows**. Corroboration of non-start. Runtime handler count 0 is authoritative. |
| Q-MCP-EXECUTED | ATTACK | LIVE SPLUNK | IDENTITY OBSERVE + MCP ALLOW rows; `has_started=1` `has_completed=1` `execution_state=mcp.completed`. Control-row `executed=false` is existing Q-MCP field semantics, not the handler count. |
| Q-MCP-EXECUTED | RETEST | LIVE SPLUNK | IDENTITY OBSERVE + MCP DENY; `has_started=0` `execution_state=no_mcp_execution_event` |
| DET-MCP-001 | both | LIVE SPLUNK | **0 rows**. ATTACK ALLOWs then starts (no DENY). RETEST DENYs then does not start. `0 rows != SAFE` |

Runtime handler counts (launch JSON, OBSERVED) are authoritative for privileged execution / non-execution. Splunk `mcp.completed` on ATTACK is corroboration that `lookup_customer_tier` ran. Splunk empty `mcp.started` on RETEST is corroboration only.

Q-MCP-EXECUTED `executed=false` on the control row is the existing control-field semantics, not a handler count. Do not rewrite Q-MCP hunts for this phase.

## Evidence readiness honesty

Launch JSON returns `WAITING_FOR_EVIDENCE` / `splunk_verified=false` immediately. HEC acceptance ≠ searchable evidence.

Completeness in this document is Splunk CLI `dc(_raw)` vs local `events.jsonl`. Re-measured after Splunk restart: ATTACK 10=10, RETEST 9=9.

## Teaching statement MEASURED

SAME PRINCIPAL. SAME CALLER. SAME CALLEE. SAME DELEGATION CLAIM. SAME PRIVILEGED REQUEST. DIFFERENT AUTHORIZATION. DIFFERENT EXECUTION.

CTRL-IDENTITY-001 OBSERVEd on both. CTRL-MCP-001 changed. WHO AUTHENTICATED remains NOT PROVEN / NOT MODELED.

Do not claim CTRL-IDENTITY-001 granted the ATTACK tool. Do not claim caller_agent_id authenticated anyone. Do not claim Splunk denied RETEST.

Playwright later minted UX pairs ATTACK `00cd3a63-1dee-4f87-8e77-921ab9610679` / RETEST `abf4ffcb-5856-44cb-a281-af1dabc55d70` and ATTACK `d8ff6007-2bdb-475e-8734-a2c73a16989e` / RETEST `b03aef31-9797-4acc-b8bf-a342bfac9f25`. Those ids prove the launcher UI. They are **not** this official Splunk pair.

Offline pytest MEASURED: **848 passed, 2 deselected** (`not live_ollama and not live_splunk`).

Classify: MEASURED (runtime + Splunk counts), OBSERVED (launch JSON / UI / health=defended after concurrent pair), DOCUMENTED (12C REPLAY ids), INFERRED (none claimed as live), NOT PROVEN (cryptographic identity, OAuth/OIDC/SPIFFE, universal prevention).
