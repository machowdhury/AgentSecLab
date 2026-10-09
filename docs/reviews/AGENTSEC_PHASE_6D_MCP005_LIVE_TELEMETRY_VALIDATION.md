# AGENTSEC PHASE 6D — MCP-005 live telemetry validation

**Verdict:** PHASE 6D PARTIAL — EVIDENCE OR VALIDATION INCOMPLETE

**Date:** 2026-10-09  
**Repository:** `machowdhury/AgentSecLab`  
**Branch:** `develop`  
**Workspace (actual clone):** `/Users/mahamudc/Documents/workspace/AgentSecLab`

This phase resolves conversation Phase 6C (invented SPL rejection). It is **not** a rewrite of the September 2026 repository Phase 6C/6D MCP-005 workshop delivery. Historical hunts remain on disk; this session did **not** re-execute them against live Splunk.

---

## SHAs

| Item | SHA |
|------|-----|
| Starting SHA (6D begin, matched `origin/develop`) | `d0fb5a0cec3c3f1cafe3a677e0d237a3342aa641` |
| Concurrent P1.4 commit preserved as parent (not modified by 6D) | `f4f480793e8ef89f4c5bd398d2f85469284bbf37` |
| Implementation SHA | `591eb282c86c70dea06d3e3cca0c3932116b40b2` |
| Report SHA | `3359b511590d9d3dbe0695a64a398dcde52e0181` |
| Final remote SHA | `3359b511590d9d3dbe0695a64a398dcde52e0181` |

Starting-condition check: `develop` tracked `origin/develop` at `d0fb5a0` with divergence `0/0`. During the session a concurrent authorized P1.4 commit landed locally, then 6D implementation was stacked on top and pushed. P1.4 files were not edited by this phase after that commit.

---

## Phase 6C rejection — immutable baseline

Rejected candidate (must never enter learner-facing SPL, saved searches, dashboards, or workshop content):

```spl
index=agentsec agent.super_secret_field=admin
| stats count by agent.super_secret_field
```

Rejection reasons (unchanged):

- `agent.super_secret_field` was not validated.
- `index=agentsec` was not validated.
- No live search was executed.
- No performance result was measured.
- No detection outcome was established.

**This session did not repeat that query and did not invent replacement fields.**

Auditable preservation:

- `docs/reviews/phase6d-mcp005-live-evidence/BASELINE_MANIFEST.json`
- `learning/level_1/LAB-MCP-005/searches/catalog.json` `prohibited_fields` now includes `agent.super_secret_field`
- `tests/splunk/test_phase6d_rejected_query_not_published.py`

---

## Gate A — live field discovery

### Connectivity (MEASURED / OBSERVED)

| Check | Result | Class |
|-------|--------|--------|
| AgentSec compose services | none running | OBSERVED |
| `agentsec_splunk` | Exited (137) since 2026-10-03T00:26:03Z | OBSERVED |
| `docker start agentsec_splunk` | **FAILED:** `Bind for 127.0.0.1:8000 failed: port is already allocated` | MEASURED |
| Port holder | `splunk-netspout-standalone` on `127.0.0.1:8000` and `8088-8089` | OBSERVED |
| NetSpout | left running; not stopped | OBSERVED |
| Official Splunk image entrypoint without password env | fails: `Splunk password must be supplied!` | OBSERVED |
| Splunk binary start on shared volumes, no host ports | reached index validation including `agentsec_telemetry`; did **not** remain up for search | OBSERVED |
| Live `splunk search` CLI | **not executed** | NOT MEASURED |

Host ports for AgentSec Splunk were not remapped in committed compose. NetSpout was not taken down. Credentials were not copied out of Docker env into files or argv.

### Actual index on disk (OBSERVED)

Not assumed from the rejected query. Not assumed solely from docs.

| Item | Value |
|------|--------|
| Index directory | `/opt/splunk/var/lib/splunk/agentsec_telemetry` |
| Size | 6.1M |
| `.dirty_database` | present (unclean prior shutdown) |
| Warm buckets | `db_1789182388_1789182309_0` … `db_1790979353_1790902152_57` |
| Hot bucket | `hot_v1_58` |
| Bucket-name UTC range | 2026-09-12T14:31:52Z through 2026-10-02T22:15:53Z (closed); hot bucket present |
| Configured index stanza | `splunk_app/agentsec/default/indexes.conf` → `[agentsec_telemetry]` |
| Configured macro | `index=agentsec_telemetry sourcetype=otel:agentic:json` |

**There is no on-disk index named `agentsec`.** Using `index=agentsec` remains invalid.

### Sourcetype (DOCUMENTED, not live-proven this session)

`props.conf` `[otel:agentic:json]` sets `INDEXED_EXTRACTIONS = json` **and** `KV_MODE = json`. Historical Phase 6C classified the resulting `mvcount>1` as extraction duplication, not duplicate events. This session did **not** re-measure `mvcount` or `dc(_raw)`.

### MCP-005 run identifiers (local artifacts OBSERVED)

| Spec | `agentsec.run.id` | Local `events.jsonl` | Schema |
|------|-------------------|---------------------:|--------|
| A BASELINE | `3013aa39-fe08-4b58-9898-f3abb092ac06` | 8 | 1.3.0 |
| B ATTACK | `f3f48182-df57-4b38-b069-17a199dc4939` | 13 | 1.3.0 |
| C RETEST | `0ab10594-a7fc-48b6-81bf-4cbca54a64c6` | 12 | 1.3.0 |
| F handler fail | `6fe7370c-a288-4634-91a5-d6c78b52bd01` | 8 | 1.3.0 |

These packs exist under `artifacts/<run-id>/`. Runtime `export.json` for B still records `splunk.verified=false` (honest: OTLP flush is not Splunk proof). Historical 2026-09-13 Splunk CLI completeness is **DOCUMENTED**, not re-measured today.

Current emitter schema is **1.9.0**. Historical MCP-005 specimens are **1.3.0**. Do not silently treat 1.9.0 live events as the 1.3.0 inventory.

### Field inventory — local JSON keys vs indexed fields

Local B ATTACK `events.jsonl` contains 55 JSON keys (full list in evidence). Candidate fields requested by this phase:

| Field | In local JSONL | Live indexed this session |
|-------|----------------|---------------------------|
| `agentsec.run.id` | yes | NOT MEASURED |
| `gen_ai.agent.id` | yes (hop-scoped) | NOT MEASURED |
| `agentsec.control.decision` | yes | NOT MEASURED |
| `agent.super_secret_field` | **no** | not searched; rejected |

Authority / identity / tool / policy / result keys present in **local JSON** (not claimed as currently indexed):

`agentsec.control.id`, `agentsec.control.type`, `agentsec.control.reason`, `agentsec.mcp.requested_scope`, `agentsec.mcp.allowed_scope`, `agentsec.mcp.resource.id`, `agentsec.mcp.allowed_resource.ids`, `agentsec.mcp.result.trust`, `agentsec.mcp.result.provenance`, `gen_ai.tool.name`, `mcp.method.name`, `agentsec.hop.index`, `agentsec.principal.id`, `agentsec.trust_boundary`, `event.name`, `trace_id`, `span_id`

Still **absent** from local JSONL (matches historical field validation): `agentsec.mcp.allowed_tools`, `gen_ai.tool.call.id`, `agent.super_secret_field`.

**Do not claim a JSON key is an indexed Splunk field merely because it appears in `_raw` or `events.jsonl`.** Live `fieldsummary` / `| field` was not executed.

### Sample events

Sanitized samples are in `LOCAL_EVENTS_JSONL_FIELD_INVENTORY.json`. They are local runtime evidence, class **OBSERVED**, **not** Splunk `_raw`.

### Exact search commands executed

No Splunk search string was executed against a live REST/CLI session.

Disk inspection (read-only volume mount) used `busybox` `ls`/`du` of `/opt/splunk/var/lib/splunk`. That is filesystem evidence, not SPL.

---

## Gate B — security question

**Question (supported by LAB-MCP-005 spec, used only if telemetry exists):** Did result-derived data influence authorization state, and what follow-on decision and execution were indexed?

| Item | Definition |
|------|------------|
| Threat behavior | After an authorized `lookup_policy` call, returned bytes are treated as authority so a follow-on `lookup_customer_tier` is allowed |
| Trust boundaries | `mcp.tool.result` (CTRL-MCP-RESULT-001) then `acmebank.mcp.authorize` (CTRL-MCP-001) |
| Required events | hop-0 CTRL-MCP-001; `mcp.completed` for first tool; CTRL-MCP-RESULT-001; optional hop-1 CTRL-MCP-001; optional hop-1 `mcp.started`/`mcp.completed` |
| Required fields | `event.name`, `agentsec.run.id`, `gen_ai.tool.name`, `agentsec.control.id`, `agentsec.control.decision`, `agentsec.control.reason`, `agentsec.hop.index`, scopes, profile/mode, bounded preview |
| Expected evidence | A: OBSERVE `result_is_data`, derived absent, no follow-on. B: RESULT-001 ALLOW `result_derived_grant`, follow-on ALLOW overlay, hop-1 execution observed. C: OBSERVE, follow-on DENY `tool_not_granted`, no hop-1 execution event |
| Cannot prove | Attacker intent from a DENY; that a handler never ran (runtime count is authoritative); server-owned tool allow-list as a first-class indexed field; that zero hunt rows mean the control worked |

Splunk is not the PDP. CTRL-MCP-001 remains authoritative for tool grant. CTRL-MCP-RESULT-001 is the result-trust decision. This phase does not change that.

---

## Gate C — SPL development

**No publishable SPL was developed or re-executed this session.**

Sequence status:

1. Index name from disk: `agentsec_telemetry` — confirmed on filesystem, not via search.
2. Target runs: local packs present; not confirmed in the live index via SPL.
3. Fields: local JSON keys inventoried; indexed extraction **not** re-validated.
4. Filters: not live-tested.
5. Correlation: not live-tested.
6. Aggregation: not added.
7. Raw evidence comparison: local JSONL only.
8. Final exact SPL: **none executed**.

Existing hunt `Q-MCP-RESULT-AUTHORITY` (index=`agentsec_telemetry`, schema-agnostic, uses observed 1.3.0 field names) remains the historical 2026-09-13 candidate. This phase **does not** promote it as 2026-10-09 live-validated and **does not** substitute MCP-001-only fields.

Zero results were not interpreted as proof a control worked, because no search ran.

---

## Gate D — independent validation

| Check | Result |
|-------|--------|
| Referenced fields exist in live evidence | UNVERIFIED (no live search) |
| Index and sourcetype correct | Index directory OBSERVED; sourcetype DOCUMENTED; live query UNVERIFIED |
| Query executes successfully | **No** |
| Results reconcile with events | **No live results** |
| Counts reproducible | **No** |
| Interpretation within evidence | Yes: this report does not claim live detection outcomes |
| Secrets exposed by search | No search output produced |
| Query modifies Splunk data | No search run; see certificate side-effect below |

Independent reviewer execution of SPL: **unavailable**. Marked **UNVERIFIED**.

Pytest (local, not live Splunk): **1602 passed, 15 skipped** on `591eb28`. Distinct from the historical 1,513 passed / 3 skipped count. These tests are unit/integration/contract/mocked. They are **not** live Splunk CLI.

---

## Gate E — publication decision

**DO NOT PUBLISH new MCP-005 SPL from this phase.**

| Target | Decision |
|--------|----------|
| Rejected invented query | **not published** |
| New detector `DET-MCP-005` | **not created** |
| `ws_lab_mcp_001` Dashboard Studio | **not modified** |
| Existing `Q-MCP-RESULT-AUTHORITY` | left in place as **historical 2026-09-13 VALIDATED**; **not** re-certified today |
| Learner denylist | **published** (`catalog.json` + tests) |

A search that cannot be executed cannot answer the security question. Historical validation is not current live validation.

---

## Security Review Required — certificates

Splunk start on the shared `/opt/splunk/etc` volume emitted: `New certs have been generated in '/opt/splunk/etc/auth'`.

OBSERVED new files (mtime ~ 2026-10-09 13:38 UTC):

- `dp_ca.pem`
- `dp_ca.srl`
- `server_dp.pem`

`server.pem` mtime remained ~ 2026-09-12 01:37. `splunk.secret` was **not read**.

OpenSSL inspection of the new files: **NOT COMPLETED** (overridden entrypoint had no `openssl` on PATH; copying key-bearing PEM to the host was refused).

Unverified certificates may contain critical vulnerabilities. Required verification before treating this instance as unchanged:

```
openssl x509 -text -noout -in <certificate_file>
```

- Expiration: Certificate must not be expired or not yet valid
- Key Strength: RSA keys must be at least 2048-bit; EC keys must use P-256 or higher curve
- Signature Algorithm: Must use SHA-2 family (not MD5 or SHA-1)
- Self-Signed: If self-signed, must only be used for development, testing, or internal services

These look like lab Splunk instance certs. They should never be used for public-facing production. Unintended regeneration during a no-port replica start is a TLS artifact on the existing volume. Owner should verify and replace if this was not an intended rotation. This phase did not rotate `SPLUNK_PASSWORD` or HEC tokens.

---

## Test results

| Suite | Result | Class |
|-------|--------|--------|
| MCP-005 unit/telemetry/workshop/splunk contracts + new integrity tests | pass (included in full suite) | MEASURED, local |
| `tests/security` including `test_mcp_result_trust.py` | pass (included in full suite) | MEASURED, local |
| Full `pytest -q` | **1602 passed, 15 skipped** | MEASURED, local, not live Splunk |
| Live Splunk search tests | not run | NOT MEASURED |

---

## Evidence bundle

Location: `docs/reviews/phase6d-mcp005-live-evidence/`

| File | SHA-256 |
|------|---------|
| `BASELINE_MANIFEST.json` | `ae39d2061ed859582774cf3ab10e27a09cb8fe43231c37ae2cf398a4b7de8d76` |
| `GATE_A_DISK_AND_CONNECTIVITY.json` | `6ddc297537af5eb3d9de200e8f67b7bf4c52ef0dd7c1f49861e9f51c4d5c1b34` |
| `LOCAL_EVENTS_JSONL_FIELD_INVENTORY.json` | `3c88a4b03ba22d755f2b0fd700607ff4fb28c68a0a8544b9b354bb3a009b1288` |
| `SHA256SUMS.json` | `1cf3084a8915865097eb6331e2bdfa7b2207212f1da99b6af0188d3cee618c9a` |

---

## Unresolved dependencies

1. AgentSec Splunk cannot bind `127.0.0.1:8000` while NetSpout Splunk is running.
2. Official `splunk/splunk:10.2` entrypoint requires `SPLUNK_PASSWORD` in env even when `/opt/splunk/etc` already has accounts; copying that env was not performed.
3. Live fieldsummary / MCP-005 SPL against `index=agentsec_telemetry` was not executed.
4. Indexed vs search-time vs raw JSON distinction for current buckets is therefore incomplete.
5. New Splunk DP certificates on the shared volume need owner `openssl` verification.
6. Schema 1.9.0 runtime vs 1.3.0 historical MCP-005 specimens — a future live run must inventory **current** events, not assume 1.3.0.
7. No first-class `agentsec.mcp.allowed_tools` field; still blocks a general detector (historical NO NEW DETECTOR decision stands).
8. Exited temporary containers `agentsec_splunk_phase6d*` remain; volumes were not deleted. Owner may remove those **containers** only; do not delete Splunk volumes.

---

## Impact on MCP-005 workshop readiness

The LAB-MCP-005 workshop and `Q-MCP-RESULT-AUTHORITY` remain **historically** validated (2026-09-13). This phase does **not** authorize telling learners that live Splunk revalidation succeeded on 2026-10-09.

Do not add unverified MCP-005 detections to the learner-facing interface. Do not use `index=agentsec` or `agent.super_secret_field`. CTRL-MCP-001 / CTRL-MCP-RESULT-001 remain the authorization engines; Splunk remains investigation.

P1.4 Academy work was not blocked and was not rewritten by 6D.

---

## Rules application notes

- **No hardcoded credentials:** `.env` was not committed; Docker env was not dumped to the repo; report contains no passwords, HEC tokens, or private keys. Lab placeholders in `.env.example` were not changed.
- **Certificates:** new `dp_ca.pem` / `server_dp.pem` flagged above; `openssl` verification incomplete.
- **Crypto algorithms:** no algorithm or protocol changes.

---

## Final verdict

**PHASE 6D PARTIAL — EVIDENCE OR VALIDATION INCOMPLETE**
