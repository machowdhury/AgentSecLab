# AgentSec Attack Service runtime contract (Phase 14D)

**Status:** IMPLEMENTED for LAB-PI-001 BASELINE + ATTACK + RETEST.  
**Schema:** 1.9.0 unchanged. Launch records are **in-memory**, not security-event schema rows.  
**Do not start Phase 15 from this file.** Closed MCP launches remain catalog-only.

---

## Endpoints

| Method | Path | Role |
|--------|------|------|
| GET | `/` | Learner launch page (predict + LIVE BASELINE/ATTACK/RETEST) |
| GET | `/health` | Service identity + localhost limitation labels |
| GET | `/api/allowlist` | Public allowlist rows (no payloads, no profile picker) |
| GET | `/api/labs/LAB-PI-001` | Learner manifest (not policy) |
| GET | `/api/target-health` | Same-origin AcmeBank `/health` probe |
| POST | `/api/launch` | Typed closed launch |
| POST | `/api/compare-handoff` | Server-built dual-`run.id` Search URL (UUIDs only, not learner SPL) |
| GET | `/api/launches/<run_id>` | Last in-memory launch body |
| GET | `/api/launches/<run_id>/evidence` | Bounded Splunk probe (`timeout_seconds`, default 0 = one shot) |
| POST | `/api/attacks/ATK-002` | Legacy fire; kept (no `experiment_id`; uses process-global profile) |

---

## Launch request

Closed JSON. Duplicate keys ERROR. Unknown keys ERROR. `profile` is authority-like and rejected.

```json
{
  "lab_id": "LAB-PI-001",
  "specimen_id": "ATK-002",
  "mode": "ATTACK",
  "execution": "live"
}
```

The browser selects a predefined specimen. It does not send profile, grants, tools, scope, policy, SPL, Python, shell, or environment variables.

`execution` must be `live`. Replay is not a launch.

---

## Launch response (success)

HTTP 200 even when CTRL-INPUT-001 DENY’d (existing PI contract).

Includes `run_id`, `experiment_id`, server-owned `profile`, `execution_mode=LIVE`, `evidence_state=WAITING_FOR_EVIDENCE`, `splunk_verified=false`, `input_fingerprint`, `search_handoff`, `prediction`, nested `runtime` hops.

Control DENY/ALLOW lives in `runtime.hops`, never in `error_class`. HTTP 200 is not EVIDENCE READY.

---

## Runtime mapping (PI only)

| Tuple | Server-owned ExperimentContext | AcmeBank call |
|-------|--------------------------------|---------------|
| LAB-PI-001 / ATK-001 / BASELINE / live | `LAB-PI-001:BASELINE` defended | `POST /process` benign loan + `experiment_id` |
| LAB-PI-001 / ATK-002 / ATTACK / live | `LAB-PI-001:ATTACK` vulnerable | same ATK-002 payload + `experiment_id` |
| LAB-PI-001 / ATK-002 / RETEST / live | `LAB-PI-001:RETEST` defended | same ATK-002 payload + `experiment_id` |

No MCP, RAG, memory, or goal routes are registered on Attack Service.

Direct AcmeBank `/process` without `experiment_id` keeps the UI auto-mode path (`resolve_testbed_mode` + process-global profile).

Unknown or mismatched `experiment_id` is ERROR. There is no silent vulnerable fallback.

---

## Concurrency

ATTACK and RETEST may run concurrently. Each request uses an immutable `ExperimentContext`. Process environment is not mutated. `MemorySink` is locked. Launch records are locked only around the in-memory map.

Coded CTRL-INPUT-001 regex rules do not change between experiments. Only the per-request profile copy changes.

---

## Phase 14E — LAB-MCP-001

**Status:** IMPLEMENTED. Schema 1.9.0 unchanged.

GET `/labs/LAB-MCP-001` is the Tool Authorization launcher. GET `/api/labs/<lab_id>` serves any published manifest. Allowlist now includes LAB-MCP-001 BASELINE/ATTACK/RETEST.

Launch still accepts only `{lab_id, specimen_id, mode, execution}`. For MCP the server posts `{tool, requested_scope, arguments, user_id, experiment_id}` to `POST /mcp/invoke`. The browser never sends tool, scope, resource, grant, or profile.

ATTACK and RETEST share the measured request fingerprint of `lookup_customer_tier` / `customer:read` / `{customer_id: cust-001}`. CTRL-MCP-001 remains the tool PDP.

---

## Bind / Docker honesty

Compose publishes `127.0.0.1:5001:5001`. Inside the container `AGENTSEC_BIND_HOST=0.0.0.0` is required for the mesh (existing). Host-run default remains `127.0.0.1`.

Artifacts are mounted so Attack Service can count `events.jsonl`. Splunk probe uses `docker exec` into `agentsec_splunk` with password **inside the Splunk container env**, not in Attack Service JSON.
