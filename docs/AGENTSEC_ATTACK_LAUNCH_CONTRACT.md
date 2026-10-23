# AgentSec attack launch contract

**Status:** Phase 14A DESIGN ONLY. **Not implemented** beyond today’s ATK-002 POST.  
**Schema:** 1.9.0 unchanged. No new event fields required for 14A.  
**Do not start Phase 14B from this file.**

Smallest honest contract. Do not invent authentication guarantees.

---

## Request (conceptual)

Closed JSON. Unknown keys → reject.

```json
{
  "lab_id": "LAB-PI-001",
  "specimen_id": "ATK-002",
  "mode": "ATTACK",
  "execution": "live"
}
```

| Field | Allowed values (v1) | Notes |
|-------|---------------------|-------|
| `lab_id` | Allowlisted published labs | No free text |
| `specimen_id` | Allowlisted per lab | Resolves payload/fixture server-side |
| `mode` | `BASELINE` \| `ATTACK` \| `RETEST` | Must match `testbed.mode` semantics |
| `execution` | `live` | Replay is not a launch |

**Not in the request:** payload, tool name, SPL, grants, target URL, credentials, and `profile`. The security profile is derived server-side from the specimen (`ATTACK` runs `vulnerable`; `BASELINE` and `RETEST` run `defended`); the request parser has always rejected a `profile` field as `unknown_fields` (`tests/unit/` pins this). The earlier text of this contract listed it by mistake.

Today’s ATK-002 endpoint sends only `input` + `user_id` to AcmeBank. A future allowlisted API must not grow into an open proxy.

---

## Response (conceptual)

```json
{
  "run_id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
  "lab_id": "LAB-PI-001",
  "specimen_id": "ATK-002",
  "profile": "vulnerable",
  "mode": "ATTACK",
  "execution_mode": "LIVE",
  "telemetry_fidelity": "OBSERVED",
  "runtime_status": "COMPLETED",
  "evidence_state": "WAITING_FOR_EVIDENCE",
  "local_event_count": 22,
  "splunk_verified": false,
  "intentionally_vulnerable": true
}
```

| Field | Rule |
|-------|------|
| `run_id` | Server-minted. Never learner-supplied as authority. |
| `execution_mode` | `LIVE` for this service. Never label REPLAY as LIVE. |
| `telemetry_fidelity` | `OBSERVED` for real runtime. `SYNTHETIC` only if a lab already emits it. |
| `evidence_state` | See lifecycle. Never `EVIDENCE_READY` solely because HEC returned 200. |
| `splunk_verified` | Default `false`. True only after a later Search/count against the index. |
| `intentionally_vulnerable` | `true` iff profile is vulnerable |

HTTP 4xx on allowlist miss or extra fields. HTTP 5xx on runtime/dependency failure. Do not report DENY as HTTP failure when the lab’s defended control correctly DENY’d (PI ATK-002 defended is HTTP 200 + DENY today).

---

## run.id lifecycle (design states)

These are **product states**, not schema enums.

| State | Meaning | Who knows |
|-------|---------|-----------|
| REQUESTED | Allowlist accepted; runtime call not finished | Attack Service |
| RUNNING | Runtime in progress | Attack Service |
| TELEMETRY_SENT | Runtime finished; OTEL export attempted | Runtime / export.json |
| WAITING_FOR_EVIDENCE | Events may not be searchable yet | Honest default after LIVE launch |
| EVIDENCE_READY | A Splunk count for that `run.id` matched the local completeness contract | Splunk investigation, not HEC health |
| ERROR | Launch or runtime failed | Attack Service |

`otlp.ok` / HEC 200 ≠ `EVIDENCE_READY`. Existing packs keep `splunk.verified=false` until a search runs. Keep that honesty.

Indexing delay is expected. The learner UI (Attack Service page, later) should say: copy `run.id`, wait, search `index=agentsec_telemetry "agentsec.run.id"=…`. Do not auto-declare success from transport.

---

## Binding the workshop

After launch, Studio tokens are **not** automatically updated. Native options:

1. Learner opens Search with a linked query containing the `run.id` (Attack Service page or markdown URL).
2. Learner continues on canonical REPLAY dropdown (Investigate specimen) — that is a **different** copy.
3. Custom JS that writes Studio tokens from the launch JSON — **NOT SUPPORTED / DO NOT BUILD** unless a later phase proves native links insufficient.

Do not mix a fresh LIVE `run.id` into a table that is still bound to a canonical REPLAY id without labeling both.

---

## Profile and RETEST honesty

OBSERVED: `testbed.mode` for RETEST is often `settings.testbed_mode_override` (process env), not a per-request field. MCP `POST /mcp/invoke` rejects unknown fields.

Therefore:

- Advertising one-click LIVE RETEST from Attack Service is **false** until runtime accepts `mode` without becoming an open policy API.
- 14A does not change runtime authorization.
- 14B may either (a) add a **closed** mode field that maps only to allowlisted specimens, or (b) keep RETEST as an operator procedure. Choose in 14B; do not pretend it works now.

---

## Example allowlist rows (catalog, not implemented)

| lab_id | specimen_id | Typical profile | Typical mode |
|--------|-------------|-----------------|--------------|
| LAB-PI-001 | ATK-001 | defended | BASELINE |
| LAB-PI-001 | ATK-002 | vulnerable | ATTACK |
| LAB-PI-001 | ATK-002 | defended | RETEST (if mode actually applied) |
| LAB-MCP-001 | lookup_policy-granted | defended | BASELINE |
| LAB-MCP-001 | lookup_customer_tier-ungranted | vulnerable | ATTACK |

Do not add rows for unpublished Identity Studio.

---

## Future production (not claimed)

Authentication, per-learner tenancy, rate limiting, network isolation beyond `127.0.0.1`, and multi-user audit. Local classroom remains bind-localhost, unauthenticated, as today.

## Request security policy (Increment 6B)

Applies to every state-changing request (POST/PUT/PATCH/DELETE) on the Attack Service and AcmeBank.

- **Cross-origin browsers are rejected (403 `cross_origin_rejected`).** A request is refused when `Sec-Fetch-Site` is anything but `same-origin`/`none`, or when `Origin` is present and its host:port differs from `Host` (`Origin: null` is refused). This is CSRF defence, **not authentication**.
- **Non-browser clients are allowed.** curl, scripts, tests and service-to-service calls send neither header, so they pass. This is the documented policy, not an oversight: network reachability (security group / bind address) remains the access control. A caller can forge these headers; they only constrain real browsers.
- `POST /api/launch` and `POST /api/compare-handoff` additionally require `Content-Type: application/json` (415), a body of at most 16 KiB (413), and no query parameters (400 `unexpected_parameters`). The closed field allowlist, duplicate-key rejection and server-owned profile are unchanged.
- **Concurrency:** at most `AGENTSEC_MAX_CONCURRENT_LAUNCHES` (default 2) launches run at once. The check is non-blocking and happens after validation, before any runtime call; excess requests get 429 `launch_busy` with `Retry-After: 5`. The permit is released on success, error, exception and timeout (the existing 180 s AcmeBank timeout still bounds a launch).
- **Links:** stored launch records carry the configured Splunk Web base (`AGENTSEC_SPLUNK_WEB_URL`). The browser-facing base is derived per response from a validated Host header (invalid hosts fall back to `127.0.0.1`) and never stored.
