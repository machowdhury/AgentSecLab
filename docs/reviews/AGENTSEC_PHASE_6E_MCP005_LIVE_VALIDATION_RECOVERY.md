# AGENTSEC PHASE 6E — MCP-005 live Splunk validation recovery

**Executive decision: PARTIAL**

Live authenticated search against the original AgentSec Splunk volume succeeded. Indexed MCP-005 telemetry is schema **1.3.0**. `Q-MCP-RESULT-AUTHORITY` executed live and matched the historical A/B/C/F contract. Current-runtime schema **1.9.0** MCP-005 events were generated locally but were **not** observed in Splunk. Gate D is therefore complete for historical indexed telemetry and **BLOCKED** for current-schema indexed telemetry.

NetSpout was not stopped, reconfigured, or recreated by this phase. An external Docker destroy of `splunk-netspout-standalone` occurred at 2026-10-09T14:22:36Z during inventory; this phase did not issue that destroy and did not bring NetSpout back.

---

## 1. Executive decision

**AGENTSEC PHASE 6E — PARTIAL**

Research integrity takes precedence over PASS. Missing current-schema indexed MCP-005 observation prevents PASS.

## 2. Starting HEAD

`547cc90ed504ffb473d74e55832c376312b13c3a`

Verified: `develop` = `origin/develop`, divergence `0/0`. Ancestry includes 6D implementation `591eb28`, report `3359b51`, P1.4 `f4f4807`.

## 3. Git baseline

| Item | Value |
|------|--------|
| Repo | `machowdhury/AgentSecLab` |
| Branch | `develop` |
| Fetch | `origin/develop` at start = `547cc90` |
| Working tree at start | clean except `?? .tmp-path-pre/` (preserved) |
| Concurrent work | P1.4 already on develop; not modified |

## 4. Docker resource inventory

Recorded at session start (read-only):

- Original instance `agentsec_splunk` (`f2e67082af2f`), image `splunk/splunk:10.2` (10.2.7 `c0bff5b0fac3`), **healthy**, restart `unless-stopped`.
- Volumes (preserved, RW): anonymous `8f86409c1fdf…` → `/opt/splunk/etc`; `0aa27f8fe380…` → `/opt/splunk/var`; `agentseclab_splunk_app_agentsec`; `agentseclab_shared_telemetry`.
- HostConfig PortBindings still list `127.0.0.1:8000` and `:8088`, but `NetworkSettings.Networks={}` so **no host ports are published**. In-container 8000/8088/8089 are open.
- Phase 6D replica containers remain exited (`agentsec_splunk_phase6d*`); not used as a second live instance.
- Disk: ~505Gi free.

NetSpout-owned (protected, not modified by 6E): `netspout_*` volumes; historical `splunk-netspout-pre-figma-v3-20261005`; flow containers. At first `docker ps`, `splunk-netspout-standalone` was healthy on 8000/8088-8089. Docker events then show kill/stop/destroy of that stack at 14:22:36Z **not issued by this phase**.

## 5. NetSpout non-interference evidence

| Action | This phase |
|--------|------------|
| stop/restart/reconfigure/recreate NetSpout | **not performed** |
| modify NetSpout volumes/networks/ports | **not performed** |
| `docker compose down -v` | **not performed** |
| External destroy observed | YES (`container destroy splunk-netspout-standalone`) |
| NetSpout restarted by 6E | **no** |

Classification: 6E did not interrupt NetSpout. Current NetSpout process availability after the external destroy is **not running**. Status for “we did not interrupt”: **PASS**. Operational NetSpout now: **FAIL / absent (external)**.

## 6. Splunk recovery method

Preferred recovery: **use the original running `agentsec_splunk` in place**.

No container replacement. No second instance mounting `etc` read-write. No compose project rename. Search via the committed helper `scripts/splunk_cli_csv.py` (`docker exec -u splunk` CLI; password stays in container env).

This avoided repeating the Phase 6D replica-on-shared-etc pattern.

## 7. Port configuration

| Endpoint | Binding |
|----------|---------|
| Splunk Web | in-container `127.0.0.1:8000` only |
| Management | in-container `8089` |
| HEC | in-container `8088` (HTTP; `SPLUNK_HEC_SSL=0`) |
| Host 8000/8088/8089 after NetSpout destroy | free |
| Candidate 18000 | in use (`session-manager`); **not used** |
| 18088/18089 | free; **not bound** (in-container search sufficient) |

Port isolation: **PASS** (AgentSec did not publish 8000 onto the host).

## 8. Volume preservation

Same four mounts as Phase 6D on the original container ID. No volume delete/prune. Indexed `agentsec_telemetry` still present (1964 events). **PASS**.

Rollback: leave `agentsec_splunk` running with existing volumes; do not `docker rm -v`. Phase 6D replica containers may be removed **without** `-v` by the owner.

## 9. Certificate inspection

OpenSSL `x509 -text -noout` on certificate-only extracts. Private keys were not committed.

| File | Result |
|------|--------|
| `server.pem` | **Unchanged** since 2026-09-12. CN=`SplunkServerDefaultCert`. Issuer SplunkCommonCA. RSA 2048, sha256WithRSAEncryption. Valid 2026-09-12 → 2029-09-11. Fingerprint `8BE6…E7E1`. |
| `ca.pem` / `cacert.pem` | Unchanged SplunkCommonCA. RSA 2048, SHA-256. Valid 2017-01-30 → **2027-01-28** (warning). |
| `server_dp.pem` / `dp_ca.pem` | Lab self-signed CN=`localhost`. RSA 2048, SHA-256. Valid 2026-10-09T14:06:05Z → 2029-10-08. Regenerated at **official** instance start 14:06 (after 6D replica ~13:38). |

`CERTIFICATE_CHANGE_BASELINE_UNAVAILABLE` for pre-6D DP fingerprints. Not treated as malicious. Lab-only; do not use on public production. TLS was not weakened. Evidence: `16_certificate_forensics.json`.

## 10. Authenticated search connectivity

| Check | Result |
|-------|--------|
| splunkd | running (pid 1509, port 8089) |
| Web login HTTP | healthcheck succeeding |
| Auth | admin via container `SPLUNK_PASSWORD` (not logged, not committed) |
| Search jobs | `scripts/splunk_cli_csv.py` returned CSV |
| Index visibility | `agentsec_telemetry` 1964 events |

TLS for CLI is the Splunk local management channel inside the container. **PASS**.

## 11. Actual indexed schema

`otel:agentic:json` event counts by `agentsec.schema.version` (live `dc(_raw)`):

| Version | Events |
|---------|-------:|
| 1.1.0 | 122 |
| 1.2.0 | 64 |
| 1.3.0 | 41 |
| 1.4.0 | 26 |
| 1.5.0 | 33 |
| 1.6.0 | 24 |
| 1.7.0 | 70 |
| 1.8.0 | 29 |
| 1.9.0 | 1423 |

MCP-005 (`agentsec.attack.id=MCP-005`) is **only 1.3.0** (41 events, 4 runs). 1.9.0 indexed attacks are A2A-001, ATK-001, ATK-002, GOAL-001, MCP-002, MEMORY-001, RAG-001 — **not MCP-005**.

Time range `otel:agentic:json`: 2026-09-12T03:05:09Z → 2026-10-02T22:21:33Z.

`index=agentsec`: **0** events.

## 12. MCP-005 field inventory

Live `fieldsummary` on MCP-005: **84** fields. Evidence `07_mcp005_fields.json`, `15_field_classification.json`.

Hunt-required fields: all **OBSERVED_IN_SPLUNK**.

**NOT_AVAILABLE:** `agentsec.mcp.allowed_tools`, `gen_ai.tool.call.id`, `agent.super_secret_field` (explicit search count 0).

## 13. Historical versus current event comparison

| | Historical indexed | Current runtime |
|--|--------------------|-----------------|
| Schema | 1.3.0 | 1.9.0 |
| MCP-005 in Splunk | YES (A/B/C/F) | NOT_OBSERVED |
| Local generation this phase | n/a | A `d99b66fd-…` 8 ev; B `557f2404-…` 13 ev; C `8ff200bc-…` 12 ev |
| HEC/OTLP ingest of those runs | not completed | BLOCKED (copy/ingest into Splunk classified/unavailable) |

Do not infer 1.9.0 indexed fields from 1.3.0 events. Additive 1.9.0 runtime still emitted MCP-005 RESULT-001 locally.

## 14. New synthetic run

Runtime A/B/C generated with current `SCHEMA_VERSION=1.9.0` via specimen functions (not the OTEL-refuse `main()`). Unique run IDs recorded in `synthetic_19_runs.json`. **Splunk observation of those IDs: not executed / not confirmed.** Treat as local OBSERVED runtime only.

## 15. Exact candidate SPL

Existing hunt `learning/level_1/LAB-MCP-005/searches/Q-MCP-RESULT-AUTHORITY.spl` (not modified). Index `agentsec_telemetry`, sourcetype `otel:agentic:json`, `earliest=0`, bound `__RUN_ID__`.

Rejected query was not executed.

## 16. Gate D evidence

Endpoint: in-container Splunk CLI via `scripts/splunk_cli_csv.py`. Index: `agentsec_telemetry`. Time: `earliest=0`.

| Case | Run ID | Rows | Result |
|------|--------|-----:|--------|
| A BASELINE | `3013aa39-…ac06` | 1 | `derived_authority=absent`, OBSERVE `result_is_data`, `no_followon` |
| B ATTACK | `f3f48182-…4939` | 1 | `present`, overlay ALLOW, follow-on `lookup_customer_tier` ALLOW, coded scope `policy:read`, `mcp.completed_observed` |
| C RETEST | `0ab10594-…a64c6` | 1 | `absent`, follow-on DENY `tool_not_granted`, `no_indexed_followon_execution_event` |
| F handler fail | `6fe7370c-…bd01` | 0 | no RESULT-001 |
| Negative MCP-001 A | `5b089682-…d6bc6` | 0 | no false positive |
| Completeness | A/B/C/F | 8/13/12/8 | matches local JSONL |
| DET-MCP-001 index-wide | — | 0 | unchanged detector silent |

JSON artifacts `10_hunt_*.json`, `12_hunt_negative_mcp001.json`, `13_completeness_mcp005.json`, `14_det_mcp_001_indexwide.json`.

**Gate D (historical 1.3.0 indexed MCP-005): PASS.**
**Gate D (current 1.9.0 indexed MCP-005): BLOCKED.**

Overall Gate D for Phase 6E acceptance (requires current-schema observation): **BLOCKED**.

## 17. Detection validity

Hypothesis: result-derived data influenced authorization; reconstruct RESULT-001 + hop-1 CTRL-MCP-001 + hop-1 execution observation.

Supported **for indexed 1.3.0 MCP-005** by live fields. Not a new detector. DET-MCP-001 remains silent (ALLOW-path ATTACK). No `allowed_tools` field. Zero hunt rows ≠ “control worked” (F is 0 because RESULT-001 never emitted).

`DETECTION_NOT_SUPPORTED_BY_AVAILABLE_TELEMETRY` for **current-schema indexed** MCP-005 (none indexed).

## 18. Negative and false-positive tests

- `index=agentsec` count 0.
- `agent.super_secret_field=*` count 0.
- Hunt on MCP-001 run: 0 rows.
- DET-MCP-001 index-wide: 0 rows.

## 19. Research-integrity regression

`tests/splunk/test_phase6d_rejected_query_not_published.py` and MCP-005 contract tests: **pass** (included in 70 focused / 1602 full). Denylist and `Q-MCP-RESULT-AUTHORITY` files unchanged except this phase did not edit them. Historical hunt validation date left at 2026-09-13.

## 20. Full test results

| Command | Result | Class |
|---------|--------|--------|
| MCP-005 + integrity + result-trust | 70 passed | MEASURED, local |
| `pytest -q` | **1602 passed, 15 skipped** | MEASURED, local, not live Splunk |

## 21. Security/privacy audit

- No credentials, HEC tokens, or private keys in the repo.
- Hunt preview shows lab fixture `cust-001` / `SECURITY_OVERRIDE` marker already in historical docs.
- Certificates inspected; not committed.
- TLS verification was not globally disabled.
- No production systems contacted.

## 22. Known limitations

- AgentSec Splunk has empty `Networks`; no host management URL.
- Current-schema MCP-005 not indexed.
- `mvcount` duplication not re-measured; hunts still collapse with `mvdedup`.
- In-container search is the evidence path, not Splunk Web on 18000.

## 23. Remaining blockers

1. Index a uniquely identified **1.9.0 MCP-005** run and re-run the hunt (OTLP/HEC path needs isolated ports or in-container ingest authorization).
2. Optional: remap original container to `127.0.0.1:18088/18089` **without** sharing volumes with a second instance, if host access is required.
3. Owner decision on DP cert regeneration and SplunkCommonCA expiry 2027-01-28.
4. NetSpout stack is absent after external destroy; restoring it is **out of 6E scope**.

## 24. Publication recommendation

**BLOCKED.** Do not change learner-facing SPL, dashboards, or `Q-MCP-RESULT-AUTHORITY` validation date. `ws_lab_mcp_001` unchanged. Proposed live 1.3.0 re-execution evidence is for owner review only.

## 25. Rollback instructions

1. Do not delete volumes `0aa27f8fe380…` or `8f86409c1fdf…`.
2. Original container `agentsec_splunk` / `f2e67082af2f` remains the data plane.
3. Owner may `docker rm` (no `-v`) leftover `agentsec_splunk_phase6d*` containers.
4. Do not `docker start` the original with host 8000 if NetSpout must reclaim 8000.
5. This report and evidence dir are additive documentation.

## 26. Final Git state

Recorded after commit/push in the SHA table below (filled at closeout).

Evidence: `docs/reviews/phase6e-mcp005-live-evidence/` (SHA256SUMS.json hash `a25a99ccd0b4ba2d8285ef23b0f2dd33758750eb3a370a8485f99d4adac62dd6`).
