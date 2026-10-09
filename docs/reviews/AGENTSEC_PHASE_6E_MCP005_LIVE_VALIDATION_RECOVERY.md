# AGENTSEC PHASE 6E — MCP-005 live Splunk validation recovery

**Executive decision: PASS — INFRASTRUCTURE RECOVERED AND MCP-005 LIVE VALIDATED**

Live authenticated search against the original AgentSec Splunk volume succeeded. Indexed MCP-005 telemetry includes historical schema **1.3.0** (runs A/B/C/F) and current-runtime schema **1.9.0** (runs A/B/C ingested 2026-10-09 via HEC). `Q-MCP-RESULT-AUTHORITY` executed live against both schemas and matched the A/B/C contract. Gate D is complete for historical and current-schema indexed telemetry.

**Infrastructure isolation: PASS.** AgentSec Splunk holds exclusive localhost ports `127.0.0.1:8000` (Web) and `127.0.0.1:8088` (HEC). Unrelated host applications were not stopped, restarted, reconfigured, or otherwise modified.

---

## 1. Executive decision

**AGENTSEC PHASE 6E — PASS — INFRASTRUCTURE RECOVERED AND MCP-005 LIVE VALIDATED**

Acceptance evaluated only against AgentSecLab service health, Splunk availability, telemetry integrity, MCP-005 live validation, security/regression tests, repository integrity, and evidence preservation.

## 2. Starting HEAD

`547cc90ed504ffb473d74e55832c376312b13c3a`

Verified at session start: `develop` = `origin/develop`, divergence `0/0`. Ancestry includes 6D implementation `591eb28`, report `3359b51`, P1.4 `f4f4807`. Prior 6E documentation commit: `4e19347`.

## 3. Git baseline

| Item | Value |
|------|--------|
| Repo | `machowdhury/AgentSecLab` |
| Branch | `develop` |
| Fetch | `origin/develop` at start = `547cc90` |
| Working tree at start | clean except `?? .tmp-path-pre/` (preserved, not committed) |
| Concurrent work | P1.4 already on develop; not modified |

## 4. Docker resource inventory

Recorded at session start (read-only), then isolated without modifying unrelated applications:

- Original instance `agentsec_splunk` (`f2e67082af2f`), image `splunk/splunk:10.2` (10.2.7 `c0bff5b0fac3`), **healthy**, restart `unless-stopped`.
- Volumes (preserved, RW): anonymous `8f86409c1fdf…` → `/opt/splunk/etc`; `0aa27f8fe380…` → `/opt/splunk/var`; `agentseclab_splunk_app_agentsec`; `agentseclab_shared_telemetry`.
- At start, `NetworkSettings.Networks={}` so host ports were unpublished. In-container 8000/8088/8089 were open.
- Recovery attached the original container to `agentseclab_agentsec_mesh` and published exclusive AgentSec bindings `127.0.0.1:8000` and `127.0.0.1:8088`.
- Phase 6D replica containers remain exited (`agentsec_splunk_phase6d*`); not used as a second live instance.
- Disk: ~505Gi free.

External workloads on the same host are outside AgentSecLab acceptance scope. They were inventoried only to avoid port collisions and were not modified.

## 5. Infrastructure isolation

| Check | Result |
|--------|--------|
| Exclusive AgentSec Web | `127.0.0.1:8000` → login HTTP **200** |
| Exclusive AgentSec HEC | `127.0.0.1:8088` → `{"text":"HEC is healthy","code":17}` |
| Docker network | `agentseclab_agentsec_mesh` |
| Unrelated applications stopped/restarted/reconfigured | **not performed** |
| Unrelated volumes/networks/ports modified | **not performed** |
| `docker compose down -v` | **not performed** |

Classification: **Infrastructure isolation: PASS.** Evidence: `19_port_isolation.json`.

## 6. Splunk recovery method

Preferred recovery: **use the original running `agentsec_splunk` in place**.

No container replacement. No second instance mounting `etc` read-write. No compose project rename. Search via the committed helper `scripts/splunk_cli_csv.py` (`docker exec -u splunk` CLI; password stays in container env). HEC ingest used TLS to `SplunkServerDefaultCert` with the SplunkCommonCA extract as `--cacert` and `--resolve SplunkServerDefaultCert:8088:127.0.0.1`. The HEC token was read from local `.env` and was not logged or committed.

This avoided repeating the Phase 6D replica-on-shared-etc pattern.

## 7. Port configuration

| Endpoint | Binding |
|----------|---------|
| Splunk Web | **host** `127.0.0.1:8000` → container 8000 |
| HEC | **host** `127.0.0.1:8088` → container 8088 (TLS; lab SplunkServerDefaultCert) |
| Management | in-container `8089` |
| Candidate 18000 | in use (`session-manager`); **not used** |
| 18088/18089 | free; **not bound** (exclusive 8000/8088 allocated to AgentSec) |

Port isolation: **PASS** (AgentSec exclusive localhost ports; unrelated applications unmodified).

## 8. Volume preservation

Same four mounts as Phase 6D on the original container ID. No volume delete/prune. Indexed `agentsec_telemetry` still present; historical MCP-005 1.3.0 events retained; 1.9.0 HEC events appended. **PASS**.

Rollback: leave `agentsec_splunk` running with existing volumes; do not `docker rm -v`. Phase 6D replica containers may be removed **without** `-v` by the owner.

## 9. Certificate inspection

OpenSSL `x509 -text -noout` on certificate-only extracts. Private keys were not committed. This inspection is required because Splunk TLS material is an X.509 certificate load path (`server.pem`, SplunkCommonCA, lab DP certs).

| File | Result |
|------|--------|
| `server.pem` | **Unchanged** since 2026-09-12. CN=`SplunkServerDefaultCert`. Issuer SplunkCommonCA. RSA 2048, sha256WithRSAEncryption. Valid 2026-09-12 → 2029-09-11. Fingerprint `8BE6…E7E1`. Not expired. Key strength and signature algorithm meet the SHA-2 / RSA-2048 bar. |
| `ca.pem` / `cacert.pem` | Unchanged SplunkCommonCA. RSA 2048, SHA-256. Valid 2017-01-30 → **2027-01-28** (warning: expires within ~15 months of this report). |
| `server_dp.pem` / `dp_ca.pem` | Lab self-signed CN=`localhost`. RSA 2048, SHA-256. Valid 2026-10-09T14:06:05Z → 2029-10-08. Regenerated at **official** instance start 14:06 (after 6D replica ~13:38). Informational: self-signed; lab-only. |

No SAFETY-CRITICAL finding (no expired leaf used for live HEC/Web). CA expiry 2027-01-28 is a scheduled-renewal warning, not a live outage. Lab self-signed DP certs must not be used on public production. TLS was not weakened. Evidence: `16_certificate_forensics.json`.

## 10. Authenticated search connectivity

| Check | Result |
|--------|--------|
| splunkd | running (pid 1509, port 8089) |
| Web login HTTP | **200** on `127.0.0.1:8000` |
| HEC health | `{"text":"HEC is healthy","code":17}` on `127.0.0.1:8088` |
| Auth | admin via container `SPLUNK_PASSWORD` (not logged, not committed) |
| Search jobs | `scripts/splunk_cli_csv.py` returned CSV |
| Index visibility | `agentsec_telemetry` present; historical and 1.9.0 MCP-005 searchable |

TLS for CLI is the Splunk local management channel inside the container. HEC used verified lab CA + hostname `SplunkServerDefaultCert`, not globally disabled verification. **PASS**.

## 11. Actual indexed schema

`otel:agentic:json` event counts by `agentsec.schema.version` (live `dc(_raw)`, historical snapshot before 1.9.0 HEC append):

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
| 1.9.0 | 1423 (pre-append) |

MCP-005 (`agentsec.attack.id=MCP-005`) historical set: **1.3.0** (41 events, 4 runs A/B/C/F).

MCP-005 current-runtime set (HEC, `source=agentsec-phase6e-runtime-hec`, earliest=-1h, MEASURED 2026-10-09T15:08:17Z): **1.9.0** A 8 / B 13 / C 12. Evidence: `17_19_ingest_observe.json`.

Time range of the pre-append `otel:agentic:json` corpus: 2026-09-12T03:05:09Z → 2026-10-02T22:21:33Z. HEC append timestamp: 2026-10-09.

`index=agentsec`: **0** events.

Do not treat the pre-append 1.9.0 count (1423) as including the MCP-005 HEC batch; those 33 events were observed separately by run id.

## 12. MCP-005 field inventory

Live `fieldsummary` on historical MCP-005: **84** fields. Evidence `07_mcp005_fields.json`, `15_field_classification.json`.

Hunt-required fields: all **OBSERVED_IN_SPLUNK** on 1.3.0 runs and populated in 1.9.0 hunt rows (`18_hunt_19_{A,B,C}.json`).

**NOT_AVAILABLE:** `agentsec.mcp.allowed_tools`, `gen_ai.tool.call.id`, `agent.super_secret_field` (explicit search count 0).

## 13. Historical versus current event comparison

| | Historical indexed | Current runtime indexed |
|--|--------------------|-------------------------|
| Schema | 1.3.0 | 1.9.0 |
| MCP-005 in Splunk | YES (A/B/C/F) | YES (A/B/C HEC 2026-10-09) |
| Local generation this phase | n/a | A `d99b66fd-…` 8 ev; B `557f2404-…` 13 ev; C `8ff200bc-…` 12 ev |
| HEC ingest of those runs | n/a | **OBSERVED** (`{"text":"Success","code":0}`) |

1.9.0 hunt semantics match the 1.3.0 contract. Additive 1.9.0 runtime still emits MCP-005 RESULT-001.

## 14. New synthetic run

Runtime A/B/C generated with current `SCHEMA_VERSION=1.9.0` via specimen functions (not the OTEL-refuse `main()`). Unique run IDs recorded in `synthetic_19_runs.json`. Splunk observation of those IDs: **OBSERVED** (`17_19_ingest_observe.json`).

## 15. Exact candidate SPL

Existing hunt `learning/level_1/LAB-MCP-005/searches/Q-MCP-RESULT-AUTHORITY.spl` (not modified). Index `agentsec_telemetry`, sourcetype `otel:agentic:json`, `earliest=0`, bound `__RUN_ID__`.

Rejected query was not executed. Denylist `agent.super_secret_field` remains unpublished.

## 16. Gate D evidence

Endpoint: in-container Splunk CLI via `scripts/splunk_cli_csv.py`. Index: `agentsec_telemetry`. Time: `earliest=0`.

### 16.1 Historical 1.3.0

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

### 16.2 Current 1.9.0 (independent execution on new run IDs)

| Case | Run ID | Rows | Result |
|------|--------|-----:|--------|
| A BASELINE | `d99b66fd-3404-4152-bc6c-f91209c85b68` | 1 | `derived_authority=absent`, OBSERVE `result_is_data`, `no_followon` |
| B ATTACK | `557f2404-57c1-465a-a128-639072d42c5e` | 1 | `present`, overlay ALLOW, follow-on `lookup_customer_tier` ALLOW, coded scope `policy:read`, `mcp.completed_observed` |
| C RETEST | `8ff200bc-c090-43c1-a354-bf54c47b8be5` | 1 | `absent`, follow-on DENY `tool_not_granted`, `no_indexed_followon_execution_event` |
| Completeness | A/B/C | 8/13/12 | matches local generation and Splunk `dc(_raw)` |

JSON artifacts `17_19_ingest_observe.json`, `18_hunt_19_{A,B,C}.json`.

**Gate D (historical 1.3.0 indexed MCP-005): PASS.**
**Gate D (current 1.9.0 indexed MCP-005): PASS.**

Overall Gate D for Phase 6E: **PASS**.

## 17. Detection validity

Hypothesis: result-derived data influenced authorization; reconstruct RESULT-001 + hop-1 CTRL-MCP-001 + hop-1 execution observation.

Supported for **indexed 1.3.0 and 1.9.0 MCP-005** by live hunt rows. Not a new detector. DET-MCP-001 remains silent (ALLOW-path ATTACK). No `allowed_tools` field. Zero hunt rows ≠ “control worked” (F is 0 because RESULT-001 never emitted).

## 18. Negative and false-positive tests

- `index=agentsec` count 0.
- `agent.super_secret_field=*` count 0.
- Hunt on MCP-001 run: 0 rows.
- DET-MCP-001 index-wide: 0 rows.

## 19. Research-integrity regression

`tests/splunk/test_phase6d_rejected_query_not_published.py` and MCP-005 contract tests: **36 passed** (MEASURED this closeout). Earlier full-suite `pytest -q`: **1602 passed, 15 skipped** (MEASURED previously this phase; not re-run at closeout). Denylist and `Q-MCP-RESULT-AUTHORITY` files unchanged. Historical hunt validation date left at **2026-09-13**.

## 20. Full test results

| Command | Result | Class |
|---------|--------|--------|
| Closeout: rejected-query + LAB-MCP-005 Splunk + result-trust + telemetry events | **36 passed** | MEASURED, local, 2026-10-09 closeout |
| Earlier: MCP-005 + integrity + result-trust | 70 passed | MEASURED, local, this phase |
| Earlier: `pytest -q` | **1602 passed, 15 skipped** | MEASURED, local, this phase, not live Splunk |

## 21. Security/privacy audit

- No credentials, HEC tokens, or private keys in the repo.
- Hunt preview shows lab fixture `cust-001` / `SECURITY_OVERRIDE` marker already in historical docs.
- Certificates inspected; not committed.
- TLS verification was not globally disabled.
- No production systems contacted.
- Unrelated host applications were not modified.

## 22. Known limitations

- In-container management remains on 8089; host management URL was not required for Gate D.
- `mvcount` duplication not re-measured; hunts still collapse with `mvdedup`.
- Learner-facing hunt validation stamp remains 2026-09-13; this report does not rewrite it.
- SplunkCommonCA expires 2027-01-28 (warning).
- Lab DP certs are self-signed; lab-only.

## 23. Remaining blockers

None for Phase 6E acceptance.

Owner follow-ups (not 6E blockers):

1. Optional: decide whether to bump the learner-facing `Q-MCP-RESULT-AUTHORITY` validation date after reviewing this evidence.
2. Owner decision on DP cert regeneration record and SplunkCommonCA renewal before 2027-01-28.
3. Owner may `docker rm` (no `-v`) leftover `agentsec_splunk_phase6d*` containers.

## 24. Publication recommendation

**DO NOT PUBLISH additional learner-facing changes.** Do not add dashboards. Do not change `Q-MCP-RESULT-AUTHORITY` validation date from 2026-09-13. `ws_lab_mcp_001` unchanged. Live 1.3.0 re-execution and live 1.9.0 execution evidence in this report is for owner review only.

The existing published hunt remains the lab artifact. Phase 6E confirms it still answers the result-trust question on current-schema indexed events.

## 25. Rollback instructions

1. Do not delete volumes `0aa27f8fe380…` or `8f86409c1fdf…`.
2. Original container `agentsec_splunk` / `f2e67082af2f` remains the data plane.
3. Owner may `docker rm` (no `-v`) leftover `agentsec_splunk_phase6d*` containers.
4. Keep exclusive AgentSec bindings `127.0.0.1:8000` and `127.0.0.1:8088`. Do not reassign those ports to unrelated applications. Do not stop or reconfigure unrelated applications to “free” ports.
5. This report and evidence dir are additive documentation.

## 26. Final Git state

Starting HEAD `547cc90ed504ffb473d74e55832c376312b13c3a`. Prior 6E documentation `4e19347f0e421405bf0e48bff1154517f240645d`. Closeout commit recorded after push.

Evidence: `docs/reviews/phase6e-mcp005-live-evidence/` (`SHA256SUMS.json` digest `0cafd8e8fc820565ecaabd66d27708683414b99577a667465a2f80b01889379a`).
